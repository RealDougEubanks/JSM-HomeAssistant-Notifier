"""
Async Home Assistant REST API client.

Responsibilities:
  1. Build a natural-language TTS announcement from alert data, including
     priority, title, entity, and a truncated description.
  2. Call media_player.play_media with rich metadata so HA shows the real
     alert title instead of "Playing Default Media Receiver".
  3. Create/update a persistent_notification so the alert is visible in the
     HA dashboard even after the audio plays.

All calls are fire-and-forget safe — errors are logged but do not raise, so
a transient HA outage cannot break the webhook handler.
"""

from __future__ import annotations

import logging
import re
import string
import urllib.parse
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT = 10.0

# Priority → (spoken label, emoji)
_PRIORITY_META: dict[str, tuple[str, str]] = {
    "P1": ("Priority 1, Critical", "🔴"),
    "P2": ("Priority 2, High", "🟠"),
    "P3": ("Priority 3, Medium", "🟡"),
    "P4": ("Priority 4, Low", "🟢"),
    "P5": ("Priority 5, Information", "⚪"),
}

# Maximum characters kept from the description inside a TTS message.
_DESC_MAX_CHARS = 200


class _SafeFormatter(string.Formatter):
    """
    A restricted str.format() replacement that only allows simple field names.

    Standard ``str.format()`` permits attribute access (``{obj.__class__}``)
    and index lookups (``{obj[0]}``), which is a potential information-disclosure
    or DoS vector when the format string comes from user-configurable input
    (e.g. the .env file).

    This formatter rejects any format field that contains ``.`` or ``[``
    characters, limiting templates to plain ``{name}`` placeholders only.
    """

    def get_field(self, field_name: str, args: Any, kwargs: Any) -> Any:
        # Reject attribute access ({foo.bar}) and index access ({foo[0]}).
        if "." in field_name or "[" in field_name:
            raise ValueError(
                f"Unsafe format field {field_name!r} — "
                "only simple {{name}} placeholders are allowed"
            )
        return super().get_field(field_name, args, kwargs)


_safe_fmt = _SafeFormatter()

# Characters that could be interpreted as shell metacharacters, command
# substitution, or script injection if the TTS text or notification content
# is ever passed through a shell, template engine, or markup renderer.
_SHELL_META_RE = re.compile(r"[`$;|&<>{}()\\\x00-\x1f]")


def _sanitize(text: str) -> str:
    """Strip shell metacharacters and control characters from untrusted text."""
    return _SHELL_META_RE.sub("", text)


# Broad regex covering the main Unicode emoji ranges.  Used when emojis are
# disabled to strip both internal priority emojis and any emojis arriving in
# incoming alert text from JSM or other sources.
_EMOJI_RE = re.compile(
    "["
    "\U0001f600-\U0001f64f"  # Emoticons
    "\U0001f300-\U0001f5ff"  # Misc Symbols and Pictographs
    "\U0001f680-\U0001f6ff"  # Transport and Map
    "\U0001f1e0-\U0001f1ff"  # Flags
    "\U0001f900-\U0001f9ff"  # Supplemental Symbols and Pictographs
    "\U0001fa00-\U0001fa6f"  # Chess Symbols
    "\U0001fa70-\U0001faff"  # Symbols and Pictographs Extended-A
    "\U00002702-\U000027b0"  # Dingbats
    "\U000024c2-\U0001f251"  # Enclosed characters
    "\U0000fe0f"  # Variation Selector-16
    "\U0000200d"  # Zero Width Joiner
    "\U00002600-\U000026ff"  # Misc symbols (⚠, ⬆, ☀, etc.)
    "\U00002b05-\U00002b55"  # Arrows and geometric shapes
    "]+",
    flags=re.UNICODE,
)


def _strip_emojis(text: str) -> str:
    """Remove all emoji characters and clean up leftover whitespace."""
    return _EMOJI_RE.sub("", text).strip()


class HAClient:
    def __init__(
        self,
        ha_url: str,
        ha_token: str,
        media_player: str,
        tts_service: str,
        tts_language: str,
        tts_voice: str,
        notifier_label: str = "JSM Alert Notifier",
        announcement_format: str = (
            "{action_prefix} {priority} alert from Jira Service Management. "
            "Alert: {message}.{entity_part}{description_part}"
        ),
        terse_announcement_format: str = "{action_prefix} {priority} alert. {message}.",
        volume_default: float | None = None,
        volume_terse: float | None = None,
        enable_emojis: bool = True,
    ) -> None:
        self.ha_url = ha_url.rstrip("/")
        self.media_player = media_player
        self.tts_service = tts_service  # e.g. "tts.home_assistant_cloud"
        self.tts_language = tts_language  # e.g. "en-US"
        self.tts_voice = tts_voice  # e.g. "JennyNeural"
        self.notifier_label = notifier_label  # shown as "artist" in media player UI
        self.announcement_format = announcement_format
        self.terse_announcement_format = terse_announcement_format
        self.volume_default = volume_default
        self.volume_terse = volume_terse
        self.enable_emojis = enable_emojis
        self._headers = {
            "Authorization": f"Bearer {ha_token}",
            "Content-Type": "application/json",
        }
        # Persistent HTTP client — reused across requests to avoid socket churn.
        self._http: httpx.AsyncClient = httpx.AsyncClient(trust_env=False)

    async def aclose(self) -> None:
        """Close the underlying HTTP client.  Called during application shutdown."""
        await self._http.aclose()

    # ── Message building ──────────────────────────────────────────────────

    def _clean(self, text: str) -> str:
        """Sanitize text and optionally strip emojis."""
        text = _sanitize(text)
        if not self.enable_emojis:
            text = _strip_emojis(text)
        return text

    def _emoji(self, emoji: str) -> str:
        """Return *emoji* when emojis are enabled, otherwise empty string."""
        return emoji if self.enable_emojis else ""

    def _format_vars(self, alert: Any, action: str) -> dict[str, str]:
        """Return the common template variables for announcement formats.

        All alert-sourced fields are sanitized to strip shell metacharacters
        and control characters before they reach TTS or notification output.
        When emojis are disabled, emoji characters in alert text are also stripped.
        """
        spoken_priority, _ = _PRIORITY_META.get(
            alert.priority, ("Unknown priority", "⚠️")
        )
        action_prefix = "Escalated alert!" if action == "EscalateNext" else "Attention!"

        message = self._clean(alert.message)
        entity = self._clean(alert.entity) if alert.entity else ""
        description = (
            self._clean(alert.description)[:_DESC_MAX_CHARS] if alert.description else ""
        )

        entity_part = f" System: {entity}." if entity else ""
        description_part = ""
        if description:
            desc = description
            if alert.description and len(alert.description) > _DESC_MAX_CHARS:
                desc += "..."
            description_part = f" Details: {desc}."

        return {
            "action_prefix": action_prefix,
            "priority": spoken_priority,
            "message": message,
            "entity": entity,
            "description": description,
            "entity_part": entity_part,
            "description_part": description_part,
        }

    def _build_tts_text(self, alert: Any, action: str) -> str:
        """Compose the spoken TTS announcement using the configured format."""
        variables = self._format_vars(alert, action)
        return _safe_fmt.format(self.announcement_format, **variables)

    def _build_terse_tts_text(self, alert: Any, action: str) -> str:
        """Compose a short TTS announcement using the terse format."""
        variables = self._format_vars(alert, action)
        return _safe_fmt.format(self.terse_announcement_format, **variables)

    def _build_media_metadata(self, alert: Any, action: str) -> dict[str, Any]:
        """Build the rich metadata block shown in the HA media player UI."""
        _, emoji = _PRIORITY_META.get(alert.priority, ("Unknown", "⚠️"))

        message = self._clean(alert.message)
        prefix = f"{self._emoji(emoji)} " if emoji else ""
        title = f"{prefix}{alert.priority}: {message}".strip()
        if action == "EscalateNext":
            esc_prefix = (
                f"{self._emoji('⬆️')} ESCALATED — "
                if self.enable_emojis
                else "ESCALATED — "
            )
            title = f"{esc_prefix}{title}"
        if len(title) > 80:
            title = title[:77] + "…"

        artist = self.notifier_label
        album = self._clean(alert.entity) if alert.entity else "JSM Alert"

        return {
            "title": title,
            "artist": artist,
            "album": album,
            "media_class": "app",
            "children_media_class": None,
        }

    def _build_tts_content_id(self, tts_text: str) -> str:
        """Encode the TTS text into the HA media-source URI."""
        encoded = urllib.parse.quote(tts_text, safe="")
        return (
            f"media-source://tts/{self.tts_service}"
            f"?message={encoded}"
            f"&language={self.tts_language}"
            f"&voice={self.tts_voice}"
        )

    # ── HA service calls ──────────────────────────────────────────────────

    async def _call_service(
        self, domain: str, service: str, payload: dict[str, Any]
    ) -> bool:
        """POST to /api/services/{domain}/{service}.  Returns True on success."""
        url = f"{self.ha_url}/api/services/{domain}/{service}"
        try:
            resp = await self._http.post(
                url,
                headers=self._headers,
                json=payload,
                timeout=_REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            return True
        except httpx.HTTPStatusError as exc:
            logger.error(
                "HA service call %s.%s failed: HTTP %s — %s",
                domain,
                service,
                exc.response.status_code,
                exc.response.text[:200],
            )
        except Exception as exc:
            logger.error("HA service call %s.%s error: %s", domain, service, exc)
        return False

    async def _set_volume(self, entity_id: str, volume: float) -> bool:
        """Set volume on a media player entity (0.0–1.0)."""
        payload = {"entity_id": entity_id, "volume_level": volume}
        logger.info("Setting volume on %s to %.2f", entity_id, volume)
        return await self._call_service("media_player", "volume_set", payload)

    async def play_tts_alert(
        self,
        alert: Any,
        action: str = "Create",
        *,
        terse: bool = False,
        target_entity: str | None = None,
    ) -> bool:
        """
        Play a TTS announcement on the configured media player with rich
        metadata so the player displays the actual alert title.

        If *terse* is True, the short announcement format is used.
        If *target_entity* is given, play on that entity instead of the default.
        """
        entity = target_entity or self.media_player

        # Set volume before playback if configured.
        volume = (
            self.volume_terse
            if terse and self.volume_terse is not None
            else self.volume_default
        )
        if volume is not None:
            await self._set_volume(entity, volume)

        if terse:
            tts_text = self._build_terse_tts_text(alert, action)
        else:
            tts_text = self._build_tts_text(alert, action)
        content_id = self._build_tts_content_id(tts_text)
        metadata = self._build_media_metadata(alert, action)

        payload: dict[str, Any] = {
            "entity_id": entity,
            "media_content_id": content_id,
            "media_content_type": "provider",
            "extra": {
                "metadata": {
                    **metadata,
                    "navigateIds": [
                        {},
                        {
                            "media_content_type": "app",
                            "media_content_id": "media-source://tts",
                        },
                        {
                            "media_content_type": "provider",
                            "media_content_id": content_id,
                        },
                    ],
                }
            },
        }

        logger.info(
            "Playing TTS: entity=%s title=%r terse=%s",
            entity,
            metadata["title"],
            terse,
        )
        return await self._call_service("media_player", "play_media", payload)

    async def play_tts_batch(
        self,
        alerts: list[Any],
        actions: list[str],
        *,
        target_entity: str | None = None,
    ) -> bool:
        """Play a batched announcement for multiple alerts."""
        entity = target_entity or self.media_player
        if self.volume_default is not None:
            await self._set_volume(entity, self.volume_default)

        parts = [f"{len(alerts)} new alerts."]
        for alert, action in zip(alerts, actions, strict=False):
            variables = self._format_vars(alert, action)
            parts.append(f"{variables['priority']}: {alert.message}.")

        tts_text = " ".join(parts)
        content_id = self._build_tts_content_id(tts_text)

        # Use the first alert for metadata display.
        metadata = self._build_media_metadata(alerts[0], actions[0])
        metadata["title"] = f"Batch: {len(alerts)} alerts"

        payload: dict[str, Any] = {
            "entity_id": entity,
            "media_content_id": content_id,
            "media_content_type": "provider",
            "extra": {
                "metadata": {
                    **metadata,
                    "navigateIds": [
                        {},
                        {
                            "media_content_type": "app",
                            "media_content_id": "media-source://tts",
                        },
                        {
                            "media_content_type": "provider",
                            "media_content_id": content_id,
                        },
                    ],
                }
            },
        }

        logger.info("Playing batched TTS for %d alerts on %s", len(alerts), entity)
        return await self._call_service("media_player", "play_media", payload)

    async def send_persistent_notification(
        self, alert: Any, action: str = "Create"
    ) -> bool:
        """
        Create (or replace) a persistent notification in HA for the alert.
        Uses the alertId as notification_id so re-deliveries update rather
        than duplicate.  All alert-sourced text is sanitized.
        """
        _, emoji = _PRIORITY_META.get(alert.priority, ("Unknown", "⚠️"))

        prefix = f"{self._emoji(emoji)} " if emoji else ""
        title = f"{prefix}JSM {alert.priority} Alert".strip()
        if action == "EscalateNext":
            esc_prefix = (
                f"{self._emoji('⬆️')} ESCALATED — "
                if self.enable_emojis
                else "ESCALATED — "
            )
            title = f"{esc_prefix}{title}"

        message = self._clean(alert.message)
        entity = self._clean(alert.entity) if alert.entity else ""
        source = self._clean(alert.source) if alert.source else ""
        description = self._clean(alert.description) if alert.description else ""

        lines = [f"**{message}**", ""]
        if entity:
            lines.append(f"**System:** {entity}")
        if source:
            lines.append(f"**Source:** {source}")
        if description:
            lines.append(f"\n{description}")

        payload = {
            "notification_id": f"jsm_alert_{alert.alertId}",
            "title": title,
            "message": "\n".join(lines),
        }

        logger.info("Creating persistent notification for alert %s", alert.alertId)
        return await self._call_service("persistent_notification", "create", payload)

    async def dismiss_notification(self, alert_id: str) -> bool:
        """Dismiss the persistent notification when an alert is closed/acked."""
        payload = {"notification_id": f"jsm_alert_{alert_id}"}
        return await self._call_service("persistent_notification", "dismiss", payload)

    async def play_tts_message(self, text: str) -> bool:
        """Play an arbitrary TTS string — used for system alerts like token expiry."""
        content_id = self._build_tts_content_id(text)
        payload: dict[str, Any] = {
            "entity_id": self.media_player,
            "media_content_id": content_id,
            "media_content_type": "provider",
            "extra": {
                "metadata": {
                    "title": f"{self._emoji('⚠️')} JSM Notifier System Alert".strip(),
                    "artist": self.notifier_label,
                    "media_class": "app",
                    "children_media_class": None,
                    "navigateIds": [
                        {},
                        {
                            "media_content_type": "app",
                            "media_content_id": "media-source://tts",
                        },
                        {
                            "media_content_type": "provider",
                            "media_content_id": content_id,
                        },
                    ],
                }
            },
        }
        return await self._call_service("media_player", "play_media", payload)

    async def send_credential_alert(
        self, error_detail: str = "", *, suppress_tts: bool = False
    ) -> None:
        """
        Fire a TTS announcement and a persistent HA notification when the
        Atlassian API token is invalid or has expired.  Both calls are attempted
        regardless of whether the first one fails.

        If *suppress_tts* is True, the TTS announcement is skipped (e.g. during
        silent/quiet hours) but the persistent notification is still created so
        the user sees it on the dashboard.
        """
        tts_text = (
            "Warning! The Atlassian API token used by your JSM alert notifier "
            "is invalid or has expired. You will not receive on-call alerts "
            "until the token is updated in the dot-env configuration file."
        )
        notif_message = (
            "The `JSM_API_TOKEN` in your `.env` file is invalid or has been revoked.\n\n"
            f"**Error:** {_sanitize(error_detail)}\n\n"
            "**Action required:** Create a new token at "
            "https://id.atlassian.com/manage-profile/security/api-tokens "
            "and update `JSM_API_TOKEN` in `.env`, then run `docker compose restart`."
        )

        tts_ok: bool | str
        if suppress_tts:
            tts_ok = "suppressed (quiet hours)"
        else:
            tts_ok = await self.play_tts_message(tts_text)

        notif_ok = await self._call_service(
            "persistent_notification",
            "create",
            {
                "notification_id": "jsm_notifier_credential_alert",
                "title": f"{self._emoji('⚠️')} JSM Notifier: Invalid API Token".strip(),
                "message": notif_message,
            },
        )
        logger.warning(
            "Credential alert dispatched — tts=%s  notification=%s",
            tts_ok,
            notif_ok,
        )

    async def verify_connectivity(self) -> tuple[bool, str]:
        """
        Quick check that the HA REST API is reachable and the token is valid.
        Returns (True, "") on success or (False, detail) on failure.
        """
        url = f"{self.ha_url}/api/"
        try:
            resp = await self._http.get(
                url,
                headers=self._headers,
                timeout=_REQUEST_TIMEOUT,
            )
            if resp.status_code == 401:
                return False, "401 Unauthorized — HA token is invalid"
            resp.raise_for_status()
            return True, ""
        except Exception as exc:
            return False, str(exc)

    # Allowed characters in HA webhook IDs.
    _WEBHOOK_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,200}$")

    async def fire_webhook(self, webhook_id: str, data: dict[str, Any]) -> bool:
        """
        POST to HA's webhook trigger endpoint.

        HA webhook triggers don't require authentication — they are fired
        via ``/api/webhook/{webhook_id}`` and pass the JSON body as trigger
        variables to any automation with a matching ``webhook`` trigger.
        """
        if not self._WEBHOOK_ID_RE.match(webhook_id):
            logger.warning("Rejecting invalid HA webhook ID: %r", webhook_id)
            return False
        url = f"{self.ha_url}/api/webhook/{webhook_id}"
        try:
            resp = await self._http.post(
                url,
                json=data,
                timeout=_REQUEST_TIMEOUT,
            )
            # HA returns 200 even if no automation matches — that's fine.
            resp.raise_for_status()
            logger.info("Fired HA webhook %s", webhook_id)
            return True
        except Exception as exc:
            logger.error("Failed to fire HA webhook %s: %s", webhook_id, exc)
            return False

    async def fire_webhooks(
        self,
        webhook_ids: str,
        data: dict[str, Any],
    ) -> None:
        """Fire one or more comma-separated HA webhook IDs."""
        if not webhook_ids.strip():
            return
        for wid in webhook_ids.split(","):
            wid = wid.strip()
            if wid:
                await self.fire_webhook(wid, data)

    async def dismiss_credential_alert(self) -> None:
        """
        Silently dismiss the 'invalid token' persistent notification from HA.
        Called after a successful credential check so a stale warning doesn't
        linger in the dashboard after a token rotation.
        HA returns 200 even if the notification doesn't exist, so this is safe
        to call unconditionally on every successful check.
        """
        await self._call_service(
            "persistent_notification",
            "dismiss",
            {"notification_id": "jsm_notifier_credential_alert"},
        )
