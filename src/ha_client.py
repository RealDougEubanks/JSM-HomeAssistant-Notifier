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
import urllib.parse
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT = 10.0

# Priority → (spoken label, emoji)
_PRIORITY_META: Dict[str, tuple[str, str]] = {
    "P1": ("Priority 1, Critical",   "🔴"),
    "P2": ("Priority 2, High",       "🟠"),
    "P3": ("Priority 3, Medium",     "🟡"),
    "P4": ("Priority 4, Low",        "🟢"),
    "P5": ("Priority 5, Information","⚪"),
}

# Maximum characters kept from the description inside a TTS message.
_DESC_MAX_CHARS = 200


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
        volume_default: Optional[float] = None,
        volume_terse: Optional[float] = None,
    ) -> None:
        self.ha_url = ha_url.rstrip("/")
        self.media_player = media_player
        self.tts_service = tts_service      # e.g. "tts.home_assistant_cloud"
        self.tts_language = tts_language    # e.g. "en-US"
        self.tts_voice = tts_voice          # e.g. "JennyNeural"
        self.notifier_label = notifier_label  # shown as "artist" in media player UI
        self.announcement_format = announcement_format
        self.terse_announcement_format = terse_announcement_format
        self.volume_default = volume_default
        self.volume_terse = volume_terse
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

    def _format_vars(self, alert: Any, action: str) -> Dict[str, str]:
        """Return the common template variables for announcement formats."""
        spoken_priority, _ = _PRIORITY_META.get(
            alert.priority, ("Unknown priority", "⚠️")
        )
        action_prefix = "Escalated alert!" if action == "EscalateNext" else "Attention!"

        entity_part = f" System: {alert.entity}." if alert.entity else ""

        description_part = ""
        if alert.description:
            desc = alert.description[:_DESC_MAX_CHARS]
            if len(alert.description) > _DESC_MAX_CHARS:
                desc += "..."
            description_part = f" Details: {desc}."

        return {
            "action_prefix": action_prefix,
            "priority": spoken_priority,
            "message": alert.message,
            "entity": alert.entity or "",
            "description": (alert.description or "")[:_DESC_MAX_CHARS],
            "entity_part": entity_part,
            "description_part": description_part,
        }

    def _build_tts_text(self, alert: Any, action: str) -> str:
        """Compose the spoken TTS announcement using the configured format."""
        variables = self._format_vars(alert, action)
        return self.announcement_format.format(**variables)

    def _build_terse_tts_text(self, alert: Any, action: str) -> str:
        """Compose a short TTS announcement using the terse format."""
        variables = self._format_vars(alert, action)
        return self.terse_announcement_format.format(**variables)

    def _build_media_metadata(self, alert: Any, action: str) -> Dict[str, Any]:
        """Build the rich metadata block shown in the HA media player UI."""
        _, emoji = _PRIORITY_META.get(alert.priority, ("Unknown", "⚠️"))

        title = f"{emoji} {alert.priority}: {alert.message}"
        if action == "EscalateNext":
            title = f"⬆️ ESCALATED — {title}"
        if len(title) > 80:
            title = title[:77] + "…"

        artist = self.notifier_label
        album = alert.entity or "JSM Alert"

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
        self, domain: str, service: str, payload: Dict[str, Any]
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
        target_entity: Optional[str] = None,
    ) -> bool:
        """
        Play a TTS announcement on the configured media player with rich
        metadata so the player displays the actual alert title.

        If *terse* is True, the short announcement format is used.
        If *target_entity* is given, play on that entity instead of the default.
        """
        entity = target_entity or self.media_player

        # Set volume before playback if configured.
        volume = self.volume_terse if terse and self.volume_terse is not None else self.volume_default
        if volume is not None:
            await self._set_volume(entity, volume)

        if terse:
            tts_text = self._build_terse_tts_text(alert, action)
        else:
            tts_text = self._build_tts_text(alert, action)
        content_id = self._build_tts_content_id(tts_text)
        metadata = self._build_media_metadata(alert, action)

        payload: Dict[str, Any] = {
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
        self, alerts: list[Any], actions: list[str], *, target_entity: Optional[str] = None,
    ) -> bool:
        """Play a batched announcement for multiple alerts."""
        entity = target_entity or self.media_player
        if self.volume_default is not None:
            await self._set_volume(entity, self.volume_default)

        parts = [f"{len(alerts)} new alerts."]
        for alert, action in zip(alerts, actions):
            variables = self._format_vars(alert, action)
            parts.append(f"{variables['priority']}: {alert.message}.")

        tts_text = " ".join(parts)
        content_id = self._build_tts_content_id(tts_text)

        # Use the first alert for metadata display.
        metadata = self._build_media_metadata(alerts[0], actions[0])
        metadata["title"] = f"Batch: {len(alerts)} alerts"

        payload: Dict[str, Any] = {
            "entity_id": entity,
            "media_content_id": content_id,
            "media_content_type": "provider",
            "extra": {
                "metadata": {
                    **metadata,
                    "navigateIds": [
                        {},
                        {"media_content_type": "app", "media_content_id": "media-source://tts"},
                        {"media_content_type": "provider", "media_content_id": content_id},
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
        than duplicate.
        """
        _, emoji = _PRIORITY_META.get(alert.priority, ("Unknown", "⚠️"))

        title = f"{emoji} JSM {alert.priority} Alert"
        if action == "EscalateNext":
            title = f"⬆️ ESCALATED — {title}"

        lines = [f"**{alert.message}**", ""]
        if alert.entity:
            lines.append(f"**System:** {alert.entity}")
        if alert.source:
            lines.append(f"**Source:** {alert.source}")
        if alert.description:
            lines.append(f"\n{alert.description}")

        payload = {
            "notification_id": f"jsm_alert_{alert.alertId}",
            "title": title,
            "message": "\n".join(lines),
        }

        logger.info(
            "Creating persistent notification for alert %s", alert.alertId
        )
        return await self._call_service(
            "persistent_notification", "create", payload
        )

    async def dismiss_notification(self, alert_id: str) -> bool:
        """Dismiss the persistent notification when an alert is closed/acked."""
        payload = {"notification_id": f"jsm_alert_{alert_id}"}
        return await self._call_service(
            "persistent_notification", "dismiss", payload
        )

    async def play_tts_message(self, text: str) -> bool:
        """Play an arbitrary TTS string — used for system alerts like token expiry."""
        content_id = self._build_tts_content_id(text)
        payload: Dict[str, Any] = {
            "entity_id": self.media_player,
            "media_content_id": content_id,
            "media_content_type": "provider",
            "extra": {
                "metadata": {
                    "title": "⚠️ JSM Notifier System Alert",
                    "artist": self.notifier_label,
                    "media_class": "app",
                    "children_media_class": None,
                    "navigateIds": [
                        {},
                        {"media_content_type": "app", "media_content_id": "media-source://tts"},
                        {"media_content_type": "provider", "media_content_id": content_id},
                    ],
                }
            },
        }
        return await self._call_service("media_player", "play_media", payload)

    async def send_credential_alert(self, error_detail: str = "") -> None:
        """
        Fire a TTS announcement and a persistent HA notification when the
        Atlassian API token is invalid or has expired.  Both calls are attempted
        regardless of whether the first one fails.
        """
        tts_text = (
            "Warning! The Atlassian API token used by your JSM alert notifier "
            "is invalid or has expired. You will not receive on-call alerts "
            "until the token is updated in the dot-env configuration file."
        )
        notif_message = (
            "The `JSM_API_TOKEN` in your `.env` file is invalid or has been revoked.\n\n"
            f"**Error:** {error_detail}\n\n"
            "**Action required:** Create a new token at "
            "https://id.atlassian.com/manage-profile/security/api-tokens "
            "and update `JSM_API_TOKEN` in `.env`, then run `docker compose restart`."
        )

        # Fire both — don't let a TTS failure block the dashboard notification.
        tts_ok = await self.play_tts_message(tts_text)
        notif_ok = await self._call_service(
            "persistent_notification",
            "create",
            {
                "notification_id": "jsm_notifier_credential_alert",
                "title": "⚠️ JSM Notifier: Invalid API Token",
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
                url, headers=self._headers, timeout=_REQUEST_TIMEOUT,
            )
            if resp.status_code == 401:
                return False, "401 Unauthorized — HA token is invalid"
            resp.raise_for_status()
            return True, ""
        except Exception as exc:
            return False, str(exc)

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
