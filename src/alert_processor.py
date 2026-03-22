"""
Core alert routing and notification logic.

Decision tree for each incoming webhook
────────────────────────────────────────
1.  Is the action one we care about?      (Create | EscalateNext)
    No  → drop silently.

2.  Have we already processed this exact alert+action recently?
    Yes → drop (dedup).

3.  Was always_notify=True passed from the route?
    Yes → notify immediately (Internal Systems_schedule etc.)

4.  Is action == EscalateNext AND is the recipient / any responder me?
    Yes → notify (escalation path).

5.  Is action == Create AND am I currently on-call for any watched schedule?
    Yes → notify.

6.  None of the above → drop.

Bonus: on Close / Acknowledge actions we dismiss the persistent HA
       notification (no TTS spam).
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from typing import Dict, Optional, Tuple

from .config import Settings
from .ha_client import HAClient
from .jsm_client import JSMClient
from .models import JSMWebhookPayload
from .time_windows import in_any_window

logger = logging.getLogger(__name__)

# Actions that produce an audible / visible notification.
_NOTIFY_ACTIONS = {"Create", "EscalateNext"}

# Actions that should dismiss the persistent HA notification.
_DISMISS_ACTIONS = {"Acknowledge", "Close"}


class AlertProcessor:
    def __init__(
        self,
        settings: Settings,
        jsm_client: JSMClient,
        ha_client: HAClient,
    ) -> None:
        self.settings = settings
        self.jsm_client = jsm_client
        self.ha_client = ha_client
        # alert_key → epoch timestamp of last processing
        self._dedup_cache: Dict[str, float] = {}

    # ── Deduplication ─────────────────────────────────────────────────────

    def _dedup_key(self, payload: JSMWebhookPayload) -> str:
        return f"{payload.alert.alertId}:{payload.action}"

    def _is_duplicate(self, payload: JSMWebhookPayload) -> bool:
        """Return True and skip if we processed this alert+action recently."""
        key = self._dedup_key(payload)
        now = time.monotonic()
        ttl = self.settings.alert_dedup_ttl_seconds

        # Prune stale entries to prevent unbounded growth.
        stale = [k for k, ts in self._dedup_cache.items() if now - ts > ttl]
        for k in stale:
            del self._dedup_cache[k]

        if key in self._dedup_cache:
            logger.info("Duplicate suppressed: %s", key)
            return True

        self._dedup_cache[key] = now
        return False

    # ── Routing logic ─────────────────────────────────────────────────────

    def _escalated_to_me(self, payload: JSMWebhookPayload) -> bool:
        """True when an EscalateNext action targets my user ID."""
        if payload.action != "EscalateNext":
            return False

        my_id = self.settings.jsm_my_user_id

        # Check the top-level recipient field (most reliable).
        if payload.recipient and payload.recipient.id == my_id:
            logger.info("Escalation recipient matches my user ID")
            return True

        # Fallback: check the alert's responders list.
        for responder in payload.alert.responders:
            if responder.get("id") == my_id:
                logger.info("Found my user ID in alert responders (escalation)")
                return True

        return False

    async def _on_call_for_any_schedule(self) -> Tuple[bool, Optional[str]]:
        """
        Check every schedule in check_oncall_schedule_names.
        Returns (True, schedule_name) on first match, (False, None) otherwise.
        """
        for name in self.settings.check_oncall_schedule_names:
            schedule_id = await self.jsm_client.get_schedule_id(name)
            if not schedule_id:
                logger.warning(
                    "Schedule '%s' not found — skipping on-call check", name
                )
                continue
            if await self.jsm_client.is_on_call(
                schedule_id, self.settings.oncall_cache_ttl_seconds
            ):
                return True, name

        return False, None

    async def _should_notify(
        self, payload: JSMWebhookPayload, always_notify: bool
    ) -> Tuple[bool, str]:
        """Return (notify: bool, reason: str)."""

        if payload.action not in _NOTIFY_ACTIONS:
            return False, f"ignored action '{payload.action}'"

        if always_notify:
            return True, "always_notify mode"

        if self._escalated_to_me(payload):
            return True, "escalated to me"

        if payload.action == "Create":
            on_call, sched = await self._on_call_for_any_schedule()
            if on_call:
                return True, f"on-call for '{sched}'"
            return False, "not on-call for any watched schedule"

        # EscalateNext but not to me
        return False, "escalation not targeted at me"

    # ── Public entry point ────────────────────────────────────────────────

    async def process(
        self,
        payload: JSMWebhookPayload,
        always_notify: bool = False,
    ) -> dict:
        """
        Process one incoming JSM webhook.  Returns a status dict suitable for
        returning as the HTTP response body.
        """
        result = {
            "alert_id": payload.alert.alertId,
            "action":   payload.action,
            "notified": False,
            "dismissed": False,
            "reason":   "",
        }

        # ── Dismiss on close / ack ────────────────────────────────────────
        if payload.action in _DISMISS_ACTIONS:
            await self.ha_client.dismiss_notification(payload.alert.alertId)
            result["dismissed"] = True
            result["reason"] = f"dismissed on action '{payload.action}'"
            logger.info(
                "Dismissed notification for alert %s (action=%s)",
                payload.alert.alertId,
                payload.action,
            )
            return result

        # ── Deduplication ─────────────────────────────────────────────────
        if self._is_duplicate(payload):
            result["reason"] = "duplicate"
            return result

        # ── Routing decision ──────────────────────────────────────────────
        notify, reason = await self._should_notify(payload, always_notify)
        result["reason"] = reason

        if not notify:
            logger.info(
                "No notification for alert %s: %s", payload.alert.alertId, reason
            )
            return result

        # ── Determine announcement verbosity based on time windows ─────────
        now_time = datetime.now().time()
        silent = in_any_window(now_time, self.settings._silent_windows)
        terse = (
            not silent
            and in_any_window(now_time, self.settings._terse_windows)
        )

        if silent:
            result["announcement_mode"] = "silent"
            logger.info(
                "Silent window active — suppressing TTS for alert %s",
                payload.alert.alertId,
            )
        elif terse:
            result["announcement_mode"] = "terse"
            logger.info(
                "Terse window active — using short announcement for alert %s",
                payload.alert.alertId,
            )
        else:
            result["announcement_mode"] = "full"

        # ── Send notifications concurrently ───────────────────────────────
        coros = []
        if not silent:
            coros.append(
                self.ha_client.play_tts_alert(
                    payload.alert, payload.action, terse=terse,
                )
            )
        # Persistent notification is always sent (visible in dashboard).
        coros.append(
            self.ha_client.send_persistent_notification(
                payload.alert, payload.action
            )
        )

        results = await asyncio.gather(*coros, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.error("Notification call raised: %s", r)

        result["notified"] = True
        logger.info(
            "Notification sent — alert_id=%s action=%s reason=%s mode=%s",
            payload.alert.alertId,
            payload.action,
            reason,
            result["announcement_mode"],
        )
        return result
