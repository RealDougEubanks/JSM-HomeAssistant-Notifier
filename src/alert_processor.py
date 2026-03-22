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
       notification (no TTS spam) and cancel any pending TTS repeats.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .config import Settings
from .ha_client import HAClient
from .jsm_client import JSMClient
from .models import JSMWebhookPayload
from .time_windows import in_any_window, parse_player_routing, resolve_player

logger = logging.getLogger(__name__)

# Actions that produce an audible / visible notification.
_NOTIFY_ACTIONS = {"Create", "EscalateNext"}

# Hard cap on dedup cache entries to prevent unbounded memory growth
# (e.g. from an attacker sending alerts with random IDs).
_MAX_DEDUP_CACHE_SIZE = 10_000

# Actions that should dismiss the persistent HA notification.
_DISMISS_ACTIONS = {"Acknowledge", "Close"}


def _parse_priority_set(raw: str) -> frozenset[str]:
    """Parse a comma-separated priority string like 'P1,P2' into a frozenset."""
    if not raw.strip():
        return frozenset()
    return frozenset(p.strip() for p in raw.split(",") if p.strip())


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

        # Parsed derived config.
        self._player_routes = parse_player_routing(settings.ha_media_player_routing)
        self._silent_override_priorities = _parse_priority_set(
            settings.silent_window_override_priorities
        )
        self._repeat_priorities = _parse_priority_set(settings.tts_repeat_priorities)

        # Batching state.
        self._batch_queue: List[Tuple[Any, str]] = []  # (alert, action)
        self._batch_task: Optional[asyncio.Task[None]] = None
        self._batch_notif_coros: List[Any] = []  # persistent-notif coros to run

        # TTS repeat state: alert_id → asyncio.Task
        self._repeat_tasks: Dict[str, asyncio.Task[None]] = {}

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

        # Hard cap: evict oldest half if cache is too large (DoS protection).
        if len(self._dedup_cache) >= _MAX_DEDUP_CACHE_SIZE:
            oldest = sorted(self._dedup_cache, key=self._dedup_cache.get)  # type: ignore[arg-type]
            for k in oldest[: len(oldest) // 2]:
                del self._dedup_cache[k]
            logger.warning(
                "Dedup cache hit max size (%d) — evicted %d oldest entries",
                _MAX_DEDUP_CACHE_SIZE,
                len(oldest) // 2,
            )

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

    # ── Media player routing ──────────────────────────────────────────────

    def _resolve_media_player(self) -> str:
        """Resolve the media player entity for the current time."""
        if not self._player_routes:
            return self.ha_client.media_player
        now_time = datetime.now().time()
        return resolve_player(
            now_time, self._player_routes, self.ha_client.media_player
        )

    # ── TTS repeat (pager mode) ──────────────────────────────────────────

    def _should_repeat(self, priority: str) -> bool:
        """Return True if the alert priority warrants TTS repeats."""
        return (
            self.settings.tts_repeat_interval_seconds > 0
            and priority in self._repeat_priorities
        )

    async def _repeat_tts_loop(
        self, alert: Any, action: str, target_entity: str,
    ) -> None:
        """Background task: repeat TTS at intervals until cancelled or max reached."""
        interval = self.settings.tts_repeat_interval_seconds
        max_repeats = self.settings.tts_repeat_max
        alert_id = alert.alertId

        try:
            for i in range(max_repeats):
                await asyncio.sleep(interval)
                logger.info(
                    "TTS repeat %d/%d for alert %s", i + 1, max_repeats, alert_id
                )
                await self.ha_client.play_tts_alert(
                    alert, action, target_entity=target_entity,
                )
            logger.info("TTS repeat exhausted (%d repeats) for alert %s", max_repeats, alert_id)
        except asyncio.CancelledError:
            logger.info("TTS repeat cancelled for alert %s", alert_id)
        finally:
            self._repeat_tasks.pop(alert_id, None)

    def _start_tts_repeat(
        self, alert: Any, action: str, target_entity: str,
    ) -> None:
        """Start a background repeat loop for this alert."""
        alert_id = alert.alertId

        # Cancel any existing repeat before starting a new one.
        old_task = self._repeat_tasks.pop(alert_id, None)
        if old_task and not old_task.done():
            old_task.cancel()

        task = asyncio.create_task(
            self._repeat_tts_loop(alert, action, target_entity)
        )
        self._repeat_tasks[alert_id] = task
        logger.info("Started TTS repeat for alert %s", alert_id)

    def cancel_tts_repeat(self, alert_id: str) -> None:
        """Cancel any pending TTS repeat for the given alert."""
        task = self._repeat_tasks.pop(alert_id, None)
        if task and not task.done():
            task.cancel()
            logger.info("Cancelled TTS repeat for alert %s", alert_id)

    # ── Alert batching ───────────────────────────────────────────────────

    async def _flush_batch(self) -> None:
        """Called when the batch timer fires. Announce all queued alerts."""
        if not self._batch_queue:
            return

        alerts = [a for a, _ in self._batch_queue]
        actions = [act for _, act in self._batch_queue]
        self._batch_queue.clear()

        target_entity = self._resolve_media_player()

        # Fire persistent notifications (one per alert).
        if self._batch_notif_coros:
            results = await asyncio.gather(*self._batch_notif_coros, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    logger.error("Batch persistent notification raised: %s", r)
            self._batch_notif_coros.clear()

        # Single batched TTS.
        if len(alerts) == 1:
            await self.ha_client.play_tts_alert(
                alerts[0], actions[0], target_entity=target_entity,
            )
        else:
            await self.ha_client.play_tts_batch(
                alerts, actions, target_entity=target_entity,
            )

        # Start repeats for qualifying alerts.
        for alert, action in zip(alerts, actions):
            if self._should_repeat(alert.priority):
                self._start_tts_repeat(alert, action, target_entity)

        self._batch_task = None
        logger.info("Flushed batch of %d alert(s)", len(alerts))

    def _enqueue_batch(
        self, alert: Any, action: str, notif_coro: Any,
    ) -> None:
        """Add an alert to the batch queue and start/reset the batch timer."""
        self._batch_queue.append((alert, action))
        self._batch_notif_coros.append(notif_coro)

        if self._batch_task is None or self._batch_task.done():
            self._batch_task = asyncio.create_task(self._batch_timer())

    async def _batch_timer(self) -> None:
        """Wait for the batch window, then flush."""
        await asyncio.sleep(self.settings.alert_batch_window_seconds)
        await self._flush_batch()

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
        result: dict = {
            "alert_id": payload.alert.alertId,
            "action":   payload.action,
            "notified": False,
            "dismissed": False,
            "reason":   "",
        }

        # ── Dismiss on close / ack ────────────────────────────────────────
        if payload.action in _DISMISS_ACTIONS:
            dismiss_ok = await self.ha_client.dismiss_notification(payload.alert.alertId)
            self.cancel_tts_repeat(payload.alert.alertId)
            result["dismissed"] = True
            result["reason"] = f"dismissed on action '{payload.action}'"
            logger.info(
                "Dismissed notification for alert %s (action=%s ha_dismiss=%s)",
                payload.alert.alertId,
                payload.action,
                "ok" if dismiss_ok else "failed",
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

        # Priority override: P1 (etc.) can bypass silent windows.
        if silent and payload.alert.priority in self._silent_override_priorities:
            logger.info(
                "Priority %s overrides silent window for alert %s",
                payload.alert.priority,
                payload.alert.alertId,
            )
            silent = False

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

        # ── Resolve target media player ───────────────────────────────────
        target_entity = self._resolve_media_player()

        # ── Send notifications ────────────────────────────────────────────
        notif_coro = self.ha_client.send_persistent_notification(
            payload.alert, payload.action
        )

        batch_window = self.settings.alert_batch_window_seconds

        if silent:
            # Only persistent notification, no TTS / batching.
            notif_result = await notif_coro
            if isinstance(notif_result, Exception):
                logger.error("Persistent notification raised: %s", notif_result)
        elif batch_window > 0:
            # Batching mode: queue the alert for combined announcement.
            self._enqueue_batch(payload.alert, payload.action, notif_coro)
            result["batched"] = True
        else:
            # Immediate mode: TTS + persistent notification concurrently.
            tts_result, notif_result = await asyncio.gather(
                self.ha_client.play_tts_alert(
                    payload.alert, payload.action,
                    terse=terse, target_entity=target_entity,
                ),
                notif_coro,
                return_exceptions=True,
            )
            if isinstance(tts_result, Exception):
                logger.error("TTS call raised: %s", tts_result)
            if isinstance(notif_result, Exception):
                logger.error("Persistent notification raised: %s", notif_result)

            # Start TTS repeat if enabled for this priority.
            if self._should_repeat(payload.alert.priority):
                self._start_tts_repeat(
                    payload.alert, payload.action, target_entity,
                )

        result["notified"] = True
        logger.info(
            "Notification sent — alert_id=%s action=%s reason=%s mode=%s",
            payload.alert.alertId,
            payload.action,
            reason,
            result.get("announcement_mode", "full"),
        )
        return result
