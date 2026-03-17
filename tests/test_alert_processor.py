"""
Tests for AlertProcessor — the core routing / notification decision logic.

All external I/O (JSM API + HA API) is mocked so tests run offline and fast.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.alert_processor import AlertProcessor
from src.config import Settings
from src.ha_client import HAClient
from src.jsm_client import JSMClient
from tests.conftest import make_alert


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_processor(
    settings: Settings,
    is_on_call: bool = False,
) -> AlertProcessor:
    """Return an AlertProcessor with mocked JSM and HA clients."""
    jsm = MagicMock(spec=JSMClient)
    jsm.my_user_id = settings.jsm_my_user_id
    jsm.get_schedule_id = AsyncMock(return_value="sched-001")
    jsm.is_on_call = AsyncMock(return_value=is_on_call)
    jsm.invalidate_oncall_cache = MagicMock()

    ha = MagicMock(spec=HAClient)
    ha.play_tts_alert = AsyncMock(return_value=True)
    ha.send_persistent_notification = AsyncMock(return_value=True)
    ha.dismiss_notification = AsyncMock(return_value=True)

    return AlertProcessor(settings, jsm, ha)


# ── always_notify mode ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_always_notify_creates_notification(settings: Settings):
    proc = _make_processor(settings, is_on_call=False)
    payload = make_alert(action="Create")
    result = await proc.process(payload, always_notify=True)
    assert result["notified"] is True
    assert result["reason"] == "always_notify mode"
    proc.ha_client.play_tts_alert.assert_awaited_once()


# ── On-call check ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_on_call_notifies(settings: Settings):
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action="Create")
    result = await proc.process(payload)
    assert result["notified"] is True
    assert "on-call" in result["reason"]


@pytest.mark.asyncio
async def test_not_on_call_no_notification(settings: Settings):
    proc = _make_processor(settings, is_on_call=False)
    payload = make_alert(action="Create")
    result = await proc.process(payload)
    assert result["notified"] is False
    assert "not on-call" in result["reason"]


# ── Escalation path ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_escalation_to_me_notifies(settings: Settings):
    """EscalateNext addressed to my user ID must notify even when not on-call."""
    proc = _make_processor(settings, is_on_call=False)
    payload = make_alert(
        action="EscalateNext",
        recipient_id=settings.jsm_my_user_id,
    )
    result = await proc.process(payload)
    assert result["notified"] is True
    assert "escalated" in result["reason"].lower()


@pytest.mark.asyncio
async def test_escalation_to_someone_else_no_notify(settings: Settings):
    proc = _make_processor(settings, is_on_call=False)
    payload = make_alert(
        action="EscalateNext",
        recipient_id="other-user-id",
    )
    result = await proc.process(payload)
    assert result["notified"] is False


@pytest.mark.asyncio
async def test_escalation_via_responders_list(settings: Settings):
    """If EscalateNext has no recipient field but my ID is in responders, notify."""
    proc = _make_processor(settings, is_on_call=False)
    payload = make_alert(
        action="EscalateNext",
        responder_ids=[settings.jsm_my_user_id],
    )
    result = await proc.process(payload)
    assert result["notified"] is True


# ── Ignored actions ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["Acknowledge", "AddNote", "AssignOwnership", "Seen"])
async def test_ignored_actions_do_not_notify(action: str, settings: Settings):
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action=action)
    result = await proc.process(payload)
    assert result["notified"] is False


@pytest.mark.asyncio
async def test_acknowledge_dismisses_notification(settings: Settings):
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action="Acknowledge")
    result = await proc.process(payload)
    assert result["dismissed"] is True
    proc.ha_client.dismiss_notification.assert_awaited_once_with(payload.alert.alertId)


@pytest.mark.asyncio
async def test_close_dismisses_notification(settings: Settings):
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action="Close")
    result = await proc.process(payload)
    assert result["dismissed"] is True


# ── Deduplication ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_duplicate_alert_suppressed(settings: Settings):
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action="Create")

    r1 = await proc.process(payload)
    assert r1["notified"] is True

    r2 = await proc.process(payload)
    assert r2["notified"] is False
    assert r2["reason"] == "duplicate"
    # HA should only have been called once
    assert proc.ha_client.play_tts_alert.await_count == 1


@pytest.mark.asyncio
async def test_same_alert_different_action_not_duplicate(settings: Settings):
    """Create and EscalateNext for the same alert are distinct events."""
    proc = _make_processor(settings, is_on_call=True)

    r_create = await proc.process(make_alert(action="Create"))
    r_escalate = await proc.process(
        make_alert(action="EscalateNext", recipient_id=settings.jsm_my_user_id)
    )
    assert r_create["notified"] is True
    assert r_escalate["notified"] is True


# ── Schedule not found ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_schedule_not_found_skipped(settings: Settings):
    """If the schedule ID can't be resolved, skip it and move on."""
    proc = _make_processor(settings, is_on_call=False)
    proc.jsm_client.get_schedule_id = AsyncMock(return_value=None)  # not found
    payload = make_alert(action="Create")
    result = await proc.process(payload)
    assert result["notified"] is False
    # is_on_call should never be called if ID lookup failed
    proc.jsm_client.is_on_call.assert_not_awaited()
