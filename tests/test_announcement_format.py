"""Tests for configurable announcement formats, time-window integration, and new features."""
from __future__ import annotations

from datetime import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.alert_processor import AlertProcessor
from src.config import Settings
from src.ha_client import HAClient
from src.jsm_client import JSMClient
from tests.conftest import make_alert


# ── HAClient format tests ───────────────────────────────────────────────────

def test_default_format_matches_original(ha_client: HAClient):
    """The default configurable format should produce the same output as before."""
    alert = make_alert(priority="P1", entity="web-01", description="Service down").alert
    text = ha_client._build_tts_text(alert, "Create")
    assert "Attention!" in text
    assert "Priority 1, Critical" in text
    assert "Jira Service Management" in text
    assert "Server CPU High" in text
    assert "web-01" in text
    assert "Service down" in text


def test_custom_format():
    client = HAClient(
        ha_url="https://ha.example.com",
        ha_token="token",
        media_player="media_player.test",
        tts_service="tts.test",
        tts_language="en-US",
        tts_voice="TestVoice",
        announcement_format="{action_prefix} {priority}. {message}.",
    )
    alert = make_alert(priority="P2", message="Disk full").alert
    text = client._build_tts_text(alert, "Create")
    assert text == "Attention! Priority 2, High. Disk full."


def test_terse_format():
    client = HAClient(
        ha_url="https://ha.example.com",
        ha_token="token",
        media_player="media_player.test",
        tts_service="tts.test",
        tts_language="en-US",
        tts_voice="TestVoice",
        terse_announcement_format="Alert: {message}.",
    )
    alert = make_alert(message="CPU high").alert
    text = client._build_terse_tts_text(alert, "Create")
    assert text == "Alert: CPU high."


def test_terse_format_with_escalation():
    client = HAClient(
        ha_url="https://ha.example.com",
        ha_token="token",
        media_player="media_player.test",
        tts_service="tts.test",
        tts_language="en-US",
        tts_voice="TestVoice",
        terse_announcement_format="{action_prefix} {message}.",
    )
    alert = make_alert(message="DB down").alert
    text = client._build_terse_tts_text(alert, "EscalateNext")
    assert text == "Escalated alert! DB down."


# ── AlertProcessor time-window integration ──────────────────────────────────

def _make_processor(
    settings: Settings,
    is_on_call: bool = False,
) -> AlertProcessor:
    jsm = MagicMock(spec=JSMClient)
    jsm.my_user_id = settings.jsm_my_user_id
    jsm.get_schedule_id = AsyncMock(return_value="sched-001")
    jsm.is_on_call = AsyncMock(return_value=is_on_call)
    jsm.invalidate_oncall_cache = MagicMock()

    ha = MagicMock(spec=HAClient)
    ha.media_player = settings.ha_media_player_entity
    ha.play_tts_alert = AsyncMock(return_value=True)
    ha.play_tts_batch = AsyncMock(return_value=True)
    ha.send_persistent_notification = AsyncMock(return_value=True)
    ha.dismiss_notification = AsyncMock(return_value=True)
    ha._set_volume = AsyncMock(return_value=True)

    return AlertProcessor(settings, jsm, ha)


def _settings_with(**kwargs) -> Settings:
    defaults = dict(
        jsm_cloud_id="test-cloud-id",
        jsm_username="test@example.com",
        jsm_api_token="test-token",
        jsm_my_user_id="my-user-id",
        check_oncall_schedule_names=["Cloud Engineering On-Call Schedule"],
        always_notify_schedule_names=["Internal Systems_schedule"],
        ha_url="https://ha.example.com",
        ha_token="ha-test-token",
    )
    defaults.update(kwargs)
    return Settings(**defaults)


# ── Silent / terse window tests ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_silent_window_suppresses_tts():
    """During a silent window, TTS should not be called but notification should."""
    settings = _settings_with(silent_window="00:00-23:59")
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action="Create")

    result = await proc.process(payload)

    assert result["notified"] is True
    assert result["announcement_mode"] == "silent"
    proc.ha_client.play_tts_alert.assert_not_awaited()
    proc.ha_client.send_persistent_notification.assert_awaited_once()


@pytest.mark.asyncio
async def test_terse_window_uses_terse_format():
    """During a terse window, TTS should be called with terse=True."""
    settings = _settings_with(terse_window="00:00-23:59")
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action="Create")

    result = await proc.process(payload)

    assert result["notified"] is True
    assert result["announcement_mode"] == "terse"
    proc.ha_client.play_tts_alert.assert_awaited_once()
    call_kwargs = proc.ha_client.play_tts_alert.call_args
    assert call_kwargs.kwargs.get("terse") is True


@pytest.mark.asyncio
async def test_no_windows_uses_full_format():
    """With no windows configured, full announcement mode is used."""
    settings = _settings_with()
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action="Create")

    result = await proc.process(payload)

    assert result["notified"] is True
    assert result["announcement_mode"] == "full"
    proc.ha_client.play_tts_alert.assert_awaited_once()
    call_kwargs = proc.ha_client.play_tts_alert.call_args
    assert call_kwargs.kwargs.get("terse") is False


@pytest.mark.asyncio
async def test_silent_wins_over_terse():
    """If time is in both silent and terse windows, silent should win."""
    settings = _settings_with(silent_window="00:00-23:59", terse_window="00:00-23:59")
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action="Create")

    result = await proc.process(payload)

    assert result["announcement_mode"] == "silent"
    proc.ha_client.play_tts_alert.assert_not_awaited()


# ── Priority override for silent windows ─────────────────────────────────────

@pytest.mark.asyncio
async def test_priority_override_bypasses_silent():
    """P1 alerts should bypass silent window when configured."""
    settings = _settings_with(
        silent_window="00:00-23:59",
        silent_window_override_priorities="P1",
    )
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action="Create", priority="P1")

    result = await proc.process(payload)

    assert result["notified"] is True
    assert result["announcement_mode"] == "full"
    proc.ha_client.play_tts_alert.assert_awaited_once()


@pytest.mark.asyncio
async def test_priority_override_does_not_bypass_for_low_priority():
    """P3 should remain silent when only P1 overrides."""
    settings = _settings_with(
        silent_window="00:00-23:59",
        silent_window_override_priorities="P1",
    )
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action="Create", priority="P3")

    result = await proc.process(payload)

    assert result["announcement_mode"] == "silent"
    proc.ha_client.play_tts_alert.assert_not_awaited()


@pytest.mark.asyncio
async def test_priority_override_multiple_priorities():
    """P1 and P2 should both bypass silent mode."""
    settings = _settings_with(
        silent_window="00:00-23:59",
        silent_window_override_priorities="P1,P2",
    )
    proc = _make_processor(settings, is_on_call=True)

    r1 = await proc.process(make_alert(action="Create", priority="P1", alert_id="a1"))
    assert r1["announcement_mode"] == "full"

    r2 = await proc.process(make_alert(action="Create", priority="P2", alert_id="a2"))
    assert r2["announcement_mode"] == "full"


# ── Media player routing ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_media_player_routing_uses_time_based_player():
    """TTS should be routed to the time-matched media player."""
    settings = _settings_with(
        ha_media_player_routing="media_player.bedroom@00:00-23:59",
    )
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action="Create")

    result = await proc.process(payload)

    assert result["notified"] is True
    call_kwargs = proc.ha_client.play_tts_alert.call_args
    assert call_kwargs.kwargs.get("target_entity") == "media_player.bedroom"


@pytest.mark.asyncio
async def test_media_player_routing_falls_back_to_default():
    """When no routing matches, use the default media player."""
    settings = _settings_with(
        # Window that's unlikely to match current time
        ha_media_player_routing="media_player.bedroom@03:00-03:01",
    )
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action="Create")

    result = await proc.process(payload)
    # Just verify it processes — the fallback is HA_MEDIA_PLAYER_ENTITY
    assert result["notified"] is True


# ── Dismiss cancels TTS repeat ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dismiss_cancels_tts_repeat():
    """Acknowledging an alert should cancel its TTS repeat task."""
    settings = _settings_with(
        tts_repeat_interval_seconds=60,
        tts_repeat_max=5,
        tts_repeat_priorities="P1",
    )
    proc = _make_processor(settings, is_on_call=True)

    # First, process a P1 alert (which should start a repeat).
    create_payload = make_alert(action="Create", priority="P1")
    r1 = await proc.process(create_payload)
    assert r1["notified"] is True

    # A repeat task should now be active.
    assert "alert-001" in proc._repeat_tasks

    # Now acknowledge it.
    ack_payload = make_alert(action="Acknowledge", alert_id="alert-001")
    r2 = await proc.process(ack_payload)
    assert r2["dismissed"] is True
    assert "alert-001" not in proc._repeat_tasks


# ── TTS repeat not started for non-qualifying priorities ─────────────────────

@pytest.mark.asyncio
async def test_no_repeat_for_low_priority():
    """P3 alerts should not start TTS repeats when only P1 is configured."""
    settings = _settings_with(
        tts_repeat_interval_seconds=60,
        tts_repeat_max=5,
        tts_repeat_priorities="P1",
    )
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action="Create", priority="P3")

    await proc.process(payload)
    assert "alert-001" not in proc._repeat_tasks


@pytest.mark.asyncio
async def test_no_repeat_when_disabled():
    """TTS repeat should not start when interval is 0."""
    settings = _settings_with(
        tts_repeat_interval_seconds=0,
        tts_repeat_priorities="P1",
    )
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action="Create", priority="P1")

    await proc.process(payload)
    assert "alert-001" not in proc._repeat_tasks


# ── Config parsing of window strings ────────────────────────────────────────

def test_config_parses_silent_window():
    s = _settings_with(silent_window="22:00-07:00")
    assert len(s._silent_windows) == 1
    assert s._silent_windows[0] == (time(22, 0), time(7, 0))


def test_config_parses_multiple_terse_windows():
    s = _settings_with(terse_window="06:00-08:00, 20:00-21:00")
    assert len(s._terse_windows) == 2


def test_config_empty_windows():
    s = _settings_with()
    assert s._silent_windows == []
    assert s._terse_windows == []
