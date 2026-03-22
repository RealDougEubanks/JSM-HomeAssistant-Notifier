"""Tests for configurable announcement formats and time-window integration."""
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
    ha.play_tts_alert = AsyncMock(return_value=True)
    ha.send_persistent_notification = AsyncMock(return_value=True)
    ha.dismiss_notification = AsyncMock(return_value=True)

    return AlertProcessor(settings, jsm, ha)


def _settings_with_windows(
    silent: str = "", terse: str = "",
) -> Settings:
    return Settings(
        jsm_cloud_id="test-cloud-id",
        jsm_username="test@example.com",
        jsm_api_token="test-token",
        jsm_my_user_id="my-user-id",
        check_oncall_schedule_names=["Cloud Engineering On-Call Schedule"],
        always_notify_schedule_names=["Internal Systems_schedule"],
        ha_url="https://ha.example.com",
        ha_token="ha-test-token",
        silent_window=silent,
        terse_window=terse,
    )


@pytest.mark.asyncio
async def test_silent_window_suppresses_tts():
    """During a silent window, TTS should not be called but notification should."""
    settings = _settings_with_windows(silent="00:00-23:59")
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
    settings = _settings_with_windows(terse="00:00-23:59")
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
    settings = _settings_with_windows()
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
    settings = _settings_with_windows(silent="00:00-23:59", terse="00:00-23:59")
    proc = _make_processor(settings, is_on_call=True)
    payload = make_alert(action="Create")

    result = await proc.process(payload)

    assert result["announcement_mode"] == "silent"
    proc.ha_client.play_tts_alert.assert_not_awaited()


# ── Config parsing of window strings ────────────────────────────────────────

def test_config_parses_silent_window():
    s = _settings_with_windows(silent="22:00-07:00")
    assert len(s._silent_windows) == 1
    assert s._silent_windows[0] == (time(22, 0), time(7, 0))


def test_config_parses_multiple_terse_windows():
    s = _settings_with_windows(terse="06:00-08:00, 20:00-21:00")
    assert len(s._terse_windows) == 2


def test_config_empty_windows():
    s = _settings_with_windows()
    assert s._silent_windows == []
    assert s._terse_windows == []
