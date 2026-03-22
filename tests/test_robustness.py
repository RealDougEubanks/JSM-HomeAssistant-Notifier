"""Tests for robustness improvements: dedup bounds, dismiss tracking, client lifecycle."""
from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.alert_processor import AlertProcessor, _MAX_DEDUP_CACHE_SIZE
from src.config import Settings
from src.ha_client import HAClient
from src.jsm_client import JSMClient
from tests.conftest import make_alert


def _settings(**kwargs) -> Settings:
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


def _processor(settings: Settings, is_on_call: bool = True) -> AlertProcessor:
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


# ── Dedup cache max size ─────────────────────────────────────────────────────

def test_dedup_cache_bounded():
    """Dedup cache must not grow past _MAX_DEDUP_CACHE_SIZE."""
    s = _settings()
    proc = _processor(s)

    # Directly stuff the cache beyond the limit.
    now = time.monotonic()
    for i in range(_MAX_DEDUP_CACHE_SIZE + 100):
        proc._dedup_cache[f"alert-{i}:Create"] = now

    # Process one more alert — this triggers the size check.
    payload = make_alert(alert_id="overflow-alert", action="Create")
    proc._is_duplicate(payload)

    # Cache should have been evicted down.
    assert len(proc._dedup_cache) <= _MAX_DEDUP_CACHE_SIZE


# ── Dismiss result tracking ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dismiss_logs_ha_result():
    """Dismiss action should still mark dismissed=True even if HA call fails."""
    s = _settings()
    proc = _processor(s)
    proc.ha_client.dismiss_notification = AsyncMock(return_value=False)  # HA failed

    payload = make_alert(action="Acknowledge")
    result = await proc.process(payload)

    assert result["dismissed"] is True
    proc.ha_client.dismiss_notification.assert_awaited_once()


# ── Persistent httpx client ──────────────────────────────────────────────────

def test_jsm_client_has_persistent_http():
    """JSMClient should have a persistent httpx.AsyncClient."""
    import httpx
    client = JSMClient(
        api_url="https://api.atlassian.com",
        cloud_id="test",
        username="test@example.com",
        api_token="token",
        my_user_id="user-id",
    )
    assert isinstance(client._http, httpx.AsyncClient)


def test_ha_client_has_persistent_http():
    """HAClient should have a persistent httpx.AsyncClient."""
    import httpx
    client = HAClient(
        ha_url="https://ha.example.com",
        ha_token="token",
        media_player="media_player.test",
        tts_service="tts.test",
        tts_language="en-US",
        tts_voice="TestVoice",
    )
    assert isinstance(client._http, httpx.AsyncClient)


@pytest.mark.asyncio
async def test_jsm_client_aclose():
    """JSMClient.aclose() should close the HTTP client without error."""
    client = JSMClient(
        api_url="https://api.atlassian.com",
        cloud_id="test",
        username="test@example.com",
        api_token="token",
        my_user_id="user-id",
    )
    await client.aclose()
    assert client._http.is_closed


@pytest.mark.asyncio
async def test_ha_client_aclose():
    """HAClient.aclose() should close the HTTP client without error."""
    client = HAClient(
        ha_url="https://ha.example.com",
        ha_token="token",
        media_player="media_player.test",
        tts_service="tts.test",
        tts_language="en-US",
        tts_voice="TestVoice",
    )
    await client.aclose()
    assert client._http.is_closed


# ── TTS repeat race condition fix ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_start_repeat_cancels_existing():
    """Starting a repeat for the same alert should cancel the old one."""
    import asyncio

    s = _settings(tts_repeat_interval_seconds=60, tts_repeat_max=5, tts_repeat_priorities="P1")
    proc = _processor(s)

    alert = make_alert(priority="P1").alert

    # Start first repeat.
    proc._start_tts_repeat(alert, "Create", "media_player.test")
    first_task = proc._repeat_tasks.get("alert-001")
    assert first_task is not None

    # Start second repeat for same alert — should cancel the first.
    proc._start_tts_repeat(alert, "Create", "media_player.test")
    second_task = proc._repeat_tasks.get("alert-001")
    assert second_task is not None
    assert second_task is not first_task

    # Let the event loop process the cancellation.
    await asyncio.sleep(0)
    assert first_task.cancelled()
