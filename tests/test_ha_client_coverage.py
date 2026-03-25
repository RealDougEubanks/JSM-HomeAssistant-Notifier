"""Coverage tests for HAClient methods: TTS, batch, webhooks, notifications."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from src.ha_client import HAClient
from src.models import AlertDetails


def _client(**kwargs) -> HAClient:
    defaults = {
        "ha_url": "https://ha.example.com",
        "ha_token": "token",
        "media_player": "media_player.test",
        "tts_service": "tts.test",
        "tts_language": "en-US",
        "tts_voice": "TestVoice",
    }
    defaults.update(kwargs)
    return HAClient(**defaults)


def _alert(**kwargs) -> AlertDetails:
    defaults = {"alertId": "a1", "message": "Server down", "priority": "P1"}
    defaults.update(kwargs)
    return AlertDetails(**defaults)


# ── _call_service exception handling ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_call_service_generic_exception():
    """Non-HTTP exceptions should be caught and return False."""
    client = _client()
    client._http = AsyncMock()
    client._http.post = AsyncMock(side_effect=ConnectionError("down"))

    result = await client._call_service("media_player", "play_media", {})
    assert result is False


@pytest.mark.asyncio
async def test_call_service_http_status_error():
    """HTTPStatusError should be caught and return False."""
    client = _client()
    response = httpx.Response(
        500, text="Internal Server Error", request=httpx.Request("POST", "http://test")
    )
    client._http = AsyncMock()
    client._http.post = AsyncMock(
        side_effect=httpx.HTTPStatusError(
            "err", request=response.request, response=response
        )
    )

    result = await client._call_service("media_player", "play_media", {})
    assert result is False


# ── _set_volume ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_set_volume():
    client = _client()
    client._call_service = AsyncMock(return_value=True)

    result = await client._set_volume("media_player.test", 0.7)
    assert result is True
    call_args = client._call_service.call_args
    assert call_args[0][0] == "media_player"
    assert call_args[0][1] == "volume_set"
    assert call_args[0][2]["volume_level"] == 0.7


# ── play_tts_alert with volume and terse mode ───────────────────────────────


@pytest.mark.asyncio
async def test_play_tts_alert_with_volume():
    client = _client(volume_default=0.6)
    client._set_volume = AsyncMock(return_value=True)
    client._call_service = AsyncMock(return_value=True)

    await client.play_tts_alert(_alert())
    client._set_volume.assert_called_once_with("media_player.test", 0.6)


@pytest.mark.asyncio
async def test_play_tts_alert_terse_with_volume():
    client = _client(volume_default=0.6, volume_terse=0.3)
    client._set_volume = AsyncMock(return_value=True)
    client._call_service = AsyncMock(return_value=True)

    await client.play_tts_alert(_alert(), terse=True)
    client._set_volume.assert_called_once_with("media_player.test", 0.3)


@pytest.mark.asyncio
async def test_play_tts_alert_terse_text():
    """Terse mode should use the terse format template."""
    client = _client()
    client._call_service = AsyncMock(return_value=True)

    result = await client.play_tts_alert(_alert(), terse=True)
    assert result is True
    client._call_service.assert_called_once()


@pytest.mark.asyncio
async def test_play_tts_alert_custom_entity():
    client = _client()
    client._call_service = AsyncMock(return_value=True)

    await client.play_tts_alert(_alert(), target_entity="media_player.bedroom")
    payload = client._call_service.call_args[0][2]
    assert payload["entity_id"] == "media_player.bedroom"


# ── play_tts_batch ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_play_tts_batch_multiple():
    client = _client(volume_default=0.5)
    client._set_volume = AsyncMock(return_value=True)
    client._call_service = AsyncMock(return_value=True)

    alerts = [_alert(alertId="a1", priority="P1"), _alert(alertId="a2", priority="P2")]
    result = await client.play_tts_batch(alerts, ["Create", "Create"])
    assert result is True
    client._set_volume.assert_called_once()
    # Verify the metadata title mentions the batch count
    payload = client._call_service.call_args[0][2]
    assert "2 alerts" in payload["extra"]["metadata"]["title"]


@pytest.mark.asyncio
async def test_play_tts_batch_single():
    client = _client()
    client._call_service = AsyncMock(return_value=True)

    alerts = [_alert()]
    result = await client.play_tts_batch(alerts, ["Create"])
    assert result is True


@pytest.mark.asyncio
async def test_play_tts_batch_custom_entity():
    client = _client()
    client._call_service = AsyncMock(return_value=True)

    alerts = [_alert()]
    await client.play_tts_batch(alerts, ["Create"], target_entity="media_player.office")
    payload = client._call_service.call_args[0][2]
    assert payload["entity_id"] == "media_player.office"


# ── send_persistent_notification ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_notification_escalation_with_emoji():
    client = _client(enable_emojis=True)
    client._call_service = AsyncMock(return_value=True)

    await client.send_persistent_notification(_alert(), action="EscalateNext")
    payload = client._call_service.call_args[0][2]
    assert "ESCALATED" in payload["title"]


@pytest.mark.asyncio
async def test_notification_escalation_without_emoji():
    client = _client(enable_emojis=False)
    client._call_service = AsyncMock(return_value=True)

    await client.send_persistent_notification(_alert(), action="EscalateNext")
    payload = client._call_service.call_args[0][2]
    assert "ESCALATED" in payload["title"]
    assert "\u2b06" not in payload["title"]  # ⬆️ emoji stripped


@pytest.mark.asyncio
async def test_notification_includes_source():
    client = _client()
    client._call_service = AsyncMock(return_value=True)

    alert = _alert(source="Nagios")
    await client.send_persistent_notification(alert)
    payload = client._call_service.call_args[0][2]
    assert "Nagios" in payload["message"]


@pytest.mark.asyncio
async def test_notification_no_source():
    client = _client()
    client._call_service = AsyncMock(return_value=True)

    alert = _alert()
    await client.send_persistent_notification(alert)
    payload = client._call_service.call_args[0][2]
    assert "Source:" not in payload["message"]


# ── play_tts_message ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_play_tts_message():
    client = _client()
    client._call_service = AsyncMock(return_value=True)

    result = await client.play_tts_message("Token expired")
    assert result is True
    payload = client._call_service.call_args[0][2]
    assert payload["entity_id"] == "media_player.test"
    assert "System Alert" in payload["extra"]["metadata"]["title"]


# ── verify_connectivity ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_connectivity_401():
    client = _client()
    client._http = AsyncMock()
    client._http.get = AsyncMock(return_value=MagicMock(status_code=401))

    ok, err = await client.verify_connectivity()
    assert ok is False
    assert "401" in err


@pytest.mark.asyncio
async def test_verify_connectivity_connection_error():
    client = _client()
    client._http = AsyncMock()
    client._http.get = AsyncMock(side_effect=ConnectionError("timeout"))

    ok, err = await client.verify_connectivity()
    assert ok is False
    assert "timeout" in err


@pytest.mark.asyncio
async def test_verify_connectivity_success():
    client = _client()
    resp_mock = MagicMock(status_code=200)
    resp_mock.raise_for_status = MagicMock()
    client._http = AsyncMock()
    client._http.get = AsyncMock(return_value=resp_mock)

    ok, err = await client.verify_connectivity()
    assert ok is True
    assert err == ""


# ── fire_webhook ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fire_webhook_valid_id():
    client = _client()
    resp_mock = MagicMock()
    resp_mock.raise_for_status = MagicMock()
    client._http = AsyncMock()
    client._http.post = AsyncMock(return_value=resp_mock)

    result = await client.fire_webhook("my_webhook_123", {"event": "Create"})
    assert result is True


@pytest.mark.asyncio
async def test_fire_webhook_invalid_id_slash():
    client = _client()
    result = await client.fire_webhook("webhook/path", {})
    assert result is False


@pytest.mark.asyncio
async def test_fire_webhook_invalid_id_empty():
    client = _client()
    result = await client.fire_webhook("", {})
    assert result is False


@pytest.mark.asyncio
async def test_fire_webhook_invalid_id_too_long():
    client = _client()
    result = await client.fire_webhook("x" * 201, {})
    assert result is False


@pytest.mark.asyncio
async def test_fire_webhook_connection_error():
    client = _client()
    client._http = AsyncMock()
    client._http.post = AsyncMock(side_effect=ConnectionError("down"))

    result = await client.fire_webhook("valid_id", {})
    assert result is False


# ── fire_webhooks ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fire_webhooks_empty_string():
    client = _client()
    client.fire_webhook = AsyncMock()

    await client.fire_webhooks("", {})
    client.fire_webhook.assert_not_called()


@pytest.mark.asyncio
async def test_fire_webhooks_whitespace():
    client = _client()
    client.fire_webhook = AsyncMock()

    await client.fire_webhooks("   ", {})
    client.fire_webhook.assert_not_called()


@pytest.mark.asyncio
async def test_fire_webhooks_multiple():
    client = _client()
    client.fire_webhook = AsyncMock(return_value=True)

    await client.fire_webhooks("hook1, hook2, hook3", {"event": "Create"})
    assert client.fire_webhook.call_count == 3


# ── dismiss_credential_alert ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dismiss_credential_alert():
    client = _client()
    client._call_service = AsyncMock(return_value=True)

    await client.dismiss_credential_alert()
    call_args = client._call_service.call_args
    assert call_args[0][0] == "persistent_notification"
    assert call_args[0][1] == "dismiss"
    assert call_args[0][2]["notification_id"] == "jsm_notifier_credential_alert"
