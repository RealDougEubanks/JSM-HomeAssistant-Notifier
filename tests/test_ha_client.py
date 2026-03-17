"""Tests for the Home Assistant client: TTS text, metadata, and API calls."""
from __future__ import annotations

import pytest
import respx
import httpx

from src.ha_client import HAClient
from src.models import AlertDetails
from tests.conftest import make_alert


# ── TTS text building ─────────────────────────────────────────────────────────

def test_tts_text_p1_create(ha_client: HAClient):
    alert = make_alert(priority="P1", entity="web-01", description="Service down").alert
    text = ha_client._build_tts_text(alert, "Create")
    assert "Attention" in text
    assert "Priority 1, Critical" in text
    assert "Server CPU High" in text
    assert "web-01" in text
    assert "Service down" in text


def test_tts_text_escalation(ha_client: HAClient):
    alert = make_alert(priority="P2").alert
    text = ha_client._build_tts_text(alert, "EscalateNext")
    assert "Escalated alert" in text
    assert "Priority 2, High" in text


def test_tts_long_description_truncated(ha_client: HAClient):
    long_desc = "x" * 500
    alert = AlertDetails(alertId="t", message="Long", description=long_desc)
    text = ha_client._build_tts_text(alert, "Create")
    # Description portion should be <= 200 chars plus "..."
    assert len(text) < 600


# ── Media metadata ────────────────────────────────────────────────────────────

def test_media_metadata_p1(ha_client: HAClient):
    alert = make_alert(priority="P1", message="DB Down").alert
    meta = ha_client._build_media_metadata(alert, "Create")
    assert "🔴" in meta["title"]
    assert "P1" in meta["title"]
    assert "DB Down" in meta["title"]
    assert meta["artist"] == "JSM — Atlantic BT"


def test_media_metadata_escalation_prefix(ha_client: HAClient):
    alert = make_alert(priority="P2").alert
    meta = ha_client._build_media_metadata(alert, "EscalateNext")
    assert "ESCALATED" in meta["title"]


def test_media_metadata_long_title_truncated(ha_client: HAClient):
    alert = make_alert(message="A" * 100).alert
    meta = ha_client._build_media_metadata(alert, "Create")
    assert len(meta["title"]) <= 80


# ── TTS content ID ────────────────────────────────────────────────────────────

def test_tts_content_id_format(ha_client: HAClient):
    content_id = ha_client._build_tts_content_id("Hello World")
    assert content_id.startswith("media-source://tts/")
    assert "message=Hello%20World" in content_id
    assert "language=" in content_id
    assert "voice=" in content_id


# ── HA service calls (mocked with respx) ──────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_play_tts_alert_success(ha_client: HAClient):
    route = respx.post("https://ha.example.com/api/services/media_player/play_media").mock(
        return_value=httpx.Response(200, json=[])
    )
    payload = make_alert(priority="P1")
    result = await ha_client.play_tts_alert(payload.alert, "Create")
    assert result is True
    assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_play_tts_alert_ha_error(ha_client: HAClient):
    respx.post("https://ha.example.com/api/services/media_player/play_media").mock(
        return_value=httpx.Response(401, json={"message": "Unauthorized"})
    )
    payload = make_alert()
    result = await ha_client.play_tts_alert(payload.alert)
    assert result is False  # errors are logged but not raised


@pytest.mark.asyncio
@respx.mock
async def test_persistent_notification(ha_client: HAClient):
    route = respx.post(
        "https://ha.example.com/api/services/persistent_notification/create"
    ).mock(return_value=httpx.Response(200, json=[]))
    payload = make_alert(alert_id="n-001")
    result = await ha_client.send_persistent_notification(payload.alert)
    assert result is True
    body = route.calls[0].request.content
    import json
    data = json.loads(body)
    assert data["notification_id"] == "jsm_alert_n-001"


@pytest.mark.asyncio
@respx.mock
async def test_dismiss_notification(ha_client: HAClient):
    route = respx.post(
        "https://ha.example.com/api/services/persistent_notification/dismiss"
    ).mock(return_value=httpx.Response(200, json=[]))
    result = await ha_client.dismiss_notification("n-001")
    assert result is True
    import json
    data = json.loads(route.calls[0].request.content)
    assert data["notification_id"] == "jsm_alert_n-001"
