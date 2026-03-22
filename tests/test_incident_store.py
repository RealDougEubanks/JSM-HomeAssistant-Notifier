"""Tests for the incident store and HA automation webhooks."""

from __future__ import annotations

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.alert_processor import AlertProcessor
from src.config import Settings
from src.ha_client import HAClient
from src.incident_store import IncidentStore
from src.jsm_client import JSMClient
from tests.conftest import make_alert


# ── Incident store ────────────────────────────────────────────────────────────


@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def store(db_path: str) -> IncidentStore:
    return IncidentStore(db_path)


async def test_upsert_and_get(store: IncidentStore):
    alert = {"alertId": "inc-001", "message": "Server down", "priority": "P1", "entity": "prod-01"}
    await store.upsert(alert, "Create")

    result = await store.get_one("inc-001")
    assert result is not None
    assert result["alert_id"] == "inc-001"
    assert result["message"] == "Server down"
    assert result["priority"] == "P1"
    assert result["status"] == "open"


async def test_upsert_acknowledge_updates_status(store: IncidentStore):
    alert = {"alertId": "inc-002", "message": "Disk full", "priority": "P2"}
    await store.upsert(alert, "Create")
    await store.upsert(alert, "Acknowledge")

    result = await store.get_one("inc-002")
    assert result["status"] == "acknowledged"
    assert result["acknowledged_at"] is not None


async def test_upsert_close_updates_status(store: IncidentStore):
    alert = {"alertId": "inc-003", "message": "Memory leak", "priority": "P3"}
    await store.upsert(alert, "Create")
    await store.upsert(alert, "Close")

    result = await store.get_one("inc-003")
    assert result["status"] == "closed"
    assert result["closed_at"] is not None


async def test_get_all_filters_by_status(store: IncidentStore):
    await store.upsert({"alertId": "a1", "message": "m1", "priority": "P1"}, "Create")
    await store.upsert({"alertId": "a2", "message": "m2", "priority": "P2"}, "Create")
    await store.upsert({"alertId": "a2", "message": "m2", "priority": "P2"}, "Close")

    open_incidents = await store.get_all(status="open")
    assert len(open_incidents) == 1
    assert open_incidents[0]["alert_id"] == "a1"

    closed_incidents = await store.get_all(status="closed")
    assert len(closed_incidents) == 1
    assert closed_incidents[0]["alert_id"] == "a2"


async def test_get_all_filters_by_priority(store: IncidentStore):
    await store.upsert({"alertId": "a1", "message": "m1", "priority": "P1"}, "Create")
    await store.upsert({"alertId": "a2", "message": "m2", "priority": "P2"}, "Create")

    p1_only = await store.get_all(priority="P1")
    assert len(p1_only) == 1
    assert p1_only[0]["priority"] == "P1"


async def test_get_summary(store: IncidentStore):
    await store.upsert({"alertId": "a1", "message": "m1", "priority": "P1"}, "Create")
    await store.upsert({"alertId": "a2", "message": "m2", "priority": "P2"}, "Create")
    await store.upsert({"alertId": "a3", "message": "m3", "priority": "P1"}, "Create")
    await store.upsert({"alertId": "a3", "message": "m3", "priority": "P1"}, "Close")

    summary = await store.get_summary()
    assert summary["total_open"] == 2
    assert summary["total_closed"] == 1
    assert summary["by_priority"]["P1"] == 1  # Only open P1 (a1)
    assert summary["by_priority"]["P2"] == 1


async def test_bulk_upsert(store: IncidentStore):
    alerts = [
        {"id": "sync-1", "message": "Alert 1", "priority": "P1"},
        {"id": "sync-2", "message": "Alert 2", "priority": "P3"},
    ]
    count = await store.bulk_upsert(alerts)
    assert count == 2

    all_incidents = await store.get_all()
    assert len(all_incidents) == 2


async def test_get_one_not_found(store: IncidentStore):
    result = await store.get_one("nonexistent")
    assert result is None


async def test_close_store(store: IncidentStore):
    await store.upsert({"alertId": "a1", "message": "m1", "priority": "P1"}, "Create")
    await store.close()
    # After close, the connection should be None.
    assert store._conn is None


# ── HA automation webhooks ────────────────────────────────────────────────────


def _settings(**kwargs) -> Settings:
    defaults = dict(
        jsm_cloud_id="test-cloud-id",
        jsm_username="test@example.com",
        jsm_api_token="test-token",
        jsm_my_user_id="my-user-id",
        ha_url="https://ha.example.com",
        ha_token="ha-test-token",
    )
    defaults.update(kwargs)
    return Settings(**defaults)


async def test_fire_webhooks_on_create():
    settings = _settings(ha_webhook_on_create="jsm_alert_created")
    ha = HAClient(
        ha_url=settings.ha_url, ha_token=settings.ha_token,
        media_player="media_player.test", tts_service="tts.test",
        tts_language="en-US", tts_voice="TestVoice",
    )
    ha.fire_webhook = AsyncMock(return_value=True)
    ha.play_tts_alert = AsyncMock(return_value=True)
    ha.send_persistent_notification = AsyncMock(return_value=True)

    jsm = MagicMock(spec=JSMClient)
    proc = AlertProcessor(settings, jsm, ha)

    payload = make_alert(action="Create")
    await proc._fire_automation_webhooks(payload)

    ha.fire_webhook.assert_called_once()
    call_args = ha.fire_webhook.call_args
    assert call_args[0][0] == "jsm_alert_created"
    assert call_args[0][1]["event"] == "Create"
    assert call_args[0][1]["priority"] == "P1"


async def test_fire_webhooks_skips_when_empty():
    settings = _settings()  # All webhook configs empty.
    ha = HAClient(
        ha_url=settings.ha_url, ha_token=settings.ha_token,
        media_player="media_player.test", tts_service="tts.test",
        tts_language="en-US", tts_voice="TestVoice",
    )
    ha.fire_webhook = AsyncMock(return_value=True)

    jsm = MagicMock(spec=JSMClient)
    proc = AlertProcessor(settings, jsm, ha)

    payload = make_alert(action="Create")
    await proc._fire_automation_webhooks(payload)

    ha.fire_webhook.assert_not_called()


async def test_fire_webhooks_on_sla_breach():
    settings = _settings(ha_webhook_on_sla_breach="sla_breach_hook")
    ha = HAClient(
        ha_url=settings.ha_url, ha_token=settings.ha_token,
        media_player="media_player.test", tts_service="tts.test",
        tts_language="en-US", tts_voice="TestVoice",
    )
    ha.fire_webhook = AsyncMock(return_value=True)

    jsm = MagicMock(spec=JSMClient)
    proc = AlertProcessor(settings, jsm, ha)

    payload = make_alert(action="SlaBreached")
    await proc._fire_automation_webhooks(payload)

    ha.fire_webhook.assert_called_once_with("sla_breach_hook", pytest.approx({
        "event": "SlaBreached",
        "alert_id": "alert-001",
        "message": "Server CPU High",
        "priority": "P1",
        "entity": "prod-server-01",
        "description": "CPU usage above 90%",
        "source": "",
        "tags": [],
    }, abs=0))


async def test_process_updates_incident_store():
    """Verify the processor updates the incident store on every action."""
    settings = _settings(always_notify_schedule_names=["test"])
    ha = HAClient(
        ha_url=settings.ha_url, ha_token=settings.ha_token,
        media_player="media_player.test", tts_service="tts.test",
        tts_language="en-US", tts_voice="TestVoice",
    )
    ha.play_tts_alert = AsyncMock(return_value=True)
    ha.send_persistent_notification = AsyncMock(return_value=True)
    ha.dismiss_notification = AsyncMock(return_value=True)

    jsm = MagicMock(spec=JSMClient)
    store = MagicMock(spec=IncidentStore)
    store.upsert = AsyncMock()

    proc = AlertProcessor(settings, jsm, ha, store)

    # Create
    payload = make_alert(action="Create")
    await proc.process(payload, always_notify=True)
    store.upsert.assert_called_once()
    call_args = store.upsert.call_args[0]
    assert call_args[0]["alertId"] == "alert-001"
    assert call_args[1] == "Create"

    store.upsert.reset_mock()

    # Acknowledge (also updates store)
    ack_payload = make_alert(action="Acknowledge")
    await proc.process(ack_payload)
    store.upsert.assert_called_once()
    assert store.upsert.call_args[0][1] == "Acknowledge"
