"""
Tests for aggregate-state reconciliation.

State webhooks are edge-triggered: they fire when an alert event arrives. If the
service is offline while an alert is acknowledged or closed, that edge is missed
permanently and any downstream indicator stays wrong until an unrelated alert
happens to arrive.

``reconcile_state_webhook()`` re-derives the state from the incident store and
fires the matching webhook without needing an incoming event. These tests pin
that behaviour and the three call sites that use it.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.alert_processor import AlertProcessor
from src.config import Settings
from src.ha_client import HAClient
from src.incident_store import IncidentStore
from src.jsm_client import JSMClient


def _proc(counts: dict[str, int] | None = None, **kwargs) -> AlertProcessor:
    defaults = {
        "jsm_cloud_id": "c",
        "jsm_username": "u@example.com",
        "jsm_api_token": "t",
        "jsm_my_user_id": "me",
        "ha_url": "https://ha.example.com",
        "ha_token": "tok",
        "ha_webhook_on_create": "unacked_hook",
        "ha_webhook_on_acknowledge": "acked_hook",
        "ha_webhook_on_close": "clear_hook",
    }
    defaults.update(kwargs)
    ha = MagicMock(spec=HAClient)
    ha.media_player = "media_player.test"
    ha.fire_webhooks = AsyncMock(return_value=True)
    store = None
    if counts is not None:
        store = MagicMock(spec=IncidentStore)
        store.get_open_counts = AsyncMock(return_value=counts)
    return AlertProcessor(Settings(**defaults), MagicMock(spec=JSMClient), ha, store)


# ── Count-to-state mapping ───────────────────────────────────────────────


@pytest.mark.parametrize(
    "counts,expected",
    [
        ({"unacked": 1, "acked": 0, "total_open": 1}, "ha_webhook_on_create"),
        ({"unacked": 3, "acked": 2, "total_open": 5}, "ha_webhook_on_create"),
        ({"unacked": 0, "acked": 2, "total_open": 2}, "ha_webhook_on_acknowledge"),
        ({"unacked": 0, "acked": 0, "total_open": 0}, "ha_webhook_on_close"),
    ],
)
def test_state_field_for_counts(counts, expected):
    assert _proc()._state_field_for_counts(counts) == expected


# ── reconcile_state_webhook ──────────────────────────────────────────────


async def test_reconcile_fires_unacked():
    proc = _proc({"unacked": 2, "acked": 1, "total_open": 3})
    assert await proc.reconcile_state_webhook("startup") == "ha_webhook_on_create"
    ids, data = proc.ha_client.fire_webhooks.call_args[0]
    assert ids == "unacked_hook"
    assert data["state"] == "create"
    assert data["event"] == "Reconcile"
    assert data["reason"] == "startup"
    assert data["unacked_count"] == 2
    assert data["acked_count"] == 1
    assert data["total_open"] == 3


async def test_reconcile_fires_acked_when_all_acknowledged():
    proc = _proc({"unacked": 0, "acked": 2, "total_open": 2})
    assert await proc.reconcile_state_webhook() == "ha_webhook_on_acknowledge"
    assert proc.ha_client.fire_webhooks.call_args[0][0] == "acked_hook"


async def test_reconcile_fires_clear_when_nothing_open():
    """The offline-close case: nothing open, so the indicator must be cleared."""
    proc = _proc({"unacked": 0, "acked": 0, "total_open": 0})
    assert await proc.reconcile_state_webhook() == "ha_webhook_on_close"
    assert proc.ha_client.fire_webhooks.call_args[0][0] == "clear_hook"


async def test_reconcile_noop_without_incident_store():
    proc = _proc(None)
    assert await proc.reconcile_state_webhook() is None
    proc.ha_client.fire_webhooks.assert_not_called()


async def test_reconcile_noop_when_webhook_not_configured():
    proc = _proc({"unacked": 1, "acked": 0, "total_open": 1}, ha_webhook_on_create="")
    assert await proc.reconcile_state_webhook() is None
    proc.ha_client.fire_webhooks.assert_not_called()


async def test_reconcile_survives_store_error():
    """A broken store must not take down startup."""
    proc = _proc({"unacked": 1, "acked": 0, "total_open": 1})
    proc.incident_store.get_open_counts = AsyncMock(side_effect=RuntimeError("db gone"))
    assert await proc.reconcile_state_webhook() is None
    proc.ha_client.fire_webhooks.assert_not_called()


async def test_reason_is_passed_through():
    proc = _proc({"unacked": 0, "acked": 0, "total_open": 0})
    await proc.reconcile_state_webhook("manual-sync")
    assert proc.ha_client.fire_webhooks.call_args[0][1]["reason"] == "manual-sync"


async def test_reconcile_payload_has_no_alert_specific_values():
    """Reconcile is not tied to one alert; per-alert fields must be blank."""
    proc = _proc({"unacked": 1, "acked": 0, "total_open": 1})
    await proc.reconcile_state_webhook()
    data = proc.ha_client.fire_webhooks.call_args[0][1]
    assert data["alert_id"] == ""
    assert data["priority"] == ""
    assert data["tags"] == []


# ── Shared mapping between reconcile and the event path ──────────────────


async def test_event_path_and_reconcile_agree():
    """
    Both paths must resolve the same state from the same counts. They were
    duplicated logic before; this pins that they stay in sync.
    """
    from tests.conftest import make_alert

    for counts in (
        {"unacked": 1, "acked": 0, "total_open": 1},
        {"unacked": 0, "acked": 1, "total_open": 1},
        {"unacked": 0, "acked": 0, "total_open": 0},
    ):
        proc = _proc(counts)
        expected = proc._state_field_for_counts(counts)

        await proc._fire_state_webhooks(make_alert(action="Acknowledge"))
        event_ids = proc.ha_client.fire_webhooks.call_args[0][0]

        proc.ha_client.fire_webhooks.reset_mock()
        assert await proc.reconcile_state_webhook() == expected
        reconcile_ids = proc.ha_client.fire_webhooks.call_args[0][0]

        assert event_ids == reconcile_ids
