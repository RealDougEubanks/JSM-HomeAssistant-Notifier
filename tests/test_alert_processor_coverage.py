"""Coverage tests for AlertProcessor: batch, repeat, process paths, webhooks."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.alert_processor import AlertProcessor
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


def _processor(
    settings: Settings | None = None, is_on_call: bool = True
) -> AlertProcessor:
    s = settings or _settings()
    jsm = MagicMock(spec=JSMClient)
    jsm.my_user_id = s.jsm_my_user_id
    jsm.get_schedule_id = AsyncMock(return_value="sched-001")
    jsm.is_on_call = AsyncMock(return_value=is_on_call)
    jsm.invalidate_oncall_cache = MagicMock()
    jsm.get_alert_details = AsyncMock(return_value=None)

    ha = MagicMock(spec=HAClient)
    ha.media_player = s.ha_media_player_entity
    ha.play_tts_alert = AsyncMock(return_value=True)
    ha.play_tts_batch = AsyncMock(return_value=True)
    ha.send_persistent_notification = AsyncMock(return_value=True)
    ha.dismiss_notification = AsyncMock(return_value=True)
    ha._set_volume = AsyncMock(return_value=True)
    ha.fire_webhooks = AsyncMock()

    return AlertProcessor(s, jsm, ha)


# ── Batch flush ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_flush_batch_single_alert():
    """Single alert in batch should call play_tts_alert, not play_tts_batch."""
    s = _settings(alert_batch_window_seconds=5)
    proc = _processor(s)
    alert = make_alert().alert

    # Manually enqueue
    proc._batch_queue.append((alert, "Create"))
    proc._batch_notif_coros.append(
        proc.ha_client.send_persistent_notification(alert, "Create")
    )

    await proc._flush_batch()
    proc.ha_client.play_tts_alert.assert_called_once()
    proc.ha_client.play_tts_batch.assert_not_called()


@pytest.mark.asyncio
async def test_flush_batch_multiple_alerts():
    """Multiple alerts in batch should call play_tts_batch."""
    s = _settings(alert_batch_window_seconds=5)
    proc = _processor(s)
    a1 = make_alert(alert_id="a1").alert
    a2 = make_alert(alert_id="a2").alert

    proc._batch_queue.append((a1, "Create"))
    proc._batch_queue.append((a2, "Create"))
    proc._batch_notif_coros.append(
        proc.ha_client.send_persistent_notification(a1, "Create")
    )
    proc._batch_notif_coros.append(
        proc.ha_client.send_persistent_notification(a2, "Create")
    )

    await proc._flush_batch()
    proc.ha_client.play_tts_batch.assert_called_once()
    proc.ha_client.play_tts_alert.assert_not_called()


@pytest.mark.asyncio
async def test_flush_batch_empty():
    """Flushing an empty batch should be a no-op."""
    proc = _processor()
    await proc._flush_batch()
    proc.ha_client.play_tts_alert.assert_not_called()
    proc.ha_client.play_tts_batch.assert_not_called()


@pytest.mark.asyncio
async def test_flush_batch_starts_repeat():
    """Batch flush should start TTS repeat for qualifying alerts."""
    s = _settings(
        alert_batch_window_seconds=5,
        tts_repeat_interval_seconds=60,
        tts_repeat_max=3,
        tts_repeat_priorities="P1",
    )
    proc = _processor(s)
    alert = make_alert(priority="P1").alert

    proc._batch_queue.append((alert, "Create"))
    proc._batch_notif_coros.append(
        proc.ha_client.send_persistent_notification(alert, "Create")
    )

    await proc._flush_batch()
    assert alert.alertId in proc._repeat_tasks


# ── Enqueue batch ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_enqueue_batch_creates_timer():
    """First enqueue should create a batch timer task."""
    s = _settings(alert_batch_window_seconds=5)
    proc = _processor(s)
    alert = make_alert().alert

    # Mock _batch_timer to avoid actual sleep
    proc._batch_timer = AsyncMock()

    notif_coro = proc.ha_client.send_persistent_notification(alert, "Create")
    proc._enqueue_batch(alert, "Create", notif_coro)

    assert len(proc._batch_queue) == 1
    assert proc._batch_task is not None


# ── TTS repeat loop ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_repeat_tts_loop_exhausted():
    """Repeat loop should run max_repeats times then clean up."""
    s = _settings(
        tts_repeat_interval_seconds=0, tts_repeat_max=2, tts_repeat_priorities="P1"
    )
    proc = _processor(s)
    # Override interval to 0 for fast test
    proc.settings = proc.settings.model_copy(update={"tts_repeat_interval_seconds": 0})
    alert = make_alert(priority="P1").alert

    # Run the loop directly
    proc._repeat_tasks[alert.alertId] = MagicMock()
    await proc._repeat_tts_loop(alert, "Create", "media_player.test")

    assert proc.ha_client.play_tts_alert.call_count == 2
    assert alert.alertId not in proc._repeat_tasks


@pytest.mark.asyncio
async def test_repeat_tts_loop_cancelled():
    """Cancelling the loop should clean up the task."""
    s = _settings(
        tts_repeat_interval_seconds=9999, tts_repeat_max=10, tts_repeat_priorities="P1"
    )
    proc = _processor(s)
    alert = make_alert(priority="P1").alert

    # Start the repeat and cancel it immediately
    proc._start_tts_repeat(alert, "Create", "media_player.test")
    assert alert.alertId in proc._repeat_tasks

    proc.cancel_tts_repeat(alert.alertId)
    await asyncio.sleep(0)  # let event loop process
    assert alert.alertId not in proc._repeat_tasks


# ── Automation webhooks ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fire_automation_webhooks_configured():
    """Webhooks should fire when configured for the action."""
    s = _settings(ha_webhook_on_create="my_hook")
    proc = _processor(s)
    payload = make_alert()

    await proc._fire_automation_webhooks(payload)
    proc.ha_client.fire_webhooks.assert_called_once()
    call_args = proc.ha_client.fire_webhooks.call_args
    assert call_args[0][0] == "my_hook"
    assert call_args[0][1]["event"] == "Create"


@pytest.mark.asyncio
async def test_fire_automation_webhooks_not_configured():
    """No webhooks should fire when not configured."""
    proc = _processor()
    payload = make_alert()

    await proc._fire_automation_webhooks(payload)
    proc.ha_client.fire_webhooks.assert_not_called()


@pytest.mark.asyncio
async def test_fire_automation_webhooks_unknown_action():
    """Unknown actions should not fire any webhook."""
    s = _settings(ha_webhook_on_create="my_hook")
    proc = _processor(s)
    payload = make_alert(action="UnknownAction")

    await proc._fire_automation_webhooks(payload)
    proc.ha_client.fire_webhooks.assert_not_called()


# ── process(): immediate mode with repeat ────────────────────────────────────


@pytest.mark.asyncio
async def test_process_immediate_starts_repeat():
    """In immediate mode, P1 should start a TTS repeat."""
    s = _settings(
        tts_repeat_interval_seconds=60,
        tts_repeat_max=3,
        tts_repeat_priorities="P1",
    )
    proc = _processor(s)
    payload = make_alert(priority="P1")

    result = await proc.process(payload, always_notify=True)
    assert result["notified"] is True
    assert payload.alert.alertId in proc._repeat_tasks


@pytest.mark.asyncio
async def test_process_immediate_no_repeat_for_p3():
    """In immediate mode, P3 should NOT start a TTS repeat."""
    s = _settings(
        tts_repeat_interval_seconds=60,
        tts_repeat_max=3,
        tts_repeat_priorities="P1",
    )
    proc = _processor(s)
    payload = make_alert(priority="P3")

    result = await proc.process(payload, always_notify=True)
    assert result["notified"] is True
    assert payload.alert.alertId not in proc._repeat_tasks


# ── process(): batch mode ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_process_batch_mode():
    """Alerts should be batched when batch_window > 0."""
    s = _settings(alert_batch_window_seconds=10)
    proc = _processor(s)
    payload = make_alert()

    result = await proc.process(payload, always_notify=True)
    assert result.get("batched") is True
    assert len(proc._batch_queue) == 1


# ── process(): incident store error handling ─────────────────────────────────


@pytest.mark.asyncio
async def test_process_incident_store_error():
    """Incident store errors should be caught, not crash processing."""
    proc = _processor()
    store = MagicMock()
    store.upsert = AsyncMock(side_effect=RuntimeError("db error"))
    proc.incident_store = store

    payload = make_alert()
    result = await proc.process(payload, always_notify=True)
    # Should still process despite store error
    assert result["notified"] is True


# ── process(): incident store enrichment ─────────────────────────────────────


@pytest.mark.asyncio
async def test_process_enriches_alert_on_create():
    """On Create, process should enrich alert from JSM API."""
    proc = _processor()
    store = MagicMock()
    store.upsert = AsyncMock()
    proc.incident_store = store
    proc.jsm_client.get_alert_details = AsyncMock(
        return_value={
            "tags": ["production"],
            "teams": [{"id": "t1"}],
            "responders": [],
            "details": {"runbook": "http://run.book"},
        }
    )

    payload = make_alert(action="Create")
    await proc.process(payload, always_notify=True)
    store.upsert.assert_called_once()
    call_args = store.upsert.call_args[0]
    assert call_args[0]["tags"] == ["production"]


# ── process(): TTS exception handling ────────────────────────────────────────


@pytest.mark.asyncio
async def test_process_tts_exception_does_not_crash():
    """TTS failure should be logged but not prevent notification."""
    proc = _processor()
    proc.ha_client.play_tts_alert = AsyncMock(side_effect=RuntimeError("TTS down"))

    payload = make_alert()
    result = await proc.process(payload, always_notify=True)
    assert result["notified"] is True


# ── operational_stats ────────────────────────────────────────────────────────


def test_operational_stats_empty():
    proc = _processor()
    stats = proc.operational_stats()
    assert stats["dedup_cache_size"] == 0
    assert stats["batch_queue_size"] == 0
    assert stats["active_tts_repeats"] == 0
    assert stats["tts_repeat_alert_ids"] == []


def test_operational_stats_with_data():
    proc = _processor()
    proc._dedup_cache["a:Create"] = 1.0
    proc._batch_queue.append((MagicMock(), "Create"))
    proc._repeat_tasks["alert-1"] = MagicMock()

    stats = proc.operational_stats()
    assert stats["dedup_cache_size"] == 1
    assert stats["batch_queue_size"] == 1
    assert stats["active_tts_repeats"] == 1
    assert stats["tts_repeat_alert_ids"] == ["alert-1"]


def test_operational_stats_caps_alert_ids():
    """Alert IDs in stats should be capped at 50."""
    proc = _processor()
    for i in range(60):
        proc._repeat_tasks[f"alert-{i}"] = MagicMock()

    stats = proc.operational_stats()
    assert len(stats["tts_repeat_alert_ids"]) == 50
