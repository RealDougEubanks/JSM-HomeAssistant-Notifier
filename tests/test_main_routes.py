"""Tests for main.py FastAPI routes."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

# Patch environment before importing main (module-level _build_app runs on import)
_ENV = {
    "JSM_CLOUD_ID": "test-cloud",
    "JSM_USERNAME": "u@e.com",
    "JSM_API_TOKEN": "tok",
    "JSM_MY_USER_ID": "uid",
    "HA_URL": "http://ha.local:8123",
    "HA_TOKEN": "ha-tok",
    "WEBHOOK_SECRET": "",
    "WEBHOOK_API_KEY": "",
    "INCIDENT_DASHBOARD_ENABLED": "false",
}


@pytest.fixture
def _patch_env(monkeypatch):
    for k, v in _ENV.items():
        monkeypatch.setenv(k, v)


@pytest.fixture
def app(_patch_env):
    """Import the app fresh with patched env."""
    # Patch verify calls made during lifespan
    with (
        patch(
            "src.jsm_client.JSMClient.verify_credentials",
            new_callable=AsyncMock,
            return_value=(True, ""),
        ),
        patch(
            "src.ha_client.HAClient.verify_connectivity",
            new_callable=AsyncMock,
            return_value=(True, ""),
        ),
        patch("src.ha_client.HAClient.dismiss_credential_alert", new_callable=AsyncMock),
    ):
        import importlib

        import src.main as main_mod

        importlib.reload(main_mod)
        yield main_mod.app


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ── Health ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ── Cache invalidate ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cache_invalidate(client):
    resp = await client.post("/cache/invalidate")
    assert resp.status_code == 200
    assert resp.json()["status"] == "cache invalidated"


# ── Alert endpoint ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_alert_invalid_payload(client):
    resp = await client.post("/alert", content=b"not json")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_alert_oversized_body(client):
    resp = await client.post("/alert", content=b"x" * (1_048_577))
    assert resp.status_code == 413


@pytest.mark.asyncio
async def test_alert_valid_payload(client):
    payload = {
        "action": "Create",
        "alert": {
            "alertId": "a-1",
            "message": "Test",
            "priority": "P3",
        },
    }
    with patch(
        "src.alert_processor.AlertProcessor.process",
        new_callable=AsyncMock,
        return_value={"status": "processed"},
    ):
        resp = await client.post("/alert", content=json.dumps(payload).encode())
        assert resp.status_code == 200
        assert resp.json()["status"] == "processed"


@pytest.mark.asyncio
async def test_alert_always_mode(client):
    payload = {
        "action": "Create",
        "alert": {
            "alertId": "a-2",
            "message": "Test",
            "priority": "P1",
        },
    }
    with patch(
        "src.alert_processor.AlertProcessor.process",
        new_callable=AsyncMock,
        return_value={"status": "always"},
    ):
        resp = await client.post(
            "/alert?mode=always", content=json.dumps(payload).encode()
        )
        assert resp.status_code == 200


# ── Incidents (disabled) ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_incidents_disabled(client):
    resp = await client.get("/incidents")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_incidents_summary_disabled(client):
    resp = await client.get("/incidents/summary")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_incidents_single_disabled(client):
    resp = await client.get("/incidents/abc123")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_incidents_close_disabled(client):
    resp = await client.post("/incidents/abc123/close")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_incidents_sync_disabled(client):
    resp = await client.post("/incidents/sync")
    assert resp.status_code == 404


# ── Acknowledge endpoint ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_acknowledge_invalid_id(client):
    resp = await client.post("/alert/../../etc/passwd/acknowledge")
    assert resp.status_code in (400, 404, 422)


@pytest.mark.asyncio
async def test_acknowledge_success(client):
    with (
        patch(
            "src.jsm_client.JSMClient.acknowledge_alert",
            new_callable=AsyncMock,
            return_value=(True, ""),
        ),
        patch(
            "src.ha_client.HAClient.dismiss_notification",
            new_callable=AsyncMock,
            return_value=True,
        ),
        patch(
            "src.alert_processor.AlertProcessor.cancel_tts_repeat",
            return_value=None,
        ),
    ):
        resp = await client.post("/alert/abc-123/acknowledge")
        assert resp.status_code == 200
        assert resp.json()["acknowledged"] is True


@pytest.mark.asyncio
async def test_acknowledge_jsm_failure(client):
    with patch(
        "src.jsm_client.JSMClient.acknowledge_alert",
        new_callable=AsyncMock,
        return_value=(False, "timeout"),
    ):
        resp = await client.post("/alert/abc-123/acknowledge")
        assert resp.status_code == 502


# ── API key auth ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_api_key_required_when_set(client):
    import src.main as main_mod

    main_mod._settings = main_mod._settings.model_copy(
        update={"webhook_api_key": "secret123"}
    )
    try:
        resp = await client.post(
            "/alert",
            content=b'{"action":"Create","alert":{"alertId":"x","message":"m","priority":"P1"}}',
        )
        assert resp.status_code == 401
    finally:
        main_mod._settings = main_mod._settings.model_copy(update={"webhook_api_key": ""})


# ── Webhook signature ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_signature_required_when_set(client):
    import src.main as main_mod

    main_mod._settings = main_mod._settings.model_copy(
        update={"webhook_secret": "mysecret"}
    )
    try:
        resp = await client.post(
            "/alert",
            content=b'{"action":"Create","alert":{"alertId":"x","message":"m","priority":"P1"}}',
        )
        assert resp.status_code == 401
    finally:
        main_mod._settings = main_mod._settings.model_copy(update={"webhook_secret": ""})


# ── Deep health check ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_deep_health_all_ok(client):
    with (
        patch(
            "src.jsm_client.JSMClient.verify_credentials",
            new_callable=AsyncMock,
            return_value=(True, ""),
        ),
        patch(
            "src.ha_client.HAClient.verify_connectivity",
            new_callable=AsyncMock,
            return_value=(True, ""),
        ),
    ):
        resp = await client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["healthy"] is True


@pytest.mark.asyncio
async def test_deep_health_jsm_down(client):
    with (
        patch(
            "src.jsm_client.JSMClient.verify_credentials",
            new_callable=AsyncMock,
            return_value=(False, "timeout"),
        ),
        patch(
            "src.ha_client.HAClient.verify_connectivity",
            new_callable=AsyncMock,
            return_value=(True, ""),
        ),
    ):
        resp = await client.get("/healthz")
        assert resp.status_code == 503
        assert resp.json()["healthy"] is False


# ── On-call status ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_status_endpoint(client):
    with (
        patch(
            "src.jsm_client.JSMClient.get_schedule_id",
            new_callable=AsyncMock,
            return_value=None,
        ),
    ):
        resp = await client.get("/status")
        assert resp.status_code == 200
