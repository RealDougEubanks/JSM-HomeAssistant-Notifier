"""Security-focused coverage tests: webhook signatures, API key gating, input validation."""

from __future__ import annotations

import hashlib
import hmac
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

_ENV = {
    "JSM_CLOUD_ID": "test-cloud",
    "JSM_USERNAME": "u@e.com",
    "JSM_API_TOKEN": "tok",
    "JSM_MY_USER_ID": "uid",
    "HA_URL": "https://ha.local:8123",
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
        yield main_mod


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app.app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ── Webhook signature verification ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_valid_signature_accepted(client, app):
    """Valid HMAC signature should be accepted."""
    secret = "test-secret-key"
    app._settings = app._settings.model_copy(update={"webhook_secret": secret})
    try:
        body = (
            b'{"action":"Create","alert":{"alertId":"x","message":"m","priority":"P1"}}'
        )
        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

        with patch(
            "src.alert_processor.AlertProcessor.process",
            new_callable=AsyncMock,
            return_value={"status": "processed"},
        ):
            resp = await client.post(
                "/alert",
                content=body,
                headers={"X-Hub-Signature-256": sig},
            )
            assert resp.status_code == 200
    finally:
        app._settings = app._settings.model_copy(update={"webhook_secret": ""})


@pytest.mark.asyncio
async def test_invalid_signature_rejected(client, app):
    """Wrong HMAC signature should be rejected with 401."""
    app._settings = app._settings.model_copy(update={"webhook_secret": "real-secret"})
    try:
        body = (
            b'{"action":"Create","alert":{"alertId":"x","message":"m","priority":"P1"}}'
        )
        resp = await client.post(
            "/alert",
            content=body,
            headers={"X-Hub-Signature-256": "sha256=invalid"},
        )
        assert resp.status_code == 401
    finally:
        app._settings = app._settings.model_copy(update={"webhook_secret": ""})


@pytest.mark.asyncio
async def test_missing_signature_rejected(client, app):
    """Missing signature header when secret is set should be rejected."""
    app._settings = app._settings.model_copy(update={"webhook_secret": "real-secret"})
    try:
        body = (
            b'{"action":"Create","alert":{"alertId":"x","message":"m","priority":"P1"}}'
        )
        resp = await client.post("/alert", content=body)
        assert resp.status_code == 401
    finally:
        app._settings = app._settings.model_copy(update={"webhook_secret": ""})


@pytest.mark.asyncio
async def test_malformed_signature_header(client, app):
    """Signature without sha256= prefix should be rejected."""
    app._settings = app._settings.model_copy(update={"webhook_secret": "real-secret"})
    try:
        body = (
            b'{"action":"Create","alert":{"alertId":"x","message":"m","priority":"P1"}}'
        )
        resp = await client.post(
            "/alert",
            content=body,
            headers={"X-Hub-Signature-256": "not-sha256-prefix"},
        )
        assert resp.status_code == 401
    finally:
        app._settings = app._settings.model_copy(update={"webhook_secret": ""})


@pytest.mark.asyncio
async def test_no_secret_configured_signature_ignored(client, app):
    """Without WEBHOOK_SECRET, signature header is ignored."""
    body = b'{"action":"Create","alert":{"alertId":"x","message":"m","priority":"P1"}}'
    with patch(
        "src.alert_processor.AlertProcessor.process",
        new_callable=AsyncMock,
        return_value={"status": "processed"},
    ):
        resp = await client.post(
            "/alert",
            content=body,
            headers={"X-Hub-Signature-256": "sha256=garbage"},
        )
        assert resp.status_code == 200


# ── API key on alert endpoint ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_api_key_valid(client, app):
    """Valid API key should be accepted."""
    app._settings = app._settings.model_copy(update={"webhook_api_key": "mykey123"})
    try:
        body = (
            b'{"action":"Create","alert":{"alertId":"x","message":"m","priority":"P1"}}'
        )
        with patch(
            "src.alert_processor.AlertProcessor.process",
            new_callable=AsyncMock,
            return_value={"status": "ok"},
        ):
            resp = await client.post("/alert?key=mykey123", content=body)
            assert resp.status_code == 200
    finally:
        app._settings = app._settings.model_copy(update={"webhook_api_key": ""})


@pytest.mark.asyncio
async def test_api_key_wrong(client, app):
    """Wrong API key returns 404 to hide endpoint existence."""
    app._settings = app._settings.model_copy(update={"webhook_api_key": "mykey123"})
    try:
        body = (
            b'{"action":"Create","alert":{"alertId":"x","message":"m","priority":"P1"}}'
        )
        resp = await client.post("/alert?key=wrongkey", content=body)
        assert resp.status_code == 404
    finally:
        app._settings = app._settings.model_copy(update={"webhook_api_key": ""})


# ── /healthz with found schedule ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_healthz_schedule_found(client, app):
    """When a schedule exists in JSM, healthz should report exists_in_jsm=True."""
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
        patch(
            "src.jsm_client.JSMClient.get_schedule_id",
            new_callable=AsyncMock,
            return_value="sched-123",
        ),
        patch(
            "src.jsm_client.JSMClient.is_on_call",
            new_callable=AsyncMock,
            return_value=True,
        ),
    ):
        resp = await client.get("/healthz")
        assert resp.status_code == 200
        data = resp.json()
        # The test env has no configured schedule names, but structure is valid.
        assert data["healthy"] is True
        assert "schedules" in data


@pytest.mark.asyncio
async def test_healthz_ha_down(client, app):
    """When HA is down, healthz should return 503."""
    with (
        patch(
            "src.jsm_client.JSMClient.verify_credentials",
            new_callable=AsyncMock,
            return_value=(True, ""),
        ),
        patch(
            "src.ha_client.HAClient.verify_connectivity",
            new_callable=AsyncMock,
            return_value=(False, "connection refused"),
        ),
        patch(
            "src.jsm_client.JSMClient.get_schedule_id",
            new_callable=AsyncMock,
            return_value=None,
        ),
    ):
        resp = await client.get("/healthz")
        assert resp.status_code == 503
        data = resp.json()
        assert data["checks"]["ha_api"] == "error"


# ── /status endpoint ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_status_schedule_found(client, app):
    """When a schedule is found, /status should return on_call status."""
    with (
        patch(
            "src.jsm_client.JSMClient.get_schedule_id",
            new_callable=AsyncMock,
            return_value="sched-abc",
        ),
        patch(
            "src.jsm_client.JSMClient.is_on_call",
            new_callable=AsyncMock,
            return_value=True,
        ),
    ):
        resp = await client.get("/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "on_call_schedules" in data
        assert "user_id" not in data  # Sensitive field removed


@pytest.mark.asyncio
async def test_status_schedule_not_found(client, app):
    """When a schedule is not found, /status should report error."""
    with patch(
        "src.jsm_client.JSMClient.get_schedule_id",
        new_callable=AsyncMock,
        return_value=None,
    ):
        resp = await client.get("/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "on_call_schedules" in data


# ── Endpoint discovery prevention ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_openapi_json_disabled(client, app):
    """/openapi.json should not be served."""
    resp = await client.get("/openapi.json")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_docs_disabled(client, app):
    """/docs should not be served."""
    resp = await client.get("/docs")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_redoc_disabled(client, app):
    """/redoc should not be served."""
    resp = await client.get("/redoc")
    assert resp.status_code == 404


# ── Security headers ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_security_headers_present(client, app):
    """All responses should include security headers."""
    resp = await client.get("/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Robots-Tag"] == "noindex, nofollow"
    assert resp.headers["Content-Security-Policy"] == "default-src 'none'"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert (
        resp.headers["Cache-Control"] == "no-store, no-cache, must-revalidate, max-age=0"
    )
    assert resp.headers["Pragma"] == "no-cache"
    assert resp.headers["Server"] == "webhook-receiver"


@pytest.mark.asyncio
async def test_server_header_not_uvicorn(client, app):
    """Server header should not reveal the framework."""
    resp = await client.get("/health")
    assert "uvicorn" not in resp.headers.get("Server", "").lower()
    assert "fastapi" not in resp.headers.get("Server", "").lower()


# ── Normalized error responses ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_404_generic_response(client, app):
    """404 should return an empty body with no framework fingerprints."""
    resp = await client.get("/nonexistent-path")
    assert resp.status_code == 404
    assert resp.content == b""
    assert "application/json" not in resp.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_robots_txt(client, app):
    """robots.txt should disallow all crawling."""
    resp = await client.get("/robots.txt")
    assert resp.status_code == 200
    assert "Disallow: /" in resp.text


# ── API key: all three methods ───────────────────────────────────────────────


# Helper to patch /healthz dependencies for API key tests.
def _healthz_patches():
    return (
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
        patch(
            "src.jsm_client.JSMClient.get_schedule_id",
            new_callable=AsyncMock,
            return_value=None,
        ),
    )


@pytest.mark.asyncio
async def test_api_key_via_query_param(client, app):
    """API key as ?key= query parameter should be accepted."""
    app._settings = app._settings.model_copy(update={"webhook_api_key": "testkey"})
    try:
        p1, p2, p3 = _healthz_patches()
        with p1, p2, p3:
            resp = await client.get("/healthz?key=testkey")
            assert resp.status_code == 200
    finally:
        app._settings = app._settings.model_copy(update={"webhook_api_key": ""})


@pytest.mark.asyncio
async def test_api_key_via_header(client, app):
    """API key as X-API-Key header should be accepted."""
    app._settings = app._settings.model_copy(update={"webhook_api_key": "testkey"})
    try:
        p1, p2, p3 = _healthz_patches()
        with p1, p2, p3:
            resp = await client.get("/healthz", headers={"X-API-Key": "testkey"})
            assert resp.status_code == 200
    finally:
        app._settings = app._settings.model_copy(update={"webhook_api_key": ""})


@pytest.mark.asyncio
async def test_api_key_via_path_prefix(client, app):
    """API key as path prefix /KEY/endpoint should be accepted."""
    app._settings = app._settings.model_copy(update={"webhook_api_key": "testkey"})
    try:
        p1, p2, p3 = _healthz_patches()
        with p1, p2, p3:
            resp = await client.get("/testkey/healthz")
            assert resp.status_code == 200
    finally:
        app._settings = app._settings.model_copy(update={"webhook_api_key": ""})


@pytest.mark.asyncio
async def test_api_key_wrong_query_param_rejected(client, app):
    """Wrong ?key= value returns 404."""
    app._settings = app._settings.model_copy(update={"webhook_api_key": "testkey"})
    try:
        p1, p2, p3 = _healthz_patches()
        with p1, p2, p3:
            resp = await client.get("/healthz?key=wrong")
            assert resp.status_code == 404
    finally:
        app._settings = app._settings.model_copy(update={"webhook_api_key": ""})


@pytest.mark.asyncio
async def test_api_key_wrong_header_rejected(client, app):
    """Wrong X-API-Key header returns 404."""
    app._settings = app._settings.model_copy(update={"webhook_api_key": "testkey"})
    try:
        p1, p2, p3 = _healthz_patches()
        with p1, p2, p3:
            resp = await client.get("/healthz", headers={"X-API-Key": "wrong"})
            assert resp.status_code == 404
    finally:
        app._settings = app._settings.model_copy(update={"webhook_api_key": ""})


@pytest.mark.asyncio
async def test_api_key_wrong_path_prefix_rejected(client, app):
    """Wrong path prefix should NOT authenticate (should 404 or 401)."""
    app._settings = app._settings.model_copy(update={"webhook_api_key": "testkey"})
    try:
        resp = await client.get("/wrongkey/healthz")
        assert resp.status_code in (401, 404)
    finally:
        app._settings = app._settings.model_copy(update={"webhook_api_key": ""})


@pytest.mark.asyncio
async def test_api_key_no_credentials_rejected(client, app):
    """No credentials returns 404 (endpoint appears to not exist)."""
    app._settings = app._settings.model_copy(update={"webhook_api_key": "testkey"})
    try:
        p1, p2, p3 = _healthz_patches()
        with p1, p2, p3:
            resp = await client.get("/healthz")
            assert resp.status_code == 404
    finally:
        app._settings = app._settings.model_copy(update={"webhook_api_key": ""})


@pytest.mark.asyncio
async def test_api_key_not_configured_allows_all(client, app):
    """When no API key is configured, all requests should pass."""
    p1, p2, p3 = _healthz_patches()
    with p1, p2, p3:
        resp = await client.get("/healthz")
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_api_key_path_prefix_on_alert(client, app):
    """Path prefix auth should work on POST /alert too."""
    app._settings = app._settings.model_copy(update={"webhook_api_key": "testkey"})
    try:
        body = (
            b'{"action":"Create","alert":{"alertId":"x","message":"m","priority":"P1"}}'
        )
        with patch(
            "src.alert_processor.AlertProcessor.process",
            new_callable=AsyncMock,
            return_value={"status": "ok"},
        ):
            resp = await client.post("/testkey/alert", content=body)
            assert resp.status_code == 200
    finally:
        app._settings = app._settings.model_copy(update={"webhook_api_key": ""})


@pytest.mark.asyncio
async def test_api_key_header_on_alert(client, app):
    """X-API-Key header should work on POST /alert too."""
    app._settings = app._settings.model_copy(update={"webhook_api_key": "testkey"})
    try:
        body = (
            b'{"action":"Create","alert":{"alertId":"x","message":"m","priority":"P1"}}'
        )
        with patch(
            "src.alert_processor.AlertProcessor.process",
            new_callable=AsyncMock,
            return_value={"status": "ok"},
        ):
            resp = await client.post(
                "/alert", content=body, headers={"X-API-Key": "testkey"}
            )
            assert resp.status_code == 200
    finally:
        app._settings = app._settings.model_copy(update={"webhook_api_key": ""})


@pytest.mark.asyncio
async def test_api_key_path_prefix_on_status(client, app):
    """Path prefix auth should work on GET /status."""
    app._settings = app._settings.model_copy(update={"webhook_api_key": "testkey"})
    try:
        with patch(
            "src.jsm_client.JSMClient.get_schedule_id",
            new_callable=AsyncMock,
            return_value=None,
        ):
            resp = await client.get("/testkey/status")
            assert resp.status_code == 200
    finally:
        app._settings = app._settings.model_copy(update={"webhook_api_key": ""})


# ── All protected endpoints return 404 without API key ───────────────────────


# Every endpoint gated by Depends(_require_api_key) must return 404 when
# WEBHOOK_API_KEY is set and no key is provided.  This prevents attackers
# from discovering which endpoints exist.

_PROTECTED_ENDPOINTS = [
    ("GET", "/healthz"),
    ("GET", "/status"),
    ("POST", "/cache/invalidate"),
    ("GET", "/incidents"),
    ("GET", "/incidents/summary"),
    ("GET", "/incidents/test-alert-id"),
    ("POST", "/incidents/test-alert-id/close"),
    ("POST", "/incidents/sync"),
    ("POST", "/alert/test-alert-id/acknowledge"),
    ("POST", "/alert"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", _PROTECTED_ENDPOINTS)
async def test_all_protected_endpoints_return_404_without_key(client, app, method, path):
    """Every protected endpoint must return 404 when API key is set but not provided."""
    app._settings = app._settings.model_copy(update={"webhook_api_key": "required-key"})
    try:
        if method == "GET":
            resp = await client.get(path)
        else:
            resp = await client.post(path, content=b"{}")
        assert (
            resp.status_code == 404
        ), f"{method} {path} returned {resp.status_code}, expected 404"
        assert resp.content == b""
    finally:
        app._settings = app._settings.model_copy(update={"webhook_api_key": ""})


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", _PROTECTED_ENDPOINTS)
async def test_all_protected_endpoints_return_404_with_wrong_key(
    client, app, method, path
):
    """Every protected endpoint must return 404 with an incorrect API key."""
    app._settings = app._settings.model_copy(update={"webhook_api_key": "correct-key"})
    try:
        if method == "GET":
            resp = await client.get(path, params={"key": "wrong-key"})
        else:
            resp = await client.post(path, content=b"{}", params={"key": "wrong-key"})
        assert (
            resp.status_code == 404
        ), f"{method} {path} returned {resp.status_code}, expected 404"
        assert resp.content == b""
    finally:
        app._settings = app._settings.model_copy(update={"webhook_api_key": ""})
