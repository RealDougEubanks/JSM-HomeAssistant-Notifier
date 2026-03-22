"""
JSM Home Assistant Notifier — FastAPI application entry point.

Webhook endpoints
─────────────────
  POST /alert
      Main endpoint.  JSM posts all alert events here.

      Query params:
        mode=always   Skip the on-call check and always notify.
                      Use this URL for schedules that should ALWAYS page you
                      (e.g. Internal Systems_schedule).

  GET  /health        Kubernetes / Docker health probe.
  GET  /status        On-call status snapshot across all watched schedules.
  POST /cache/invalidate
                      Force-refresh the on-call cache (e.g. after a rotation).

Security
────────
If WEBHOOK_SECRET is set in .env, every inbound POST must include an
  X-Hub-Signature-256: sha256=<hmac>
header.  JSM supports adding a custom header to outgoing webhook calls; set
the value to the HMAC-SHA256 hex digest of the raw request body using your
shared secret.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import re
import secrets
import sys
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse

from .alert_processor import AlertProcessor
from .config import Settings
from .ha_client import HAClient
from .incident_store import IncidentStore
from .jsm_client import JSMClient
from .models import JSMWebhookPayload

# Maximum allowed request body size (1 MB).  JSM webhook payloads are typically
# a few KB; anything larger is likely malicious or malformed.
_MAX_BODY_BYTES = 1_048_576

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── Application bootstrap ─────────────────────────────────────────────────────


def _build_app() -> tuple[FastAPI, Settings, AlertProcessor, IncidentStore | None]:
    settings = Settings()  # Reads from .env / env vars

    jsm_client = JSMClient(
        api_url=settings.jsm_api_url,
        cloud_id=settings.jsm_cloud_id,
        username=settings.jsm_username,
        api_token=settings.jsm_api_token,
        my_user_id=settings.jsm_my_user_id,
        jira_base_url=settings.jira_base_url,
    )

    ha_client = HAClient(
        ha_url=settings.ha_url,
        ha_token=settings.ha_token,
        media_player=settings.ha_media_player_entity,
        tts_service=settings.ha_tts_service,
        tts_language=settings.ha_tts_language,
        tts_voice=settings.ha_tts_voice,
        notifier_label=settings.ha_notifier_label,
        announcement_format=settings.announcement_format,
        terse_announcement_format=settings.terse_announcement_format,
        volume_default=(
            float(settings.ha_volume_default) if settings.ha_volume_default else None
        ),
        volume_terse=(
            float(settings.ha_volume_terse) if settings.ha_volume_terse else None
        ),
        enable_emojis=settings.enable_emojis,
    )

    # ── Incident dashboard (optional) ────────────────────────────────────
    incident_store: IncidentStore | None = None
    if settings.incident_dashboard_enabled:
        incident_store = IncidentStore(settings.incident_db_path)
        logger.info(
            "Incident dashboard enabled — db=%s sync=%dm",
            settings.incident_db_path,
            settings.incident_sync_interval_minutes,
        )

    processor = AlertProcessor(settings, jsm_client, ha_client, incident_store)

    async def _incident_sync_loop() -> None:
        """Background task: periodically sync open alerts from JSM and run retention cleanup."""
        interval = settings.incident_sync_interval_minutes * 60
        if interval <= 0 or not incident_store:
            return
        # Initial delay to let the service boot cleanly.
        await asyncio.sleep(60)
        while True:
            try:
                logger.info("Running scheduled JSM incident sync…")
                alerts = await jsm_client.list_open_alerts()
                if alerts:
                    count = await incident_store.bulk_upsert(alerts)
                    logger.info("Incident sync: upserted %d alert(s)", count)
                # Run retention cleanup if configured.
                open_days = settings.incident_retention_open_days
                closed_days = settings.incident_retention_closed_days
                if open_days > 0 or closed_days > 0:
                    await incident_store.cleanup(open_days, closed_days)
            except Exception as exc:
                logger.error("Incident sync failed: %s", exc)
            await asyncio.sleep(interval)

    async def _credential_check_loop() -> None:
        """
        Background task: verify the Atlassian API token is still valid.

        Runs an initial check 30 s after startup (gives the service time to
        finish booting before hitting external APIs), then repeats every
        TOKEN_CHECK_INTERVAL_HOURS hours.  Fires a HA TTS announcement and
        persistent notification if the token is invalid or revoked.
        """
        interval_seconds = settings.token_check_interval_hours * 3600
        # Short initial delay so startup logs are clean.
        await asyncio.sleep(30)

        while True:
            logger.info("Running scheduled Atlassian credential check…")
            is_valid, error = await jsm_client.verify_credentials()
            if is_valid:
                logger.info("Credential check passed — token is valid.")
                # Dismiss any lingering "invalid token" notification in HA so
                # the dashboard doesn't show a stale warning after a rotation.
                await ha_client.dismiss_credential_alert()
            else:
                logger.error("Credential check FAILED: %s — firing HA alert.", error)
                await ha_client.send_credential_alert(error)

            await asyncio.sleep(interval_seconds)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):  # noqa: ANN001
        logger.info(
            "JSM-HA Notifier starting — always_notify=%s  check_oncall=%s  "
            "token_check_interval=%dh",
            settings.always_notify_schedule_names,
            settings.check_oncall_schedule_names,
            settings.token_check_interval_hours,
        )

        # ── Startup connectivity checks (non-blocking) ────────────────
        jsm_ok, jsm_err = await jsm_client.verify_credentials()
        if jsm_ok:
            logger.info("Startup check: JSM API — OK")
        else:
            logger.warning("Startup check: JSM API — FAILED (%s)", jsm_err)

        ha_ok, ha_err = await ha_client.verify_connectivity()
        if ha_ok:
            logger.info("Startup check: HA API — OK")
        else:
            logger.warning("Startup check: HA API — FAILED (%s)", ha_err)

        cred_task = asyncio.create_task(_credential_check_loop())
        sync_task = (
            asyncio.create_task(_incident_sync_loop())
            if incident_store and settings.incident_sync_interval_minutes > 0
            else None
        )
        try:
            yield
        finally:
            cred_task.cancel()
            with suppress(asyncio.CancelledError):
                await cred_task
            if sync_task:
                sync_task.cancel()
                with suppress(asyncio.CancelledError):
                    await sync_task
            # Close persistent HTTP clients and stores.
            await jsm_client.aclose()
            await ha_client.aclose()
            if incident_store:
                await incident_store.close()
            logger.info("JSM-HA Notifier shutting down.")

    app = FastAPI(
        title="JSM Home Assistant Notifier",
        description=(
            "Receives JSM / OpsGenie webhooks and plays TTS alerts "
            "on Home Assistant when you are on-call or escalated to."
        ),
        version="2.0.0",
        lifespan=lifespan,
    )

    return app, settings, processor, incident_store


app, _settings, _processor, _incident_store = _build_app()


# ── Webhook signature verification ───────────────────────────────────────────


def _verify_signature(request: Request, body: bytes) -> bool:
    """
    Validate the X-Hub-Signature-256 header if WEBHOOK_SECRET is configured.
    Always returns True if no secret is set (dev / internal-only deployments).
    """
    if not _settings.webhook_secret:
        return True

    try:
        sig_header = request.headers.get("X-Hub-Signature-256", "")
        if not sig_header.startswith("sha256="):
            logger.warning(
                "Webhook request missing or malformed X-Hub-Signature-256 header"
            )
            return False

        expected = (
            "sha256="
            + hmac.new(
                _settings.webhook_secret.encode("utf-8"),
                body,
                hashlib.sha256,
            ).hexdigest()
        )

        return hmac.compare_digest(sig_header, expected)
    except Exception:
        # Catch-all to prevent any exception from leaking the secret in a traceback.
        logger.error("Webhook signature verification error")
        return False


def _verify_api_key(key: str | None) -> bool:
    """
    Check the ``?key=`` query parameter against WEBHOOK_API_KEY.
    Returns True if no key is configured (disabled) or if the key matches.
    Uses constant-time comparison to prevent timing attacks.
    """
    if not _settings.webhook_api_key:
        return True
    if not key:
        logger.warning("Request rejected — missing ?key= parameter")
        return False
    return secrets.compare_digest(key, _settings.webhook_api_key)


# ── Routes ────────────────────────────────────────────────────────────────────


@app.get("/health", tags=["ops"])
async def health_check():
    """Docker / Kubernetes liveness probe."""
    return {"status": "ok"}


@app.get("/healthz", tags=["ops"])
async def deep_health_check():
    """
    Deep health check — verifies JSM and HA API connectivity.

    Returns 200 if all checks pass, 503 if any fail.  Useful for monitoring
    dashboards and more thorough readiness probes.
    """
    checks: dict = {}

    jsm_ok, jsm_err = await _processor.jsm_client.verify_credentials()
    checks["jsm_api"] = "ok" if jsm_ok else "error"
    if not jsm_ok:
        logger.warning("Deep health check: JSM API failed — %s", jsm_err)

    ha_ok, ha_err = await _processor.ha_client.verify_connectivity()
    checks["ha_api"] = "ok" if ha_ok else "error"
    if not ha_ok:
        logger.warning("Deep health check: HA API failed — %s", ha_err)

    all_ok = all(v == "ok" for v in checks.values())
    return JSONResponse(
        {"healthy": all_ok, "checks": checks},
        status_code=200 if all_ok else 503,
    )


@app.get("/status", tags=["ops"])
async def on_call_status():
    """
    Returns the current on-call status for all watched schedules.
    Useful for debugging and for verifying your JSM credentials work.
    """
    status: dict = {}

    for name in _settings.check_oncall_schedule_names:
        schedule_id = await _processor.jsm_client.get_schedule_id(name)
        if schedule_id:
            is_on_call = await _processor.jsm_client.is_on_call(
                schedule_id, cache_ttl=0  # force fresh lookup
            )
            status[name] = {"schedule_id": schedule_id, "on_call": is_on_call}
        else:
            status[name] = {"schedule_id": None, "on_call": None, "error": "not found"}

    return {
        "user_id": _settings.jsm_my_user_id,
        "on_call_schedules": status,
        "always_notify_schedules": _settings.always_notify_schedule_names,
    }


@app.post("/cache/invalidate", tags=["ops"])
async def invalidate_cache():
    """Force the next on-call check to query JSM instead of using cached data."""
    _processor.jsm_client.invalidate_oncall_cache()
    return {"status": "cache invalidated"}


# ── Incident dashboard ────────────────────────────────────────────────────────


@app.get("/incidents", tags=["dashboard"])
async def list_incidents(
    status: str | None = Query(
        default=None,
        description="Filter by status: open, acknowledged, escalated, closed",
    ),
    priority: str | None = Query(
        default=None, description="Filter by priority: P1, P2, P3, P4, P5"
    ),
    limit: int = Query(default=200, ge=1, le=1000, description="Max results"),
    key: str | None = Query(
        default=None, description="API key (required if WEBHOOK_API_KEY is set)"
    ),
):
    """
    Return current incident state.  Requires ``INCIDENT_DASHBOARD_ENABLED=true``.

    Supports optional ``?status=`` and ``?priority=`` filters.
    Output is Grafana JSON datasource compatible.
    """
    if not _verify_api_key(key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    if not _incident_store:
        raise HTTPException(
            status_code=404,
            detail="Incident dashboard is disabled. Set INCIDENT_DASHBOARD_ENABLED=true in .env",
        )
    incidents = await _incident_store.get_all(
        status=status, priority=priority, limit=limit
    )
    return JSONResponse(content={"incidents": incidents, "count": len(incidents)})


@app.get("/incidents/summary", tags=["dashboard"])
async def incident_summary(
    key: str | None = Query(
        default=None, description="API key (required if WEBHOOK_API_KEY is set)"
    ),
):
    """Return aggregate incident counts by status and priority."""
    if not _verify_api_key(key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    if not _incident_store:
        raise HTTPException(
            status_code=404,
            detail="Incident dashboard is disabled. Set INCIDENT_DASHBOARD_ENABLED=true in .env",
        )
    summary = await _incident_store.get_summary()
    return JSONResponse(content=summary)


@app.get("/incidents/{alert_id}", tags=["dashboard"])
async def get_incident(
    alert_id: str = Path(..., description="Alert ID to look up"),
    key: str | None = Query(
        default=None, description="API key (required if WEBHOOK_API_KEY is set)"
    ),
):
    """Return a single incident by alert ID."""
    if not _verify_api_key(key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    if not _incident_store:
        raise HTTPException(
            status_code=404,
            detail="Incident dashboard is disabled. Set INCIDENT_DASHBOARD_ENABLED=true in .env",
        )
    incident = await _incident_store.get_one(alert_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return JSONResponse(content=incident)


@app.post("/incidents/{alert_id}/close", tags=["dashboard"])
async def force_close_incident(
    alert_id: str = Path(..., description="Alert ID to force-close"),
    key: str | None = Query(
        default=None, description="API key (required if WEBHOOK_API_KEY is set)"
    ),
):
    """
    Force-close an incident from the dashboard.

    Sets status to 'closed' and records a ForceClose action.  Also dismisses
    any corresponding HA persistent notification and cancels TTS repeats.
    """
    if not _verify_api_key(key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    if not _incident_store:
        raise HTTPException(
            status_code=404,
            detail="Incident dashboard is disabled. Set INCIDENT_DASHBOARD_ENABLED=true in .env",
        )
    closed = await _incident_store.force_close(alert_id)
    if not closed:
        raise HTTPException(
            status_code=404, detail="Incident not found or already closed"
        )
    # Also dismiss HA notification and cancel TTS repeat.
    await _processor.ha_client.dismiss_notification(alert_id)
    _processor.cancel_tts_repeat(alert_id)
    return {"alert_id": alert_id, "status": "closed", "action": "ForceClose"}


@app.post("/incidents/sync", tags=["dashboard"])
async def force_incident_sync(
    key: str | None = Query(
        default=None, description="API key (required if WEBHOOK_API_KEY is set)"
    ),
):
    """Force an immediate sync of open alerts from JSM."""
    if not _verify_api_key(key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    if not _incident_store:
        raise HTTPException(
            status_code=404,
            detail="Incident dashboard is disabled. Set INCIDENT_DASHBOARD_ENABLED=true in .env",
        )
    alerts = await _processor.jsm_client.list_open_alerts()
    count = await _incident_store.bulk_upsert(alerts)
    return {"status": "synced", "alerts_upserted": count}


# Allowed characters in JSM alert IDs (UUIDs, alphanumeric, hyphens, underscores).
_ALERT_ID_RE = re.compile(r"^[a-zA-Z0-9\-_]{1,200}$")


@app.post("/alert/{alert_id}/acknowledge", tags=["webhook"])
async def acknowledge_alert(
    request: Request,
    alert_id: str = Path(
        ...,
        description="JSM alert ID (alphanumeric, hyphens, underscores; max 200 chars)",
    ),
    key: str | None = Query(
        default=None,
        description="API key for authentication (must match WEBHOOK_API_KEY).",
    ),
):
    """
    Acknowledge a JSM alert by alert ID.

    Intended for use from HA automations — e.g. a button on the dashboard or a
    voice command that calls this endpoint to acknowledge the alert without
    needing to open the JSM web UI.

    Returns 200 with ``{"alert_id": ..., "acknowledged": true}`` on success,
    400 for invalid alert IDs, 401 for bad API key, or 502 if the JSM API call fails.
    """
    if not _verify_api_key(key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    if not _ALERT_ID_RE.match(alert_id):
        raise HTTPException(status_code=400, detail="Invalid alert_id format")

    source_ip = request.client.host if request.client else "unknown"
    logger.info(
        "Acknowledge request — alert_id=%s source_ip=%s",
        alert_id,
        source_ip,
    )

    success, error = await _processor.jsm_client.acknowledge_alert(alert_id)
    if success:
        # Also dismiss the persistent notification and stop TTS repeats.
        await _processor.ha_client.dismiss_notification(alert_id)
        _processor.cancel_tts_repeat(alert_id)
        logger.info("Alert %s acknowledged via API from %s", alert_id, source_ip)
        return {"alert_id": alert_id, "acknowledged": True}
    logger.error("Failed to acknowledge alert %s: %s", alert_id, error)
    raise HTTPException(status_code=502, detail=f"JSM acknowledge failed: {error}")


@app.post("/alert", tags=["webhook"])
async def receive_alert(
    request: Request,
    mode: str | None = Query(
        default=None,
        description=(
            "Set to 'always' to skip the on-call check and always notify. "
            "Use this for schedules like Internal Systems_schedule."
        ),
    ),
    key: str | None = Query(
        default=None,
        description="API key for webhook authentication (must match WEBHOOK_API_KEY).",
    ),
):
    """
    Main JSM / OpsGenie inbound webhook endpoint.

    Configure two webhook URLs in JSM:
      • https://<your-host>/alert?key=YOUR_KEY               → on-call check
      • https://<your-host>/alert?mode=always&key=YOUR_KEY   → always notify
    """
    if not _verify_api_key(key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    body = await request.body()

    if len(body) > _MAX_BODY_BYTES:
        logger.warning(
            "Rejecting oversized request body (%d bytes) from %s",
            len(body),
            request.client.host if request.client else "unknown",
        )
        raise HTTPException(status_code=413, detail="Request body too large")

    if not _verify_signature(request, body):
        logger.warning(
            "Webhook signature verification failed from %s",
            request.client.host if request.client else "unknown",
        )
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    try:
        payload = JSMWebhookPayload.model_validate_json(body)
    except Exception as exc:
        logger.error("Failed to parse JSM webhook payload: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid payload format") from exc

    always_notify = mode == "always"

    logger.info(
        "Incoming webhook — alert_id=%s action=%s priority=%s message=%r mode=%s",
        payload.alert.alertId,
        payload.action,
        payload.alert.priority,
        payload.alert.message,
        "always" if always_notify else "oncall-check",
    )

    result = await _processor.process(payload, always_notify=always_notify)
    return JSONResponse(content=result)
