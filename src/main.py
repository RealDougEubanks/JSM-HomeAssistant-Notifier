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
import sys
from contextlib import asynccontextmanager
from typing import Optional

import re

from fastapi import FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse

from .alert_processor import AlertProcessor
from .config import Settings
from .ha_client import HAClient
from .jsm_client import JSMClient
from .models import JSMWebhookPayload

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── Application bootstrap ─────────────────────────────────────────────────────

def _build_app() -> tuple[FastAPI, Settings, AlertProcessor]:
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
        volume_default=float(settings.ha_volume_default) if settings.ha_volume_default else None,
        volume_terse=float(settings.ha_volume_terse) if settings.ha_volume_terse else None,
    )

    processor = AlertProcessor(settings, jsm_client, ha_client)

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
                logger.error(
                    "Credential check FAILED: %s — firing HA alert.", error
                )
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

        task = asyncio.create_task(_credential_check_loop())
        try:
            yield
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            # Close persistent HTTP clients.
            await jsm_client.aclose()
            await ha_client.aclose()
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

    return app, settings, processor


app, _settings, _processor = _build_app()


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
            logger.warning("Webhook request missing or malformed X-Hub-Signature-256 header")
            return False

        expected = "sha256=" + hmac.new(
            _settings.webhook_secret.encode("utf-8"),
            body,
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(sig_header, expected)
    except Exception:
        # Catch-all to prevent any exception from leaking the secret in a traceback.
        logger.error("Webhook signature verification error")
        return False


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
    checks["jsm_api"] = "ok" if jsm_ok else f"error: {jsm_err[:100]}"

    ha_ok, ha_err = await _processor.ha_client.verify_connectivity()
    checks["ha_api"] = "ok" if ha_ok else f"error: {ha_err[:100]}"

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


# Allowed characters in JSM alert IDs (UUIDs, alphanumeric, hyphens, underscores).
_ALERT_ID_RE = re.compile(r"^[a-zA-Z0-9\-_]{1,200}$")


@app.post("/alert/{alert_id}/acknowledge", tags=["webhook"])
async def acknowledge_alert(
    request: Request,
    alert_id: str = Path(
        ...,
        description="JSM alert ID (alphanumeric, hyphens, underscores; max 200 chars)",
    ),
):
    """
    Acknowledge a JSM alert by alert ID.

    Intended for use from HA automations — e.g. a button on the dashboard or a
    voice command that calls this endpoint to acknowledge the alert without
    needing to open the JSM web UI.

    Returns 200 with ``{"alert_id": ..., "acknowledged": true}`` on success,
    400 for invalid alert IDs, or 502 if the JSM API call fails.
    """
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
    mode: Optional[str] = Query(
        default=None,
        description=(
            "Set to 'always' to skip the on-call check and always notify. "
            "Use this for schedules like Internal Systems_schedule."
        ),
    ),
):
    """
    Main JSM / OpsGenie inbound webhook endpoint.

    Configure two webhook URLs in JSM:
      • https://<your-host>/alert              → on-call check before notifying
      • https://<your-host>/alert?mode=always  → always notify (Internal Systems)
    """
    body = await request.body()

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
        raise HTTPException(status_code=400, detail=f"Invalid payload: {exc}") from exc

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
