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
header whose value is the HMAC-SHA256 hex digest of the raw request body
keyed with the shared secret.

NOTE: JSM / OpsGenie custom webhook headers are static strings — JSM itself
cannot compute a per-request HMAC.  Use WEBHOOK_SECRET only when a signing-
capable caller (forwarding proxy, custom script) posts to this service; for
direct JSM webhooks use WEBHOOK_API_KEY instead.

If WEBHOOK_API_KEY is set, every request (except /health and /robots.txt)
must present the key via ?key= query param, X-API-Key header, or a
/KEY/path URL prefix.  Invalid keys receive a stealth 404.

Module layout
─────────────
  src/security.py        middleware + signature / API key verification
  src/routes/ops.py      health, metrics, status, reload, cache
  src/routes/incidents.py incident dashboard
  src/routes/webhook.py  /alert and /alert/{id}/acknowledge
  src/main.py (this)     logging, app composition, lifespan
"""

from __future__ import annotations

import asyncio
import json as _json
import logging
import os
import sys
import time as _time
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException, Request
from starlette.responses import Response as StarletteResponse

from .alert_processor import AlertProcessor
from .config import Settings
from .ha_client import HAClient
from .incident_store import IncidentStore
from .jsm_client import JSMClient
from .metrics import inc
from .routes import incidents as incidents_routes
from .routes import ops as ops_routes
from .routes import webhook as webhook_routes
from .security import (
    ApiKeyPathMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)
from .time_windows import in_any_window

# ── Logging ───────────────────────────────────────────────────────────────────


class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON line for log aggregators."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        return _json.dumps(entry, default=str)


# LOG_FORMAT is read from env directly because logging must be configured
# before Settings() is constructed (Settings logs during init).
_log_format = os.environ.get("LOG_FORMAT", "text").lower()

if _log_format == "json":
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(_JsonFormatter())
    logging.root.addHandler(_handler)
    logging.root.setLevel(logging.INFO)
else:
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
logger = logging.getLogger(__name__)


# ── Application bootstrap ─────────────────────────────────────────────────────


def _build_app() -> FastAPI:
    startup_monotonic = _time.monotonic()
    startup_wall = datetime.now(UTC).isoformat()
    settings = Settings()  # Reads from .env / env vars

    jsm_client = JSMClient(**settings.jsm_client_kwargs())
    ha_client = HAClient(**settings.ha_client_kwargs())

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
        if not incident_store:
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
                # Run retention cleanup if configured.  Settings are read
                # via the processor each iteration so /reload takes effect.
                open_days = processor.settings.incident_retention_open_days
                closed_days = processor.settings.incident_retention_closed_days
                if open_days > 0 or closed_days > 0:
                    await incident_store.cleanup(open_days, closed_days)
            except Exception as exc:
                logger.error("Incident sync failed: %s", exc)
            interval = max(60, processor.settings.incident_sync_interval_minutes * 60)
            await asyncio.sleep(interval)

    async def _credential_check_loop() -> None:
        """
        Background task: verify the Atlassian API token is still valid.

        Runs an initial check 30 s after startup (gives the service time to
        finish booting before hitting external APIs), then repeats every
        TOKEN_CHECK_INTERVAL_HOURS hours.  Fires a HA TTS announcement and
        persistent notification if the token is invalid or revoked.

        During silent/quiet hours the TTS announcement is suppressed, but the
        persistent dashboard notification is still created so the user sees it.
        """
        # Short initial delay so startup logs are clean.
        await asyncio.sleep(30)

        while True:
            inc("credential_checks_total")
            logger.info("Running scheduled Atlassian credential check…")
            is_valid, error = await jsm_client.verify_credentials()
            if is_valid:
                logger.info("Credential check passed — token is valid.")
                # Dismiss any lingering "invalid token" notification in HA so
                # the dashboard doesn't show a stale warning after a rotation.
                await ha_client.dismiss_credential_alert()
            else:
                inc("credential_checks_failed_total")
                now_time = datetime.now().time()  # noqa: DTZ005
                quiet = in_any_window(now_time, processor.settings._silent_windows)
                if quiet:
                    logger.warning(
                        "Credential check FAILED: %s — suppressing TTS (quiet hours).",
                        error,
                    )
                else:
                    logger.error("Credential check FAILED: %s — firing HA alert.", error)
                await ha_client.send_credential_alert(error, suppress_tts=quiet)

            # Read the interval each iteration so /reload takes effect.
            await asyncio.sleep(processor.settings.token_check_interval_hours * 3600)

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # noqa: ANN001
        settings = app.state.settings
        logger.info(
            "JSM-HA Notifier starting — always_notify=%s  check_oncall=%s  "
            "token_check_interval=%dh",
            settings.always_notify_schedule_names,
            settings.check_oncall_schedule_names,
            settings.token_check_interval_hours,
        )
        logger.info(
            "Security: api_key=%s  hmac_signature=%s  rate_limit=%s",
            "enabled" if settings.webhook_api_key else "DISABLED",
            "enabled" if settings.webhook_secret else "disabled",
            (
                f"{settings.rate_limit_requests} req / "
                f"{settings.rate_limit_window_seconds}s"
                if settings.rate_limit_requests > 0
                else "DISABLED"
            ),
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
        version="2.3.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,  # prevent /openapi.json endpoint discovery
    )

    # Shared mutable state — the single source of truth for settings.
    # /reload swaps app.state.settings; middleware and routes read it live.
    app.state.settings = settings
    app.state.processor = processor
    app.state.incident_store = incident_store
    app.state.last_reload = 0.0
    app.state.startup_monotonic = startup_monotonic
    app.state.startup_wall = startup_wall

    return app


app = _build_app()


# ── Middleware ────────────────────────────────────────────────────────────────

# Note: last-added middleware is outermost.  Request flow is therefore
# ApiKeyPath (strips key prefix) → SecurityHeaders → RateLimit → routes.
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(ApiKeyPathMiddleware)


# ── Custom error handlers (prevent FastAPI fingerprinting) ───────────────────


@app.exception_handler(404)
async def _custom_404(request: Request, exc: HTTPException):  # noqa: ARG001
    return StarletteResponse(status_code=404)


@app.exception_handler(405)
async def _custom_405(request: Request, exc: HTTPException):  # noqa: ARG001
    # Return 404 rather than 405 — prevents confirming that an endpoint exists
    # by probing with different HTTP methods.
    return StarletteResponse(status_code=404)


@app.exception_handler(422)
async def _custom_422(request: Request, exc: HTTPException):  # noqa: ARG001
    # FastAPI's 422 Unprocessable Entity format is highly distinctive.
    # Return an empty 404 to prevent framework fingerprinting.
    return StarletteResponse(status_code=404)


# ── Routes ────────────────────────────────────────────────────────────────────

app.include_router(ops_routes.router)
app.include_router(incidents_routes.router)
app.include_router(webhook_routes.router)
