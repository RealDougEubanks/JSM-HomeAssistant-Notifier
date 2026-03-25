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
import json as _json
import logging
import os
import re
import secrets
import sys
import time as _time
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

from .alert_processor import AlertProcessor
from .config import Settings
from .ha_client import HAClient
from .incident_store import IncidentStore
from .jsm_client import JSMClient
from .models import JSMWebhookPayload
from .time_windows import in_any_window

# Maximum allowed request body size (1 MB).  JSM webhook payloads are typically
# a few KB; anything larger is likely malicious or malformed.
_MAX_BODY_BYTES = 1_048_576

# ── Prometheus-compatible metrics (no external dependency) ───────────────────

_metrics: dict[str, int] = {
    "alerts_received_total": 0,
    "alerts_notified_total": 0,
    "alerts_deduplicated_total": 0,
    "alerts_dismissed_total": 0,
    "alerts_rate_limited_total": 0,
    "credential_checks_total": 0,
    "credential_checks_failed_total": 0,
    "healthz_requests_total": 0,
}


def _inc(metric: str, amount: int = 1) -> None:
    """Increment a metric counter. No-op if metric name is unknown."""
    if metric in _metrics:
        _metrics[metric] += amount


# ── Simple rate limiter (token bucket, per-IP) ──────────────────────────────

_RATE_LIMIT_REQUESTS = 60  # max requests per window
_RATE_LIMIT_WINDOW = 60.0  # seconds
_rate_buckets: dict[str, list[float]] = {}
_MAX_TRACKED_IPS = 10_000  # prevent unbounded memory growth


def _rate_limited(client_ip: str) -> bool:
    """Return True if *client_ip* has exceeded the rate limit."""
    now = _time.monotonic()

    # Evict oldest half if tracking too many IPs (DoS protection).
    if len(_rate_buckets) >= _MAX_TRACKED_IPS:
        to_remove = sorted(
            _rate_buckets, key=lambda k: _rate_buckets[k][-1] if _rate_buckets[k] else 0
        )
        for k in to_remove[: len(to_remove) // 2]:
            del _rate_buckets[k]

    timestamps = _rate_buckets.setdefault(client_ip, [])
    # Prune timestamps outside the window.
    cutoff = now - _RATE_LIMIT_WINDOW
    _rate_buckets[client_ip] = [t for t in timestamps if t > cutoff]
    timestamps = _rate_buckets[client_ip]

    if len(timestamps) >= _RATE_LIMIT_REQUESTS:
        return True
    timestamps.append(now)
    return False


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

_STARTUP_MONOTONIC: float = 0.0
_STARTUP_WALL: str = ""


def _build_app() -> tuple[FastAPI, Settings, AlertProcessor, IncidentStore | None]:
    global _STARTUP_MONOTONIC, _STARTUP_WALL  # noqa: PLW0603
    _STARTUP_MONOTONIC = _time.monotonic()
    _STARTUP_WALL = datetime.now(UTC).isoformat()
    settings = Settings()  # Reads from .env / env vars

    jsm_client = JSMClient(
        api_url=settings.jsm_api_url,
        cloud_id=settings.jsm_cloud_id,
        username=settings.jsm_username,
        api_token=settings.jsm_api_token,
        my_user_id=settings.jsm_my_user_id,
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

        During silent/quiet hours the TTS announcement is suppressed, but the
        persistent dashboard notification is still created so the user sees it.
        """
        interval_seconds = settings.token_check_interval_hours * 3600
        # Short initial delay so startup logs are clean.
        await asyncio.sleep(30)

        while True:
            _inc("credential_checks_total")
            logger.info("Running scheduled Atlassian credential check…")
            is_valid, error = await jsm_client.verify_credentials()
            if is_valid:
                logger.info("Credential check passed — token is valid.")
                # Dismiss any lingering "invalid token" notification in HA so
                # the dashboard doesn't show a stale warning after a rotation.
                await ha_client.dismiss_credential_alert()
            else:
                _inc("credential_checks_failed_total")
                from datetime import datetime

                now_time = datetime.now().time()  # noqa: DTZ005
                quiet = in_any_window(now_time, settings._silent_windows)
                if quiet:
                    logger.warning(
                        "Credential check FAILED: %s — suppressing TTS (quiet hours).",
                        error,
                    )
                else:
                    logger.error("Credential check FAILED: %s — firing HA alert.", error)
                await ha_client.send_credential_alert(error, suppress_tts=quiet)

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
        docs_url=None,
        redoc_url=None,
        openapi_url=None,  # prevent /openapi.json endpoint discovery
    )

    return app, settings, processor, incident_store


app, _settings, _processor, _incident_store = _build_app()


# ── Security middleware ──────────────────────────────────────────────────────


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to every response and strip server identification.

    - X-Content-Type-Options: prevent MIME sniffing
    - X-Frame-Options: prevent clickjacking
    - X-Robots-Tag: tell crawlers not to index (belt + suspenders with robots.txt)
    - Content-Security-Policy: restrict resource loading
    - Referrer-Policy: prevent URL leakage in Referer header
    - Cache-Control: prevent proxies/browsers from caching API responses
    - Server: replaced with generic value to prevent framework fingerprinting
    """

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001
        response: StarletteResponse = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, max-age=0"
        )
        response.headers["Pragma"] = "no-cache"
        response.headers["Server"] = "webhook-receiver"
        return response


class _ApiKeyPathMiddleware(BaseHTTPMiddleware):
    """
    Support API key as the first path segment: ``/APIKEY/healthz``.

    If WEBHOOK_API_KEY is configured and the first path segment matches,
    strip it from the path and mark the request as authenticated so
    downstream ``_verify_api_key()`` can skip re-checking.

    This supports tools (like JSM webhooks) that can only configure a URL
    and do not support custom headers or query parameters.
    """

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001
        configured_key = _settings.webhook_api_key
        if configured_key and request.url.path != "/":
            # Split path: /KEY/healthz → ["", "KEY", "healthz"]
            parts = request.url.path.split("/", 2)
            if (
                len(parts) >= 2
                and parts[1]
                and secrets.compare_digest(parts[1], configured_key)
            ):
                # Rewrite path with key segment removed.
                new_path = "/" + parts[2] if len(parts) > 2 else "/"
                request.scope["path"] = new_path
                request.state.api_key_verified = True
        return await call_next(request)


app.add_middleware(_SecurityHeadersMiddleware)
app.add_middleware(_ApiKeyPathMiddleware)


# ── Custom error handlers (prevent FastAPI fingerprinting) ───────────────────


@app.exception_handler(404)
async def _custom_404(request: Request, exc: HTTPException):  # noqa: ARG001
    return JSONResponse(status_code=404, content={"detail": "Not found"})


@app.exception_handler(405)
async def _custom_405(request: Request, exc: HTTPException):  # noqa: ARG001
    return JSONResponse(status_code=405, content={"detail": "Method not allowed"})


@app.exception_handler(422)
async def _custom_422(request: Request, exc: HTTPException):  # noqa: ARG001
    """Override FastAPI's distinctive validation error format."""
    return JSONResponse(status_code=422, content={"detail": "Validation error"})


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


def _verify_api_key(key: str | None, request: Request | None = None) -> bool:
    """
    Verify the API key from any of three sources (checked in order):

    1. Path prefix — ``/APIKEY/endpoint`` (set by ``_ApiKeyPathMiddleware``)
    2. ``X-API-Key`` request header
    3. ``?key=`` query parameter

    Returns True if no key is configured (disabled) or if any source matches.
    Uses constant-time comparison to prevent timing attacks.
    """
    if not _settings.webhook_api_key:
        return True

    # 1. Already verified by path-prefix middleware.
    if request and getattr(request.state, "api_key_verified", False):
        return True

    # 2. X-API-Key header.
    if request:
        header_key = request.headers.get("X-API-Key")
        if header_key and secrets.compare_digest(header_key, _settings.webhook_api_key):
            return True

    # 3. ?key= query parameter (existing behaviour).
    if key and secrets.compare_digest(key, _settings.webhook_api_key):
        return True

    logger.warning("Request rejected — invalid or missing API key")
    return False


async def _require_api_key(request: Request, key: str | None = Query(None)) -> None:
    """FastAPI dependency that enforces API key auth from any source.

    Returns 404 (not 401/403) when the key is invalid or missing, so
    unauthenticated clients cannot distinguish 'wrong key' from
    'endpoint does not exist'.  This prevents attackers from confirming
    that authenticated endpoints exist or brute-forcing keys.
    """
    if not _verify_api_key(key, request):
        raise HTTPException(status_code=404, detail="Not found")


# ── Routes ────────────────────────────────────────────────────────────────────


@app.get("/robots.txt", include_in_schema=False)
async def robots_txt():
    """Prevent search engine indexing."""
    from fastapi.responses import PlainTextResponse

    return PlainTextResponse("User-agent: *\nDisallow: /\n")


@app.get("/health", tags=["ops"])
async def health_check():
    """Docker / Kubernetes liveness probe."""
    return {"status": "ok"}


@app.get("/metrics", tags=["ops"], dependencies=[Depends(_require_api_key)])
async def prometheus_metrics():
    """
    Prometheus-compatible metrics in text exposition format.

    Returns counters for alert processing, credential checks, and rate limiting.
    Gated by API key when configured.
    """
    from fastapi.responses import PlainTextResponse

    lines = []
    for name, value in _metrics.items():
        lines.append(f"# TYPE jsm_notifier_{name} counter")
        lines.append(f"jsm_notifier_{name} {value}")
    uptime = round(_time.monotonic() - _STARTUP_MONOTONIC, 1)
    lines.append("# TYPE jsm_notifier_uptime_seconds gauge")
    lines.append(f"jsm_notifier_uptime_seconds {uptime}")
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain")


@app.get("/healthz", tags=["ops"], dependencies=[Depends(_require_api_key)])
async def deep_health_check():
    """
    Deep health check — verifies JSM and HA API connectivity, schedule
    validation, on-call status, and operational state.

    Returns 200 if core checks pass, 503 if any fail.  Gated by API key
    (query param, header, or path prefix) when ``WEBHOOK_API_KEY`` is set.
    """
    _inc("healthz_requests_total")

    # ── Core connectivity checks (run in parallel) ────────────────────
    jsm_coro = _processor.jsm_client.verify_credentials()
    ha_coro = _processor.ha_client.verify_connectivity()
    (jsm_ok, jsm_err), (ha_ok, ha_err) = await asyncio.gather(jsm_coro, ha_coro)

    checks: dict[str, str] = {
        "jsm_api": "ok" if jsm_ok else "error",
        "ha_api": "ok" if ha_ok else "error",
    }
    if not jsm_ok:
        logger.warning("Deep health check: JSM API failed — %s", jsm_err)
    if not ha_ok:
        logger.warning("Deep health check: HA API failed — %s", ha_err)

    # ── Schedule validation + on-call status ──────────────────────────
    # Cap to prevent abuse — only check configured schedules.
    _MAX_SCHEDULES = 50
    check_oncall: dict[str, dict[str, object]] = {}
    names = _settings.check_oncall_schedule_names[:_MAX_SCHEDULES]
    for name in names:
        schedule_id = await _processor.jsm_client.get_schedule_id(name)
        if schedule_id:
            is_on_call = await _processor.jsm_client.is_on_call(schedule_id, cache_ttl=0)
            check_oncall[name] = {
                "schedule_id": schedule_id,
                "exists_in_jsm": True,
                "on_call": is_on_call,
            }
        else:
            check_oncall[name] = {
                "schedule_id": None,
                "exists_in_jsm": False,
                "on_call": None,
                "error": "Schedule not found in JSM API",
            }

    schedules = {
        "check_oncall": check_oncall,
        "always_notify": list(_settings.always_notify_schedule_names[:_MAX_SCHEDULES]),
    }

    # ── Operational state ─────────────────────────────────────────────
    uptime = round(_time.monotonic() - _STARTUP_MONOTONIC, 1)

    op_stats = _processor.operational_stats()

    cache = _processor.jsm_client.cache_stats()
    cache["dedup_entries"] = op_stats["dedup_cache_size"]

    background_tasks = {
        "batch_queue_size": op_stats["batch_queue_size"],
        "active_tts_repeats": op_stats["active_tts_repeats"],
        "tts_repeat_alert_ids": op_stats["tts_repeat_alert_ids"],
    }

    incident_dashboard = {
        "enabled": _settings.incident_dashboard_enabled,
    }
    if _settings.incident_dashboard_enabled:
        incident_dashboard["sync_interval_minutes"] = (
            _settings.incident_sync_interval_minutes
        )

    # Non-sensitive configuration summary — no tokens, secrets, or URLs.
    configuration = {
        "oncall_cache_ttl_seconds": _settings.oncall_cache_ttl_seconds,
        "alert_dedup_ttl_seconds": _settings.alert_dedup_ttl_seconds,
        "token_check_interval_hours": _settings.token_check_interval_hours,
        "alert_batch_window_seconds": _settings.alert_batch_window_seconds,
        "tts_repeat_interval_seconds": _settings.tts_repeat_interval_seconds,
        "tts_repeat_max": _settings.tts_repeat_max,
        "tts_repeat_priorities": _settings.tts_repeat_priorities,
        "silent_window": _settings.silent_window or "(none)",
        "terse_window": _settings.terse_window or "(none)",
        "webhook_secret_configured": bool(_settings.webhook_secret),
        "webhook_api_key_configured": bool(_settings.webhook_api_key),
        "emojis_enabled": _settings.enable_emojis,
    }

    all_ok = all(v == "ok" for v in checks.values())
    return JSONResponse(
        {
            "healthy": all_ok,
            "timestamp": datetime.now(UTC).isoformat(),
            "started_at": _STARTUP_WALL,
            "uptime_seconds": uptime,
            "version": app.version,
            "checks": checks,
            "schedules": schedules,
            "cache": cache,
            "background_tasks": background_tasks,
            "incident_dashboard": incident_dashboard,
            "configuration": configuration,
        },
        status_code=200 if all_ok else 503,
    )


@app.get("/status", tags=["ops"], dependencies=[Depends(_require_api_key)])
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
        "on_call_schedules": status,
        "always_notify_schedules": _settings.always_notify_schedule_names,
    }


_last_reload: float = 0.0
_RELOAD_COOLDOWN = 10.0  # minimum seconds between reloads


@app.post("/reload", tags=["ops"], dependencies=[Depends(_require_api_key)])
async def reload_config():
    """
    Reload configuration from .env without restarting the container.

    Re-reads the .env file and applies changes to schedule routing, time
    windows, announcement formats, tuning parameters, and webhook config.
    Credentials (tokens, API keys) are also reloaded.

    Clears all caches (schedule ID, on-call, dedup) to ensure the new
    config takes effect immediately.  Rate-limited to once per 10 seconds.
    """
    global _settings, _last_reload  # noqa: PLW0603

    # Cooldown to prevent DoS via rapid reloads.
    now = _time.monotonic()
    if now - _last_reload < _RELOAD_COOLDOWN:
        raise HTTPException(
            status_code=429,
            detail=f"Reload cooldown — retry after {_RELOAD_COOLDOWN:.0f}s",
        )

    try:
        new_settings = Settings()

        # Log security-relevant changes (without revealing values).
        old_key_set = bool(_settings.webhook_api_key)
        new_key_set = bool(new_settings.webhook_api_key)
        if old_key_set != new_key_set:
            logger.warning(
                "Reload: WEBHOOK_API_KEY %s",
                "enabled" if new_key_set else "DISABLED",
            )

        # Apply atomically: update processor and caches first, then swap
        # the global _settings reference last (Python GIL makes the final
        # reference assignment atomic for concurrent readers).
        _processor.settings = new_settings
        _processor.jsm_client.invalidate_oncall_cache()
        _processor.jsm_client._schedule_id_cache.clear()
        _processor._dedup_cache.clear()
        _settings = new_settings
        _last_reload = now

        logger.info(
            "Configuration reloaded — always_notify=%s  check_oncall=%s",
            new_settings.always_notify_schedule_names,
            new_settings.check_oncall_schedule_names,
        )
        return {"status": "reloaded"}
    except Exception as exc:
        logger.error("Configuration reload failed: %s", type(exc).__name__)
        raise HTTPException(
            status_code=500, detail="Reload failed — previous config is still active"
        ) from exc


@app.post("/cache/invalidate", tags=["ops"], dependencies=[Depends(_require_api_key)])
async def invalidate_cache():
    """Force the next on-call check to query JSM instead of using cached data."""
    _processor.jsm_client.invalidate_oncall_cache()
    return {"status": "cache invalidated"}


# ── Incident dashboard ────────────────────────────────────────────────────────


@app.get("/incidents", tags=["dashboard"], dependencies=[Depends(_require_api_key)])
async def list_incidents(
    status: str | None = Query(
        default=None,
        description="Filter by status: open, acknowledged, escalated, closed",
    ),
    priority: str | None = Query(
        default=None, description="Filter by priority: P1, P2, P3, P4, P5"
    ),
    limit: int = Query(default=200, ge=1, le=1000, description="Max results"),
):
    """
    Return current incident state.  Requires ``INCIDENT_DASHBOARD_ENABLED=true``.

    Supports optional ``?status=`` and ``?priority=`` filters.
    Output is Grafana JSON datasource compatible.
    """
    if not _incident_store:
        raise HTTPException(
            status_code=404,
            detail="Incident dashboard is disabled. Set INCIDENT_DASHBOARD_ENABLED=true in .env",
        )
    incidents = await _incident_store.get_all(
        status=status, priority=priority, limit=limit
    )
    return JSONResponse(content={"incidents": incidents, "count": len(incidents)})


@app.get(
    "/incidents/summary", tags=["dashboard"], dependencies=[Depends(_require_api_key)]
)
async def incident_summary():
    """Return aggregate incident counts by status and priority."""
    if not _incident_store:
        raise HTTPException(
            status_code=404,
            detail="Incident dashboard is disabled. Set INCIDENT_DASHBOARD_ENABLED=true in .env",
        )
    summary = await _incident_store.get_summary()
    return JSONResponse(content=summary)


@app.get(
    "/incidents/{alert_id}", tags=["dashboard"], dependencies=[Depends(_require_api_key)]
)
async def get_incident(
    alert_id: str = Path(..., description="Alert ID to look up"),
):
    """Return a single incident by alert ID."""
    if not _ALERT_ID_RE.match(alert_id):
        raise HTTPException(status_code=400, detail="Invalid alert_id format")
    if not _incident_store:
        raise HTTPException(
            status_code=404,
            detail="Incident dashboard is disabled. Set INCIDENT_DASHBOARD_ENABLED=true in .env",
        )
    incident = await _incident_store.get_one(alert_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return JSONResponse(content=incident)


@app.post(
    "/incidents/{alert_id}/close",
    tags=["dashboard"],
    dependencies=[Depends(_require_api_key)],
)
async def force_close_incident(
    alert_id: str = Path(..., description="Alert ID to force-close"),
):
    """
    Force-close an incident from the dashboard.

    Sets status to 'closed' and records a ForceClose action.  Also dismisses
    any corresponding HA persistent notification and cancels TTS repeats.
    """
    if not _ALERT_ID_RE.match(alert_id):
        raise HTTPException(status_code=400, detail="Invalid alert_id format")
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


@app.post("/incidents/sync", tags=["dashboard"], dependencies=[Depends(_require_api_key)])
async def force_incident_sync():
    """Force an immediate sync of open alerts from JSM."""
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


@app.post(
    "/alert/{alert_id}/acknowledge",
    tags=["webhook"],
    dependencies=[Depends(_require_api_key)],
)
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
    400 for invalid alert IDs, 401 for bad API key, or 502 if the JSM API call fails.
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
    raise HTTPException(status_code=502, detail="JSM acknowledge failed")


@app.post("/alert", tags=["webhook"], dependencies=[Depends(_require_api_key)])
async def receive_alert(
    request: Request,
    mode: str | None = Query(
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
      • https://<your-host>/alert?key=YOUR_KEY               → on-call check
      • https://<your-host>/alert?mode=always&key=YOUR_KEY   → always notify
    """

    client_ip = request.client.host if request.client else "unknown"
    if _rate_limited(client_ip):
        _inc("alerts_rate_limited_total")
        logger.warning("Rate limit exceeded for %s", client_ip)
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    # Early rejection based on Content-Length header before reading body
    # into memory. Prevents large payloads from consuming server RAM.
    content_length = request.headers.get("content-length")
    if (
        content_length
        and content_length.isdigit()
        and int(content_length) > _MAX_BODY_BYTES
    ):
        logger.warning(
            "Rejecting request with Content-Length %s from %s",
            content_length,
            client_ip,
        )
        raise HTTPException(status_code=413, detail="Request body too large")

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

    _inc("alerts_received_total")
    result = await _processor.process(payload, always_notify=always_notify)
    if result.get("notified"):
        _inc("alerts_notified_total")
    if result.get("dismissed"):
        _inc("alerts_dismissed_total")
    if result.get("reason") == "duplicate":
        _inc("alerts_deduplicated_total")
    return JSONResponse(content=result)
