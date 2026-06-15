"""Operational routes: health checks, metrics, status, config reload, cache."""

from __future__ import annotations

import asyncio
import logging
import time as _time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from ..config import Settings
from ..metrics import METRICS, inc
from ..security import require_api_key

logger = logging.getLogger(__name__)

router = APIRouter()

_RELOAD_COOLDOWN = 10.0  # minimum seconds between reloads


@router.get("/robots.txt", include_in_schema=False)
async def robots_txt():
    """Prevent search engine indexing."""
    return PlainTextResponse("User-agent: *\nDisallow: /\n")


@router.get("/health", tags=["ops"])
async def health_check():
    """Docker / Kubernetes liveness probe."""
    return {"status": "ok"}


@router.get("/metrics", tags=["ops"], dependencies=[Depends(require_api_key)])
async def prometheus_metrics(request: Request):
    """
    Prometheus-compatible metrics in text exposition format.

    Returns counters for alert processing, credential checks, and rate limiting.
    Gated by API key when configured.
    """
    lines = []
    for name, value in METRICS.items():
        lines.append(f"# TYPE jsm_notifier_{name} counter")
        lines.append(f"jsm_notifier_{name} {value}")
    uptime = round(_time.monotonic() - request.app.state.startup_monotonic, 1)
    lines.append("# TYPE jsm_notifier_uptime_seconds gauge")
    lines.append(f"jsm_notifier_uptime_seconds {uptime}")
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain")


@router.get("/healthz", tags=["ops"], dependencies=[Depends(require_api_key)])
async def deep_health_check(request: Request):
    """
    Deep health check — verifies JSM and HA API connectivity, schedule
    validation, on-call status, and operational state.

    Returns 200 if core checks pass, 503 if any fail.  Gated by API key
    (query param, header, or path prefix) when ``WEBHOOK_API_KEY`` is set.
    """
    inc("healthz_requests_total")
    state = request.app.state
    settings = state.settings
    processor = state.processor

    # ── Core connectivity checks (run in parallel) ────────────────────
    jsm_coro = processor.jsm_client.verify_credentials()
    ha_coro = processor.ha_client.verify_connectivity()
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
    names = settings.check_oncall_schedule_names[:_MAX_SCHEDULES]
    for name in names:
        schedule_id = await processor.jsm_client.get_schedule_id(name)
        if schedule_id:
            is_on_call = await processor.jsm_client.is_on_call(schedule_id, cache_ttl=0)
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
        "always_notify": list(settings.always_notify_schedule_names[:_MAX_SCHEDULES]),
    }

    # ── Operational state ─────────────────────────────────────────────
    uptime = round(_time.monotonic() - state.startup_monotonic, 1)

    op_stats = processor.operational_stats()

    cache = processor.jsm_client.cache_stats()
    cache["dedup_entries"] = op_stats["dedup_cache_size"]

    background_tasks = {
        "batch_queue_size": op_stats["batch_queue_size"],
        "active_tts_repeats": op_stats["active_tts_repeats"],
        "tts_repeat_alert_ids": op_stats["tts_repeat_alert_ids"],
    }

    incident_dashboard = {
        "enabled": settings.incident_dashboard_enabled,
    }
    if settings.incident_dashboard_enabled:
        incident_dashboard["sync_interval_minutes"] = (
            settings.incident_sync_interval_minutes
        )

    # Non-sensitive configuration summary — no tokens, secrets, or URLs.
    configuration = {
        "oncall_cache_ttl_seconds": settings.oncall_cache_ttl_seconds,
        "alert_dedup_ttl_seconds": settings.alert_dedup_ttl_seconds,
        "token_check_interval_hours": settings.token_check_interval_hours,
        "alert_batch_window_seconds": settings.alert_batch_window_seconds,
        "tts_repeat_interval_seconds": settings.tts_repeat_interval_seconds,
        "tts_repeat_max": settings.tts_repeat_max,
        "tts_repeat_priorities": settings.tts_repeat_priorities,
        "silent_window": settings.silent_window or "(none)",
        "terse_window": settings.terse_window or "(none)",
        "webhook_secret_configured": bool(settings.webhook_secret),
        "webhook_api_key_configured": bool(settings.webhook_api_key),
        "emojis_enabled": settings.enable_emojis,
    }

    all_ok = all(v == "ok" for v in checks.values())
    return JSONResponse(
        {
            "healthy": all_ok,
            "timestamp": datetime.now(UTC).isoformat(),
            "started_at": state.startup_wall,
            "uptime_seconds": uptime,
            "version": request.app.version,
            "checks": checks,
            "schedules": schedules,
            "cache": cache,
            "background_tasks": background_tasks,
            "incident_dashboard": incident_dashboard,
            "configuration": configuration,
        },
        status_code=200 if all_ok else 503,
    )


@router.get("/status", tags=["ops"], dependencies=[Depends(require_api_key)])
async def on_call_status(request: Request):
    """
    Returns the current on-call status for all watched schedules.
    Useful for debugging and for verifying your JSM credentials work.
    """
    settings = request.app.state.settings
    processor = request.app.state.processor
    status: dict = {}

    for name in settings.check_oncall_schedule_names:
        schedule_id = await processor.jsm_client.get_schedule_id(name)
        if schedule_id:
            is_on_call = await processor.jsm_client.is_on_call(
                schedule_id, cache_ttl=0  # force fresh lookup
            )
            status[name] = {"schedule_id": schedule_id, "on_call": is_on_call}
        else:
            status[name] = {"schedule_id": None, "on_call": None, "error": "not found"}

    return {
        "on_call_schedules": status,
        "always_notify_schedules": settings.always_notify_schedule_names,
    }


@router.post("/reload", tags=["ops"], dependencies=[Depends(require_api_key)])
async def reload_config(request: Request):
    """
    Reload configuration from .env without restarting the container.

    Re-reads the .env file and applies changes to: schedule routing, time
    windows (silent/terse), media player routing, announcement formats,
    volumes, emoji settings, TTS repeat settings, tuning parameters,
    webhook secret / API key, rate limits, and JSM / HA credentials and
    URLs.  Background check intervals (token check, incident sync,
    retention) pick up new values on their next iteration.

    NOT reloadable (require a container restart): LOG_FORMAT,
    INCIDENT_DASHBOARD_ENABLED, INCIDENT_DB_PATH, and enabling/disabling
    the incident sync task itself.

    Clears all caches (schedule ID, on-call, dedup) to ensure the new
    config takes effect immediately.  Rate-limited to once per 10 seconds.
    """
    state = request.app.state

    # Cooldown to prevent DoS via rapid reloads.
    now = _time.monotonic()
    if now - state.last_reload < _RELOAD_COOLDOWN:
        raise HTTPException(
            status_code=429,
            detail=f"Reload cooldown — retry after {_RELOAD_COOLDOWN:.0f}s",
        )

    try:
        new_settings = Settings()

        # Log security-relevant changes (without revealing values).
        old_key_set = bool(state.settings.webhook_api_key)
        new_key_set = bool(new_settings.webhook_api_key)
        if old_key_set != new_key_set:
            logger.warning(
                "Reload: WEBHOOK_API_KEY %s",
                "enabled" if new_key_set else "DISABLED",
            )

        # Apply atomically: update clients, processor, and caches first,
        # then swap the state.settings reference last (Python GIL makes
        # the final reference assignment atomic for concurrent readers).
        processor = state.processor
        processor.jsm_client.update_config(**new_settings.jsm_client_kwargs())
        processor.ha_client.update_config(**new_settings.ha_client_kwargs())
        processor.reapply_settings(new_settings)
        processor.jsm_client.invalidate_oncall_cache()
        processor.jsm_client._schedule_id_cache.clear()
        processor._dedup_cache.clear()
        state.settings = new_settings
        state.last_reload = now

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


@router.post("/cache/invalidate", tags=["ops"], dependencies=[Depends(require_api_key)])
async def invalidate_cache(request: Request):
    """Force the next on-call check to query JSM instead of using cached data."""
    request.app.state.processor.jsm_client.invalidate_oncall_cache()
    return {"status": "cache invalidated"}
