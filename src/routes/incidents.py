"""Incident dashboard routes (optional, SQLite-backed)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse

from ..security import ALERT_ID_RE, require_api_key

logger = logging.getLogger(__name__)

router = APIRouter()

_DISABLED_DETAIL = (
    "Incident dashboard is disabled. Set INCIDENT_DASHBOARD_ENABLED=true in .env"
)


@router.get("/incidents", tags=["dashboard"], dependencies=[Depends(require_api_key)])
async def list_incidents(
    request: Request,
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
    incident_store = request.app.state.incident_store
    if not incident_store:
        raise HTTPException(status_code=404, detail=_DISABLED_DETAIL)
    incidents = await incident_store.get_all(
        status=status, priority=priority, limit=limit
    )
    return JSONResponse(content={"incidents": incidents, "count": len(incidents)})


@router.get(
    "/incidents/summary", tags=["dashboard"], dependencies=[Depends(require_api_key)]
)
async def incident_summary(request: Request):
    """Return aggregate incident counts by status and priority."""
    incident_store = request.app.state.incident_store
    if not incident_store:
        raise HTTPException(status_code=404, detail=_DISABLED_DETAIL)
    summary = await incident_store.get_summary()
    return JSONResponse(content=summary)


@router.get(
    "/incidents/{alert_id}", tags=["dashboard"], dependencies=[Depends(require_api_key)]
)
async def get_incident(
    request: Request,
    alert_id: str = Path(..., description="Alert ID to look up"),
):
    """Return a single incident by alert ID."""
    if not ALERT_ID_RE.match(alert_id):
        raise HTTPException(status_code=400, detail="Invalid alert_id format")
    incident_store = request.app.state.incident_store
    if not incident_store:
        raise HTTPException(status_code=404, detail=_DISABLED_DETAIL)
    incident = await incident_store.get_one(alert_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return JSONResponse(content=incident)


@router.post(
    "/incidents/{alert_id}/close",
    tags=["dashboard"],
    dependencies=[Depends(require_api_key)],
)
async def force_close_incident(
    request: Request,
    alert_id: str = Path(..., description="Alert ID to force-close"),
):
    """
    Force-close an incident from the dashboard.

    Sets status to 'closed' and records a ForceClose action.  Also dismisses
    any corresponding HA persistent notification and cancels TTS repeats.
    """
    if not ALERT_ID_RE.match(alert_id):
        raise HTTPException(status_code=400, detail="Invalid alert_id format")
    incident_store = request.app.state.incident_store
    if not incident_store:
        raise HTTPException(status_code=404, detail=_DISABLED_DETAIL)
    closed = await incident_store.force_close(alert_id)
    if not closed:
        raise HTTPException(
            status_code=404, detail="Incident not found or already closed"
        )
    # Also dismiss HA notification and cancel TTS repeat.
    processor = request.app.state.processor
    await processor.ha_client.dismiss_notification(alert_id)
    processor.cancel_tts_repeat(alert_id)
    return {"alert_id": alert_id, "status": "closed", "action": "ForceClose"}


@router.post(
    "/incidents/sync", tags=["dashboard"], dependencies=[Depends(require_api_key)]
)
async def force_incident_sync(request: Request):
    """Force an immediate sync of open alerts from JSM."""
    incident_store = request.app.state.incident_store
    if not incident_store:
        raise HTTPException(status_code=404, detail=_DISABLED_DETAIL)
    alerts = await request.app.state.processor.jsm_client.list_open_alerts()
    count = await incident_store.bulk_upsert(alerts)
    return {"status": "synced", "alerts_upserted": count}
