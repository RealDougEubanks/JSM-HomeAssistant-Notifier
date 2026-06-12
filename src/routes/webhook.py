"""Inbound webhook routes: JSM alert delivery and alert acknowledgement."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse

from ..metrics import inc
from ..models import JSMWebhookPayload
from ..security import ALERT_ID_RE, require_api_key, verify_signature

logger = logging.getLogger(__name__)

router = APIRouter()

# Maximum allowed request body size (1 MB).  JSM webhook payloads are typically
# a few KB; anything larger is likely malicious or malformed.
_MAX_BODY_BYTES = 1_048_576


@router.post(
    "/alert/{alert_id}/acknowledge",
    tags=["webhook"],
    dependencies=[Depends(require_api_key)],
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
    400 for invalid alert IDs, 404 for bad API key, or 502 if the JSM API call fails.
    """
    if not ALERT_ID_RE.match(alert_id):
        raise HTTPException(status_code=400, detail="Invalid alert_id format")

    processor = request.app.state.processor
    source_ip = request.client.host if request.client else "unknown"
    logger.info(
        "Acknowledge request — alert_id=%s source_ip=%s",
        alert_id,
        source_ip,
    )

    success, error = await processor.jsm_client.acknowledge_alert(alert_id)
    if success:
        # Also dismiss the persistent notification and stop TTS repeats.
        await processor.ha_client.dismiss_notification(alert_id)
        processor.cancel_tts_repeat(alert_id)
        logger.info("Alert %s acknowledged via API from %s", alert_id, source_ip)
        return {"alert_id": alert_id, "acknowledged": True}
    logger.error("Failed to acknowledge alert %s: %s", alert_id, error)
    raise HTTPException(status_code=502, detail="JSM acknowledge failed")


@router.post("/alert", tags=["webhook"], dependencies=[Depends(require_api_key)])
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
    settings = request.app.state.settings
    processor = request.app.state.processor
    client_ip = request.client.host if request.client else "unknown"

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
            client_ip,
        )
        raise HTTPException(status_code=413, detail="Request body too large")

    if not verify_signature(settings, request, body):
        logger.warning("Webhook signature verification failed from %s", client_ip)
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

    inc("alerts_received_total")
    result = await processor.process(payload, always_notify=always_notify)
    if result.get("notified"):
        inc("alerts_notified_total")
    if result.get("dismissed"):
        inc("alerts_dismissed_total")
    if result.get("reason") == "duplicate":
        inc("alerts_deduplicated_total")
    return JSONResponse(content=result)
