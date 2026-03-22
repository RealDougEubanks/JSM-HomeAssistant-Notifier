"""
Shared pytest fixtures.
"""
from __future__ import annotations

import pytest

from src.config import Settings
from src.ha_client import HAClient
from src.jsm_client import JSMClient
from src.models import AlertDetails, AlertRecipient, JSMWebhookPayload


# ── Common alert payloads ─────────────────────────────────────────────────────

def make_alert(
    alert_id: str = "alert-001",
    message: str = "Server CPU High",
    priority: str = "P1",
    entity: str = "prod-server-01",
    description: str = "CPU usage above 90%",
    action: str = "Create",
    recipient_id: str | None = None,
    responder_ids: list[str] | None = None,
) -> JSMWebhookPayload:
    recipient = None
    if recipient_id:
        recipient = AlertRecipient(id=recipient_id, type="user", name="Test User")

    responders = [{"id": rid, "type": "user"} for rid in (responder_ids or [])]

    return JSMWebhookPayload(
        action=action,
        alert=AlertDetails(
            alertId=alert_id,
            message=message,
            priority=priority,
            entity=entity,
            description=description,
            responders=responders,
        ),
        recipient=recipient,
    )


# ── Settings fixture ──────────────────────────────────────────────────────────

@pytest.fixture
def settings() -> Settings:
    return Settings(
        jsm_cloud_id="test-cloud-id",
        jsm_username="test@example.com",
        jsm_api_token="test-token",
        jsm_my_user_id="my-user-id",
        check_oncall_schedule_names=["Cloud Engineering On-Call Schedule"],
        always_notify_schedule_names=["Internal Systems_schedule"],
        ha_url="https://ha.example.com",
        ha_token="ha-test-token",
        oncall_cache_ttl_seconds=300,
        alert_dedup_ttl_seconds=60,
    )


# ── Client fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def jsm_client(settings: Settings) -> JSMClient:
    return JSMClient(
        api_url=settings.jsm_api_url,
        cloud_id=settings.jsm_cloud_id,
        username=settings.jsm_username,
        api_token=settings.jsm_api_token,
        my_user_id=settings.jsm_my_user_id,
    )


@pytest.fixture
def ha_client(settings: Settings) -> HAClient:
    return HAClient(
        ha_url=settings.ha_url,
        ha_token=settings.ha_token,
        media_player=settings.ha_media_player_entity,
        tts_service=settings.ha_tts_service,
        tts_language=settings.ha_tts_language,
        tts_voice=settings.ha_tts_voice,
        announcement_format=settings.announcement_format,
        terse_announcement_format=settings.terse_announcement_format,
    )
