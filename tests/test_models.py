"""Tests for the JSM webhook payload models."""
from __future__ import annotations

import json

import pytest

from src.models import AlertDetails, AlertRecipient, JSMWebhookPayload


SAMPLE_CREATE = {
    "action": "Create",
    "alert": {
        "alertId": "abc-123",
        "message": "Disk space low",
        "priority": "P2",
        "entity": "storage-01",
        "description": "Disk at 95%",
        "tags": ["storage", "production"],
        "details": {"host": "storage-01"},
        "responders": [{"id": "team-id", "type": "team"}],
        "teams": [],
    },
    "source": {"name": "CloudWatch", "type": "API"},
}

SAMPLE_ESCALATE = {
    "action": "EscalateNext",
    "alert": {
        "alertId": "abc-456",
        "message": "Database connection lost",
        "priority": "P1",
        "responders": [{"id": "user-999", "type": "user"}],
    },
    "recipient": {
        "id": "user-999",
        "name": "Doug Eubanks",
        "type": "user",
    },
}


def test_parse_create_alert():
    payload = JSMWebhookPayload.model_validate(SAMPLE_CREATE)
    assert payload.action == "Create"
    assert payload.alert.alertId == "abc-123"
    assert payload.alert.priority == "P2"
    assert payload.alert.entity == "storage-01"
    assert "storage" in payload.alert.tags


def test_parse_escalation():
    payload = JSMWebhookPayload.model_validate(SAMPLE_ESCALATE)
    assert payload.action == "EscalateNext"
    assert payload.recipient is not None
    assert payload.recipient.id == "user-999"
    assert payload.recipient.name == "Doug Eubanks"


def test_parse_from_json_bytes():
    raw = json.dumps(SAMPLE_CREATE).encode()
    payload = JSMWebhookPayload.model_validate_json(raw)
    assert payload.alert.alertId == "abc-123"


def test_missing_optional_fields():
    minimal = {
        "action": "Create",
        "alert": {
            "alertId": "min-001",
            "message": "Minimal alert",
        },
    }
    payload = JSMWebhookPayload.model_validate(minimal)
    assert payload.alert.priority == "P3"  # default
    assert payload.alert.tags == []
    assert payload.alert.responders == []
    assert payload.recipient is None


def test_extra_fields_ignored():
    """Unknown fields in the payload must not raise an error (future-proofing)."""
    data = dict(SAMPLE_CREATE)
    data["unknownField"] = "some-value"
    data["alert"] = dict(SAMPLE_CREATE["alert"])
    data["alert"]["futureFeature"] = {"nested": True}
    payload = JSMWebhookPayload.model_validate(data)
    assert payload.action == "Create"
