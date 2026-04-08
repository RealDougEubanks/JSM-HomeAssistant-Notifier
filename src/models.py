"""
Pydantic models for the JSM / OpsGenie webhook payload.

JSM Ops webhooks follow the OpsGenie webhook format.  Not every field is
present for every action, so most fields are Optional with sensible defaults.
`model_config extra="allow"` keeps us future-proof against Atlassian adding
new fields.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AlertSource(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str | None = None
    type: str | None = None


class AlertDetails(BaseModel):
    model_config = ConfigDict(extra="allow")

    alertId: str
    message: str
    alias: str | None = None
    description: str | None = None
    priority: str = "P3"
    source: str | None = None
    entity: str | None = None
    tags: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    responders: list[dict[str, Any] | str] = Field(default_factory=list)
    teams: list[dict[str, Any] | str] = Field(default_factory=list)
    createdAt: int | None = None
    updatedAt: int | None = None
    # Integration / username that created the alert
    username: str | None = None


class AlertRecipient(BaseModel):
    """Present on EscalateNext / AddRecipient actions — who received the alert."""

    model_config = ConfigDict(extra="allow")

    name: str | None = None
    id: str | None = None
    type: str | None = None  # "user" | "team" | "schedule"


class JSMWebhookPayload(BaseModel):
    """
    Top-level JSM / OpsGenie webhook payload.

    Relevant action values:
      Create            – new alert
      EscalateNext      – alert escalated to the next responder
      Acknowledge       – alert acknowledged (we ignore this)
      Close             – alert closed (we ignore this)
      AddNote           – note added (we ignore this)
      UnAcknowledge     – un-acknowledged (we ignore this)
      AssignOwnership   – ownership changed (we ignore this)
    """

    model_config = ConfigDict(extra="allow")

    action: str
    alert: AlertDetails
    source: AlertSource | None = None
    # Who this notification was sent to (populated for escalation actions)
    recipient: AlertRecipient | None = None
