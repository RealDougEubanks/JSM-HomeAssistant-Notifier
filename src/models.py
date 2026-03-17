"""
Pydantic models for the JSM / OpsGenie webhook payload.

JSM Ops webhooks follow the OpsGenie webhook format.  Not every field is
present for every action, so most fields are Optional with sensible defaults.
`model_config extra="allow"` keeps us future-proof against Atlassian adding
new fields.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class AlertSource(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: Optional[str] = None
    type: Optional[str] = None


class AlertDetails(BaseModel):
    model_config = ConfigDict(extra="allow")

    alertId: str
    message: str
    alias: Optional[str] = None
    description: Optional[str] = None
    priority: str = "P3"
    source: Optional[str] = None
    entity: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    responders: List[Dict[str, Any]] = Field(default_factory=list)
    teams: List[Dict[str, Any]] = Field(default_factory=list)
    createdAt: Optional[int] = None
    updatedAt: Optional[int] = None
    # Integration / username that created the alert
    username: Optional[str] = None


class AlertRecipient(BaseModel):
    """Present on EscalateNext / AddRecipient actions — who received the alert."""

    model_config = ConfigDict(extra="allow")

    name: Optional[str] = None
    id: Optional[str] = None
    type: Optional[str] = None  # "user" | "team" | "schedule"


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
    source: Optional[AlertSource] = None
    # Who this notification was sent to (populated for escalation actions)
    recipient: Optional[AlertRecipient] = None
