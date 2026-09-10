"""
Pydantic models for the JSM / OpsGenie webhook payload.

JSM Ops webhooks follow the OpsGenie webhook format.  Not every field is
present for every action, so most fields are Optional with sensible defaults.
`model_config extra="allow"` keeps us future-proof against Atlassian adding
new fields.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ── Action name aliases ───────────────────────────────────────────────────
# The escalation action has two spellings in the wild. JSM's integration
# configuration calls it "EscalateToNext" (the actionMappingType returned by
# /v1/integrations/{id}/actions), while OpsGenie's webhook documentation — which
# this payload format descends from — calls it "EscalateNext".
#
# Which one arrives in the payload is not something we can rely on, so accept
# both and normalise to a single canonical value. Matching only one spelling
# silently drops escalations: the action falls through every lookup, so no TTS
# is played, no escalate webhook fires, and the alert is stored as plain "open".
#
# Keyed by the alias, valued by the canonical form used throughout the codebase.
_ACTION_ALIASES: dict[str, str] = {
    "EscalateToNext": "EscalateNext",
}


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
                          (also accepted as "EscalateToNext"; see
                          ``_ACTION_ALIASES`` above)
      Acknowledge       – alert acknowledged
      UnAcknowledge     – un-acknowledged
      Close             – alert closed
      AddNote           – note added
      AssignOwnership   – ownership changed

    ``action`` is normalised on the way in, so downstream code only ever needs
    to match the canonical spelling.
    """

    model_config = ConfigDict(extra="allow")

    action: str

    @field_validator("action", mode="before")
    @classmethod
    def _normalise_action(cls, v: Any) -> Any:
        """Fold known action-name aliases onto their canonical spelling."""
        if isinstance(v, str):
            return _ACTION_ALIASES.get(v.strip(), v.strip())
        return v

    alert: AlertDetails
    source: AlertSource | None = None
    # Who this notification was sent to (populated for escalation actions)
    recipient: AlertRecipient | None = None
