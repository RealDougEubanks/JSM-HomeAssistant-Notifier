"""
Tests for action-name normalisation and status-transition safety.

Two related defects are covered here, both caused by an action the code did not
recognise:

1. JSM's integration config calls the escalation action ``EscalateToNext``;
   OpsGenie's webhook format — which this payload descends from — calls it
   ``EscalateNext``. The code matched only the latter, so an escalation arriving
   under the other spelling fell through every lookup: no TTS, no escalate
   webhook, and stored as plain "open".

2. Any unrecognised action defaulted the stored status to "open", so enabling an
   innocuous webhook action (``Alert description is updated``) resurrected closed
   incidents and flipped acknowledged ones back to unacked.
"""

from __future__ import annotations

import contextlib
import os
import tempfile

import pytest

from src.alert_processor import _NOTIFY_ACTIONS, _STATE_ACTIONS
from src.incident_store import IncidentStore
from src.models import JSMWebhookPayload

# ── Action alias normalisation ───────────────────────────────────────────


def _payload(action: str) -> JSMWebhookPayload:
    return JSMWebhookPayload.model_validate(
        {"action": action, "alert": {"alertId": "a1", "message": "m", "priority": "P1"}}
    )


@pytest.mark.parametrize("incoming", ["EscalateToNext", "EscalateNext"])
def test_escalation_spellings_normalise_to_one_value(incoming: str):
    """Both spellings must land on the canonical form."""
    assert _payload(incoming).action == "EscalateNext"


def test_normalised_escalation_is_recognised_everywhere():
    """
    The regression: JSM sends EscalateToNext, so unless it is normalised the
    action matches neither the notify set nor the state set, and the escalation
    is silently dropped.
    """
    action = _payload("EscalateToNext").action
    assert action in _NOTIFY_ACTIONS, "escalation would not trigger a notification"
    assert action in _STATE_ACTIONS, "escalation would not drive the status light"


def test_raw_escalate_to_next_would_not_have_matched():
    """Pins why the alias is needed rather than asserting it is harmless."""
    assert "EscalateToNext" not in _NOTIFY_ACTIONS
    assert "EscalateToNext" not in _STATE_ACTIONS


def test_action_whitespace_is_stripped():
    assert _payload("  Acknowledge  ").action == "Acknowledge"


@pytest.mark.parametrize(
    "action", ["Create", "Acknowledge", "UnAcknowledge", "Close", "AddNote"]
)
def test_other_actions_pass_through_unchanged(action: str):
    assert _payload(action).action == action


def test_unknown_action_is_left_alone():
    """Normalisation must not invent mappings for actions we do not know."""
    assert _payload("SomeFutureAction").action == "SomeFutureAction"


# ── Status transition safety ─────────────────────────────────────────────


@pytest.fixture
def store():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield IncidentStore(path)
    with contextlib.suppress(OSError):
        os.unlink(path)


_ALERT = {"alertId": "inc-1", "message": "Test", "priority": "P3"}

# Actions JSM can forward that carry no lifecycle meaning.
_NON_LIFECYCLE = [
    "UpdateDescription",
    "UpdateMessage",
    "UpdatePriority",
    "AddNote",
    "AddTags",
    "TakeOwnership",
    "AssignOwnership",
]


@pytest.mark.parametrize("action", _NON_LIFECYCLE)
async def test_non_lifecycle_action_cannot_reopen_a_closed_incident(
    store: IncidentStore, action: str
):
    """The live footgun: a description edit must not resurrect a closed alert."""
    await store.upsert(_ALERT, "Create")
    await store.upsert(_ALERT, "Close")
    assert (await store.get_one("inc-1"))["status"] == "closed"

    await store.upsert(_ALERT, action)
    assert (await store.get_one("inc-1"))[
        "status"
    ] == "closed", f"{action} reopened a closed incident"


@pytest.mark.parametrize("action", _NON_LIFECYCLE)
async def test_non_lifecycle_action_cannot_unacknowledge(
    store: IncidentStore, action: str
):
    """Equally bad: a priority tweak flipping acked -> unacked turns the light red."""
    await store.upsert(_ALERT, "Create")
    await store.upsert(_ALERT, "Acknowledge")
    await store.upsert(_ALERT, action)
    assert (await store.get_one("inc-1"))["status"] == "acknowledged"


async def test_non_lifecycle_action_on_unseen_incident_is_open(store: IncidentStore):
    """A never-before-seen incident arriving via such an action is genuinely open."""
    await store.upsert(_ALERT, "UpdateDescription")
    assert (await store.get_one("inc-1"))["status"] == "open"


async def test_non_lifecycle_action_still_updates_other_fields(store: IncidentStore):
    """Preserving status must not mean discarding the payload entirely."""
    await store.upsert(_ALERT, "Create")
    await store.upsert(_ALERT, "Close")
    await store.upsert({**_ALERT, "message": "Edited message"}, "UpdateMessage")
    row = await store.get_one("inc-1")
    assert row["message"] == "Edited message"
    assert row["status"] == "closed"


@pytest.mark.parametrize(
    "action,expected",
    [
        ("Create", "open"),
        ("Acknowledge", "acknowledged"),
        ("Close", "closed"),
        ("EscalateNext", "escalated"),
        ("UnAcknowledge", "open"),
    ],
)
async def test_lifecycle_actions_still_set_status(
    store: IncidentStore, action: str, expected: str
):
    await store.upsert(_ALERT, action)
    assert (await store.get_one("inc-1"))["status"] == expected


async def test_unacknowledge_reopens_an_acknowledged_incident(store: IncidentStore):
    """UnAcknowledge is a real transition and must drive the light back to red."""
    await store.upsert(_ALERT, "Create")
    await store.upsert(_ALERT, "Acknowledge")
    await store.upsert(_ALERT, "UnAcknowledge")
    assert (await store.get_one("inc-1"))["status"] == "open"


async def test_escalation_counts_as_unacked(store: IncidentStore):
    """Escalated incidents must register as unacked so the light shows red."""
    await store.upsert(_ALERT, "Create")
    await store.upsert(_ALERT, "EscalateNext")
    counts = await store.get_open_counts()
    assert counts["unacked"] == 1
    assert counts["acked"] == 0
