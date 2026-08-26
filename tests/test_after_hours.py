"""
Tests for after-hours suppression and weekday-aware business-hours windows.

Two independent suppression triggers are covered:
  * priority — outside business hours only AFTER_HOURS_AUDIBLE_PRIORITIES speak
  * tags     — optional, for honouring an upstream platform's own decision

The tag path exists because JSM tags deferrable alerts and holds them via a
notification policy, but outgoing webhooks are not subject to notification
policies — so without a local check this service announces what JSM held.
"""

from __future__ import annotations

from datetime import datetime, time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.alert_processor import AlertProcessor
from src.config import Settings
from src.ha_client import HAClient
from src.jsm_client import JSMClient
from src.time_windows import in_any_day_window, parse_day_windows
from tests.conftest import make_alert

# ── Weekday window parsing ───────────────────────────────────────────────


def test_parse_day_windows_basic():
    windows = parse_day_windows("Mon-Fri 09:00-17:00")
    assert len(windows) == 1
    days, start, end = windows[0]
    assert days == frozenset({0, 1, 2, 3, 4})
    assert start == time(9, 0)
    assert end == time(17, 0)


def test_parse_day_windows_single_day():
    days, _, _ = parse_day_windows("Sat 10:00-14:00")[0]
    assert days == frozenset({5})


def test_parse_day_windows_wraps_around_week():
    """Fri-Mon must wrap through the weekend, not produce an empty set."""
    days, _, _ = parse_day_windows("Fri-Mon 17:00-09:00")[0]
    assert days == frozenset({4, 5, 6, 0})


def test_parse_day_windows_multiple():
    assert len(parse_day_windows("Mon-Fri 09:00-17:00, Sat 10:00-14:00")) == 2


def test_parse_day_windows_empty():
    assert parse_day_windows("") == []
    assert parse_day_windows("   ") == []


@pytest.mark.parametrize("bad", ["09:00-17:00", "Xyz 09:00-17:00", "Mon 9-17", "Mon"])
def test_parse_day_windows_rejects_malformed(bad: str):
    with pytest.raises(ValueError):
        parse_day_windows(bad)


# ── Window membership ────────────────────────────────────────────────────

# 2026-08-24 is a Monday.
_MON = datetime(2026, 8, 24, 12, 0)
_MON_EARLY = datetime(2026, 8, 24, 3, 0)
_FRI_EVE = datetime(2026, 8, 28, 22, 0)
_SAT_NOON = datetime(2026, 8, 29, 14, 0)
_SAT_EARLY = datetime(2026, 8, 29, 2, 0)


def test_in_day_window_inside_business_hours():
    w = parse_day_windows("Mon-Fri 09:00-17:00")
    assert in_any_day_window(_MON, w) is True


def test_in_day_window_outside_on_weekday():
    w = parse_day_windows("Mon-Fri 09:00-17:00")
    assert in_any_day_window(_MON_EARLY, w) is False


def test_in_day_window_weekend_is_outside():
    """The whole point of weekday awareness: Saturday afternoon is off-hours."""
    w = parse_day_windows("Mon-Fri 09:00-17:00")
    assert in_any_day_window(_SAT_NOON, w) is False


def test_in_day_window_crossing_midnight_matches_start_day():
    """Fri 17:00-09:00 must cover early Saturday, and not early Friday."""
    w = parse_day_windows("Fri 17:00-09:00")
    assert in_any_day_window(_FRI_EVE, w) is True
    assert in_any_day_window(_SAT_EARLY, w) is True
    assert in_any_day_window(datetime(2026, 8, 28, 3, 0), w) is False  # Fri 03:00


# ── Suppression logic ────────────────────────────────────────────────────


def _proc(**kwargs) -> AlertProcessor:
    defaults = {
        "jsm_cloud_id": "c",
        "jsm_username": "u@example.com",
        "jsm_api_token": "t",
        "jsm_my_user_id": "me",
        "ha_url": "https://ha.example.com",
        "ha_token": "tok",
        "business_hours_window": "Mon-Fri 09:00-17:00",
    }
    defaults.update(kwargs)
    settings = Settings(**defaults)
    ha = MagicMock(spec=HAClient)
    # media_player is set in HAClient.__init__, so spec= does not provide it.
    ha.media_player = "media_player.test"
    jsm = MagicMock(spec=JSMClient)
    return AlertProcessor(settings, jsm, ha)


def _at(dt: datetime):
    """Patch datetime.now() inside alert_processor to a fixed moment."""
    m = MagicMock(wraps=datetime)
    m.now.return_value = dt
    return patch("src.alert_processor.datetime", m)


# ── Priority-based suppression (the out-of-the-box behaviour) ────────────


def test_p3_suppressed_overnight_with_no_tags_at_all():
    """The default path: a new user sets only BUSINESS_HOURS_WINDOW."""
    proc = _proc()
    payload = make_alert(priority="P3")
    with _at(_MON_EARLY):
        assert proc._suppress_after_hours(payload) is True


def test_p3_not_suppressed_during_business_hours():
    proc = _proc()
    payload = make_alert(priority="P3")
    with _at(_MON):
        assert proc._suppress_after_hours(payload) is False


def test_p3_suppressed_on_weekend_afternoon():
    """A plain time-of-day silent window could not express this."""
    proc = _proc()
    payload = make_alert(priority="P3")
    with _at(_SAT_NOON):
        assert proc._suppress_after_hours(payload) is True


def test_p1_stays_audible_overnight():
    proc = _proc()
    payload = make_alert(priority="P1")
    with _at(_MON_EARLY):
        assert proc._suppress_after_hours(payload) is False


def test_p2_stays_audible_overnight_by_default():
    proc = _proc()
    payload = make_alert(priority="P2")
    with _at(_MON_EARLY):
        assert proc._suppress_after_hours(payload) is False


def test_audible_priorities_configurable():
    """Narrowing to P1 means an overnight P2 is suppressed too."""
    proc = _proc(after_hours_audible_priorities="P1")
    payload = make_alert(priority="P2")
    with _at(_MON_EARLY):
        assert proc._suppress_after_hours(payload) is True


def test_empty_audible_priorities_silences_everything():
    proc = _proc(after_hours_audible_priorities="")
    payload = make_alert(priority="P1")
    with _at(_MON_EARLY):
        assert proc._suppress_after_hours(payload) is True


def test_disabled_when_business_hours_unset():
    """Empty BUSINESS_HOURS_WINDOW is the master switch — feature fully off."""
    proc = _proc(business_hours_window="")
    payload = make_alert(priority="P5", tags=["business-hours-only"])
    with _at(_MON_EARLY):
        assert proc._suppress_after_hours(payload) is False


# ── Tag-based suppression (optional platform parity) ─────────────────────


def test_tag_suppresses_even_an_audible_priority():
    """A tag overrides the audible-priority allowance — that is its purpose."""
    proc = _proc(after_hours_silent_tags="business-hours-only")
    payload = make_alert(priority="P1", tags=["business-hours-only"])
    with _at(_MON_EARLY):
        assert proc._suppress_after_hours(payload) is True


def test_tag_ignored_during_business_hours():
    proc = _proc(after_hours_silent_tags="business-hours-only")
    payload = make_alert(priority="P1", tags=["business-hours-only"])
    with _at(_MON):
        assert proc._suppress_after_hours(payload) is False


def test_tag_matching_is_case_insensitive():
    proc = _proc(after_hours_silent_tags="business-hours-only")
    payload = make_alert(priority="P1", tags=["Business-Hours-Only"])
    with _at(_MON_EARLY):
        assert proc._suppress_after_hours(payload) is True


def test_tags_default_to_empty_so_priority_alone_decides():
    """No tags configured by default — an audible P1 stays audible."""
    proc = _proc()
    payload = make_alert(priority="P1", tags=["business-hours-only"])
    with _at(_MON_EARLY):
        assert proc._suppress_after_hours(payload) is False


def test_custom_tag_names_with_whitespace():
    proc = _proc(after_hours_silent_tags="defer-me , other")
    payload = make_alert(priority="P1", tags=["OTHER"])
    with _at(_MON_EARLY):
        assert proc._suppress_after_hours(payload) is True


# ── End-to-end through process() ─────────────────────────────────────────


def _wire(proc: AlertProcessor) -> AlertProcessor:
    proc.ha_client.play_tts_alert = AsyncMock(return_value=True)
    proc.ha_client.send_persistent_notification = AsyncMock(return_value=True)
    proc.ha_client.fire_webhooks = AsyncMock(return_value=True)
    return proc


async def test_process_suppresses_tts_but_keeps_notification():
    """The original regression: a P3 at 02:00 must not speak, but must post."""
    proc = _wire(_proc())

    payload = make_alert(priority="P3")
    with _at(_MON_EARLY):
        result = await proc.process(payload, always_notify=True)

    assert result["notified"] is True
    assert result["announcement_mode"] == "silent"
    assert result["suppressed_after_hours"] is True
    proc.ha_client.play_tts_alert.assert_not_called()
    proc.ha_client.send_persistent_notification.assert_called_once()


async def test_process_speaks_p1_overnight():
    proc = _wire(_proc())

    payload = make_alert(priority="P1")
    with _at(_MON_EARLY):
        result = await proc.process(payload, always_notify=True)

    assert result["announcement_mode"] == "full"
    assert "suppressed_after_hours" not in result
    proc.ha_client.play_tts_alert.assert_called_once()


async def test_silent_override_cannot_unmute_a_suppressed_alert():
    """
    SILENT_WINDOW_OVERRIDE_PRIORITIES must not resurrect an alert that
    after-hours suppression muted — otherwise it reintroduces the 2am page.
    """
    proc = _wire(
        _proc(
            silent_window="22:00-07:00",
            silent_window_override_priorities="P1,P2,P3",
        )
    )

    payload = make_alert(priority="P3")
    with _at(_MON_EARLY):
        result = await proc.process(payload, always_notify=True)

    assert result["announcement_mode"] == "silent"
    proc.ha_client.play_tts_alert.assert_not_called()


async def test_process_unaffected_when_feature_disabled():
    """Default config (no BUSINESS_HOURS_WINDOW) must behave exactly as before."""
    proc = _wire(_proc(business_hours_window=""))

    payload = make_alert(priority="P5")
    with _at(_MON_EARLY):
        result = await proc.process(payload, always_notify=True)

    assert result["announcement_mode"] == "full"
    proc.ha_client.play_tts_alert.assert_called_once()
