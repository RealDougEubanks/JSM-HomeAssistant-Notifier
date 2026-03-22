"""Tests for time window parsing and matching."""

from __future__ import annotations

from datetime import time

import pytest

from src.time_windows import (
    in_any_window,
    in_window,
    parse_player_routing,
    parse_windows,
    resolve_player,
)

# ── parse_windows ────────────────────────────────────────────────────────────


def test_parse_empty_string():
    assert parse_windows("") == []


def test_parse_whitespace():
    assert parse_windows("   ") == []


def test_parse_single_window():
    windows = parse_windows("09:00-17:00")
    assert len(windows) == 1
    assert windows[0] == (time(9, 0), time(17, 0))


def test_parse_multiple_windows():
    windows = parse_windows("09:00-17:00, 22:00-06:00")
    assert len(windows) == 2
    assert windows[0] == (time(9, 0), time(17, 0))
    assert windows[1] == (time(22, 0), time(6, 0))


def test_parse_cross_midnight():
    windows = parse_windows("22:30-07:00")
    assert windows[0] == (time(22, 30), time(7, 0))


def test_parse_invalid_format():
    with pytest.raises(ValueError, match="Invalid window"):
        parse_windows("09:00")


def test_parse_invalid_time():
    with pytest.raises(ValueError, match="out of range"):
        parse_windows("25:00-06:00")


def test_parse_leading_zero_optional():
    windows = parse_windows("9:00-17:00")
    assert windows[0] == (time(9, 0), time(17, 0))


# ── in_window — same-day ────────────────────────────────────────────────────


def test_same_day_inside():
    w = (time(9, 0), time(17, 0))
    assert in_window(time(12, 0), w) is True


def test_same_day_at_start():
    w = (time(9, 0), time(17, 0))
    assert in_window(time(9, 0), w) is True


def test_same_day_at_end():
    """End is exclusive."""
    w = (time(9, 0), time(17, 0))
    assert in_window(time(17, 0), w) is False


def test_same_day_before():
    w = (time(9, 0), time(17, 0))
    assert in_window(time(8, 59), w) is False


def test_same_day_after():
    w = (time(9, 0), time(17, 0))
    assert in_window(time(17, 1), w) is False


# ── in_window — cross-midnight ──────────────────────────────────────────────


def test_cross_midnight_late_night():
    w = (time(22, 30), time(7, 0))
    assert in_window(time(23, 0), w) is True


def test_cross_midnight_at_start():
    w = (time(22, 30), time(7, 0))
    assert in_window(time(22, 30), w) is True


def test_cross_midnight_early_morning():
    w = (time(22, 30), time(7, 0))
    assert in_window(time(3, 0), w) is True


def test_cross_midnight_at_end():
    """End is exclusive."""
    w = (time(22, 30), time(7, 0))
    assert in_window(time(7, 0), w) is False


def test_cross_midnight_daytime():
    w = (time(22, 30), time(7, 0))
    assert in_window(time(12, 0), w) is False


def test_cross_midnight_just_before_end():
    w = (time(22, 30), time(7, 0))
    assert in_window(time(6, 59), w) is True


# ── in_any_window ───────────────────────────────────────────────────────────


def test_in_any_empty():
    assert in_any_window(time(12, 0), []) is False


def test_in_any_matches_second_window():
    windows = [(time(9, 0), time(12, 0)), (time(14, 0), time(18, 0))]
    assert in_any_window(time(15, 0), windows) is True


def test_in_any_no_match():
    windows = [(time(9, 0), time(12, 0)), (time(14, 0), time(18, 0))]
    assert in_any_window(time(13, 0), windows) is False


# ── parse_player_routing ─────────────────────────────────────────────────────


def test_parse_routing_empty():
    assert parse_player_routing("") == []


def test_parse_routing_single():
    routes = parse_player_routing("media_player.bedroom@22:00-08:00")
    assert len(routes) == 1
    assert routes[0][0] == "media_player.bedroom"
    assert routes[0][1] == (time(22, 0), time(8, 0))


def test_parse_routing_multiple():
    routes = parse_player_routing(
        "media_player.bedroom@22:00-08:00, media_player.office@08:00-18:00"
    )
    assert len(routes) == 2
    assert routes[0][0] == "media_player.bedroom"
    assert routes[1][0] == "media_player.office"


def test_parse_routing_invalid_no_at():
    with pytest.raises(ValueError, match="Invalid routing entry"):
        parse_player_routing("media_player.bedroom")


# ── resolve_player ───────────────────────────────────────────────────────────


def test_resolve_player_matches():
    routes = [("media_player.bedroom", (time(22, 0), time(8, 0)))]
    assert (
        resolve_player(time(23, 0), routes, "media_player.default")
        == "media_player.bedroom"
    )


def test_resolve_player_falls_back():
    routes = [("media_player.bedroom", (time(22, 0), time(8, 0)))]
    assert (
        resolve_player(time(12, 0), routes, "media_player.default")
        == "media_player.default"
    )


def test_resolve_player_empty_routes():
    assert (
        resolve_player(time(12, 0), [], "media_player.default") == "media_player.default"
    )
