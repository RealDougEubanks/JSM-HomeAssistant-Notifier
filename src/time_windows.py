"""
Time-window helpers for silent and terse announcement modes.

A window is a string like ``"22:30-07:00"`` (crosses midnight) or
``"09:00-17:00"`` (same day).  Multiple windows are separated by commas:
``"22:30-07:00, 12:00-13:00"``.

The module exposes:
  * ``parse_windows()``  – parse a CSV string into a list of (start, end) tuples
  * ``in_any_window()``  – check if a given time falls inside any window
"""

from __future__ import annotations

import re
from datetime import time
from typing import List, Tuple

# HH:MM with optional leading zero
_TIME_RE = re.compile(r"^(\d{1,2}):(\d{2})$")

Window = Tuple[time, time]


def _parse_time(s: str) -> time:
    """Parse ``"HH:MM"`` into a :class:`datetime.time`."""
    m = _TIME_RE.match(s.strip())
    if not m:
        raise ValueError(f"Invalid time format {s!r} — expected HH:MM")
    h, mi = int(m.group(1)), int(m.group(2))
    if not (0 <= h <= 23 and 0 <= mi <= 59):
        raise ValueError(f"Time out of range: {s!r}")
    return time(h, mi)


def parse_windows(raw: str) -> List[Window]:
    """
    Parse a comma-separated list of ``"HH:MM-HH:MM"`` windows.

    Returns an empty list for empty / whitespace-only input.
    """
    raw = raw.strip()
    if not raw:
        return []
    windows: List[Window] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" not in token:
            raise ValueError(f"Invalid window {token!r} — expected HH:MM-HH:MM")
        parts = token.split("-", 1)
        start = _parse_time(parts[0])
        end = _parse_time(parts[1])
        windows.append((start, end))
    return windows


def in_window(t: time, window: Window) -> bool:
    """Return True if *t* falls inside the given window (inclusive start, exclusive end)."""
    start, end = window
    if start <= end:
        # Same-day window, e.g. 09:00-17:00
        return start <= t < end
    else:
        # Crosses midnight, e.g. 22:30-07:00
        return t >= start or t < end


def in_any_window(t: time, windows: List[Window]) -> bool:
    """Return True if *t* falls inside any of the given windows."""
    return any(in_window(t, w) for w in windows)


# ── Media player routing ─────────────────────────────────────────────────

PlayerRoute = Tuple[str, Window]  # (entity_id, time_window)


def parse_player_routing(raw: str) -> List[PlayerRoute]:
    """
    Parse a comma-separated list of ``"entity@HH:MM-HH:MM"`` routes.

    Returns an empty list for empty / whitespace-only input.
    """
    raw = raw.strip()
    if not raw:
        return []
    routes: List[PlayerRoute] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if "@" not in token:
            raise ValueError(
                f"Invalid routing entry {token!r} — expected entity@HH:MM-HH:MM"
            )
        entity, window_str = token.rsplit("@", 1)
        entity = entity.strip()
        if "-" not in window_str:
            raise ValueError(
                f"Invalid time window in routing {token!r} — expected HH:MM-HH:MM"
            )
        parts = window_str.split("-", 1)
        start = _parse_time(parts[0])
        end = _parse_time(parts[1])
        routes.append((entity, (start, end)))
    return routes


def resolve_player(
    t: time, routes: List[PlayerRoute], default: str,
) -> str:
    """Return the media player entity for the given time, or the default."""
    for entity, window in routes:
        if in_window(t, window):
            return entity
    return default
