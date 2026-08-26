"""
Time-window helpers for silent and terse announcement modes.

A window is a string like ``"22:30-07:00"`` (crosses midnight) or
``"09:00-17:00"`` (same day).  Multiple windows are separated by commas:
``"22:30-07:00, 12:00-13:00"``.

Business-hours windows additionally carry a weekday range, e.g.
``"Mon-Fri 09:00-17:00"``.  These are needed because a plain time-of-day
window cannot express "outside office hours" — it would correctly mute
02:00 Tuesday but leave 14:00 Saturday audible.

The module exposes:
  * ``parse_windows()``      – parse a CSV string into a list of (start, end) tuples
  * ``in_any_window()``      – check if a given time falls inside any window
  * ``parse_day_windows()``  – parse ``"Mon-Fri 09:00-17:00"`` style windows
  * ``in_any_day_window()``  – check if a given datetime falls inside any of them
"""

from __future__ import annotations

import re
from datetime import datetime, time

# HH:MM with optional leading zero
_TIME_RE = re.compile(r"^(\d{1,2}):(\d{2})$")

Window = tuple[time, time]

# ── Weekday-aware windows ────────────────────────────────────────────────
# Monday is 0 to match datetime.weekday().
_DAY_NAMES: dict[str, int] = {
    "mon": 0,
    "tue": 1,
    "wed": 2,
    "thu": 3,
    "fri": 4,
    "sat": 5,
    "sun": 6,
}

# "Mon-Fri 09:00-17:00" or "Sat 10:00-14:00"
_DAY_WINDOW_RE = re.compile(
    r"^(?P<days>[A-Za-z]{3}(?:\s*-\s*[A-Za-z]{3})?)\s+"
    r"(?P<start>\d{1,2}:\d{2})\s*-\s*(?P<end>\d{1,2}:\d{2})$"
)

# (set of weekday ints, start time, end time)
DayWindow = tuple[frozenset[int], time, time]


def _parse_time(s: str) -> time:
    """Parse ``"HH:MM"`` into a :class:`datetime.time`."""
    m = _TIME_RE.match(s.strip())
    if not m:
        raise ValueError(f"Invalid time format {s!r} — expected HH:MM")
    h, mi = int(m.group(1)), int(m.group(2))
    if not (0 <= h <= 23 and 0 <= mi <= 59):
        raise ValueError(f"Time out of range: {s!r}")
    return time(h, mi)


def parse_windows(raw: str) -> list[Window]:
    """
    Parse a comma-separated list of ``"HH:MM-HH:MM"`` windows.

    Returns an empty list for empty / whitespace-only input.
    """
    raw = raw.strip()
    if not raw:
        return []
    windows: list[Window] = []
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


def in_any_window(t: time, windows: list[Window]) -> bool:
    """Return True if *t* falls inside any of the given windows."""
    return any(in_window(t, w) for w in windows)


# ── Weekday-aware windows ────────────────────────────────────────────────


def _parse_day_range(raw: str) -> frozenset[int]:
    """
    Parse ``"Mon"`` or ``"Mon-Fri"`` into a set of weekday ints (Mon=0).

    Ranges wrap around the week, so ``"Fri-Mon"`` yields {Fri, Sat, Sun, Mon}.
    """
    parts = [p.strip().lower()[:3] for p in raw.split("-")]
    for p in parts:
        if p not in _DAY_NAMES:
            raise ValueError(f"Unknown weekday {p!r} — expected Mon..Sun")
    if len(parts) == 1:
        return frozenset({_DAY_NAMES[parts[0]]})
    start, end = _DAY_NAMES[parts[0]], _DAY_NAMES[parts[1]]
    # Walk forward from start to end so wrap-around ranges work.
    days = []
    d = start
    while True:
        days.append(d)
        if d == end:
            break
        d = (d + 1) % 7
    return frozenset(days)


def parse_day_windows(raw: str) -> list[DayWindow]:
    """
    Parse a comma-separated list of ``"Mon-Fri 09:00-17:00"`` windows.

    Returns an empty list for empty / whitespace-only input.
    """
    raw = raw.strip()
    if not raw:
        return []
    windows: list[DayWindow] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        m = _DAY_WINDOW_RE.match(token)
        if not m:
            raise ValueError(
                f"Invalid business-hours window {token!r} — "
                "expected 'Mon-Fri HH:MM-HH:MM'"
            )
        days = _parse_day_range(m.group("days"))
        start = _parse_time(m.group("start"))
        end = _parse_time(m.group("end"))
        windows.append((days, start, end))
    return windows


def in_day_window(dt: datetime, window: DayWindow) -> bool:
    """
    Return True if *dt* falls inside *window*.

    For windows that cross midnight the weekday is matched against the day the
    window *started* on, so "Fri 17:00-09:00" covers early Saturday morning.
    """
    days, start, end = window
    if start <= end:
        return dt.weekday() in days and start <= dt.time() < end
    # Crosses midnight: either late on a matching day, or early the next day.
    if dt.time() >= start:
        return dt.weekday() in days
    return (dt.weekday() - 1) % 7 in days


def in_any_day_window(dt: datetime, windows: list[DayWindow]) -> bool:
    """Return True if *dt* falls inside any of the given weekday windows."""
    return any(in_day_window(dt, w) for w in windows)


# ── Media player routing ─────────────────────────────────────────────────

PlayerRoute = tuple[str, Window]  # (entity_id, time_window)


def parse_player_routing(raw: str) -> list[PlayerRoute]:
    """
    Parse a comma-separated list of ``"entity@HH:MM-HH:MM"`` routes.

    Returns an empty list for empty / whitespace-only input.
    """
    raw = raw.strip()
    if not raw:
        return []
    routes: list[PlayerRoute] = []
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
    t: time,
    routes: list[PlayerRoute],
    default: str,
) -> str:
    """Return the media player entity for the given time, or the default."""
    for entity, window in routes:
        if in_window(t, window):
            return entity
    return default
