"""
Tests for Settings / config parsing — specifically the CSV list fields that
were crashing pydantic-settings with a JSONDecodeError before this fix.
"""
from __future__ import annotations

from src.config import Settings, _parse_csv_or_json

# ── Unit tests for the CSV parser helper ──────────────────────────────────────

def test_parse_csv_plain_string():
    result = _parse_csv_or_json("always_notify_schedule_names", "Internal Systems_schedule")
    assert result == ["Internal Systems_schedule"]


def test_parse_csv_multiple_values():
    result = _parse_csv_or_json(
        "check_oncall_schedule_names",
        "Cloud Engineering On-Call Schedule, Internal Systems_schedule",
    )
    assert result == ["Cloud Engineering On-Call Schedule", "Internal Systems_schedule"]


def test_parse_csv_json_array():
    result = _parse_csv_or_json(
        "always_notify_schedule_names",
        '["Internal Systems_schedule", "Another Schedule"]',
    )
    assert result == ["Internal Systems_schedule", "Another Schedule"]


def test_parse_csv_empty_string():
    result = _parse_csv_or_json("always_notify_schedule_names", "")
    assert result == []


def test_parse_csv_whitespace_only():
    result = _parse_csv_or_json("check_oncall_schedule_names", "   ")
    assert result == []


def test_parse_csv_non_csv_field_unchanged():
    """Fields not in _CSV_FIELDS must pass through untouched."""
    sentinel = object()
    result = _parse_csv_or_json("jsm_cloud_id", sentinel)
    assert result is sentinel


def test_parse_csv_already_a_list():
    """If the value is already a list, pass it through."""
    value = ["A", "B"]
    result = _parse_csv_or_json("always_notify_schedule_names", value)
    assert result == value


# ── Integration: Settings parses CSV strings from init kwargs ─────────────────

def test_settings_csv_single(tmp_path):
    """Settings accepts a plain string for list fields (the crash scenario)."""
    s = Settings(
        jsm_cloud_id="cloud-id",
        jsm_username="user@example.com",
        jsm_api_token="token",
        jsm_my_user_id="user-id",
        ha_url="https://ha.example.com",
        ha_token="ha-token",
        always_notify_schedule_names="Internal Systems_schedule",
        check_oncall_schedule_names="Cloud Engineering On-Call Schedule",
    )
    assert s.always_notify_schedule_names == ["Internal Systems_schedule"]
    assert s.check_oncall_schedule_names == ["Cloud Engineering On-Call Schedule"]


def test_settings_csv_empty(tmp_path):
    """Empty string must produce an empty list, not a crash."""
    s = Settings(
        jsm_cloud_id="cloud-id",
        jsm_username="user@example.com",
        jsm_api_token="token",
        jsm_my_user_id="user-id",
        ha_url="https://ha.example.com",
        ha_token="ha-token",
        always_notify_schedule_names="",
        check_oncall_schedule_names="",
    )
    assert s.always_notify_schedule_names == []
    assert s.check_oncall_schedule_names == []


def test_settings_csv_multiple():
    s = Settings(
        jsm_cloud_id="cloud-id",
        jsm_username="user@example.com",
        jsm_api_token="token",
        jsm_my_user_id="user-id",
        ha_url="https://ha.example.com",
        ha_token="ha-token",
        always_notify_schedule_names="Sched A, Sched B, Sched C",
    )
    assert s.always_notify_schedule_names == ["Sched A", "Sched B", "Sched C"]
