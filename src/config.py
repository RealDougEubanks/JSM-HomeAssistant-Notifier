"""
Configuration loaded from environment variables / .env file.
All secrets live here — never hardcoded anywhere else.

Why the custom settings sources?
─────────────────────────────────
pydantic-settings v2 calls `decode_complex_value()` (which does `json.loads()`)
on raw env-var strings *before* any Pydantic field validators run.  That means
a plain comma-separated value like:

    ALWAYS_NOTIFY_SCHEDULE_NAMES=Internal Systems_schedule

crashes with JSONDecodeError before our validators can touch it.  The fix is
to subclass both `EnvSettingsSource` and `DotEnvSettingsSource`, intercept
`decode_complex_value` for our two list fields, and handle CSV ourselves.
"""

from __future__ import annotations

import json
from typing import Any, List, Tuple, Type

from pydantic import field_validator, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from .time_windows import Window, parse_windows

# Fields that accept plain comma-separated strings in addition to JSON arrays.
_CSV_FIELDS = frozenset({"always_notify_schedule_names", "check_oncall_schedule_names"})


def _parse_csv_or_json(field_name: str, value: Any) -> Any:
    """
    If *field_name* is a CSV field and *value* is a plain string, convert it
    to a list by trying JSON first, then splitting on commas.  An empty or
    whitespace-only string becomes an empty list.

    Returns the original *value* unchanged for all other fields / types.
    """
    if field_name not in _CSV_FIELDS or not isinstance(value, str):
        return value
    value = value.strip()
    if not value:
        return []
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else [str(parsed)]
    except (json.JSONDecodeError, ValueError):
        return [s.strip() for s in value.split(",") if s.strip()]


class _CsvAwareEnvSource(EnvSettingsSource):
    """Reads process environment variables; handles CSV list fields."""

    def decode_complex_value(
        self, field_name: str, field: FieldInfo, value: Any
    ) -> Any:
        result = _parse_csv_or_json(field_name, value)
        # If _parse_csv_or_json returned a list we're done; otherwise delegate.
        if isinstance(result, list) and field_name in _CSV_FIELDS:
            return result
        return super().decode_complex_value(field_name, field, value)


class _CsvAwareDotEnvSource(DotEnvSettingsSource):
    """Reads .env file; handles CSV list fields."""

    def decode_complex_value(
        self, field_name: str, field: FieldInfo, value: Any
    ) -> Any:
        result = _parse_csv_or_json(field_name, value)
        if isinstance(result, list) and field_name in _CSV_FIELDS:
            return result
        return super().decode_complex_value(field_name, field, value)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Atlassian / JSM ──────────────────────────────────────────────────────
    jsm_api_url: str = "https://api.atlassian.com"
    jira_base_url: str = ""  # e.g. https://your-org.atlassian.net (reserved; not currently used)
    jsm_cloud_id: str
    jsm_username: str
    jsm_api_token: str
    jsm_my_user_id: str

    # ── Schedule routing ─────────────────────────────────────────────────────
    # Schedules listed here ALWAYS trigger a notification (no on-call check).
    # Accepts a plain comma-separated string or a JSON array in .env:
    #   ALWAYS_NOTIFY_SCHEDULE_NAMES=Internal Systems_schedule
    #   ALWAYS_NOTIFY_SCHEDULE_NAMES=["Internal Systems_schedule","Another"]
    always_notify_schedule_names: List[str] = []

    # Schedules listed here only notify when you are currently on-call.
    check_oncall_schedule_names: List[str] = []

    # ── Home Assistant ───────────────────────────────────────────────────────
    ha_url: str
    ha_token: str
    ha_media_player_entity: str = "media_player.home"
    ha_tts_service: str = "tts.home_assistant_cloud"
    ha_tts_language: str = "en-US"
    ha_tts_voice: str = "JennyNeural"
    # Label shown as the "artist" field in the HA media player UI.
    # Set this to something that identifies the service to you.
    ha_notifier_label: str = "JSM Alert Notifier"

    # ── Webhook security ─────────────────────────────────────────────────────
    webhook_secret: str = ""

    # ── Announcement format ─────────────────────────────────────────────────
    # Template for the full (detailed) TTS announcement.  Available placeholders:
    #   {action_prefix}  – "Escalated alert!" or "Attention!"
    #   {priority}       – e.g. "Priority 1, Critical"
    #   {message}        – alert title / summary
    #   {entity}         – system / host name (empty string if absent)
    #   {description}    – truncated description (empty string if absent)
    announcement_format: str = (
        "{action_prefix} {priority} alert from Jira Service Management. "
        "Alert: {message}.{entity_part}{description_part}"
    )

    # Template for terse (short) announcements during terse windows.
    terse_announcement_format: str = "{action_prefix} {priority} alert. {message}."

    # ── Time windows (quiet hours) ───────────────────────────────────────
    # Comma-separated HH:MM-HH:MM windows.  Cross-midnight is supported.
    # During silent windows, no TTS is played (persistent notification only).
    # During terse windows, only the terse format is spoken.
    # Leave empty to disable.
    silent_window: str = ""
    terse_window: str = ""

    # Parsed window lists — populated by the model validator below.
    _silent_windows: list[Window] = []
    _terse_windows: list[Window] = []

    # ── Tuning ───────────────────────────────────────────────────────────────
    oncall_cache_ttl_seconds: int = 300
    alert_dedup_ttl_seconds: int = 60
    # How often (hours) to verify the Atlassian API token is still valid.
    # An HA notification + TTS announcement fires if the check fails.
    token_check_interval_hours: int = 24

    # ── Validators ───────────────────────────────────────────────────────────
    # These run when values arrive via __init__ kwargs (e.g. in tests).
    # The custom sources above handle the same conversion for .env / env vars.
    @field_validator("always_notify_schedule_names", "check_oncall_schedule_names", mode="before")
    @classmethod
    def _coerce_csv(cls, v: object) -> List[str]:
        if isinstance(v, str):
            return _parse_csv_or_json("always_notify_schedule_names", v)  # type: ignore[arg-type]
        return v  # type: ignore[return-value]

    @model_validator(mode="after")
    def _parse_time_windows(self) -> "Settings":
        object.__setattr__(self, "_silent_windows", parse_windows(self.silent_window))
        object.__setattr__(self, "_terse_windows", parse_windows(self.terse_window))
        return self

    # ── Custom sources ────────────────────────────────────────────────────────
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            _CsvAwareEnvSource(settings_cls),
            _CsvAwareDotEnvSource(
                settings_cls,
                env_file=cls.model_config.get("env_file", ".env"),
                env_file_encoding=cls.model_config.get("env_file_encoding", "utf-8"),
            ),
            file_secret_settings,
        )
