# Changelog

All notable changes to this project will be documented in this file.

## [2.1.0] — 2026-03-22

### Added

#### Configurable Announcements
- **Configurable TTS format templates** (`ANNOUNCEMENT_FORMAT`, `TERSE_ANNOUNCEMENT_FORMAT`) — customise spoken announcements using `{action_prefix}`, `{priority}`, `{message}`, `{entity}`, `{description}`, `{entity_part}`, `{description_part}` placeholders.
- **Silent time windows** (`SILENT_WINDOW`) — suppress TTS during configurable hours (persistent notifications still created). Cross-midnight windows supported (e.g. `22:30-07:00`). Multiple comma-separated windows allowed.
- **Terse time windows** (`TERSE_WINDOW`) — use a shorter announcement format during configurable hours.
- **Priority override for silent windows** (`SILENT_WINDOW_OVERRIDE_PRIORITIES`) — P1/P2 alerts can bypass silent mode so critical incidents always produce audio.

#### Media Player & Volume
- **Per-media-player time-based routing** (`HA_MEDIA_PLAYER_ROUTING`) — route TTS to different speakers by time of day (e.g. `media_player.bedroom@22:00-08:00`).
- **Volume control** (`HA_VOLUME_DEFAULT`, `HA_VOLUME_TERSE`) — set media player volume before TTS playback, with separate levels for full and terse modes.

#### Alert Handling
- **Alert batching** (`ALERT_BATCH_WINDOW_SECONDS`) — combine multiple alerts arriving within N seconds into a single TTS announcement.
- **TTS repeat / pager mode** (`TTS_REPEAT_INTERVAL_SECONDS`, `TTS_REPEAT_MAX`, `TTS_REPEAT_PRIORITIES`) — repeat TTS at intervals for critical alerts until acknowledged/closed.
- **Acknowledge from HA** (`POST /alert/{id}/acknowledge`) — acknowledge JSM alerts directly from Home Assistant automations; dismisses HA notification and cancels TTS repeats.

#### Security
- **API key authentication** (`WEBHOOK_API_KEY`) — optional `?key=` query parameter on webhook URLs. Simpler alternative to HMAC signatures; both can be used together for defense in depth.
- **Safe format templates** — announcement format strings use a restricted formatter (`_SafeFormatter`) that blocks attribute/index access, preventing format string injection attacks.
- **Request body size limit** — rejects payloads over 1 MB (413 Payload Too Large) to prevent memory exhaustion.
- **Input validation on acknowledge endpoint** — alert IDs validated against `[a-zA-Z0-9\-_]{1,200}` regex.
- **Audit logging on acknowledge endpoint** — logs source IP for every acknowledge request.
- **Webhook signature exception safety** — wrapped in try/except to prevent secrets leaking in tracebacks.
- **Sanitized error responses** — Pydantic validation errors no longer returned verbatim to clients.

#### Observability
- **Deep health check** (`GET /healthz`) — verifies JSM credential validity and HA API reachability; returns 503 if either fails.
- **Startup connectivity checks** — non-blocking verification of JSM and HA APIs at boot with warnings if unreachable.
- **Dismiss result tracking** — logs whether HA `persistent_notification.dismiss` succeeded or failed.

#### Robustness
- **Persistent HTTP clients** — `JSMClient` and `HAClient` reuse a single `httpx.AsyncClient` instead of creating one per request, preventing socket exhaustion under load.
- **Graceful HTTP client shutdown** — `aclose()` called on both clients during application shutdown.
- **Dedup cache max size** — hard cap of 10,000 entries with oldest-half eviction to prevent DoS via random alert IDs.
- **TTS repeat task race fix** — cancel-before-create pattern with `try/finally` cleanup prevents orphaned background tasks.

### Fixed
- Pre-existing `test_media_metadata_p1` assertion mismatch (expected wrong artist name).

### Changed
- Webhook URL format now supports `?key=YOUR_KEY` parameter (backwards compatible — key is optional unless `WEBHOOK_API_KEY` is set).
- Error responses from `/alert` endpoint no longer include raw Pydantic validation details.

---

## [2.0.0] — Initial release

- On-call aware alert routing via JSM Ops API
- Escalation detection (`EscalateNext`)
- Always-notify mode via `?mode=always` query parameter
- Rich TTS announcements with priority, title, system, description
- Media player metadata (real alert title instead of "Playing Default Media Receiver")
- Persistent HA notifications with auto-dismiss on Acknowledge/Close
- Webhook HMAC-SHA256 signature verification
- Background token health check with HA alerts on expiry
- Deduplication with configurable TTL
- Docker multi-arch build (amd64 + arm64)
- Non-root container, read-only filesystem
