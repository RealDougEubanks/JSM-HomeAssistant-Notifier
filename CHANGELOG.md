# Changelog

All notable changes to this project will be documented in this file.

## [2.2.0] — 2026-03-25

### Added

#### Health Check & Observability
- **Enriched `/healthz` endpoint** — now returns schedule validation (verifies `.env` schedule names exist in JSM), on-call status, uptime, version, cache sizes, background task state, and non-sensitive configuration summary.
- **Prometheus `/metrics` endpoint** — counters for alerts received/notified/deduplicated/dismissed, credential checks, rate limiting, and uptime gauge. Compatible with Prometheus scraping and Grafana dashboards.
- **Structured JSON logging** (`LOG_FORMAT=json`) — optional JSON log output for Datadog, Loki, CloudWatch, and ELK. Set `LOG_FORMAT=json` in `.env`; default remains human-readable text.
- **Quiet-hours TTS suppression for credential checks** — the 24-hour token health check suppresses TTS during `SILENT_WINDOW` hours but still creates a persistent dashboard notification.

#### Configuration & Operations
- **Hot config reload** (`POST /reload`) — re-reads `.env` and applies changes without restarting the container. Clears all caches on reload.
- **Timezone support** (`TZ`) — documented in `.env.example`. Time windows are evaluated in the container's local timezone.

#### API Key Authentication
- **Three authentication methods** — API key can now be passed via query parameter (`?key=`), HTTP header (`X-API-Key`), or URL path prefix (`/KEY/endpoint`). All methods work on all authenticated endpoints.
- **Stealth 404 on auth failure** — unauthenticated requests return 404 (not 401) to prevent endpoint discovery.

#### Security Hardening
- **HTTPS enforcement** — `JSM_API_URL` and `HA_URL` must use HTTPS (validated at startup).
- **SQLite thread-safety** — added `threading.Lock` to prevent concurrent write corruption.
- **Pagination SSRF protection** — JSM `paging.next` URL validated against expected API base; capped at 100 pages.
- **Per-IP rate limiting** — 60 requests/minute on `/alert` with bounded IP tracking (10k max IPs).
- **Content-Length pre-check** — rejects oversized requests before reading body into memory.
- **Security headers** — `X-Content-Type-Options`, `X-Frame-Options`, `X-Robots-Tag`, `Content-Security-Policy`, `Referrer-Policy`, `Cache-Control: no-store`, generic `Server` header.
- **Anti-fingerprinting** — `/openapi.json`, `/docs`, `/redoc` disabled; normalized 404/405/422 error responses; `robots.txt` endpoint.
- **Endpoint authentication** — `/status`, `/cache/invalidate`, and all incident dashboard endpoints now require API key when configured.
- **Alert ID validation** — added to `/incidents/{id}` and `/incidents/{id}/close` endpoints.
- **Error detail sanitization** — JSM error messages no longer leaked in 502 responses or credential alert notifications.
- **Schedule name redaction** — log warnings show count of visible schedules instead of names.
- **Docker port binding** — defaults to `127.0.0.1:8080` (localhost only).

#### Documentation
- **Production recommendations** — external uptime monitoring (NodePing example), single-worker resilience notes, persistent storage setup.
- **External access rewrite** — removed direct port-forward option; Cloudflare Tunnel as primary recommendation with TLS warning.
- **Troubleshooting** — added 404 auth behavior section; updated schedule-not-found guidance.
- **Local Docker build testing** — added to README with `--no-cache` cache invalidation tip.
- **Cloud ID discovery** — updated to use simpler `_edge/tenant_info` endpoint.

#### Testing
- **90% code coverage** — 269 tests covering security (HMAC signatures, API key all methods, parametrized 404 checks on all endpoints), batch/repeat logic, HA client, and alert processor.

### Changed
- Removed unused `jira_base_url` configuration field.
- `/status` endpoint no longer exposes `user_id` field.
- `pip-audit` in CI scoped to `requirements.txt` only (prevents false positives from dev dependencies).

---

## [2.1.0] — 2026-03-22

### Added

#### HA Automation Webhooks
- **HA automation webhooks** — fire HA webhook triggers on all alert lifecycle events: Create, Escalate, Acknowledge, Close, Update (AddNote/AssignOwnership/UnAcknowledge/Seen), and SLA Breach. Configure per-event webhook IDs via `HA_WEBHOOK_ON_CREATE`, `HA_WEBHOOK_ON_ESCALATE`, `HA_WEBHOOK_ON_ACKNOWLEDGE`, `HA_WEBHOOK_ON_CLOSE`, `HA_WEBHOOK_ON_UPDATE`, `HA_WEBHOOK_ON_SLA_BREACH`. Passes alert data (event, alert_id, message, priority, entity, description, source, tags) as trigger variables.
- **Multiple webhooks per event** — comma-separated webhook IDs fire multiple automations for a single event.

#### Incident State Dashboard
- **Incident dashboard** (`INCIDENT_DASHBOARD_ENABLED`) — SQLite-backed incident tracker exposing `GET /incidents`, `GET /incidents/summary`, `GET /incidents/{id}`, `POST /incidents/{id}/close`, and `POST /incidents/sync` endpoints. Tracks all alert lifecycle events automatically from webhooks. Filterable by status and priority.
- **Force-close endpoint** (`POST /incidents/{id}/close`) — close stale incidents directly from the dashboard without waiting for JSM. Dismisses HA notification and cancels TTS repeats.
- **Retention policy** (`INCIDENT_RETENTION_OPEN_DAYS`, `INCIDENT_RETENTION_CLOSED_DAYS`) — automatically delete stale open and resolved incidents after configurable number of days. Runs during each sync cycle.
- **Alert enrichment** — on `Create` events, fetches full alert details from JSM API (tags, teams, responders, custom details) and stores them in the incident database.
- **Pre-built Grafana dashboard** — `grafana/incident-dashboard.json` ready to import, with stat panels, incident table, and pie charts.
- **JSM background sync** (`INCIDENT_SYNC_INTERVAL_MINUTES`) — optional periodic sync of open alerts from JSM Ops API to keep the dashboard current even for alerts not delivered via webhook.
- **Grafana compatibility** — JSON output from `/incidents` is compatible with Grafana's Infinity datasource plugin for building incident dashboards.

#### CI/CD Improvements
- **Python matrix testing** — CI now tests against Python 3.11, 3.12, and 3.13.
- **pip-audit** — scans Python dependencies for known CVEs on every CI run.
- **bandit** — runs Python code security analysis (advisory, non-blocking).
- **Trivy container scanning** — scans Docker images for vulnerabilities before push, uploads SARIF results to GitHub Security.
- **Coverage threshold** — CI fails if test coverage drops below 70%.
- **Explicit permissions** — both workflows now use minimal `permissions:` blocks.
- **OCI labels** — Docker images include `org.opencontainers.image.*` metadata labels.

#### Emoji Control & Generic Webhook Support
- **Emoji toggle** (`ENABLE_EMOJIS`) — when `false`, all emojis are stripped from notification titles, media metadata, and incoming alert text. Default is `true`. Useful for HA setups that don't render emojis well.
- **Generic webhook support** — documented payload format and examples for Uptime Kuma, Grafana, Prometheus Alertmanager, Home Assistant automations, and shell scripts. Any system that can send HTTP POST can trigger HA alerts.

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
