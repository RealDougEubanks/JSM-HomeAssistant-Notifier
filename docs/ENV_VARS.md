<!--
doc: ENV_VARS
last-refreshed: 2026-08-26
generated-by: doc-refresh skill
-->

# Environment Variables

> **SECURITY:** Never log, share, or commit values from `.env`. It is excluded by
> `.gitignore` — keep it that way. Rotate any secret immediately if it is exposed
> in a commit, screenshot, log paste, or issue report.

All configuration is read from `.env` at startup. Copy the template and fill it in:

```bash
cp .env.example .env
```

Only **6 variables are required**. Everything else has a working default.

Settings are defined in `src/config.py:80` and consumed through
`Settings.jsm_client_kwargs()` and `Settings.ha_client_kwargs()`.

Most variables can be changed without a restart — edit `.env` and
`POST /reload` (see [RUNBOOK.md](RUNBOOK.md#reload-config-without-a-restart)).

## Required

Startup fails with a `ValidationError` listing every missing field if any of
these are absent.

| Variable | Description | Where to find it |
|----------|-------------|-----------------|
| `JSM_CLOUD_ID` | Atlassian Cloud instance ID (a UUID) | Visit `https://<your-site>.atlassian.net/_edge/tenant_info` |
| `JSM_USERNAME` | Atlassian account email used for API auth | Your Atlassian login email |
| `JSM_API_TOKEN` | Atlassian API token | <https://id.atlassian.com/manage-profile/security/api-tokens> → Create API token |
| `JSM_MY_USER_ID` | Your JSM Ops user ID, used to detect escalations aimed at you | JSM Ops → Teams → your profile; the ID appears in the URL |
| `HA_URL` | Base URL of your Home Assistant instance, no trailing slash | e.g. `https://ha.example.com` or `http://homeassistant.local:8123` |
| `HA_TOKEN` | Home Assistant long-lived access token | HA → click your profile → Security → Long-lived access tokens → Create |

> **SECURITY:** `JSM_API_TOKEN` grants API access to your Atlassian account, and
> `HA_TOKEN` grants full control of your Home Assistant instance — including
> locks, alarms, and cameras. Treat both as passwords. Create a dedicated HA user
> with only the permissions this service needs rather than using your admin
> account. The service verifies both tokens every `TOKEN_CHECK_INTERVAL_HOURS`
> and announces an alert through HA if either stops working.

## Authentication and rate limiting

> **SECURITY:** Set `WEBHOOK_API_KEY`. Without it, anyone who can reach the
> service can make your speakers say anything. There is no default key and no
> auth is enforced when it is empty.

| Variable | Required | Default | Description | Used in |
|----------|----------|---------|-------------|---------|
| `WEBHOOK_API_KEY` | Strongly recommended | *(empty — auth disabled)* | Shared secret accepted as the `X-API-Key` header, a `?key=` query parameter, or a URL path prefix | `src/security.py` |
| `WEBHOOK_SECRET` | No | *(empty)* | HMAC-SHA256 secret for `X-Hub-Signature-256` body signing | `src/security.py` |
| `RATE_LIMIT_REQUESTS` | No | `60` | Max requests per IP per window; `0` disables rate limiting | `src/security.py` |
| `RATE_LIMIT_WINDOW_SECONDS` | No | `60` | Length of the sliding rate-limit window, in seconds | `src/security.py` |

> **SECURITY:** Prefer the `X-API-Key` header. The `?key=` and path-prefix forms
> exist only because JSM webhooks can be configured with a bare URL and nothing
> else — but any secret in a URL is written to reverse-proxy access logs, browser
> history, and intermediate proxies. If you use a URL-borne key, scrub it from
> your proxy logs; the README has nginx and Caddy examples.

> **SECURITY:** `WEBHOOK_SECRET` only works if the caller can compute a
> per-request HMAC. **JSM cannot** — its outgoing-webhook custom headers are
> static strings with no template functions. Leave this empty when JSM posts
> directly to the service, or signature verification will reject every alert.

## JSM connection and routing

| Variable | Required | Default | Description | Used in |
|----------|----------|---------|-------------|---------|
| `JSM_API_URL` | No | `https://api.atlassian.com` | Atlassian API base URL | `src/jsm_client.py` |
| `CHECK_ONCALL_SCHEDULE_NAMES` | No | *(empty)* | Comma-separated schedules to check; alerts announce only when you are on-call for one | `src/alert_processor.py` |
| `ALWAYS_NOTIFY_SCHEDULE_NAMES` | No | *(empty)* | Comma-separated schedules that always announce, regardless of on-call state | `src/alert_processor.py` |
| `ONCALL_CACHE_TTL_SECONDS` | No | `300` | How long an on-call lookup is cached | `src/jsm_client.py` |
| `ALERT_DEDUP_TTL_SECONDS` | No | `60` | Window in which a repeated alert ID + action is suppressed | `src/alert_processor.py` |
| `TOKEN_CHECK_INTERVAL_HOURS` | No | `24` | How often to verify the JSM and HA tokens still work | `src/main.py` |

Schedule names must match JSM **exactly**, including case and spacing. A
mismatch logs `Schedule '<name>' not found — skipping on-call check` and that
schedule is silently ignored.

## Home Assistant output

| Variable | Required | Default | Description | Used in |
|----------|----------|---------|-------------|---------|
| `HA_MEDIA_PLAYER_ENTITY` | No | `media_player.home` | Media player entity that speaks alerts | `src/ha_client.py` |
| `HA_TTS_SERVICE` | No | `tts.home_assistant_cloud` | HA TTS service to call | `src/ha_client.py` |
| `HA_TTS_LANGUAGE` | No | `en-US` | TTS language code | `src/ha_client.py` |
| `HA_TTS_VOICE` | No | `JennyNeural` | TTS voice name | `src/ha_client.py` |
| `HA_NOTIFIER_LABEL` | No | `JSM Alert Notifier` | Title used on HA persistent notifications | `src/ha_client.py` |
| `HA_VOLUME_DEFAULT` | No | *(empty — volume untouched)* | Volume `0.0`–`1.0` for normal announcements | `src/ha_client.py` |
| `HA_VOLUME_TERSE` | No | *(empty — volume untouched)* | Volume `0.0`–`1.0` for terse-window announcements | `src/ha_client.py` |
| `HA_MEDIA_PLAYER_ROUTING` | No | *(empty)* | Time-based player routing, e.g. `22:00-07:00=media_player.bedroom` | `src/time_windows.py` |
| `ENABLE_EMOJIS` | No | `true` | Include emoji in HA notification text | `src/ha_client.py` |
| `ANNOUNCEMENT_FORMAT` | No | *(see `.env.example`)* | Template for the full spoken announcement | `src/ha_client.py` |
| `TERSE_ANNOUNCEMENT_FORMAT` | No | `{action_prefix} {priority} alert. {message}.` | Template used inside a terse window | `src/ha_client.py` |

## Quiet hours and repeat behaviour

| Variable | Required | Default | Description | Used in |
|----------|----------|---------|-------------|---------|
| `TZ` | No | *(container default, UTC)* | Timezone used to evaluate all windows below | container / `src/time_windows.py` |
| `SILENT_WINDOW` | No | *(empty)* | Window with no TTS, e.g. `23:00-06:30`; notifications still post | `src/time_windows.py` |
| `TERSE_WINDOW` | No | *(empty)* | Window using the shortened announcement format | `src/time_windows.py` |
| `SILENT_WINDOW_OVERRIDE_PRIORITIES` | No | *(empty)* | Priorities that speak anyway during a silent window, e.g. `P1` | `src/alert_processor.py` |
| `BUSINESS_HOURS_WINDOW` | No | *(empty, disabled)* | Master switch. Weekday-aware office hours, e.g. `Mon-Fri 09:00-17:00` | `src/time_windows.py` |
| `AFTER_HOURS_AUDIBLE_PRIORITIES` | No | `P1,P2` | Outside business hours, only these priorities are spoken aloud | `src/alert_processor.py` |
| `AFTER_HOURS_SILENT_TAGS` | No | *(empty)* | Optional. Tags forcing silence after hours even for an audible priority | `src/alert_processor.py` |
| `ALERT_BATCH_WINDOW_SECONDS` | No | `0` (immediate) | Collect alerts for N seconds and announce them as one summary | `src/alert_processor.py` |
| `TTS_REPEAT_INTERVAL_SECONDS` | No | `0` (disabled) | Re-announce an unacknowledged alert every N seconds | `src/alert_processor.py` |
| `TTS_REPEAT_MAX` | No | `5` | Maximum re-announcements before giving up | `src/alert_processor.py` |
| `TTS_REPEAT_PRIORITIES` | No | `P1` | Priorities eligible for repeat | `src/alert_processor.py` |

### After-hours suppression

Alerting platforms let you defer low-priority notifications outside office hours,
but those rules apply only to the platform's **own** delivery channels (mobile,
email, SMS). Outgoing webhooks are not one of them — a webhook fires the instant
the alert is created, before any notification policy applies.

The effect is that the whole team is protected by the platform rule while the
person on the webhook is not. `BUSINESS_HOURS_WINDOW` closes that gap.

Set it and, outside those hours, only `AFTER_HOURS_AUDIBLE_PRIORITIES` are spoken
aloud. Everything else still posts the persistent HA notification and still
updates the status light — only TTS is withheld, so nothing is lost.

`BUSINESS_HOURS_WINDOW` is weekday-aware, unlike `SILENT_WINDOW`. That matters: a
time-of-day silent window correctly mutes 02:00 Tuesday but leaves 14:00 Saturday
audible. Day ranges wrap the week, so `Fri-Mon` covers Fri, Sat, Sun and Mon. For
windows crossing midnight the weekday matches the day the window started.

Note that `TERSE_WINDOW` does **not** make anything quiet — it only shortens the
spoken text. A terse announcement is still played at full volume.

`AFTER_HOURS_SILENT_TAGS` is optional and empty by default. Use it when your
alerting platform already tags deferrable alerts (JSM alert policies can do this)
and you would rather honour that decision than duplicate the rule here. A listed
tag forces silence even if the priority is otherwise audible.

Suppression is applied *after* `SILENT_WINDOW_OVERRIDE_PRIORITIES`, so that
override cannot resurrect an alert suppression has muted.

See the [README section](../README.md#quiet-hours--after-hours-suppression) for
worked examples and a verification procedure.

Set `TZ` if you use any window setting. Without it the container runs in UTC and
your quiet hours will fire at the wrong local time.

Repeats are cancelled automatically when the alert is acknowledged or closed.

## HA automation webhooks

Fire HA automations on alert events — for example driving a status light.

| Variable | Required | Default | Description | Used in |
|----------|----------|---------|-------------|---------|
| `HA_WEBHOOK_ON_CREATE` | No | *(empty)* | Fired when any open, unacknowledged alert exists | `src/alert_processor.py` |
| `HA_WEBHOOK_ON_ACKNOWLEDGE` | No | *(empty)* | Fired when all open alerts are acknowledged | `src/alert_processor.py` |
| `HA_WEBHOOK_ON_CLOSE` | No | *(empty)* | Fired when no open alerts remain | `src/alert_processor.py` |
| `HA_WEBHOOK_ON_ESCALATE` | No | *(empty)* | Fired on the `EscalateNext` action | `src/alert_processor.py` |
| `HA_WEBHOOK_ON_UPDATE` | No | *(empty)* | Fired on `AddNote`, `Seen`, `AssignOwnership`, `UnAcknowledge` | `src/alert_processor.py` |
| `HA_WEBHOOK_ON_SLA_BREACH` | No | *(empty)* | Fired on the `SlaBreached` action | `src/alert_processor.py` |

The first three reflect **aggregate** state across all open incidents, not
individual events. They require `INCIDENT_DASHBOARD_ENABLED=true` — the counts
come from the incident store. A startup warning is logged if you configure them
without it. Full HA YAML examples are in the README.

Each value accepts a comma-separated list to fan out to several automations.

## Incident dashboard

| Variable | Required | Default | Description | Used in |
|----------|----------|---------|-------------|---------|
| `INCIDENT_DASHBOARD_ENABLED` | No | `false` | Enable the SQLite incident tracker and `/incidents` API | `src/main.py` |
| `INCIDENT_DB_PATH` | No | `/tmp/incidents.db` | SQLite database file path | `src/incident_store.py` |
| `INCIDENT_SYNC_INTERVAL_MINUTES` | No | `0` (webhook-only) | How often to reconcile open alerts from the JSM API | `src/main.py` |

> **State is reconciled at startup regardless of this setting.** Every state
> webhook is edge-triggered — it fires only when an alert event arrives. Anything
> that changed while the service was down was never delivered, so on boot the
> store is refreshed from JSM and the matching state webhook is re-fired. Setting
> a sync interval additionally re-checks on a schedule, which catches drift while
> the service is *up* (a webhook that never arrived, say).
| `INCIDENT_RETENTION_OPEN_DAYS` | No | `0` (never purge) | Delete open incidents older than N days | `src/incident_store.py` |
| `INCIDENT_RETENTION_CLOSED_DAYS` | No | `0` (never purge) | Delete closed incidents older than N days | `src/incident_store.py` |

> **SECURITY:** The incident database stores alert messages, descriptions, entity
> names, and responder names. If your alert text contains hostnames, internal IPs,
> or customer identifiers, treat the DB file as sensitive and restrict access to
> the volume.

The default path is on the container's tmpfs mount, so **history is wiped on
every restart**. To persist it, mount a volume and set
`INCIDENT_DB_PATH=/data/incidents.db`; `docker-compose.yml` ships a
commented-out named-volume example. Persisting matters for status lights — see
the failure mode in [RUNBOOK.md](RUNBOOK.md#known-failure-modes).

## Logging

| Variable | Required | Default | Description | Used in |
|----------|----------|---------|-------------|---------|
| `LOG_FORMAT` | No | `text` | `text` for human-readable, `json` for structured log shipping | `src/main.py` |

## Getting secret values

There is no shared vault — this is a self-hosted single-operator service. Each
credential is issued by the system it belongs to:

| Secret | Issued by | Rotation |
|--------|-----------|----------|
| `JSM_API_TOKEN` | <https://id.atlassian.com/manage-profile/security/api-tokens> | Revoke the old token after updating `.env` |
| `HA_TOKEN` | Home Assistant → profile → Security → Long-lived access tokens | Delete the old token in HA after updating `.env` |
| `WEBHOOK_API_KEY` | Generate yourself: `openssl rand -base64 24` | Update every JSM webhook URL at the same time |
| `WEBHOOK_SECRET` | Generate yourself: `openssl rand -hex 32` | Only used with a signing-capable caller |

After rotating any of these, apply without downtime:

```bash
curl -X POST -H "X-API-Key: $WEBHOOK_API_KEY" http://localhost:8080/reload
```

> **SECURITY:** Rotating `WEBHOOK_API_KEY` invalidates every JSM webhook URL that
> carries the key in the URL. Update the webhook configuration in JSM in the same
> maintenance window, or alerts will be silently rejected with a `404`.
