<!--
doc: RUNBOOK
last-refreshed: 2026-08-26
generated-by: doc-refresh skill
-->

# Runbook — JSM Home Assistant Notifier

> **You were just paged. Start here.**

This service receives alert webhooks from Jira Service Management (JSM) Operations
and speaks them aloud through Home Assistant (HA) text-to-speech (TTS).

**If this service is down, you will not hear spoken alerts.** JSM still records
alerts normally. Check the JSM Ops web UI or your phone's JSM app for anything
you may have missed while it was down.

## Is the service alive?

```bash
# 1. Liveness — returns instantly, no external calls
curl -f http://localhost:8080/health || echo "HEALTH CHECK FAILED"

# 2. Tail the last 50 log lines
docker compose logs --tail=50 jsm-ha-notifier
```

Expected healthy response from `/health`:

```json
{"status": "ok"}
```

> **SECURITY:** `/health` is the only endpoint exempt from API-key auth and rate
> limiting. Every other endpoint below needs your `WEBHOOK_API_KEY`. Pass it as
> the `X-API-Key` header, never in the URL — URLs land in proxy access logs.

Deep health check, which actually calls the JSM and HA APIs:

```bash
curl -H "X-API-Key: $WEBHOOK_API_KEY" http://localhost:8080/healthz
```

`/healthz` returns HTTP `503` if either upstream API is unreachable. It returns
`200` when both respond. Use it to tell "my service is broken" apart from
"Atlassian or HA is broken".

## Service Overview

| Property | Value |
|----------|-------|
| Port | `8080` inside the container, bound to `127.0.0.1:8080` on the host |
| Liveness endpoint | `/health` (no auth, no rate limit) |
| Deep health endpoint | `/healthz` (auth required, checks JSM + HA) |
| Status / diagnostics | `/status` (auth required) |
| Metrics | `/metrics` (auth required, Prometheus text format) |
| Log location | `docker compose logs jsm-ha-notifier` — JSON-file driver, 10 MB × 5 files |
| Restart command | `docker compose restart jsm-ha-notifier` |
| Deployed via | Docker Compose (`docker-compose.yml`) |
| Container name | `jsm-ha-notifier` |
| Runs as | Non-root user `appuser`, uid 1000, read-only root filesystem |
| Entry point | `src/main.py` — `uvicorn src.main:app`, single worker |

## Start / Stop / Restart

Run all commands from the repository directory, which is where `.env` and
`docker-compose.yml` live.

```bash
# Start (builds the image if needed)
docker compose up -d

# Stop (graceful — in-flight requests finish)
docker compose down

# Restart without rebuilding
docker compose restart jsm-ha-notifier

# Rebuild after a code change, then start
docker compose up -d --build

# Follow logs live
docker compose logs -f jsm-ha-notifier
```

> **SECURITY:** If you are restarting because you suspect a security incident —
> unexpected traffic, a leaked API key, unexplained alerts — do NOT restart in
> place. Restarting destroys in-memory state and rotates the logs you need for
> forensics. Instead: stop the container (`docker compose stop`), copy the logs
> somewhere safe (`docker compose logs > /tmp/incident-$(date +%s).log`), rotate
> `WEBHOOK_API_KEY` and any exposed upstream token, then bring it back up.

## Reload config without a restart

Most settings can be reloaded from `.env` in place. This re-reads the file and
re-applies credentials, formats, routing, and intervals.

```bash
curl -X POST -H "X-API-Key: $WEBHOOK_API_KEY" http://localhost:8080/reload
```

If the new config is invalid, the reload fails with HTTP `500` and the previous
working config stays active. The service does not go down on a bad reload.

A full restart is still required to change the listening port, worker count, or
anything in `docker-compose.yml`.

## Known Failure Modes

| Symptom | Root cause | Immediate fix |
|---------|-----------|---------------|
| Container exits immediately on start; log shows `ValidationError` and a list of fields | A required variable is missing from `.env`, or `.env` was never mounted or created | Confirm `.env` exists in the repo directory and contains all 6 required values. See [docs/ENV_VARS.md](ENV_VARS.md). |
| Log shows `Startup check: JSM API — FAILED` | `JSM_API_TOKEN` is expired or revoked, or `JSM_CLOUD_ID` is wrong | Generate a new Atlassian API token, update `.env`, then `POST /reload`. |
| Log shows `Startup check: HA API — FAILED` | `HA_TOKEN` expired, or `HA_URL` unreachable from the container | Verify `curl -H "Authorization: Bearer $HA_TOKEN" $HA_URL/api/` works from the Docker host. |
| Alerts arrive in JSM but nothing is spoken | You are not on-call for any schedule in `CHECK_ONCALL_SCHEDULE_NAMES` — this is correct behaviour | Check `/status` for the resolved on-call state. Use the `?mode=always` webhook URL for schedules that must always page you. |
| **A low-priority alert was announced in the middle of the night, and nobody else on the team was paged for it** | Your alerting platform's quiet-hours or deferral policy applies only to **its own** channels — mobile, email, SMS. Outgoing webhooks fire at alert creation and bypass notification policies entirely, so you are the only person not protected by that rule | Set `BUSINESS_HOURS_WINDOW` (e.g. `Mon-Fri 09:00-17:00`). Outside it only `AFTER_HOURS_AUDIBLE_PRIORITIES` (default `P1,P2`) speak. See [ENV_VARS.md](ENV_VARS.md#after-hours-suppression). |
| Set `TERSE_WINDOW` overnight and it still speaks aloud | `TERSE_WINDOW` only **shortens** the spoken text. It does not silence anything — a terse announcement plays at full volume | Use `SILENT_WINDOW` for clock-time silence, or `BUSINESS_HOURS_WINDOW` for weekday-aware office hours. `TERSE_WINDOW` is a verbosity control, not a mute. |
| Nothing is spoken outside office hours and you expected it to be | `BUSINESS_HOURS_WINDOW` is set and the alert's priority is not in `AFTER_HOURS_AUDIBLE_PRIORITIES` — working as configured | Check the response for `"suppressed_after_hours": true`, or grep logs for `After-hours suppression`. Widen `AFTER_HOURS_AUDIBLE_PRIORITIES` if a priority should always wake you. |
| Business hours appear shifted by several hours | `TZ` is unset, so the container runs in **UTC** and evaluates every window against UTC time | Set `TZ` (e.g. `TZ=America/New_York`) in `.env`, then recreate the container. `TZ` is read at process start — `POST /reload` will not pick it up. |
| A weekend afternoon alert is audible despite a silent window | `SILENT_WINDOW` is time-of-day only and has no concept of weekdays, so `22:00-06:00` leaves Saturday 14:00 fully audible | Use `BUSINESS_HOURS_WINDOW`, which is weekday-aware. |
| Log shows `Schedule '<name>' not found — skipping on-call check` | A name in `CHECK_ONCALL_SCHEDULE_NAMES` does not match JSM exactly | Names are case- and whitespace-sensitive. Copy the exact name from the JSM Ops schedule list. |
| Log shows `Request rejected — invalid or missing API key`, caller gets `404` | Caller sent the wrong `WEBHOOK_API_KEY`, or none | The `404` is deliberate — it hides endpoint existence from scanners. Fix the key on the caller. |
| Caller gets HTTP `429` | Per-IP rate limit exceeded (default 60 requests / 60 s) | Expected under burst or abuse. Raise `RATE_LIMIT_REQUESTS` if legitimate traffic is being throttled. |
| Log shows `Webhook signature verification failed` | `WEBHOOK_SECRET` is set but the caller is not signing requests | JSM **cannot** sign webhooks — its custom headers are static strings. If JSM posts directly here, clear `WEBHOOK_SECRET` and rely on `WEBHOOK_API_KEY`. |
| Log shows `Cannot open incident database` | `INCIDENT_DB_PATH` points at a non-writable path under the read-only root filesystem | Use a path under `/tmp`, or mount a volume and point `INCIDENT_DB_PATH` at it. |
| Incident history empty after every restart | Default `INCIDENT_DB_PATH=/tmp/incidents.db` is on tmpfs, which is wiped on restart | Mount a volume and set `INCIDENT_DB_PATH=/data/incidents.db`. See the commented example in `docker-compose.yml`. |
| Status light shows the wrong colour with several alerts open | State webhooks need the incident store to count open alerts | Set `INCIDENT_DASHBOARD_ENABLED=true`. A startup warning is logged when state webhooks are configured without it. |
| Status light was wrong after the service was down | State webhooks are edge-triggered; an ack or close that happened while the container was stopped was never delivered | Fixed automatically — the service reconciles at startup. To force it now: `curl -X POST -H "X-API-Key: $WEBHOOK_API_KEY" http://localhost:8080/incidents/sync`, which returns `state_webhook_fired`. |
| Status light goes green while an alert is still open | Service restarted and the incident DB was on tmpfs, so counts came back empty | Persist the DB on a volume as above. |
| Escalated alert produced no announcement | The escalation action has two spellings (`EscalateToNext` / `EscalateNext`); before this fix only one was matched and escalations were dropped as an unknown action | Fixed — both are accepted. Confirm JSM forwards **Alert is escalated to next responder**, then check the log for `action=EscalateNext`. |
| Log shows `Failed to fire HA webhook` | HA is unreachable, or the webhook ID does not exist in HA | Confirm the automation exists in HA with a matching `webhook_id`. |
| Alerts announced twice | Both the on-call and always-notify webhook URLs are configured for the same JSM schedule | Each JSM schedule should post to exactly one of the two URLs. |
| TTS repeats forever | `TTS_REPEAT_MAX` set high with a short `TTS_REPEAT_INTERVAL_SECONDS` | Acknowledge or close the alert to cancel repeats, or `POST /reload` after lowering the values. |

## Diagnostics

```bash
# Resolved config, on-call state, uptime, queue depths
curl -H "X-API-Key: $WEBHOOK_API_KEY" http://localhost:8080/status

# Counters: alerts received, notified, suppressed, rate-limited
curl -H "X-API-Key: $WEBHOOK_API_KEY" http://localhost:8080/metrics

# Currently open incidents (requires INCIDENT_DASHBOARD_ENABLED=true)
curl -H "X-API-Key: $WEBHOOK_API_KEY" http://localhost:8080/incidents?status=open

# Force a fresh on-call lookup, bypassing the cache
curl -X POST -H "X-API-Key: $WEBHOOK_API_KEY" http://localhost:8080/cache/invalidate
```

On-call state is cached for `ONCALL_CACHE_TTL_SECONDS` (default 300). If you just
changed the JSM rotation and the service has not noticed, invalidate the cache
rather than restarting.

## Verify end to end

Send a synthetic alert and confirm it is spoken. This uses the always-notify
path so it works whether or not you are currently on-call.

> **Use `P1`.** If you are reading this at 2am and `BUSINESS_HOURS_WINDOW` is
> set, a `P3` test is **deliberately silenced** and you will hear nothing — which
> looks exactly like a broken service. `P1` is audible around the clock under the
> default `AFTER_HOURS_AUDIBLE_PRIORITIES=P1,P2`.

```bash
curl -X POST "http://localhost:8080/alert?mode=always" \
  -H "X-API-Key: $WEBHOOK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "Create",
    "alert": {
      "alertId": "runbook-test-001",
      "message": "Runbook verification test",
      "priority": "P1",
      "entity": "runbook"
    }
  }'
```

You should hear the announcement on the media player named by
`HA_MEDIA_PLAYER_ENTITY`.

The JSON response tells you what the service decided, which is faster than
guessing from silence:

| Field | Meaning |
|-------|---------|
| `"notified": true` | The routing logic chose to alert you |
| `"announcement_mode": "full"` | Spoken with the full announcement format |
| `"announcement_mode": "terse"` | Spoken, but shortened — **still audible** |
| `"announcement_mode": "silent"` | No TTS. Persistent notification only |
| `"suppressed_after_hours": true` | Silenced by `BUSINESS_HOURS_WINDOW` — not a fault |
| `"reason": "not on-call for any watched schedule"` | Correct behaviour, not a fault |

Then close it so it does not linger in the dashboard:

```bash
curl -X POST -H "X-API-Key: $WEBHOOK_API_KEY" \
  http://localhost:8080/incidents/runbook-test-001/close
```

## Rollback

```bash
# What changed recently
git log --oneline -10

# Revert the last commit — safe, creates a new commit
git revert HEAD

# Rebuild and restart on the reverted code
docker compose up -d --build
```

To roll back to a published image instead of building, pin the **previous**
release tag in `docker-compose.yml` and pull it:

```bash
# In docker-compose.yml, comment out `build: .` and set:
#   image: ghcr.io/realdougeubanks/jsm-ha-notifier:v3.1.0   <-- previous release
docker compose pull && docker compose up -d
```

> This example deliberately names the release **before** the current one. Current
> is `3.2.0`, so rolling back means `3.1.0`. Do not "correct" this to match the
> current version — that would pin you to the release you are trying to escape.

Published tags are listed at
<https://github.com/RealDougEubanks/JSM-HomeAssistant-Notifier/pkgs/container/jsm-ha-notifier>.

## Escalation Path

This is a single-maintainer personal project. There is no on-call rotation
behind it.

1. Check [open issues](https://github.com/RealDougEubanks/JSM-HomeAssistant-Notifier/issues)
   for a matching report.
2. If unresolved after 15 minutes and alerts are being missed, fall back to the
   JSM Ops mobile app for notifications and open an issue with logs attached.
3. For a suspected vulnerability, follow [SECURITY.md](../SECURITY.md) — do not
   open a public issue.

> **SECURITY:** Redact `JSM_API_TOKEN`, `HA_TOKEN`, `WEBHOOK_API_KEY`, and
> `WEBHOOK_SECRET` from any log output before attaching it to an issue.
