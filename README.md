# JSM Home Assistant Notifier

A lightweight Docker service that bridges **Jira Service Management (JSM / OpsGenie)** alerts to **Home Assistant** — with smart on-call routing, escalation detection, rich TTS announcements, and persistent dashboard notifications.

---

## How It Works

```
JSM alert created / escalated
         │
         ▼
  jsm-ha-notifier (Docker)
         │
         ├─ Parse alert payload
         ├─ Deduplicate (suppress retries within 60 s)
         ├─ Route decision:
         │    always_notify mode?   → NOTIFY
         │    escalated to me?      → NOTIFY
         │    I'm on-call?          → NOTIFY   (JSM API, cached 5 min)
         │    none of the above     → DROP
         │
         ▼
  Home Assistant REST API
    ├─ media_player.play_media  (TTS with rich metadata / real alert title)
    └─ persistent_notification  (visible in HA dashboard)

  On Acknowledge / Close → dismiss the persistent notification automatically
```

**Two webhook URLs, one for each routing mode:**

| JSM Webhook URL | Behaviour |
|---|---|
| `https://your-host:8080/alert?key=YOUR_KEY` | Notify only when on-call |
| `https://your-host:8080/alert?mode=always&key=YOUR_KEY` | Always notify regardless of schedule |

---

## Features

- **On-call aware** — queries JSM in real time and caches results; only wakes you when you are actually on-call
- **Escalation detection** — `EscalateNext` events always notify regardless of on-call status or dedup window
- **Always-notify mode** — a separate webhook path for schedules that should always page you (e.g. infrastructure monitors)
- **Rich TTS** — spoken announcements include priority, alert title, system name, and a description excerpt
- **Real media player title** — uses `extra.metadata` so HA shows the actual alert title instead of "Playing Default Media Receiver"
- **Persistent HA notifications** — created on alert, auto-dismissed on Acknowledge or Close
- **Configurable announcement formats** — customise the detailed and terse TTS templates with placeholders
- **Time-based quiet hours** — silent windows (no TTS) and terse windows (short format), with cross-midnight support
- **Priority override for silent mode** — P1/P2 alerts can bypass silent windows so critical incidents always wake you
- **Per-media-player routing** — route TTS to different speakers by time of day (e.g. bedroom at night, office during the day)
- **Volume control** — set media player volume before TTS playback, with separate levels for full and terse modes
- **Alert batching** — combine multiple alerts arriving within a configurable window into one TTS announcement
- **TTS repeat (pager mode)** — repeat TTS at intervals for critical alerts until acknowledged or max repeats hit
- **Acknowledge from HA** — `POST /alert/{id}/acknowledge` endpoint lets HA automations ack alerts without opening JSM
- **Token health check** — daily background job verifies the Atlassian API token; fires a HA TTS warning if it has expired
- **Deep health check** — `GET /healthz` verifies both JSM and HA API connectivity (returns 503 if either fails)
- **Startup connectivity checks** — verifies JSM and HA reachability at boot, logs warnings if unreachable
- **Emoji toggle** — `ENABLE_EMOJIS=false` strips all emojis from notifications, metadata, and incoming alert text
- **Generic webhook support** — any system that sends HTTP POST (Grafana, Uptime Kuma, shell scripts, HA automations) can trigger HA alerts
- **API key authentication** — optional `?key=` query parameter for webhook URL authorization
- **Webhook signature verification** — optional HMAC-SHA256 validation via `X-Hub-Signature-256`
- **Request body size limit** — rejects payloads over 1 MB to prevent memory exhaustion
- **Safe format templates** — user-configurable announcement formats use a restricted formatter that blocks attribute/index access
- **Secure container** — non-root user, read-only filesystem, tmpfs at `/tmp`

---

## Prerequisites

- Docker + Docker Compose
- A server or device accessible from the internet (or from JSM's webhook delivery IPs)
- Home Assistant with a Long-Lived Access Token and a TTS service configured
- An Atlassian API token with access to JSM Ops (OpsGenie) schedules

---

## Quick Start

```bash
git clone https://github.com/RealDougEubanks/JSM-HomeAssistant-Notifier.git
cd JSM-HomeAssistant-Notifier

cp .env.example .env
# Edit .env and fill in all required values (see Configuration below)

docker compose up -d
docker compose logs -f
```

Verify the service is running:

```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

---

## Configuration

### Step 1 — Copy and edit `.env`

```bash
cp .env.example .env
```

Open `.env` and fill in each value.  The file is fully commented with instructions for finding each value.  The sections below expand on the key ones.

### Step 2 — Find your Atlassian Cloud ID

Your Cloud ID is a UUID that identifies your Atlassian organisation.  Retrieve it with:

```bash
curl -s -u "you@yourcompany.com:YOUR_API_TOKEN" \
  https://api.atlassian.com/oauth/token/accessible-resources \
  | python3 -m json.tool
```

Look for the `"id"` field next to your org name.  Copy it into `JSM_CLOUD_ID`.

### Step 3 — Find your Atlassian Account ID

Your account ID (`JSM_MY_USER_ID`) is the UUID Atlassian uses internally for your user.  The easiest way to find it:

```bash
curl -s -u "you@yourcompany.com:YOUR_API_TOKEN" \
  "https://api.atlassian.com/jsm/ops/api/YOUR_CLOUD_ID/v1/schedules/YOUR_SCHEDULE_ID/on-calls" \
  | python3 -m json.tool
```

Find your name in the `onCallParticipants` array; the `"id"` field is your account ID.

### Step 4 — Find your exact schedule names

Schedule names are case-sensitive.  List all schedules visible to your token:

```bash
curl -s -u "you@yourcompany.com:YOUR_API_TOKEN" \
  "https://api.atlassian.com/jsm/ops/api/YOUR_CLOUD_ID/v1/schedules" \
  | python3 -m json.tool | grep '"name"'
```

Copy the exact names into `ALWAYS_NOTIFY_SCHEDULE_NAMES` and/or `CHECK_ONCALL_SCHEDULE_NAMES` in `.env`.

### Step 5 — Create a Home Assistant Long-Lived Access Token

1. In Home Assistant, click your profile picture (bottom-left)
2. Scroll to **Security** → **Long-Lived Access Tokens**
3. Click **Create token**, give it a descriptive name (e.g. `JSM Notifier`)
4. Copy the token into `HA_TOKEN` in `.env` — it is only shown once

### Step 6 — Find your media player entity ID

In Home Assistant go to **Developer Tools → States**, filter by `media_player`.  Copy the `entity_id` (e.g. `media_player.living_room`) into `HA_MEDIA_PLAYER_ENTITY`.

### Step 7 — Verify everything works

Once the container is running, check on-call status directly:

```bash
curl http://localhost:8080/status | python3 -m json.tool
```

You should see your schedules listed and an `on_call` field.  If a schedule shows `"error": "not found"`, the name in `.env` doesn't match — compare carefully against the output of the schedule listing curl above.

---

## Making the Service Externally Accessible

JSM's servers need to reach your webhook URL over the internet.

### Option 1 — Port-forward on your router

Forward external TCP port 8080 (or 443 via a reverse proxy) to your server's LAN IP.

### Option 2 — Cloudflare Tunnel (recommended — no open ports)

```bash
# Using the cloudflared Docker image
docker run -d --name cloudflared \
  cloudflare/cloudflared:latest tunnel \
  --url http://host.docker.internal:8080
```

Or install `cloudflared` on the host and run:

```bash
cloudflared tunnel --url http://localhost:8080
```

Cloudflare will print a `trycloudflare.com` URL you can use immediately, or you can configure a permanent named tunnel with your own domain.

### Option 3 — Reverse proxy (NGINX / Traefik / Caddy)

Add a location block pointing to `http://localhost:8080`.  Use TLS termination at the proxy.

---

## JSM Webhook Configuration

Configure **two** outgoing webhooks in JSM Ops — one for on-call schedules and one for always-notify schedules.

### Go to JSM Ops Settings

JSM project → **Settings** → **Integrations** → **Add Integration** → choose **Webhook** (under "Outgoing").

### Webhook for On-Call Schedule(s)

| Field | Value |
|---|---|
| **Name** | `HA Notifier — On-Call` |
| **Webhook URL** | `https://your-host/alert?key=YOUR_API_KEY` |
| **Method** | POST |
| **Send alert payload** | ✅ Enabled |
| **Alert actions** | Create, EscalateNext, Acknowledge, Close |
| **Teams / Schedules filter** | Your on-call schedule's team |

### Webhook for Always-Notify Schedule(s)

| Field | Value |
|---|---|
| **Name** | `HA Notifier — Always Notify` |
| **Webhook URL** | `https://your-host/alert?mode=always&key=YOUR_API_KEY` |
| **Method** | POST |
| **Send alert payload** | ✅ Enabled |
| **Alert actions** | Create, EscalateNext, Acknowledge, Close |
| **Teams / Schedules filter** | Your always-notify team/schedule |

### Optional — API Key Authentication (recommended)

The simplest way to secure your webhook endpoints.  Set `WEBHOOK_API_KEY` in `.env` and include the key in your JSM webhook URLs:

```
https://your-host/alert?key=YOUR_API_KEY
https://your-host/alert?mode=always&key=YOUR_API_KEY
```

Generate a key: `openssl rand -hex 32`

Requests without a valid `?key=` parameter receive a 401 Unauthorized.

### Optional — HMAC Webhook Signature

For additional security (or as an alternative to API keys), set `WEBHOOK_SECRET` in `.env` and add a custom header to each JSM webhook:

| Header name | Value |
|---|---|
| `X-Hub-Signature-256` | `sha256={{ hmac_sha256(body, "YOUR_SECRET") }}` |

You can use **both** `WEBHOOK_API_KEY` and `WEBHOOK_SECRET` together for defense in depth.

> Check the Atlassian JSM documentation for the exact Jinja/template syntax supported in your version's outgoing webhook headers.

---

## Testing With curl

### Send a test alert (on-call path)

```bash
curl -X POST http://localhost:8080/alert \
  -H "Content-Type: application/json" \
  -d '{
    "action": "Create",
    "alert": {
      "alertId": "test-001",
      "message": "Test Alert — please ignore",
      "priority": "P3",
      "entity": "dev-server",
      "description": "This is a test alert sent manually."
    }
  }'
```

If you are currently on-call, this will trigger a TTS announcement and create a persistent notification in HA.

### Send a test alert (always-notify path)

```bash
curl -X POST "http://localhost:8080/alert?mode=always" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "Create",
    "alert": {
      "alertId": "always-test-001",
      "message": "Infrastructure Monitor Test",
      "priority": "P2",
      "entity": "prod-server-01"
    }
  }'
```

This path always notifies regardless of on-call status.

### Send a test escalation

```bash
curl -X POST "http://localhost:8080/alert?mode=always" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "EscalateNext",
    "alert": {
      "alertId": "test-001",
      "message": "Test Alert — please ignore",
      "priority": "P1",
      "entity": "prod-db-01"
    }
  }'
```

### Check on-call status

```bash
curl http://localhost:8080/status | python3 -m json.tool
```

### Invalidate on-call cache

```bash
curl -X POST http://localhost:8080/cache/invalidate
```

### Test with webhook signature

If `WEBHOOK_SECRET` is set, generate the signature before sending:

```bash
SECRET="your-webhook-secret"
BODY='{"action":"Create","alert":{"alertId":"sig-test","message":"Signed test","priority":"P3"}}'
SIG="sha256=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')"

curl -X POST http://localhost:8080/alert \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: $SIG" \
  -d "$BODY"
```

---

## Using With Other Webhook Sources

The `/alert` endpoint accepts any JSON payload matching the OpsGenie webhook format.  You don't need JSM — any monitoring system, script, or automation that can send HTTP POST requests can trigger HA alerts.

### Required Payload Format

```json
{
  "action": "Create",
  "alert": {
    "alertId": "unique-id-123",
    "message": "Your alert title here",
    "priority": "P1",
    "entity": "optional-system-name",
    "description": "Optional longer description text"
  }
}
```

| Field | Required | Description |
|---|---|---|
| `action` | Yes | `Create`, `EscalateNext`, `Acknowledge`, or `Close` |
| `alert.alertId` | Yes | Unique identifier (used for dedup and notification tracking) |
| `alert.message` | Yes | Alert title / summary (spoken by TTS) |
| `alert.priority` | No | `P1`–`P5` (default: `P3`) |
| `alert.entity` | No | System / host name |
| `alert.description` | No | Longer details (first 200 chars used in TTS) |

### Example: Uptime Kuma

Configure a webhook notification in Uptime Kuma with the Notification Type set to "Webhook" / custom JSON:

```bash
# Uptime Kuma → Settings → Notifications → Add → Webhook
# URL: http://your-notifier:8080/alert?mode=always&key=YOUR_KEY
# Method: POST
# Body:
{
  "action": "Create",
  "alert": {
    "alertId": "uptime-kuma-{{ monitorJSON.id }}",
    "message": "{{ monitorJSON.name }} is {{ heartbeatJSON.status == 1 ? 'UP' : 'DOWN' }}",
    "priority": "P2",
    "entity": "{{ monitorJSON.hostname }}"
  }
}
```

### Example: Grafana Alerting

Use a Grafana "webhook" contact point with the OpsGenie payload format:

```bash
# Grafana → Alerting → Contact Points → New → Webhook
# URL: http://your-notifier:8080/alert?mode=always&key=YOUR_KEY
# Method: POST
#
# Or use curl to forward Grafana alerts via a script:
curl -X POST "http://your-notifier:8080/alert?mode=always&key=YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "Create",
    "alert": {
      "alertId": "grafana-cpu-alert-prod01",
      "message": "CPU usage above 95% on prod-01",
      "priority": "P1",
      "entity": "prod-01",
      "description": "CPU has been above 95% for the last 5 minutes. Current: 98.2%."
    }
  }'
```

### Example: Prometheus Alertmanager

Use Alertmanager's webhook receiver to POST to the notifier:

```yaml
# alertmanager.yml
receivers:
  - name: ha-notifier
    webhook_configs:
      - url: "http://your-notifier:8080/alert?mode=always&key=YOUR_KEY"
        send_resolved: true
```

Then use a small relay script or Alertmanager template to transform alerts into the expected format.

### Example: Home Assistant Automation

Trigger an alert from HA itself (e.g. a sensor threshold):

```yaml
# HA automation action
service: rest_command.trigger_notifier_alert
data:
  alert_id: "ha-temp-alert-{{ now().isoformat() }}"
  message: "Temperature sensor above threshold"
  priority: "P2"
  entity: "sensor.living_room_temperature"
  description: "Current temperature: {{ states('sensor.living_room_temperature') }}°C"
```

```yaml
# configuration.yaml
rest_command:
  trigger_notifier_alert:
    url: "http://your-notifier:8080/alert?mode=always&key=YOUR_KEY"
    method: POST
    content_type: "application/json"
    payload: >
      {"action":"Create","alert":{"alertId":"{{ alert_id }}","message":"{{ message }}","priority":"{{ priority }}","entity":"{{ entity }}","description":"{{ description }}"}}
```

### Example: Simple Shell Script

Trigger an alert from any script or cron job:

```bash
#!/bin/bash
# notify-ha.sh — send an alert to the JSM-HA Notifier
NOTIFIER_URL="http://your-notifier:8080/alert?mode=always&key=YOUR_KEY"

curl -s -X POST "$NOTIFIER_URL" \
  -H "Content-Type: application/json" \
  -d "{
    \"action\": \"Create\",
    \"alert\": {
      \"alertId\": \"script-$(date +%s)\",
      \"message\": \"$1\",
      \"priority\": \"${2:-P3}\",
      \"entity\": \"$(hostname)\"
    }
  }"
```

Usage: `./notify-ha.sh "Backup failed on NAS" P2`

### Closing / Acknowledging Alerts

To dismiss the persistent HA notification and stop TTS repeats, send a `Close` or `Acknowledge` action with the same `alertId`:

```bash
curl -X POST "http://your-notifier:8080/alert?mode=always&key=YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"action": "Close", "alert": {"alertId": "the-original-alert-id", "message": "resolved"}}'
```

Or use the dedicated acknowledge endpoint:

```bash
curl -X POST "http://your-notifier:8080/alert/the-original-alert-id/acknowledge?key=YOUR_KEY"
```

---

## Running on unRAID (or any Docker host)

### Option A — Docker Compose (recommended)

```bash
# Build locally (until you push to GHCR)
docker compose up -d --build

# Or pull the pre-built image after the first CI release
docker compose pull
docker compose up -d

# Watch logs
docker compose logs -f jsm-ha-notifier
```

### Option B — `docker run`

```bash
docker run -d \
  --name jsm-ha-notifier \
  --restart unless-stopped \
  -p 8080:8080 \
  --env-file /path/to/.env \
  --read-only \
  --tmpfs /tmp \
  ghcr.io/realdougeubanks/jsm-ha-notifier:latest
```

---

## CI/CD — GitHub Actions & GHCR

The repository includes two workflows.

### CI (`.github/workflows/ci.yml`)

Triggers on every push to `main` or `develop` and on pull requests.  Runs:
- `ruff` (lint)
- `black` (format check)
- `mypy` (type check, advisory)
- `pytest` with coverage

### Release (`.github/workflows/release.yml`)

Triggers on push to `main` or any version tag (`v*`).  Builds a multi-arch Docker image (linux/amd64 + linux/arm64) and pushes it to GitHub Container Registry (GHCR).

**No personal access tokens or manual secrets are needed** — the workflow uses the built-in `GITHUB_TOKEN` that GitHub provides automatically to every Actions run, which already has `packages: write` permission as configured in the workflow.

#### Image tags produced

| Git event | Image tags |
|---|---|
| Push to `main` | `latest`, `main`, `<short-sha>` |
| Push tag `v1.2.3` | `v1.2.3`, `<short-sha>` |

#### First-time GHCR setup

After the first successful release workflow run, your container image is private by default.  To make it public so others (and your unRAID server) can pull it without authentication:

1. Go to `https://github.com/RealDougEubanks?tab=packages`
2. Click the `jsm-ha-notifier` package
3. Click **Package settings** (right side)
4. Under **Danger Zone**, click **Change visibility** → **Public**

Alternatively, link the package to your repository:

1. On the package page, click **Connect repository** and select your repo
2. The package inherits the repository's visibility

Once public, `docker pull ghcr.io/realdougeubanks/jsm-ha-notifier:latest` works without login from any machine.

#### Updating `docker-compose.yml` to use the GHCR image

After the image has been published, edit `docker-compose.yml`:

```yaml
services:
  jsm-ha-notifier:
    image: ghcr.io/realdougeubanks/jsm-ha-notifier:latest
    # build: .   ← comment out or remove this line
```

---

## API Reference

### `POST /alert`

Receives JSM webhook payloads.

| Query param | Values | Behaviour |
|---|---|---|
| `mode` | `always` | Skip on-call check; always notify |
| *(absent)* | — | Check on-call status before notifying |

Expected payload: standard OpsGenie / JSM Ops outgoing webhook JSON.

### `POST /alert/{alert_id}/acknowledge`

Acknowledges a JSM alert, dismisses the HA notification, and cancels TTS repeats.  Intended for use from HA automations (see `.env.example` for a ready-to-use `rest_command` snippet).

Returns `{"alert_id": "...", "acknowledged": true}` on success, 502 if JSM rejects the request.

### `GET /health`

Returns `{"status": "ok"}`.  Used by Docker health-check and external monitors.

### `GET /healthz`

Deep health check — verifies JSM API credentials and HA API connectivity.  Returns 200 with `{"healthy": true, ...}` if both pass, or 503 if either fails.  Use this for readiness probes or monitoring dashboards.

### `GET /status`

Returns current on-call status for all watched schedules (forces a fresh JSM API lookup, bypasses cache).

```json
{
  "user_id": "your-account-id",
  "on_call_schedules": {
    "Your On-Call Schedule": {
      "schedule_id": "abc-123",
      "on_call": true
    }
  },
  "always_notify_schedules": ["Your Always-Notify Schedule"]
}
```

### `POST /cache/invalidate`

Clears the cached on-call status so the next alert forces a fresh JSM API check.  Useful immediately after a rotation hand-off.

---

## Notification Details

### TTS Announcement

The spoken message includes:
- Escalation prefix ("Escalated alert!") when applicable
- Priority level in plain English ("Priority 1, Critical")
- Alert message / title
- System / entity name
- Truncated description (first 200 characters)

Example: *"Attention! Priority 1, Critical alert from Jira Service Management. Alert: Database connection lost. System: prod-db-01. Details: All connections exhausted..."*

### Media Player Display

Instead of "Playing Default Media Receiver", the HA media player will show:

```
🔴 P1: Database connection lost
Your Notifier Label
prod-db-01
```

This is set via the `extra.metadata` block in the `media_player.play_media` service call.  The label shown as the artist is configurable via `HA_NOTIFIER_LABEL` in `.env`.

### Persistent Notification

A persistent notification is created in the HA dashboard with the full alert details.  It is automatically dismissed when JSM sends an Acknowledge or Close action for that alert.

---

## Local Development

```bash
# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install all dependencies
pip install -r requirements-dev.txt

# Copy and edit config
cp .env.example .env
# Fill in .env before running tests or the server

# Run tests
pytest tests/ -v

# Run the service locally
uvicorn src.main:app --reload --port 8080
```

---

## Troubleshooting

### "Schedule not found" error

The service logs all available schedule names when a lookup fails:

```bash
docker compose logs jsm-ha-notifier | grep "Available schedules"
```

Copy the exact name (case-sensitive) from the output into `.env` and restart.

### No audio / TTS not playing

1. Verify the HA token is valid:
   ```bash
   curl -H "Authorization: Bearer YOUR_HA_TOKEN" https://your-ha-url/api/
   ```
2. Verify the media player entity ID:
   ```bash
   curl -H "Authorization: Bearer YOUR_HA_TOKEN" \
     https://your-ha-url/api/states \
     | python3 -m json.tool | grep media_player
   ```
3. Check service logs: `docker compose logs -f jsm-ha-notifier`

### HA shows "Playing Default Media Receiver"

Your HA media player integration may not support the `extra.metadata` block.  This is normal for some Google Cast / Chromecast firmware versions.  The TTS audio itself will still play correctly — only the display label is affected.

### On-call check returns true when I'm not on-call

The on-call cache may be stale.  Force a refresh:

```bash
curl -X POST http://localhost:8080/cache/invalidate
```

### Invalid webhook signature

Confirm that the `WEBHOOK_SECRET` in `.env` matches the secret configured in JSM exactly.  Remember: the HMAC is computed over the **raw request body**, not the parsed JSON.

### JSM is not calling the webhook

- Confirm the URL is reachable from the internet: `curl https://your-host/health`
- Check JSM webhook delivery logs: JSM → Settings → Integrations → your webhook → Logs

### Token expiry notification in HA dashboard

The service checks token validity every `TOKEN_CHECK_INTERVAL_HOURS` hours (default: 24).  If your token has expired:

1. Create a new token at <https://id.atlassian.com/manage-profile/security/api-tokens>
2. Update `JSM_API_TOKEN` in `.env`
3. Restart the container: `docker compose restart`

The persistent HA notification will be dismissed automatically on the next successful token check (within 30 seconds of startup).

---

## Security Checklist

- [ ] Atlassian API token created with minimum necessary permissions (JSM Ops schedule access)
- [ ] `.env` is in `.gitignore` and was never committed
- [ ] `WEBHOOK_API_KEY` is set (`openssl rand -hex 32`) — or — `WEBHOOK_SECRET` is set (or both)
- [ ] Service runs as non-root user (handled in Dockerfile)
- [ ] Container filesystem is read-only (`read_only: true` in compose)
- [ ] Port 8080 is behind a TLS-terminating reverse proxy or Cloudflare Tunnel before reaching the internet
- [ ] HA long-lived token was created specifically for this service (not shared with other integrations)

---

## Project Structure

```
jsm-ha-notifier/
├── .github/
│   └── workflows/
│       ├── ci.yml          # Lint, test, coverage
│       └── release.yml     # Build & push multi-arch Docker image to GHCR
├── src/
│   ├── __init__.py
│   ├── main.py             # FastAPI app, routes, signature verification
│   ├── config.py           # Pydantic settings (all from .env)
│   ├── models.py           # JSM webhook payload models
│   ├── jsm_client.py       # Async JSM Ops API client with caching
│   ├── ha_client.py        # Async Home Assistant REST API client
│   ├── alert_processor.py  # Core routing / dedup / notification logic
│   └── time_windows.py     # Time-window parsing and media player routing
├── tests/
│   ├── conftest.py         # Shared fixtures
│   ├── test_models.py
│   ├── test_config.py
│   ├── test_ha_client.py
│   ├── test_alert_processor.py
│   ├── test_announcement_format.py  # Format, time windows, priority override, repeat
│   └── test_time_windows.py         # Window parsing, player routing
├── .env.example            # Template — copy to .env and fill in values
├── .gitignore
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml          # black, ruff, pytest, mypy config
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

---

## AI Disclosure

This project was designed and built by [Doug Eubanks](https://github.com/RealDougEubanks) to solve a real on-call alerting problem.  The architecture, requirements, testing, and deployment decisions were driven by him throughout.

Claude (Anthropic's AI assistant) was used as a collaborative engineering tool during development — writing and iterating on code, debugging issues, and helping document the project.  All code was reviewed, tested in a live environment, and validated by the author before use.

This disclosure is provided in the spirit of transparency.  The use of AI assistance does not diminish the engineering decisions, debugging work, or operational responsibility that went into this project.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
