<!--
doc: SECURITY
last-refreshed: 2026-08-26
generated-by: doc-refresh skill
-->

# Security Policy

## Reporting a Vulnerability

> **SECURITY: Do NOT open a public GitHub issue for security vulnerabilities.**

Report privately through GitHub Security Advisories:

<https://github.com/RealDougEubanks/JSM-HomeAssistant-Notifier/security/advisories/new>

Expected acknowledgment: within 48 hours. This is a single-maintainer personal
project, so please allow reasonable time for a fix before public disclosure.

Please include:

1. What the vulnerability allows an attacker to do.
2. Steps to reproduce it.
3. The version or commit you tested.
4. Any suggested fix.

> **SECURITY:** Redact all credentials from reproduction steps and logs before
> attaching them. Never paste a real `JSM_API_TOKEN`, `HA_TOKEN`,
> `WEBHOOK_API_KEY`, or `WEBHOOK_SECRET` into an advisory.

## Sensitive Data This Project Handles

| Data | Where it lives | Exposure risk if leaked |
|------|---------------|------------------------|
| `JSM_API_TOKEN` | `.env`, in-memory | Full API access to your Atlassian account |
| `HA_TOKEN` | `.env`, in-memory | Full control of Home Assistant — including locks, alarms, cameras |
| `WEBHOOK_API_KEY` | `.env`, in-memory, possibly proxy access logs | Anyone can post arbitrary alerts and make your speakers say anything |
| `WEBHOOK_SECRET` | `.env`, in-memory | Ability to forge signed webhook requests |
| Alert content | Incident SQLite DB, logs, HA notifications | Alert messages, descriptions, entity names, responder names, tags — may contain hostnames, internal IPs, or customer identifiers |

> **SECURITY:** `HA_TOKEN` is the highest-impact secret here. A Home Assistant
> long-lived access token typically grants control over every device in the home,
> not just media players. Create a dedicated HA user scoped to what this service
> needs rather than using your admin account.

## Credential and Secret Rules

> **SECURITY:** All secrets belong in `.env` or your host's secret store. Never
> commit them. Rotate immediately if exposed.

- `.env` and `*.env` are excluded by `.gitignore`. `.env.example` is the only
  env file that is committed, and it contains no real values.
- `docker-compose.override.yml` is also gitignored — it is for machine-local
  settings and often contains host paths.
- Rotation procedures for every secret are in
  [docs/ENV_VARS.md](docs/ENV_VARS.md#getting-secret-values).
- After rotating, apply without downtime via `POST /reload`.

### If a secret is exposed

1. Revoke it at the source immediately — Atlassian token page, or HA's
   long-lived token list. Revoking beats rotating; a rotated-but-live old token
   is still valid.
2. Generate a replacement and update `.env`.
3. `POST /reload` to apply.
4. If `WEBHOOK_API_KEY` was carried in a URL, also update every JSM webhook URL,
   then scrub the key from reverse-proxy access logs.
5. Review logs for use of the exposed credential before it was revoked.

## Deployment Security Requirements

> **SECURITY:** This service has no TLS and no authentication by default. Do not
> expose it directly to the internet.

| Requirement | Why |
|------------|-----|
| Set `WEBHOOK_API_KEY` | Without it every endpoint is unauthenticated and anyone who can reach the service can drive your speakers |
| Terminate TLS at a reverse proxy or tunnel | Plain HTTP transmits your API key, webhook payloads, and alert content in cleartext |
| Keep the default `127.0.0.1:8080` port binding | Changing it to `0.0.0.0` exposes the service to your whole network |
| Prefer the `X-API-Key` header over `?key=` | URL-borne secrets are written to proxy logs, browser history, and intermediate caches |

The default `docker-compose.yml` binds to `127.0.0.1` deliberately. Front the
service with nginx, Caddy, or a Cloudflare Tunnel for external access.

## Known Security Controls

These are implemented and covered by tests.

| Control | Implementation |
|---------|---------------|
| API key authentication | `src/security.py` — constant-time comparison via `secrets.compare_digest`, accepted as header, query parameter, or path prefix |
| Stealth 404 on auth failure | Rejected requests return `404`, not `401`, so scanners cannot confirm an endpoint exists |
| Pre-auth rate limiting | `RateLimitMiddleware` in `src/security.py` throttles every request *before* key verification, so brute-forcing is limited; `/health` is exempt for the Docker healthcheck |
| Rate-limit memory bounds | Tracked IPs capped at 10,000 with idle-first eviction, preventing memory exhaustion from spoofed source addresses |
| HMAC-SHA256 signature verification | `verify_signature()` in `src/security.py`, constant-time compare, optional via `WEBHOOK_SECRET` |
| Request body size cap | 1 MB limit in `src/routes/webhook.py`, enforced on both `Content-Length` and actual body size |
| Alert ID validation | `ALERT_ID_RE` in `src/security.py` restricts IDs to `[a-zA-Z0-9\-_]{1,200}` |
| TTS input sanitization | Shell metacharacters stripped from alert text before it reaches HA, on both the single and batched announcement paths |
| Alert deduplication | Suppresses repeated alert ID + action within `ALERT_DEDUP_TTL_SECONDS`, bounded at 10,000 cache entries |
| Security response headers | `SecurityHeadersMiddleware` sets `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`, `Cache-Control`, and replaces `Server` to prevent framework fingerprinting |
| Crawler exclusion | `/robots.txt` plus `X-Robots-Tag: noindex, nofollow` on every response |
| Non-root container | Runs as `appuser` (uid 1000) with `no-new-privileges:true` |
| Read-only root filesystem | `read_only: true` with a `/tmp` tmpfs for the only writable path |
| Fail-open alerting | JSM and HA API failures are logged and degrade gracefully rather than crashing the service, so a transient upstream outage cannot stop alert delivery |
| Token liveness monitoring | Credentials re-verified every `TOKEN_CHECK_INTERVAL_HOURS`; failure announces an alert through HA |

## Dependency Security

CI runs on every pull request:

```bash
# Known CVEs in runtime dependencies
pip-audit -r requirements.txt --desc

# Static analysis for common Python security issues
bandit -r src/ -c pyproject.toml
```

`pip-audit` **blocks** the build on a vulnerable dependency. `bandit` and `mypy`
are advisory and do not fail CI.

Neither `pip-audit` nor `bandit` is listed in `requirements-dev.txt` — CI installs
them inline. Install them yourself before running the commands locally:

```bash
pip install pip-audit bandit
pip-audit -r requirements.txt --desc
bandit -r src/ -c pyproject.toml
```

The release workflow additionally scans every published container image for known
CVEs. The Dockerfile tracks the `python:3.12-slim` tag rather than pinning a
digest, so scheduled rebuilds pick up upstream security patches — see the
supply-chain note at the top of the `Dockerfile` for digest-pinning instructions
if you need fully reproducible builds instead.

## Supported Versions

Only the latest release receives security fixes. Pin a specific image tag in
production so `docker compose pull` cannot swap code underneath you:

```yaml
image: ghcr.io/realdougeubanks/jsm-ha-notifier:v3.2.0
```
