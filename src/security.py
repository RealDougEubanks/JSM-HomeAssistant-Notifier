"""
Security middleware and request-authentication helpers.

Settings are always read live from ``request.app.state.settings`` so that
``/reload`` takes effect immediately for auth and rate limiting.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import time as _time

from fastapi import HTTPException, Query, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.responses import Response as StarletteResponse

from .metrics import inc

logger = logging.getLogger(__name__)

# Allowed characters in JSM alert IDs (UUIDs, alphanumeric, hyphens, underscores).
ALERT_ID_RE = re.compile(r"^[a-zA-Z0-9\-_]{1,200}$")


# ── Simple rate limiter (sliding window, per-IP) ─────────────────────────────

rate_buckets: dict[str, list[float]] = {}
_MAX_TRACKED_IPS = 10_000  # prevent unbounded memory growth


def rate_limited(client_ip: str, max_requests: int, window: float) -> bool:
    """Return True if *client_ip* has exceeded *max_requests* per *window* seconds."""
    now = _time.monotonic()
    cutoff = now - window

    # Cap tracked IPs (DoS protection).  Prefer dropping buckets whose
    # newest timestamp is already outside the window (they would deny
    # nothing); fall back to arbitrary eviction of half the table rather
    # than sorting 10k entries on the hot path under attack.
    if len(rate_buckets) >= _MAX_TRACKED_IPS:
        idle = [k for k, ts in rate_buckets.items() if not ts or ts[-1] <= cutoff]
        for k in idle:
            del rate_buckets[k]
        if len(rate_buckets) >= _MAX_TRACKED_IPS:
            for k in list(rate_buckets)[: _MAX_TRACKED_IPS // 2]:
                del rate_buckets[k]

    timestamps = rate_buckets.setdefault(client_ip, [])
    # Prune timestamps outside the window.
    rate_buckets[client_ip] = [t for t in timestamps if t > cutoff]
    timestamps = rate_buckets[client_ip]

    if len(timestamps) >= max_requests:
        return True
    timestamps.append(now)
    return False


# ── Middleware ────────────────────────────────────────────────────────────────


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to every response and strip server identification.

    - X-Content-Type-Options: prevent MIME sniffing
    - X-Frame-Options: prevent clickjacking
    - X-Robots-Tag: tell crawlers not to index (belt + suspenders with robots.txt)
    - Content-Security-Policy: restrict resource loading
    - Referrer-Policy: prevent URL leakage in Referer header
    - Cache-Control: prevent proxies/browsers from caching API responses
    - Server: replaced with generic value to prevent framework fingerprinting
    """

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001
        response: StarletteResponse = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, max-age=0"
        )
        response.headers["Pragma"] = "no-cache"
        response.headers["Server"] = "webhook-receiver"
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-IP rate limiting applied to every request BEFORE route handlers
    (and therefore before API-key verification), so invalid-key
    brute-forcing and unauthenticated probing are throttled too.

    ``/health`` is exempt — the Docker healthcheck polls it continuously
    and must never be blocked.  Limits come from ``RATE_LIMIT_REQUESTS`` /
    ``RATE_LIMIT_WINDOW_SECONDS`` (0 requests = disabled) and are read
    live so ``/reload`` takes effect.

    Registered innermost (before the path-prefix middleware in the stack)
    so it sees the rewritten path: ``/KEY/health`` is exempted as ``/health``.
    """

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001
        settings = request.app.state.settings
        max_requests = settings.rate_limit_requests
        if max_requests > 0 and request.url.path != "/health":
            client_ip = request.client.host if request.client else "unknown"
            window = float(settings.rate_limit_window_seconds)
            if rate_limited(client_ip, max_requests, window):
                inc("alerts_rate_limited_total")
                logger.warning("Rate limit exceeded for %s", client_ip)
                return JSONResponse(
                    status_code=429, content={"detail": "Rate limit exceeded"}
                )
        return await call_next(request)


class ApiKeyPathMiddleware(BaseHTTPMiddleware):
    """
    Support API key as the first path segment: ``/APIKEY/healthz``.

    If WEBHOOK_API_KEY is configured and the first path segment matches,
    strip it from the path and mark the request as authenticated so
    downstream ``verify_api_key()`` can skip re-checking.

    This supports tools (like JSM webhooks) that can only configure a URL
    and do not support custom headers or query parameters.
    """

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001
        configured_key = request.app.state.settings.webhook_api_key
        if configured_key and request.url.path != "/":
            # Split path: /KEY/healthz → ["", "KEY", "healthz"]
            parts = request.url.path.split("/", 2)
            if (
                len(parts) >= 2
                and parts[1]
                and secrets.compare_digest(parts[1], configured_key)
            ):
                # Rewrite path with key segment removed.
                new_path = "/" + parts[2] if len(parts) > 2 else "/"
                request.scope["path"] = new_path
                request.state.api_key_verified = True
        return await call_next(request)


# ── Webhook signature / API key verification ─────────────────────────────────


def verify_signature(settings, request: Request, body: bytes) -> bool:  # noqa: ANN001
    """
    Validate the X-Hub-Signature-256 header if WEBHOOK_SECRET is configured.
    Always returns True if no secret is set (dev / internal-only deployments).
    """
    if not settings.webhook_secret:
        return True

    try:
        sig_header = request.headers.get("X-Hub-Signature-256", "")
        if not sig_header.startswith("sha256="):
            logger.warning(
                "Webhook request missing or malformed X-Hub-Signature-256 header"
            )
            return False

        expected = (
            "sha256="
            + hmac.new(
                settings.webhook_secret.encode("utf-8"),
                body,
                hashlib.sha256,
            ).hexdigest()
        )

        return hmac.compare_digest(sig_header, expected)
    except Exception:
        # Catch-all to prevent any exception from leaking the secret in a traceback.
        logger.error("Webhook signature verification error")
        return False


def verify_api_key(
    settings, key: str | None, request: Request | None = None
) -> bool:  # noqa: ANN001
    """
    Verify the API key from any of three sources (checked in order):

    1. Path prefix — ``/APIKEY/endpoint`` (set by ``ApiKeyPathMiddleware``)
    2. ``X-API-Key`` request header
    3. ``?key=`` query parameter

    Returns True if no key is configured (disabled) or if any source matches.
    Uses constant-time comparison to prevent timing attacks.
    """
    if not settings.webhook_api_key:
        return True

    # 1. Already verified by path-prefix middleware.
    if request and getattr(request.state, "api_key_verified", False):
        return True

    # 2. X-API-Key header.
    if request:
        header_key = request.headers.get("X-API-Key")
        if header_key and secrets.compare_digest(header_key, settings.webhook_api_key):
            return True

    # 3. ?key= query parameter (existing behaviour).
    if key and secrets.compare_digest(key, settings.webhook_api_key):
        return True

    logger.warning("Request rejected — invalid or missing API key")
    return False


async def require_api_key(request: Request, key: str | None = Query(None)) -> None:
    """FastAPI dependency that enforces API key auth from any source.

    Returns 404 (not 401/403) when the key is invalid or missing, so
    unauthenticated clients cannot distinguish 'wrong key' from
    'endpoint does not exist'.  This prevents attackers from confirming
    that authenticated endpoints exist or brute-forcing keys.
    """
    if not verify_api_key(request.app.state.settings, key, request):
        raise HTTPException(status_code=404, detail="Not found")
