"""
Async Atlassian JSM Ops API client.

Handles schedule discovery and on-call participant lookups with two layers of
caching so we don't hammer the API on every webhook hit:

  1. Schedule name → ID cache (never expires; IDs don't change)
  2. On-call status cache (expires after oncall_cache_ttl_seconds, default 5 min)

On any API error the on-call check returns True (fail-open) so you don't
miss an alert because the API was temporarily unavailable.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# How long to wait for JSM API calls before giving up.
_REQUEST_TIMEOUT = 10.0


def _collect_user_ids(participants: list[dict]) -> set[str]:
    """Recursively collect all user IDs from a nested onCallParticipants tree.

    JSM returns a hierarchy: escalation → team → user.  Each level may have
    its own ``onCallParticipants`` list, so we walk the whole tree.
    """
    user_ids: set[str] = set()
    for p in participants:
        if p.get("type") == "user":
            user_ids.add(p["id"])
        nested = p.get("onCallParticipants") or []
        user_ids |= _collect_user_ids(nested)
    return user_ids


class JSMClient:
    def __init__(
        self,
        api_url: str,
        cloud_id: str,
        username: str,
        api_token: str,
        my_user_id: str,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.cloud_id = cloud_id
        self._auth = (username, api_token)
        self.my_user_id = my_user_id

        # name → schedule_id  (populated lazily, never invalidated)
        self._schedule_id_cache: dict[str, str] = {}
        # schedule_id → (is_on_call, fetched_at_timestamp)
        self._oncall_cache: dict[str, tuple[bool, float]] = {}

        # Persistent HTTP client — reused across requests to avoid socket churn.
        self._http: httpx.AsyncClient = httpx.AsyncClient(trust_env=False)

    async def aclose(self) -> None:
        """Close the underlying HTTP client.  Called during application shutdown."""
        await self._http.aclose()

    # ── Internal helpers ──────────────────────────────────────────────────

    def _base_headers(self) -> dict[str, str]:
        return {"Accept": "application/json"}

    def _schedules_url(self) -> str:
        return f"{self.api_url}/jsm/ops/api/{self.cloud_id}/v1/schedules"

    def _oncall_url(self, schedule_id: str) -> str:
        return f"{self._schedules_url()}/{schedule_id}/on-calls"

    # ── Public API ────────────────────────────────────────────────────────

    # Safety cap: maximum number of pagination pages to follow.
    _MAX_PAGES = 100

    async def get_all_schedules(self) -> list[dict[str, Any]]:
        """
        Return all schedules visible to the configured API token.
        Handles JSM's cursor-based pagination automatically.
        """
        url: str | None = self._schedules_url()
        schedules: list[dict[str, Any]] = []
        expected_prefix = f"{self.api_url}/"

        for _ in range(self._MAX_PAGES):
            if not url:
                break

            response = await self._http.get(
                url,
                auth=self._auth,
                headers=self._base_headers(),
                timeout=_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()

            page = data.get("values") or []
            schedules.extend(page)

            # JSM paginates via a "next" cursor URL.
            # Validate it starts with our API base to prevent credential
            # redirection via a malicious or compromised response.
            next_cursor = data.get("paging", {}).get("next")
            if next_cursor and next_cursor.startswith(expected_prefix):
                url = next_cursor
            else:
                if next_cursor:
                    logger.warning(
                        "Ignoring suspicious pagination URL: %s",
                        next_cursor[:200],
                    )
                url = None
        else:
            logger.warning(
                "Pagination safety cap reached (%d pages); "
                "some schedules may not be loaded.",
                self._MAX_PAGES,
            )

        logger.debug("Fetched %d schedules from JSM", len(schedules))
        return schedules

    async def get_schedule_id(self, schedule_name: str) -> str | None:
        """
        Return the schedule ID for *schedule_name*, refreshing the local
        name→ID cache from the API if the name is not yet known.
        """
        if schedule_name in self._schedule_id_cache:
            return self._schedule_id_cache[schedule_name]

        try:
            schedules = await self.get_all_schedules()
        except Exception as exc:
            logger.error("Failed to fetch schedules from JSM: %s", exc)
            return None

        for s in schedules:
            sid = s.get("id")
            sname = s.get("name")
            if sid and sname:
                self._schedule_id_cache[sname] = sid
                logger.debug("Cached schedule '%s' → %s", sname, sid)

        found = self._schedule_id_cache.get(schedule_name)
        if not found:
            logger.warning(
                "Schedule '%s' not found in JSM (%d schedule(s) visible).",
                schedule_name,
                len(self._schedule_id_cache),
            )
        return found

    async def is_on_call(
        self,
        schedule_id: str,
        cache_ttl: int = 300,
    ) -> bool:
        """
        Return True if *my_user_id* is currently on-call for *schedule_id*.

        Results are cached for *cache_ttl* seconds.  On any API error, returns
        True (fail-open) so critical alerts are never silently dropped.
        """
        now = time.monotonic()

        cached = self._oncall_cache.get(schedule_id)
        if cached is not None:
            is_on_call, fetched_at = cached
            if now - fetched_at < cache_ttl:
                logger.debug("On-call cache hit for %s: %s", schedule_id, is_on_call)
                return is_on_call

        try:
            response = await self._http.get(
                self._oncall_url(schedule_id),
                auth=self._auth,
                headers=self._base_headers(),
                timeout=_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()

            participants = data.get("onCallParticipants") or []
            user_ids = _collect_user_ids(participants)
            is_on_call = self.my_user_id in user_ids
            self._oncall_cache[schedule_id] = (is_on_call, now)
            logger.info(
                "On-call status for schedule %s: %s (users on-call: %s)",
                schedule_id,
                is_on_call,
                user_ids,
            )
            return is_on_call

        except Exception as exc:
            logger.error(
                "Could not check on-call status for schedule %s: %s — "
                "defaulting to notify (fail-open)",
                schedule_id,
                exc,
            )
            # Fail-open: better to over-notify than to miss a P1.
            return True

    async def verify_credentials(self) -> tuple[bool, str]:
        """
        Validate the configured API token against the JSM Ops schedules endpoint.

        This is the same endpoint used for normal schedule lookups, so if it
        returns 200 we know the token has exactly the permissions this service
        needs.

        Returns (True, "") on success, or (False, error_detail) on failure.
        """
        url = self._schedules_url()
        try:
            response = await self._http.get(
                url,
                auth=self._auth,
                headers=self._base_headers(),
                timeout=_REQUEST_TIMEOUT,
            )
            if response.status_code == 401:
                return False, "401 Unauthorized — token is invalid or has been revoked"
            if response.status_code == 403:
                return False, "403 Forbidden — token lacks required permissions"
            response.raise_for_status()
            schedule_count = len(response.json().get("values") or [])
            logger.info(
                "Credential check OK — JSM API reachable (%d schedule(s) visible)",
                schedule_count,
            )
            return True, ""
        except httpx.HTTPStatusError as exc:
            msg = f"HTTP {exc.response.status_code} from JSM schedules API"
            logger.error("Credential check failed: %s", msg)
            return False, msg
        except Exception as exc:
            msg = f"Connection error: {exc}"
            logger.error("Credential check failed: %s", msg)
            return False, msg

    async def acknowledge_alert(self, alert_id: str) -> tuple[bool, str]:
        """
        Acknowledge an alert via the JSM Ops API.

        Returns (True, "") on success, or (False, error_detail) on failure.
        """
        url = (
            f"{self.api_url}/jsm/ops/api/{self.cloud_id}/v1/alerts/{alert_id}/acknowledge"
        )
        try:
            response = await self._http.post(
                url,
                auth=self._auth,
                headers={**self._base_headers(), "Content-Type": "application/json"},
                json={"user": self.my_user_id},
                timeout=_REQUEST_TIMEOUT,
            )
            if response.status_code in (200, 202):
                logger.info("Alert %s acknowledged via JSM API", alert_id)
                return True, ""
            response.raise_for_status()
            return True, ""
        except httpx.HTTPStatusError as exc:
            msg = f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
            logger.error("Failed to acknowledge alert %s: %s", alert_id, msg)
            return False, msg
        except Exception as exc:
            msg = str(exc)
            logger.error("Failed to acknowledge alert %s: %s", alert_id, msg)
            return False, msg

    async def get_alert_details(self, alert_id: str) -> dict[str, Any] | None:
        """
        Fetch full alert details from JSM, including extra context like
        responders, teams, tags, and custom details.

        Returns the alert dict on success, None on failure.
        """
        url = f"{self.api_url}/jsm/ops/api/{self.cloud_id}/v1/alerts/{alert_id}"
        try:
            response = await self._http.get(
                url,
                auth=self._auth,
                headers=self._base_headers(),
                timeout=_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
            # JSM wraps the alert in a "data" key.
            return data.get("data", data)  # type: ignore[return-value]
        except Exception as exc:
            logger.warning("Failed to fetch alert details for %s: %s", alert_id, exc)
            return None

    async def list_open_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        """
        Fetch open alerts from the JSM Ops API.

        Returns a list of alert dicts suitable for ``IncidentStore.bulk_upsert``.
        On failure returns an empty list (non-fatal).
        """
        url = f"{self.api_url}/jsm/ops/api/{self.cloud_id}/v1/alerts"
        try:
            response = await self._http.get(
                url,
                auth=self._auth,
                headers=self._base_headers(),
                params={"limit": limit, "order": "desc", "sort": "createdAt"},
                timeout=_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
            alerts = data.get("data") or data.get("values") or []
            logger.info("Fetched %d alerts from JSM API", len(alerts))
            return alerts  # type: ignore[return-value]
        except Exception as exc:
            logger.error("Failed to fetch alerts from JSM: %s", exc)
            return []

    def invalidate_oncall_cache(self) -> None:
        """Force the next on-call check to hit the API (useful after rotation)."""
        self._oncall_cache.clear()
        logger.info("On-call cache invalidated")

    def cache_stats(self) -> dict[str, int]:
        """Return cache sizes for operational visibility (no values leaked)."""
        return {
            "schedule_id_entries": len(self._schedule_id_cache),
            "oncall_entries": len(self._oncall_cache),
        }
