"""
SQLite-backed incident state tracker.

Maintains a lightweight database of alert lifecycle events so the service
can expose a ``GET /incidents`` dashboard showing all open (and recently
closed) incidents.  The database is updated from incoming webhooks and
optionally synced from the JSM Ops API on a schedule.

Design decisions
────────────────
- Uses stdlib ``sqlite3`` with ``asyncio.to_thread()`` to avoid adding a
  dependency.  SQLite operations on this schema are sub-millisecond so
  blocking the event loop for that duration is acceptable in practice,
  but ``to_thread`` keeps things clean.
- The database is created lazily on first use.
- All timestamps are stored as ISO-8601 UTC strings.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    alert_id       TEXT PRIMARY KEY,
    message        TEXT NOT NULL,
    priority       TEXT NOT NULL DEFAULT 'P3',
    entity         TEXT DEFAULT '',
    description    TEXT DEFAULT '',
    source         TEXT DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'open',
    action         TEXT NOT NULL DEFAULT 'Create',
    tags           TEXT DEFAULT '',
    teams          TEXT DEFAULT '',
    responders     TEXT DEFAULT '',
    details_json   TEXT DEFAULT '',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    acknowledged_at TEXT,
    closed_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_priority ON incidents(priority);
"""


class IncidentStore:
    """Thread-safe async wrapper around a SQLite incident database."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.executescript(_SCHEMA)
            logger.info("Incident store opened at %s", self._db_path)
        return self._conn

    async def _run(self, fn: Any, *args: Any) -> Any:
        """Run a sync DB function in a thread, serialized by _lock."""
        return await asyncio.to_thread(self._run_locked, fn, *args)

    def _run_locked(self, fn: Any, *args: Any) -> Any:
        with self._lock:
            return fn(*args)

    # ── Write operations ──────────────────────────────────────────────────

    def _upsert_sync(self, alert: dict[str, Any], action: str) -> None:
        conn = self._get_conn()
        now = datetime.now(UTC).isoformat()

        alert_id = alert.get("alertId", alert.get("alert_id", "unknown"))
        message = alert.get("message", "")
        priority = alert.get("priority", "P3")
        entity = alert.get("entity", "") or ""
        description = alert.get("description", "") or ""
        source = alert.get("source", "") or ""

        # Enrichment fields (may come from JSM API detail calls).
        tags = (
            ",".join(alert.get("tags", [])) if isinstance(alert.get("tags"), list) else ""
        )
        teams_raw = alert.get("teams", [])
        teams = (
            ",".join(
                t.get("name", t.get("id", "")) for t in teams_raw if isinstance(t, dict)
            )
            if isinstance(teams_raw, list)
            else ""
        )
        responders_raw = alert.get("responders", [])
        responders = (
            ",".join(
                r.get("name", r.get("id", ""))
                for r in responders_raw
                if isinstance(r, dict)
            )
            if isinstance(responders_raw, list)
            else ""
        )
        details_json = (
            json.dumps(alert.get("details", {})) if alert.get("details") else ""
        )

        # Determine status from action.
        status = "open"
        ack_at = None
        closed_at = None

        if action in ("Acknowledge",):
            status = "acknowledged"
            ack_at = now
        elif action in ("Close",):
            status = "closed"
            closed_at = now
        elif action in ("EscalateNext",):
            status = "escalated"

        conn.execute(
            """
            INSERT INTO incidents
                (alert_id, message, priority, entity, description, source,
                 status, action, tags, teams, responders, details_json,
                 created_at, updated_at, acknowledged_at, closed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(alert_id) DO UPDATE SET
                message = COALESCE(excluded.message, incidents.message),
                priority = COALESCE(excluded.priority, incidents.priority),
                entity = CASE WHEN excluded.entity != '' THEN excluded.entity ELSE incidents.entity END,
                description = CASE WHEN excluded.description != '' THEN excluded.description ELSE incidents.description END,
                source = CASE WHEN excluded.source != '' THEN excluded.source ELSE incidents.source END,
                status = excluded.status,
                action = excluded.action,
                tags = CASE WHEN excluded.tags != '' THEN excluded.tags ELSE incidents.tags END,
                teams = CASE WHEN excluded.teams != '' THEN excluded.teams ELSE incidents.teams END,
                responders = CASE WHEN excluded.responders != '' THEN excluded.responders ELSE incidents.responders END,
                details_json = CASE WHEN excluded.details_json != '' THEN excluded.details_json ELSE incidents.details_json END,
                updated_at = excluded.updated_at,
                acknowledged_at = COALESCE(excluded.acknowledged_at, incidents.acknowledged_at),
                closed_at = COALESCE(excluded.closed_at, incidents.closed_at)
            """,
            (
                alert_id,
                message,
                priority,
                entity,
                description,
                source,
                status,
                action,
                tags,
                teams,
                responders,
                details_json,
                now,
                now,
                ack_at,
                closed_at,
            ),
        )
        conn.commit()

    async def upsert(self, alert: dict[str, Any], action: str) -> None:
        """Insert or update an incident from a webhook event."""
        await self._run(self._upsert_sync, alert, action)

    def _bulk_upsert_sync(self, alerts: list[dict[str, Any]]) -> int:
        """Upsert alerts from a JSM API sync.  Returns count of rows affected."""
        conn = self._get_conn()
        now = datetime.now(UTC).isoformat()
        count = 0

        for alert in alerts:
            alert_id = alert.get("id", alert.get("alertId", ""))
            if not alert_id:
                continue
            message = alert.get("message", "")
            priority = alert.get("priority", "P3")
            entity = alert.get("entity", "") or ""
            description = alert.get("description", "") or ""
            source = alert.get("source", "") or ""
            status = (alert.get("status", "") or "open").lower()
            # Map JSM statuses.
            if status in ("acked", "acknowledged"):
                status = "acknowledged"
            elif status not in ("open", "closed", "escalated"):
                status = "open"

            conn.execute(
                """
                INSERT INTO incidents
                    (alert_id, message, priority, entity, description, source,
                     status, action, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'Sync', ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET
                    message = COALESCE(excluded.message, incidents.message),
                    priority = COALESCE(excluded.priority, incidents.priority),
                    status = excluded.status,
                    updated_at = excluded.updated_at
                """,
                (
                    alert_id,
                    message,
                    priority,
                    entity,
                    description,
                    source,
                    status,
                    now,
                    now,
                ),
            )
            count += 1

        conn.commit()
        return count

    async def bulk_upsert(self, alerts: list[dict[str, Any]]) -> int:
        """Upsert alerts from a JSM API sync."""
        return await self._run(self._bulk_upsert_sync, alerts)

    # ── Read operations ───────────────────────────────────────────────────

    def _get_all_sync(
        self,
        status: str | None = None,
        priority: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        conn = self._get_conn()
        query = "SELECT * FROM incidents WHERE 1=1"
        params: list[Any] = []

        if status:
            query += " AND status = ?"
            params.append(status)
        if priority:
            query += " AND priority = ?"
            params.append(priority)

        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    async def get_all(
        self,
        status: str | None = None,
        priority: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Return incidents, optionally filtered by status and/or priority."""
        return await self._run(self._get_all_sync, status, priority, limit)

    def _get_one_sync(self, alert_id: str) -> dict[str, Any] | None:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM incidents WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        return dict(row) if row else None

    async def get_one(self, alert_id: str) -> dict[str, Any] | None:
        """Return a single incident by alert_id."""
        return await self._run(self._get_one_sync, alert_id)

    def _get_summary_sync(self) -> dict[str, Any]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT status, COUNT(*) as count FROM incidents GROUP BY status"
        ).fetchall()
        by_status = {row["status"]: row["count"] for row in rows}

        prio_rows = conn.execute(
            "SELECT priority, COUNT(*) as count FROM incidents "
            "WHERE status NOT IN ('closed') GROUP BY priority"
        ).fetchall()
        by_priority = {row["priority"]: row["count"] for row in prio_rows}

        total_open = sum(v for k, v in by_status.items() if k != "closed")
        return {
            "total_open": total_open,
            "total_closed": by_status.get("closed", 0),
            "by_status": by_status,
            "by_priority": by_priority,
        }

    async def get_summary(self) -> dict[str, Any]:
        """Return aggregate counts for the dashboard."""
        return await self._run(self._get_summary_sync)

    # ── Force-close ────────────────────────────────────────────────────────

    def _force_close_sync(self, alert_id: str) -> bool:
        conn = self._get_conn()
        now = datetime.now(UTC).isoformat()
        cur = conn.execute(
            """
            UPDATE incidents
            SET status = 'closed', action = 'ForceClose', closed_at = ?, updated_at = ?
            WHERE alert_id = ? AND status != 'closed'
            """,
            (now, now, alert_id),
        )
        conn.commit()
        return cur.rowcount > 0

    async def force_close(self, alert_id: str) -> bool:
        """Force-close an incident from the dashboard.  Returns True if found and closed."""
        return await self._run(self._force_close_sync, alert_id)

    # ── Retention cleanup ─────────────────────────────────────────────────

    def _cleanup_sync(self, open_days: int, closed_days: int) -> int:
        """Delete incidents older than the configured retention periods."""
        conn = self._get_conn()
        now = datetime.now(UTC)
        deleted = 0

        if closed_days > 0:
            cutoff = (now - timedelta(days=closed_days)).isoformat()
            cur = conn.execute(
                "DELETE FROM incidents WHERE status IN ('closed') AND updated_at < ?",
                (cutoff,),
            )
            deleted += cur.rowcount

        if open_days > 0:
            cutoff = (now - timedelta(days=open_days)).isoformat()
            cur = conn.execute(
                "DELETE FROM incidents WHERE status NOT IN ('closed') AND updated_at < ?",
                (cutoff,),
            )
            deleted += cur.rowcount

        if deleted:
            conn.commit()
            logger.info(
                "Retention cleanup: deleted %d stale incident(s) "
                "(open_days=%d, closed_days=%d)",
                deleted,
                open_days,
                closed_days,
            )
        return deleted

    async def cleanup(self, open_days: int, closed_days: int) -> int:
        """Run retention cleanup.  Returns count of deleted rows."""
        return await self._run(self._cleanup_sync, open_days, closed_days)

    async def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
