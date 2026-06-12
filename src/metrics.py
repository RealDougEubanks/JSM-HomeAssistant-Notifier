"""Prometheus-compatible in-process counters (no external dependency)."""

from __future__ import annotations

METRICS: dict[str, int] = {
    "alerts_received_total": 0,
    "alerts_notified_total": 0,
    "alerts_deduplicated_total": 0,
    "alerts_dismissed_total": 0,
    "alerts_rate_limited_total": 0,
    "credential_checks_total": 0,
    "credential_checks_failed_total": 0,
    "healthz_requests_total": 0,
}


def inc(metric: str, amount: int = 1) -> None:
    """Increment a metric counter. No-op if metric name is unknown."""
    if metric in METRICS:
        METRICS[metric] += amount
