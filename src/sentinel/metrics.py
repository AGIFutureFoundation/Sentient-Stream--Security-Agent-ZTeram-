"""
Sentinel Stream — Prometheus metrics.

Exposes /metrics endpoint with:
  - sentinel_events_ingested_total{agent_id, event_type}
  - sentinel_alerts_fired_total{alert_type, severity}
  - sentinel_clickhouse_query_latency_ms{query} (histogram)
  - sentinel_detection_latency_ms{rule} (histogram)
  - sentinel_active_agents
  - sentinel_hive_tasks{status}
  - sentinel_nl_query_total{template_id}
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Any

logger = logging.getLogger(__name__)


class MetricsRegistry:
    """Lightweight Prometheus-compatible metrics registry.

    No external dependency — emits text/plain Prometheus exposition format.
    For production, swap to prometheus_client library.
    """

    def __init__(self) -> None:
        self._counters: dict[str, dict[str, Any]] = {}
        self._histograms: dict[str, dict[str, Any]] = {}
        self._gauges: dict[str, float] = {}
        self._lock = Lock()

    def inc_counter(self, name: str, labels: dict[str, str] | None = None, value: int = 1) -> None:
        """Increment a counter metric."""
        label_key = self._label_key(labels)
        with self._lock:
            if name not in self._counters:
                self._counters[name] = {"type": "counter", "values": defaultdict(int), "label_names": list(labels.keys()) if labels else []}
            self._counters[name]["values"][label_key] += value

    def observe_histogram(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        """Observe a value for a histogram metric."""
        label_key = self._label_key(labels)
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = {
                    "type": "histogram",
                    "buckets": [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0],
                    "values": defaultdict(lambda: {"count": 0, "sum": 0.0, "buckets": defaultdict(int)}),
                    "label_names": list(labels.keys()) if labels else [],
                }
            h = self._histograms[name]["values"][label_key]
            h["count"] += 1
            h["sum"] += value
            for bucket in self._histograms[name]["buckets"]:
                if value <= bucket:
                    h["buckets"][bucket] += 1

    def set_gauge(self, name: str, value: float) -> None:
        """Set a gauge metric."""
        with self._lock:
            self._gauges[name] = value

    def render(self) -> str:
        """Render all metrics in Prometheus exposition format."""
        lines: list[str] = []
        with self._lock:
            for name, data in self._counters.items():
                lines.append(f"# TYPE {name} counter")
                for label_key, value in data["values"].items():
                    lines.append(f"{name}{label_key} {value}")
            for name, data in self._histograms.items():
                lines.append(f"# TYPE {name} histogram")
                for label_key, h in data["values"].items():
                    for bucket in data["buckets"]:
                        bucket_label = self._bucket_label(label_key, bucket, data["label_names"])
                        lines.append(f'{name}_bucket{bucket_label} {h["buckets"][bucket]}')
                    lines.append(f'{name}_bucket{self._inf_label(label_key, data["label_names"])} {h["count"]}')
                    lines.append(f'{name}_sum{label_key} {h["sum"]}')
                    lines.append(f'{name}_count{label_key} {h["count"]}')
            for name, value in self._gauges.items():
                lines.append(f"# TYPE {name} gauge")
                lines.append(f"{name} {value}")
        return "\n".join(lines) + "\n"

    def _label_key(self, labels: dict[str, str] | None) -> str:
        if not labels:
            return ""
        parts = [f'{k}="{v}"' for k, v in sorted(labels.items())]
        return "{" + ",".join(parts) + "}"

    def _bucket_label(self, label_key: str, bucket: float, label_names: list[str]) -> str:
        le_part = f'le="{bucket}"'
        if not label_key:
            return "{" + le_part + "}"
        # Insert le into existing labels
        inner = label_key[1:-1]  # strip { }
        return "{" + inner + "," + le_part + "}"

    def _inf_label(self, label_key: str, label_names: list[str]) -> str:
        le_part = 'le="+Inf"'
        if not label_key:
            return "{" + le_part + "}"
        inner = label_key[1:-1]
        return "{" + inner + "," + le_part + "}"


# Singleton
_registry: MetricsRegistry | None = None


def get_metrics() -> MetricsRegistry:
    global _registry
    if _registry is None:
        _registry = MetricsRegistry()
    return _registry


# --- Convenience wrappers ---------------------------------------------------

def record_event_ingested(agent_id: str, event_type: str) -> None:
    get_metrics().inc_counter(
        "sentinel_events_ingested_total",
        labels={"agent_id": agent_id, "event_type": event_type},
    )


def record_alert_fired(alert_type: str, severity: str) -> None:
    get_metrics().inc_counter(
        "sentinel_alerts_fired_total",
        labels={"alert_type": alert_type, "severity": severity},
    )


def record_ch_query_latency(query_name: str, latency_ms: float) -> None:
    get_metrics().observe_histogram(
        "sentinel_clickhouse_query_latency_ms",
        latency_ms,
        labels={"query": query_name},
    )


def record_detection_latency(rule: str, latency_ms: float) -> None:
    get_metrics().observe_histogram(
        "sentinel_detection_latency_ms",
        latency_ms,
        labels={"rule": rule},
    )


def record_nl_query(template_id: str) -> None:
    get_metrics().inc_counter(
        "sentinel_nl_query_total",
        labels={"template_id": template_id},
    )
