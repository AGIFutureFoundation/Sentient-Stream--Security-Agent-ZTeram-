"""
Sentinel Stream — eval metrics.

Computes precision, recall, detection latency, and ClickHouse query latency
from a list of ScenarioResult objects.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# Targets (must match EVALS.md)
TARGET_PRECISION = 0.90
TARGET_RECALL = 0.85
TARGET_LATENCY_P50_MS = 500
TARGET_LATENCY_P99_MS = 2000
TARGET_CH_QUERY_P99_MS = 100


@dataclass
class ScenarioResult:
    scenario_id: str
    name: str
    events: list[dict] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    expected_alerts: list[dict] = field(default_factory=list)
    error: str | None = None


def _alert_matches_expected(alert: dict, expected: dict) -> bool:
    """Heuristic match: alert type matches and technique matches."""
    return (
        alert.get("alert_type") == expected.get("type")
        and alert.get("technique") == expected.get("technique")
    )


def compute_precision_recall(results: list[ScenarioResult]) -> tuple[float, float]:
    """Precision = matched alerts / total alerts fired.
    Recall = matched expected / total expected."""
    matched = 0
    total_fired = 0
    total_expected = 0
    for r in results:
        total_fired += len(r.alerts)
        total_expected += len(r.expected_alerts)
        for expected in r.expected_alerts:
            for alert in r.alerts:
                if _alert_matches_expected(alert, expected):
                    matched += 1
                    break
    precision = matched / total_fired if total_fired else 0.0
    recall = matched / total_expected if total_expected else 0.0
    return precision, recall


def compute_detection_latencies(results: list[ScenarioResult]) -> list[float]:
    """For each matched alert, compute alert.ts - triggering_event.ts in ms."""
    latencies: list[float] = []
    for r in results:
        # Build event-id → ts lookup
        event_ts = {e.get("id"): e.get("ts") for e in r.events if e.get("id") and e.get("ts")}
        for alert in r.alerts:
            triggering_ts = None
            for eid in alert.get("event_ids", []):
                if eid in event_ts:
                    triggering_ts = event_ts[eid]
                    break
            if triggering_ts and alert.get("ts"):
                try:
                    delta_ms = (float(alert["ts"]) - float(triggering_ts)) * 1000
                    if delta_ms >= 0:
                        latencies.append(delta_ms)
                except (ValueError, TypeError):
                    pass
    return latencies


def percentile(values: list[float], p: float) -> float:
    """Naive percentile computation."""
    if not values:
        return 0.0
    s = sorted(values)
    k = int(round((len(s) - 1) * p / 100))
    return s[k]


def compute_metrics(results: list[ScenarioResult]) -> dict[str, Any]:
    """Compute all eval metrics. Returns a dict suitable for JSON output."""
    precision, recall = compute_precision_recall(results)
    latencies = compute_detection_latencies(results)
    p50 = percentile(latencies, 50) if latencies else 0.0
    p99 = percentile(latencies, 99) if latencies else 0.0

    # CH query latency would be collected by wrapping the API's internal
    # query timer. For now, we stub it from the alerts' `ch_query_ms` field
    # if present.
    ch_latencies = [
        a.get("ch_query_ms", 0) for r in results for a in r.alerts if a.get("ch_query_ms")
    ]
    ch_p99 = percentile(ch_latencies, 99) if ch_latencies else 0.0

    return {
        "scenarios_run": len(results),
        "events_ingested": sum(len(r.events) for r in results),
        "alerts_fired": sum(len(r.alerts) for r in results),
        "expected_alerts": sum(len(r.expected_alerts) for r in results),
        "precision": {
            "value": round(precision, 4),
            "target": TARGET_PRECISION,
            "passed": precision >= TARGET_PRECISION,
        },
        "recall": {
            "value": round(recall, 4),
            "target": TARGET_RECALL,
            "passed": recall >= TARGET_RECALL,
        },
        "detection_latency_ms": {
            "p50": round(p50, 1),
            "p99": round(p99, 1),
            "target_p50": TARGET_LATENCY_P50_MS,
            "target_p99": TARGET_LATENCY_P99_MS,
            "passed_p50": p50 <= TARGET_LATENCY_P50_MS,
            "passed_p99": p99 <= TARGET_LATENCY_P99_MS,
        },
        "ch_query_latency_ms": {
            "p99": round(ch_p99, 1),
            "target": TARGET_CH_QUERY_P99_MS,
            "passed": ch_p99 <= TARGET_CH_QUERY_P99_MS,
        },
        "per_scenario": [
            {
                "id": r.scenario_id,
                "name": r.name,
                "alerts_fired": len(r.alerts),
                "expected_alerts": len(r.expected_alerts),
                "error": r.error,
            }
            for r in results
        ],
    }


def format_report(
    results: list[ScenarioResult],
    metrics: dict[str, Any],
    scenario_paths: list[Path],
) -> str:
    """Render a human-readable markdown report."""
    lines = [
        "# Sentinel Stream — Eval Report",
        "",
        f"Generated: {__import__('datetime').datetime.now(timezone.utc).isoformat()}",
        "",
        "## Summary",
        "",
        f"- Scenarios run: **{metrics['scenarios_run']}**",
        f"- Events ingested: **{metrics['events_ingested']:,}**",
        f"- Alerts fired: **{metrics['alerts_fired']}**",
        f"- Expected alerts: **{metrics['expected_alerts']}**",
        "",
        "## Pass criteria",
        "",
        "| Metric | Value | Target | Pass |",
        "|---|---|---|---|",
        f"| Precision | {metrics['precision']['value']} | ≥{metrics['precision']['target']} | {'✓' if metrics['precision']['passed'] else '✗'} |",
        f"| Recall | {metrics['recall']['value']} | ≥{metrics['recall']['target']} | {'✓' if metrics['recall']['passed'] else '✗'} |",
        f"| Detection latency p50 | {metrics['detection_latency_ms']['p50']}ms | <{metrics['detection_latency_ms']['target_p50']}ms | {'✓' if metrics['detection_latency_ms']['passed_p50'] else '✗'} |",
        f"| Detection latency p99 | {metrics['detection_latency_ms']['p99']}ms | <{metrics['detection_latency_ms']['target_p99']}ms | {'✓' if metrics['detection_latency_ms']['passed_p99'] else '✗'} |",
        f"| CH query latency p99 | {metrics['ch_query_latency_ms']['p99']}ms | <{metrics['ch_query_latency_ms']['target']}ms | {'✓' if metrics['ch_query_latency_ms']['passed'] else '✗'} |",
        "",
        "## Per-scenario results",
        "",
        "| ID | Name | Alerts fired | Expected | Error |",
        "|---|---|---|---|---|",
    ]
    for s in metrics["per_scenario"]:
        lines.append(
            f"| {s['id']} | {s['name']} | {s['alerts_fired']} | {s['expected_alerts']} | {s['error'] or ''} |"
        )

    failures = []
    if not metrics["precision"]["passed"]:
        failures.append("Precision below target — check for false positives in benign scenarios")
    if not metrics["recall"]["passed"]:
        failures.append("Recall below target — check for missed attacks; review detection thresholds")
    if not metrics["detection_latency_ms"]["passed_p99"]:
        failures.append("Detection latency p99 above target — review MV-backed queries, ensure LLM classifier is cached")

    if failures:
        lines += ["", "## Failures", ""]
        for f in failures:
            lines.append(f"- {f}")

    lines += ["", "## Scenarios", ""]
    for path in scenario_paths:
        lines.append(f"- `{path}`")

    return "\n".join(lines) + "\n"
