"""
Sentinel Stream — eval runner.

Loads scenario YAMLs, drives the synthetic workload generator, polls the
API for alerts, computes metrics, writes a report.

Usage:
    python -m evals.runner --scenarios evals/scenarios/*.yaml --out evals/results/<ts>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml

from evals.metrics import compute_metrics, format_report


@dataclass
class ScenarioResult:
    scenario_id: str
    name: str
    events: list[dict] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    expected_alerts: list[dict] = field(default_factory=list)
    error: str | None = None


async def truncate_clickhouse(base_url: str) -> None:
    """Reset ClickHouse tables before each scenario."""
    async with httpx.AsyncClient() as client:
        # Assumes the API exposes a /v1/admin/truncate endpoint (dev mode only)
        try:
            await client.post(f"{base_url}/v1/admin/truncate", timeout=10)
        except httpx.HTTPError:
            pass  # endpoint may not exist in current build; ignore


async def drive_scenario(base_url: str, scenario: dict) -> ScenarioResult:
    """Drive a single scenario: start generator, poll alerts, collect events."""
    result = ScenarioResult(
        scenario_id=scenario["id"],
        name=scenario.get("name", scenario["id"]),
        expected_alerts=scenario.get("expected_alerts", []),
    )
    duration = scenario["duration_sec"]
    attack = scenario.get("attack", {})

    async with httpx.AsyncClient() as client:
        # Kick off the workload generator with this scenario's attack script
        try:
            await client.post(
                f"{base_url}/v1/demo/run_scenario",
                json={"scenario": scenario},
                timeout=10,
            )
        except httpx.HTTPError as e:
            result.error = f"Failed to start scenario: {e}"
            return result

        # Poll /v1/alerts every 100ms for duration_sec
        start = time.monotonic()
        seen_alert_ids: set[str] = set()
        while time.monotonic() - start < duration:
            try:
                resp = await client.get(
                    f"{base_url}/v1/alerts",
                    params={"since": int(start)},
                    timeout=2,
                )
                resp.raise_for_status()
                for alert in resp.json().get("alerts", []):
                    if alert["id"] not in seen_alert_ids:
                        seen_alert_ids.add(alert["id"])
                        result.alerts.append(alert)
            except httpx.HTTPError:
                pass  # transient; keep polling
            await asyncio.sleep(0.1)

        # Fetch events for forensic analysis (last 60s)
        try:
            resp = await client.get(
                f"{base_url}/v1/events",
                params={"limit": 10000, "since": int(start)},
                timeout=5,
            )
            resp.raise_for_status()
            result.events = resp.json().get("events", [])
        except httpx.HTTPError as e:
            result.error = f"Failed to fetch events: {e}"

    return result


async def run_scenario(base_url: str, scenario_path: Path) -> ScenarioResult:
    """Load a scenario YAML and run it end-to-end."""
    scenario = yaml.safe_load(scenario_path.read_text(encoding="utf-8"))
    await truncate_clickhouse(base_url)
    return await drive_scenario(base_url, scenario)


async def main_async(args: argparse.Namespace) -> int:
    base_url = args.api_url
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    scenario_paths = sorted(args.scenarios)
    print(f"Running {len(scenario_paths)} scenarios against {base_url}")

    results: list[ScenarioResult] = []
    for path in scenario_paths:
        print(f"  → {path.name}")
        result = await run_scenario(base_url, path)
        results.append(result)
        # Brief cooldown between scenarios
        await asyncio.sleep(2)

    metrics = compute_metrics(results)
    report = format_report(results, metrics, scenario_paths)

    # Write outputs
    (out_dir / "report.md").write_text(report, encoding="utf-8")
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    with (out_dir / "events.jsonl").open("w", encoding="utf-8") as f:
        for r in results:
            for e in r.events:
                f.write(json.dumps({"scenario": r.scenario_id, **e}) + "\n")
    with (out_dir / "alerts.jsonl").open("w", encoding="utf-8") as f:
        for r in results:
            for a in r.alerts:
                f.write(json.dumps({"scenario": r.scenario_id, **a}) + "\n")

    print(f"\nReport: {out_dir / 'report.md'}")
    print(f"Metrics: {out_dir / 'metrics.json'}")
    print(f"\nPass criteria:")
    for k, v in metrics.items():
        if isinstance(v, dict) and "target" in v:
            status = "✓" if v.get("passed") else "✗"
            print(f"  {status} {k}: {v.get('value')} (target {v.get('target')})")

    return 0 if all(m.get("passed", True) for m in metrics.values() if isinstance(m, dict)) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Sentinel Stream eval runner")
    parser.add_argument("--scenarios", nargs="+", required=True, help="Glob or list of scenario YAML paths")
    parser.add_argument("--out", required=True, help="Output directory for results")
    parser.add_argument("--api-url", default="http://localhost:8000", help="Sentinel Stream API base URL")
    args = parser.parse_args()

    # Expand globs
    scenario_paths: list[Path] = []
    for s in args.scenarios:
        p = Path(s)
        if p.is_dir():
            scenario_paths.extend(sorted(p.glob("*.yaml")))
        else:
            scenario_paths.append(p)
    args.scenarios = scenario_paths

    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
