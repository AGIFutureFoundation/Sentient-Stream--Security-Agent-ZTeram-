"""
Sentinel Stream — Heartbeat agent.

Loops every 60s, checks build health, appends to HEARTBEAT.md.
Used during the 1-hour build loop to track progress across 3 phases.
"""
from __future__ import annotations

import argparse
import os
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # scripts/ → sentinel-stream/
HEARTBEAT_PATH = ROOT / "HEARTBEAT.md"


def check_file(path: Path) -> bool:
    return path.exists() and path.stat().st_size > 0


def check_phase(phase: str) -> dict:
    """Return dict of {artifact: bool} for the given phase."""
    if phase == "p1":
        return {
            "src/sentinel/clickhouse_schema.sql": check_file(ROOT / "src/sentinel/clickhouse_schema.sql"),
            "src/sentinel/ingest.py": check_file(ROOT / "src/sentinel/ingest.py"),
            "src/sentinel/detect.py": check_file(ROOT / "src/sentinel/detect.py"),
            "src/sentinel/alert.py": check_file(ROOT / "src/sentinel/alert.py"),
            "src/sentinel/api.py": check_file(ROOT / "src/sentinel/api.py"),
            "src/sentinel/nl_query.py": check_file(ROOT / "src/sentinel/nl_query.py"),
            "src/generator/workload.py": check_file(ROOT / "src/generator/workload.py"),
            "src/dashboard/templates/index.html": check_file(ROOT / "src/dashboard/templates/index.html"),
            "evals/datasets/prompt-injection.jsonl": check_file(ROOT / "evals/datasets/prompt-injection.jsonl"),
            "evals/datasets/tool-abuse.jsonl": check_file(ROOT / "evals/datasets/tool-abuse.jsonl"),
            "evals/datasets/context-exfil.jsonl": check_file(ROOT / "evals/datasets/context-exfil.jsonl"),
            "evals/scenarios/s1-prompt-injection.yaml": check_file(ROOT / "evals/scenarios/s1-prompt-injection.yaml"),
            "evals/scenarios/s2-tool-abuse.yaml": check_file(ROOT / "evals/scenarios/s2-tool-abuse.yaml"),
            "evals/scenarios/s3-context-exfil.yaml": check_file(ROOT / "evals/scenarios/s3-context-exfil.yaml"),
        }
    if phase == "p2":
        return {
            "docs/WHITEPAPER.md": check_file(ROOT / "docs/WHITEPAPER.md"),
            "docs/architecture.md": check_file(ROOT / "docs/architecture.md"),
            "tests/test_detect.py": check_file(ROOT / "tests/test_detect.py"),
            "tests/test_nl_query.py": check_file(ROOT / "tests/test_nl_query.py"),
        }
    if phase == "p3":
        return {
            "docs/PITCH_DECK.md": check_file(ROOT / "docs/PITCH_DECK.md"),
            "pitch-deck/index.html": check_file(ROOT / "pitch-deck/index.html"),
            "docs/VIDEO_SCRIPT.md": check_file(ROOT / "docs/VIDEO_SCRIPT.md"),
            "demo-video/index.html": check_file(ROOT / "demo-video/index.html"),
        }
    return {}


def append_heartbeat(phase: str, elapsed_min: float) -> None:
    checks = check_phase(phase)
    passed = sum(1 for v in checks.values() if v)
    total = len(checks)
    status = "✅" if passed == total else ("⚠️" if passed > 0 else "❌")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with HEARTBEAT_PATH.open("a", encoding="utf-8") as f:
        f.write(f"\n## [{ts}] Phase {phase} heartbeat — {elapsed_min:.1f}min elapsed — {status}\n\n")
        f.write(f"**{passed}/{total} artifacts present.**\n\n")
        f.write("| Artifact | Status |\n|---|---|\n")
        for path, ok in checks.items():
            f.write(f"| `{path}` | {'✅' if ok else '❌'} |\n")
        f.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Sentinel Stream heartbeat")
    parser.add_argument("--phase", required=True, choices=["p1", "p2", "p3"])
    parser.add_argument("--elapsed-min", type=float, required=True)
    args = parser.parse_args()

    if not HEARTBEAT_PATH.exists():
        HEARTBEAT_PATH.write_text("# Sentinel Stream — Build Heartbeat\n\n", encoding="utf-8")

    append_heartbeat(args.phase, args.elapsed_min)
    print(f"Heartbeat written for phase {args.phase}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
