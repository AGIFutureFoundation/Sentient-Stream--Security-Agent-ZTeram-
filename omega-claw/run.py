"""
CLI entry point for the Omega-Claw framework.

Usage:
    python -m omega_claw.run --plan ROADMAP.md
    python -m omega_claw.run --track evals
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from omega_claw.orchestrator import run as run_omega


def main() -> int:
    parser = argparse.ArgumentParser(description="Omega-Claw multi-agent build runner")
    parser.add_argument("--plan", default="ROADMAP.md")
    parser.add_argument("--track", default=None,
                        help="Run only one track: claw-data | claw-detection | claw-ui | claw-evals")
    parser.add_argument("--dry-run", action="store_true",
                        help="Skip LLM calls; just log the dispatch sequence")
    args = parser.parse_args()

    plan_path = Path(args.plan).resolve()
    if not plan_path.exists():
        print(f"Plan not found: {plan_path}", file=sys.stderr)
        return 2

    return run_omega(plan_path, track=args.track)


if __name__ == "__main__":
    sys.exit(main())
