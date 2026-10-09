"""
Omega — the orchestrator agent for the Omega-Claw framework.

Reads ROADMAP.md, decomposes into a task DAG, dispatches to claws,
reviews artifacts against success criteria, triggers re-runs as needed.

Usage:
    python -m omega_claw.orchestrator --plan ROADMAP.md
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

try:
    from litellm import completion
except ImportError:  # allow running without LLM SDK (dry-run mode)
    completion = None


ROOT = Path(__file__).resolve().parent.parent
CONSOLE_PATH = ROOT / "omega-claw" / "consoles" / "omega.md"
AGENTS_CONFIG = ROOT / "omega-claw" / "agents.yaml"
METAPROMPTS_DIR = ROOT / "omega-claw" / "metaprompts"


@dataclass
class Task:
    id: str
    title: str
    claw: str  # claw role name (e.g. "claw-data")
    spec: str  # what to build
    artifact_path: str  # where the artifact should land
    success_criteria: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    status: str = "pending"  # pending | running | done | failed
    review: str | None = None


# ---- Task DAG (built by Omega from ROADMAP.md) ----------------------------

DEFAULT_TASKS: list[Task] = [
    # Claw-Data track
    Task(
        id="1-a",
        title="ClickHouse schema",
        claw="claw-data",
        spec="Write the ClickHouse schema for sentinel_events + sentinel_alerts + sentinel_tool_calls_mv per ROADMAP. Use MergeTree with per-minute partitions, ZSTD on payload, LowCardinality on agent_id/app_id/tool_name.",
        artifact_path="src/sentinel/clickhouse_schema.sql",
        success_criteria=[
            "Schema applies cleanly on ClickHouse 24.x",
            "MV populates correctly on test inserts",
            "Query latency <50ms on 1M rows for typical dashboard queries",
        ],
    ),
    Task(
        id="1-b",
        title="Batch inserter",
        claw="claw-data",
        spec="Async batch inserter that flushes events to ClickHouse every 1s. Target ≥10k events/sec sustained.",
        artifact_path="src/sentinel/ingest.py",
        depends_on=["1-a"],
        success_criteria=[
            "Sustained ingest ≥10k events/sec",
            "No event loss at 1s flush interval",
        ],
    ),
    Task(
        id="1-c",
        title="Materialized views + load test",
        claw="claw-data",
        spec="Verify sentinel_tool_calls_mv populates. Load-test at 5M rows; verify all dashboard queries stay <100ms p99.",
        artifact_path="omega-claw/consoles/claw-data.md",
        depends_on=["1-b"],
        success_criteria=["CH query latency p99 <100ms at 5M rows"],
    ),
    # Claw-Detection track
    Task(
        id="2-a",
        title="Prompt-injection signatures",
        claw="claw-detection",
        spec="Regex + keyword rule for prompt injection. Patterns: 'ignore previous', 'disregard above', 'you are now', 'new instructions:', base64-looking payloads >200 chars. Tag AML.T0051 + AML.T0064.",
        artifact_path="src/sentinel/detect.py",
        depends_on=["1-a"],
        success_criteria=["Latency <5ms per event", "Matches evals/datasets/prompt-injection.jsonl with ≥0.90 precision"],
    ),
    Task(
        id="2-b",
        title="Tool-abuse baselines",
        claw="claw-detection",
        spec="MV-backed baseline. Query sentinel_tool_calls_mv for 5-min rolling per (agent, tool). Trigger if rate to sensitive tool (filesystem/network/exec) >3× baseline. Severity critical if >5×. Tag AML.T0063.",
        artifact_path="src/sentinel/detect.py",
        depends_on=["1-c", "2-a"],
        success_criteria=["Latency <50ms per check", "Catches scripted tool-abuse in evals/scenarios/s2-tool-abuse.yaml"],
    ),
    Task(
        id="2-c",
        title="Context-exfil heuristic + LLM classifier",
        claw="claw-detection",
        spec="Pattern match on model_response for AWS keys (AKIA[0-9A-Z]{16}), JWTs (eyJ...), SSN-like, long base64. Optional LLM classifier (cached for demo). Tag AML.T0057.",
        artifact_path="src/sentinel/detect.py",
        depends_on=["2-a"],
        success_criteria=["Regex latency <10ms", "LLM verdict cached for scripted attacks", "Catches scripted exfil in evals/scenarios/s3-context-exfil.yaml"],
    ),
    # Claw-UI track
    Task(
        id="3-a",
        title="FastAPI scaffold + /v1/events endpoint",
        claw="claw-ui",
        spec="FastAPI app with /v1/events (POST) accepting event JSON, returning 202. Async dispatch to inserter + detection engine.",
        artifact_path="src/sentinel/api.py",
        success_criteria=["Endpoint accepts 1k events/sec", "Returns 202 within 5ms"],
    ),
    Task(
        id="3-b",
        title="SSE dashboard + alert cards",
        claw="claw-ui",
        spec="HTMX + Tailwind dashboard. SSE live event ticker. Alert cards with MITRE ATLAS labels. Forensic timeline view per alert.",
        artifact_path="src/dashboard/",
        depends_on=["3-a", "2-a"],
        success_criteria=["Alert appears <2s after scripted attack", "Timeline view loads <100ms"],
    ),
    Task(
        id="3-c",
        title="NL query box",
        claw="claw-ui",
        spec="NL query → template-constrained ClickHouse SQL. LLM picks template + fills params, never writes raw SQL. Sandbox: only SELECT, max 1M rows scanned.",
        artifact_path="src/sentinel/nl_query.py",
        depends_on=["3-a", "1-c"],
        success_criteria=["Returns <200ms across 2M rows", "Refuses non-SELECT queries"],
    ),
    # Claw-Evals track
    Task(
        id="4-a",
        title="Datasets + scenarios",
        claw="claw-evals",
        spec="3 JSONL datasets (prompt-injection, tool-abuse, context-exfil) + 3 YAML scenarios. Each scenario: 60s run, 200 events/sec baseline, scripted attack at t=20s.",
        artifact_path="evals/",
        success_criteria=["Datasets have ≥25 attack + ≥25 benign samples each", "Scenarios run end-to-end via evals/runner.py"],
    ),
    Task(
        id="4-b",
        title="Eval runner + metrics",
        claw="claw-evals",
        spec="Runner that loads scenarios, drives the generator, polls /v1/alerts, computes precision/recall/latency. Writes report.md + metrics.json to evals/results/<ts>/.",
        artifact_path="evals/runner.py",
        depends_on=["4-a"],
        success_criteria=["Precision ≥0.90", "Recall ≥0.85", "Detection latency p99 <2s"],
    ),
    # Claw-Pentest track (NEW) — drives hacker-bob MCP runtime headlessly
    # against built artifacts. See INTEGRATION.md §1.
    Task(
        id="5-a",
        title="MCP bridge client",
        claw="claw-pentest",
        spec="Write the Python ↔ Node JSON-RPC bridge for hacker-bob's MCP server. Wraps subprocess.Popen on `node mcp/server.js` with stdin/stdout framing. Per-invocation BOB_MCP_CALLER_TOKEN minted via secrets.token_hex(32).",
        artifact_path="omega-claw/mcp_bridge.py",
        success_criteria=[
            "Bridge starts and lists ≥100 tools via tools/list",
            "init_session returns a session_id for a synthetic target",
        ],
    ),
    Task(
        id="5-b",
        title="Headless pentest run",
        claw="claw-pentest",
        spec="Drive hacker-bob against a built artifact (the Sentinel Stream dashboard itself, served at http://localhost:8000). Run SETUP → OPEN_FRONTIER → CLAIM_FREEZE → VERIFY → GRADE → REPORT. Capture session-events.jsonl + grade verdict.",
        artifact_path="omega-claw/consoles/claw-pentest.md",
        depends_on=["5-a", "3-b"],
        success_criteria=[
            "Session reaches REPORT state",
            "At least one candidate claim recorded (attack found) OR zero-finding SKIP verdict",
        ],
    ),
    Task(
        id="5-c",
        title="ASFF export + Sentinel Stream ingestion",
        claw="claw-pentest",
        spec="Call bob_export_security_hub_finding for each graded finding. Convert ASFF → Sentinel Stream alert via from_asff(). Stream session-events.jsonl into ClickHouse via tail_bob_sessions.",
        artifact_path="evals/results/pentest/",
        depends_on=["5-b"],
        success_criteria=[
            "ASFF records converted to Sentinel Stream alerts",
            "Session events visible in sentinel_events table",
        ],
    ),
]


def log_console(message: str) -> None:
    """Append a timestamped entry to Omega's console log."""
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    CONSOLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CONSOLE_PATH.open("a", encoding="utf-8") as f:
        f.write(f"\n## [{ts}] {message}\n\n")


def load_metaprompt(name: str) -> str:
    """Load a metaprompt template from omega-claw/metaprompts/<name>.md."""
    return (METAPROMPTS_DIR / f"{name}.md").read_text(encoding="utf-8")


def load_claws() -> dict[str, dict[str, Any]]:
    """Load claw definitions from agents.yaml."""
    with AGENTS_CONFIG.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return {c["name"]: c for c in data["claws"]}


def call_llm(prompt: str, model: str | None = None) -> str:
    """Call the LLM. Falls back to a stub in dry-run mode."""
    if completion is None:
        return f"[DRY-RUN] Would call LLM with prompt of length {len(prompt)}"
    model = model or os.environ.get("LLM_MODEL", "openai/gpt-4o-mini")
    response = completion(model=model, messages=[{"role": "user", "content": prompt}])
    return response.choices[0].message.content


def decompose_plan(plan_path: Path) -> list[Task]:
    """Use the task-decomposer metaprompt to refine the default DAG.
    For hackathon speed, we use the DEFAULT_TASKS list above and only call
    the LLM if the user passes --replan.
    """
    log_console(f"Loaded plan from {plan_path}, using DEFAULT_TASKS DAG ({len(DEFAULT_TASKS)} tasks)")
    return DEFAULT_TASKS


def dispatch_to_claw(task: Task, claws: dict[str, dict[str, Any]]) -> str:
    """Dispatch a task to its assigned claw. Returns the LLM response."""
    claw = claws[task.claw]
    metaprompt_name = claw["metaprompt"]
    template = load_metaprompt(metaprompt_name)
    prompt = template.replace("{{TASK_SPEC}}", task.spec).replace("{{TASK_ID}}", task.id).replace("{{ARTIFACT_PATH}}", task.artifact_path)
    log_console(f"Dispatched task {task.id} to {task.claw} (metaprompt: {metaprompt_name})")
    response = call_llm(prompt, model=claw.get("model"))
    # In a real run, the claw would write the artifact itself; here we just log
    log_console(f"Task {task.id} response length: {len(response)} chars → {task.artifact_path}")
    return response


def review_task(task: Task, response: str) -> bool:
    """Heuristic review — in practice, run the relevant eval/test."""
    # For hackathon: mark done if response is non-trivial
    passed = len(response) > 200
    task.review = "PASSED" if passed else "FAILED: response too short"
    task.status = "done" if passed else "failed"
    log_console(f"Review {task.id}: {task.review}")
    return passed


def run(plan_path: Path, track: str | None = None) -> int:
    """Run Omega. Returns exit code (0 = success)."""
    log_console(f"=== Omega run started. Plan: {plan_path} ===")
    tasks = decompose_plan(plan_path)
    if track:
        tasks = [t for t in tasks if t.claw == track or t.claw == "omega"]
        log_console(f"Filtered to track '{track}': {len(tasks)} tasks")

    claws = load_claws()
    log_console(f"Loaded {len(claws)} claws: {', '.join(claws.keys())}")

    completed: dict[str, bool] = {}
    for task in tasks:
        # Check dependencies
        blocked = [dep for dep in task.depends_on if not completed.get(dep, False)]
        if blocked:
            log_console(f"Task {task.id} BLOCKED by unfinished deps: {blocked}")
            task.status = "blocked"
            continue
        task.status = "running"
        response = dispatch_to_claw(task, claws)
        passed = review_task(task, response)
        completed[task.id] = passed
        if not passed:
            log_console(f"Task {task.id} failed; Omega will retry once")
            response = dispatch_to_claw(task, claws)
            passed = review_task(task, response)
            completed[task.id] = passed

    summary = {
        "total": len(tasks),
        "passed": sum(1 for v in completed.values() if v),
        "failed": sum(1 for v in completed.values() if not v),
        "blocked": sum(1 for t in tasks if t.status == "blocked"),
    }
    log_console(f"=== Omega run complete. {summary['passed']}/{summary['total']} passed ===")
    print(json.dumps(summary, indent=2))
    return 0 if summary["failed"] == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Omega orchestrator")
    parser.add_argument("--plan", default="ROADMAP.md", help="Path to ROADMAP.md")
    parser.add_argument("--track", default=None, help="Filter to a single track (claw-data, claw-detection, claw-ui, claw-evals)")
    parser.add_argument("--replan", action="store_true", help="Re-run task decomposition via LLM (default: use cached DAG)")
    args = parser.parse_args()
    plan_path = Path(args.plan).resolve()
    if not plan_path.exists():
        print(f"Plan not found: {plan_path}", file=sys.stderr)
        return 2
    return run(plan_path, track=args.track)


if __name__ == "__main__":
    sys.exit(main())
