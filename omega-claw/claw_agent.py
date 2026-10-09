"""
Claw — generic worker agent for the Omega-Claw framework.

Each claw:
1. Loads its metaprompt template from omega-claw/metaprompts/<role>.md
2. Receives a task spec from Omega
3. Fills the metaprompt, calls the LLM
4. Writes the artifact to its owned path
5. Appends an entry to its console log at omega-claw/consoles/<role>.md

Usage:
    python -m omega_claw.claw_agent --role claw-data --task-id 1-a
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

try:
    from litellm import completion
except ImportError:
    completion = None

import yaml

ROOT = Path(__file__).resolve().parent.parent
AGENTS_CONFIG = ROOT / "omega-claw" / "agents.yaml"
METAPROMPTS_DIR = ROOT / "omega-claw" / "metaprompts"
CONSOLES_DIR = ROOT / "omega-claw" / "consoles"


def load_claw(role: str) -> dict:
    with AGENTS_CONFIG.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    for c in data["claws"]:
        if c["name"] == role:
            return c
    raise ValueError(f"Unknown claw role: {role}")


def console_log(role: str, message: str) -> None:
    """Append a timestamped entry to a claw's console log."""
    log_path = CONSOLES_DIR / f"{role}.md"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    with log_path.open("a", encoding="utf-8") as f:
        f.write(f"\n## [{ts}] {message}\n\n")


def call_llm(prompt: str, model: str | None = None) -> str:
    if completion is None:
        return f"[DRY-RUN] Would call LLM with prompt of length {len(prompt)}"
    model = model or os.environ.get("LLM_MODEL", "openai/gpt-4o-mini")
    response = completion(model=model, messages=[{"role": "user", "content": prompt}])
    return response.choices[0].message.content


def run_task(role: str, task_id: str, task_spec: str, artifact_path: str) -> str:
    """Run a single task as the given claw role."""
    claw = load_claw(role)
    metaprompt_template = (METAPROMPTS_DIR / f"{claw['metaprompt']}.md").read_text(encoding="utf-8")
    prompt = (
        metaprompt_template
        .replace("{{TASK_ID}}", task_id)
        .replace("{{TASK_SPEC}}", task_spec)
        .replace("{{ARTIFACT_PATH}}", artifact_path)
    )

    console_log(role, f"Task {task_id} started. Spec: {task_spec[:200]}...")
    console_log(role, f"Metaprompt: {claw['metaprompt']}.md (filled length: {len(prompt)} chars)")

    response = call_llm(prompt, model=claw.get("model"))
    console_log(role, f"LLM response received ({len(response)} chars)")

    # Write the artifact
    out_path = ROOT / artifact_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if artifact_path.endswith(".md"):
        # Console-style artifact: append
        with out_path.open("a", encoding="utf-8") as f:
            f.write(response + "\n")
    else:
        out_path.write_text(response, encoding="utf-8")
    console_log(role, f"Artifact written: {artifact_path}")

    return response


def main() -> int:
    parser = argparse.ArgumentParser(description="Claw worker agent")
    parser.add_argument("--role", required=True, help="Claw role (e.g. claw-data)")
    parser.add_argument("--task-id", required=True, help="Task ID from Omega's DAG")
    parser.add_argument("--task-spec", required=True, help="Task specification (what to build)")
    parser.add_argument("--artifact-path", required=True, help="Where to write the artifact")
    args = parser.parse_args()
    run_task(args.role, args.task_id, args.task_spec, args.artifact_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
