"""
Sentinel Stream — synthetic workload generator.

Simulates 3-5 agents emitting events at 30-100 events/sec each. Mixes in
scripted attack sequences every 60-90s.

Usage:
    python -m src.generator.workload --duration 60 --rate 200
    python -m src.generator.workload --duration 0   # run forever
"""
from __future__ import annotations

import argparse
import asyncio
import os
import random
import string
import time
from typing import Any

import httpx

API_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:8000")
EVENT_RATE_PER_SEC = int(os.environ.get("EVENT_RATE_PER_SEC", "200"))
ATTACK_INTERVAL_SEC = int(os.environ.get("ATTACK_INTERVAL_SEC", "90"))

AGENTS = [
    {"id": "agent-1", "role": "customer-support-bot", "tools": ["search.query", "http.get"]},
    {"id": "agent-2", "role": "code-review-bot", "tools": ["filesystem.read", "http.get"]},
    {"id": "agent-3", "role": "research-assistant", "tools": ["search.query", "vector.search", "http.get"]},
]

BENIGN_PROMPTS = [
    "What is the return policy for electronics?",
    "Summarize this code change for the PR review.",
    "Find recent papers on retrieval-augmented generation.",
    "How do I reset my account password?",
    "Explain this function's purpose.",
    "Search for documentation on OAuth 2.0.",
    "What's the latest status on ticket #4821?",
    "Translate this error message to plain English.",
    "Generate a SQL query for monthly active users.",
    "Recommend a library for parsing PDFs.",
]

EVENT_TYPES = ["prompt", "tool_call", "tool_response", "model_response", "retrieval"]


async def emit_event(client: httpx.AsyncClient, event: dict[str, Any]) -> None:
    try:
        await client.post(f"{API_URL}/v1/events", json={"events": [event]}, timeout=5)
    except httpx.HTTPError as e:
        # Suppress noisy errors in synthetic loop
        _ = e


def make_benign_event(agent: dict[str, str]) -> dict[str, Any]:
    etype = random.choice(EVENT_TYPES)
    tool = random.choice(agent["tools"]) if etype in ("tool_call", "tool_response") else ""
    payload = random.choice(BENIGN_PROMPTS) if etype == "prompt" else _random_payload(etype)
    return {
        "id": _random_id(),
        "ts": _now_iso(),
        "agent_id": agent["id"],
        "app_id": "demo-app",
        "event_type": etype,
        "tool_name": tool,
        "payload": payload,
        "tokens_in": random.randint(20, 500),
        "tokens_out": random.randint(50, 1000),
        "user_id": f"user-{random.randint(1,5)}",
        "session_id": _random_id(),
        "risk_score": 0.0,
        "flags": [],
    }


async def run_workload(duration_sec: int, rate_per_sec: int) -> None:
    """Emit events at the given rate for the given duration. 0 = forever."""
    interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 0.01
    start = time.monotonic()
    async with httpx.AsyncClient() as client:
        next_attack_at = time.monotonic() + ATTACK_INTERVAL_SEC
        attack_idx = 0
        events_sent = 0
        print(f"Generator started: rate={rate_per_sec}/s duration={'forever' if duration_sec == 0 else duration_sec}s")
        while duration_sec == 0 or (time.monotonic() - start) < duration_sec:
            # emit one event
            agent = random.choice(AGENTS)
            ev = make_benign_event(agent)
            await emit_event(client, ev)
            events_sent += 1

            # scripted attack?
            if time.monotonic() >= next_attack_at:
                attack = ["prompt_injection", "tool_abuse", "context_exfil"][attack_idx % 3]
                print(f"  → firing scripted attack: {attack}")
                await fire_attack(client, attack)
                attack_idx += 1
                next_attack_at = time.monotonic() + ATTACK_INTERVAL_SEC

            await asyncio.sleep(interval)
        print(f"Generator done: {events_sent} events sent")


async def fire_attack(client: httpx.AsyncClient, attack_type: str) -> None:
    try:
        await client.post(f"{API_URL}/v1/demo/attack/{attack_type}", json={}, timeout=5)
    except httpx.HTTPError:
        pass


def _random_id() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=12))


def _random_payload(etype: str) -> str:
    if etype == "model_response":
        return random.choice([
            "Here's the summary you requested.",
            "Based on my analysis, the recommendation is to proceed.",
            "I found 3 relevant documents in your knowledge base.",
            "The code looks good overall. Suggest minor refactoring on line 42.",
        ])
    if etype == "retrieval":
        return f"Retrieved chunk {random.randint(1,100)} from vector store (score {random.uniform(0.6, 0.95):.2f})"
    if etype == "tool_call":
        return f"calling tool with args: {{'query': '...'}}"
    return "ok"


def _now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Sentinel Stream synthetic workload generator")
    parser.add_argument("--duration", type=int, default=60, help="Seconds to run (0 = forever)")
    parser.add_argument("--rate", type=int, default=EVENT_RATE_PER_SEC, help="Events per second")
    args = parser.parse_args()
    asyncio.run(run_workload(args.duration, args.rate))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
