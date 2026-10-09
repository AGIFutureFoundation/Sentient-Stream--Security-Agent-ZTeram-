# Sentinel Stream

[![CI](https://github.com/AGIFutureFoundation/sentinel-stream/actions/workflows/ci.yml/badge.svg)](https://github.com/AGIFutureFoundation/sentinel-stream/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![ClickHouse](https://img.shields.io/badge/ClickHouse-24.8-blue.svg)](https://clickhouse.com/)
[![Version](https://img.shields.io/badge/version-0.3.0-green.svg)](./CHANGELOG.md)

**Real-time threat detection for LLM agents.**
Stream every LLM event into ClickHouse. Detect prompt injection, tool abuse, and context exfiltration in <2 seconds. Show me the attack, not the dashboard.

> Built at the **Cyberdefense Hackathon** (San Francisco, Oct 9, 2025) for the ClickHouse Best Use of Real-Time Analytics prize.

---

## Why this exists

Every team shipping LLM agents has the same blind spot: they have no idea when an agent is being prompt-injected, when a tool is being abused, or when sensitive context is being exfiltrated through a model response. Sentinel Stream is the **detection layer for the agent era** — the SOC for AI.

## What it does

- **Ingest** every prompt, tool call, tool response, model response, retrieval, and action as an event
- **Store** in ClickHouse (MergeTree, per-minute partitions, materialized views for fast aggregation)
- **Detect** in real time using 3 rule families: prompt-injection signatures, tool-abuse baselines, context-exfil heuristics (+ optional LLM classifier)
- **Alert** with MITRE ATLAS technique labels and full event-chain evidence
- **Investigate** via a natural-language query box that translates analyst questions into sandboxed ClickHouse SQL

## Architecture

```
LLM app (SDK drop-in) ──┐
                        ├──→ FastAPI /v1/events ──→ ClickHouse (events, alerts, MVs)
Synthetic generator ────┘                  │                  │
                                           ▼                  ▼
                              Detection rules engine ──→ Alert cards
                                           │              (SSE live)
                                           ▼
                                  NL query → SQL → results
```

See [ROADMAP.md](./ROADMAP.md) for the full build plan and [docs/architecture.md](./docs/architecture.md) for component detail.

## Quickstart

```bash
# 1. Spin up ClickHouse + API + dashboard + generator
make demo

# 2. Open dashboard
open http://localhost:8000

# 3. Trigger an attack
curl -X POST http://localhost:8000/v1/demo/attack/prompt_injection
```

Or step by step:
```bash
cp .env.example .env
docker compose up -d clickhouse
python -m src.sentinel.api &           # API + dashboard on :8000
python -m src.generator.workload &     # synthetic event stream
```

## Evals

We use a multi-agent eval framework (`omega-claw/`) that runs 4 attack scenarios against the detection engine and scores precision / recall / detection latency.

```bash
make evals
# → runs evals/runner.py with evals/scenarios/*.yaml
# → writes results to evals/results/<timestamp>/
```

See [EVALS.md](./EVALS.md) for the eval methodology and [evals/README.md](./evals/README.md) for runner docs.

## Hacker-Bob integration (v0.2.0)

Sentinel Stream integrates with [hacker-bob](https://github.com/AGIFutureFoundation/hacker-bob) — an autonomous bug-bounty hunter with 17 credited CVEs — to close the **build → attack → detect loop**:

1. **Omega-Claw builds Sentinel Stream** (5 claws: data, detection, ui, evals, pentest)
2. **claw-pentest drives hacker-bob** to attack the built artifact via MCP stdio bridge
3. **Sentinel Stream detects** the attacks in real time as session-events flow into ClickHouse

See [INTEGRATION.md](./INTEGRATION.md) for the full design.

**New since v0.1.0:**
- `claw-pentest` agent + MCP bridge client (`omega-claw/mcp_bridge.py`)
- `tail_bob_sessions()` ingester — real offensive traffic replaces synthetic generator
- `<<UNTRUSTED_DATA>>` envelope detector — 4th detection rule family
- `from_asff()` adapter — hacker-bob findings appear as Sentinel Stream alerts
- `evals/scenarios/s4-real-cve-replay.yaml` — real CVE replay scenario
- `scripts/push-to-github.sh` — one-command GitHub push helper

```bash
# Quickstart hacker-bob integration
npm install --global hacker-bob@latest
make bob-health          # verify install
make omega-pentest       # run the pentest track
make bob-tail            # ingest hacker-bob session events
```

## Omega-Claw multi-agent framework

We built Sentinel Stream itself using a multi-agent orchestration framework called **Omega-Claw**:

- **Omega** = the orchestrator agent. Decomposes the build into tasks, dispatches to claws, reviews outputs.
- **Claws** = worker agents, each with a single specialty (data, detection, UI, evals) and their own console log.

See [omega-claw/README.md](./omega-claw/README.md) for the framework, [omega-claw/consoles/](./omega-claw/consoles/) for the live build logs, and [omega-claw/metaprompts/](./omega-claw/metaprompts/) for the prompt templates.

## Tech stack

| Layer | Choice |
|---|---|
| Backend | FastAPI 0.115 + uvicorn |
| DB | ClickHouse (Cloud trial or self-hosted Docker) |
| DB driver | `clickhouse-connect` |
| LLM SDK | `litellm` (model-agnostic) |
| Frontend | HTMX + Tailwind (zero build step) |
| Container | docker-compose (3 services) |

## Team

- [Your name] — backend / data / detection
- [Teammate name] — UI / detection / evals

## License

MIT.
