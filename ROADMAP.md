# Sentinel Stream — Build Roadmap

**Hackathon:** Cyberdefense (SF, Oct 9, 2025)
**Build window:** ~5 hours (11:00 AM – 4:30 PM PT)
**Team:** 2 people
**Target prize:** ClickHouse Best Use of Real-Time Analytics ($1,000 + $500 credits)
**Scope:** Polished MVP

---

## Mission

Ship a working real-time threat detection layer for LLM agents that demonstrates, live in the demo, that ClickHouse can ingest millions of events and return detection queries in <100ms.

## Success Criteria (judge-visible)

1. Live dashboard shows a streaming event ticker (≥200 events/sec synthetic).
2. When an attack is injected, an alert card appears in <2s with MITRE ATLAS label and full event chain.
3. A natural-language query ("show all agents that called filesystem after 'ignore previous'") returns in <200ms across 2M+ rows.
4. All of the above runs from `make demo` in under 60 seconds on a clean machine.

## ClickHouse prize fit (the 3 judging criteria)

| Criterion | How Sentinel Stream demonstrates it |
|---|---|
| **Data scale** | Every LLM event is captured. Synthetic generator proves 5M+ rows during the 90s demo; production trajectory cited at 5M events/day for a mid-size agent fleet. |
| **Query/response latency** | Materialized views (`sentinel_tool_calls_mv`) + per-minute partitioning keep every dashboard query under 100ms. Live query-timer display in the dashboard footer. |
| **Insights drive detection** | Alerts fire in real time with MITRE ATLAS labels, recommended remediation, and forensic event chains — not just charts. |

---

## Architecture

```
┌─────────────────────────┐     ┌──────────────────────────┐
│  Synthetic agent        │     │  Real LLM apps (optional │
│  workload generator     │     │  SDK drop-in, demo later)│
│  (Python asyncio)       │     │                          │
└───────────┬─────────────┘     └──────────────┬───────────┘
            │ events (JSON over HTTP)          │
            ▼                                  ▼
   ┌────────────────────────────────────────────────────┐
   │  Ingestion API  (FastAPI, /v1/events, async)        │
   │  • validates + enriches (agent_id, ts, event_type)  │
   │  • pushes to ClickHouse batch inserter (1s flush)   │
   │  • runs stream rules engine inline (sync alerts)    │
   └───────────────┬────────────────────────┬───────────┘
                   │                        │
                   ▼                        ▼
   ┌──────────────────────┐   ┌──────────────────────────────┐
   │  ClickHouse          │   │  Detection rules engine       │
   │  • events MergeTree  │   │  • prompt-injection sigs       │
   │  • alerts MergeTree  │   │  • tool-abuse baselines        │
   │  • materialized views│   │  • context-exfil heuristics   │
   │  • 1-min partitions  │   │  • LLM semantic classifier   │
   └──────────┬───────────┘   └─────────────┬────────────────┘
              │                              │
              ▼                              ▼
   ┌─────────────────────────────────────────────────────────┐
   │  Dashboard (FastAPI + HTMX + Tailwind, SSE)              │
   │  • live event ticker (SSE)                              │
   │  • alert cards with MITRE ATLAS labels                 │
   │  • NL query box → ClickHouse SQL (LLM-translated)      │
   │  • forensic timeline view per alert                    │
   └─────────────────────────────────────────────────────────┘
```

## ClickHouse Schema

See [`src/sentinel/clickhouse_schema.sql`](./src/sentinel/clickhouse_schema.sql). Key design choices:

- **`MergeTree` engine** with per-minute partitioning — old partitions can be dropped/tiered, hot partitions stay in memory.
- **`ORDER BY (app_id, agent_id, ts)`** — optimizes the most common query pattern (per-agent time-range scans).
- **`ZSTD` codec** on `payload` — typical LLM payloads compress 3–5×.
- **`LowCardinality(String)`** on `agent_id`, `app_id`, `tool_name` — these have low cardinality in practice.
- **Materialized view `sentinel_tool_calls_mv`** — pre-aggregates per-(agent, tool, minute) counts so the tool-abuse detector reads pre-aggregated data, not raw events.
- **`Array(String)` for `flags`** — multi-label classification without join tables.

## Detection rules (3 families, ship all 3)

### 1. Prompt-injection signatures (`src/sentinel/detect.py`)
- **Pattern match** on incoming prompts: `ignore previous`, `disregard above`, `you are now`, `new instructions:`, base64-looking payloads (>200 chars of `[A-Za-z0-9+/=]`).
- **Severity**: `high` for explicit override phrases, `med` for suspicion patterns.
- **MITRE ATLAS**: tag with `AML.T0051` (LLM Prompt Injection) and `AML.T0064` (LLM Jailbreak).
- **Latency target**: <5ms per event (pure regex).

### 2. Tool-abuse baselines
- **Query `sentinel_tool_calls_mv`** for 5-minute rolling baseline per (agent, tool).
- **Trigger**: call rate to a sensitive tool (filesystem, network, exec) exceeds 3× baseline.
- **Severity**: `critical` if the tool is on the sensitive list AND rate >5× baseline, else `high`.
- **MITRE ATLAS**: `AML.T0063` (ML Supply Chain Compromise) for tool-poisoning patterns, `AML.T0040` (ML Model Stealing) for bulk extraction patterns.
- **Latency target**: <50ms per check (MV-backed aggregation).

### 3. Context-exfil heuristics
- **Pattern match** on `model_response` payloads: AWS keys (`AKIA[0-9A-Z]{16}`), JWTs (`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), SSN-like strings, long base64 blobs (>1KB).
- **Optional LLM classifier**: route suspected responses to LLM for yes/no exfil verdict (cached for demo).
- **Severity**: `critical` if pattern confirmed, `high` if LLM says yes, `med` for suspicion only.
- **MITRE ATLAS**: `AML.T0057` (Data Exfiltration from ML Model).
- **Latency target**: <10ms regex, <2s LLM (cached for scripted attacks in demo).

---

## Omega-Claw build orchestration

Sentinel Stream is built by a 5-agent team using the **Omega-Claw** framework (see [`omega-claw/`](./omega-claw/)):

| Agent | Role | Owns |
|---|---|---|
| **Omega** (orchestrator) | Task decomposition, dispatch, review, integration | `omega-claw/orchestrator.py`, `omega-claw/consoles/omega.md` |
| **Claw-Data** | ClickHouse schema, ingestion, MVs, load test | `src/sentinel/clickhouse_schema.sql`, `src/sentinel/ingest.py` |
| **Claw-Detection** | 3 detection rules, alert writer, MITRE ATLAS labels | `src/sentinel/detect.py`, `src/sentinel/alert.py` |
| **Claw-UI** | Dashboard, SSE live updates, NL query box | `src/dashboard/`, `src/sentinel/nl_query.py` |
| **Claw-Evals** | Attack scenarios, datasets, runner, metrics | `evals/` |

Each claw runs from a metaprompt template in [`omega-claw/metaprompts/`](./omega-claw/metaprompts/) and writes a console log to [`omega-claw/consoles/`](./omega-claw/consoles/). The orchestrator reviews outputs against the success criteria above and triggers re-runs as needed.

See [omega-claw/README.md](./omega-claw/README.md) for the framework docs.

## Evals

3 attack scenarios + benign-baseline scenario, scored on:

| Metric | Target |
|---|---|
| Detection precision | ≥0.90 (no false positives on benign workload) |
| Detection recall | ≥0.85 (catches all scripted attacks) |
| Detection latency (p50) | <500ms from event-ingest to alert-fired |
| Detection latency (p99) | <2s |
| ClickHouse query latency (p99) | <100ms across 5M rows |

See [EVALS.md](./EVALS.md) for methodology and [evals/README.md](./evals/README.md) for runner docs.

---

## Day-of Timeline (5 hours, 2 humans + 5 agents)

| Time | Person A (data/backend) | Person B (detection/UI) | Omega-Claw |
|---|---|---|---|
| 0:00–0:15 | ClickHouse Cloud signup (Docker fallback ready at min 15) | Scaffold repo, `cp .env.example .env` | Omega dispatches setup tasks to Claw-Data + Claw-UI |
| 0:15–0:45 | Schema + batch inserter; validate 10k events/s ingest | FastAPI `/v1/events` endpoint returning 202; dashboard skeleton (HTMX CDN) | Claw-Data writes schema; Claw-UI scaffolds dashboard |
| 0:45–1:15 | Materialized views; verify <50ms on 1M rows | Synthetic generator: 3 agents, mixed events, no attacks yet | Claw-Data validates MVs; Claw-UI runs generator |
| 1:15–1:45 | Alert writer + alert query endpoints | Add scripted attack sequences to generator | Claw-Detection starts on rules; Claw-Evals drafts scenarios |
| 1:45–2:30 | Wire detection rules → SSE alerts on dashboard | Prompt-injection + tool-abuse rules implemented | Claw-Detection ships rules 1 + 2; Claw-UI wires SSE |
| 2:30–3:15 | Context-exfil heuristic + LLM classifier (cached) | Alert cards w/ MITRE ATLAS labels; forensic timeline view | Claw-Detection ships rule 3; Claw-Evals ships datasets |
| 3:15–4:00 | NL query box (template-constrained, sandboxed) | UI polish; "replay attack" button; query-latency footer | Claw-Evals runs full eval pass; Claw-UI fixes NL box |
| 4:00–4:30 | Load-test 5M rows; verify all queries <100ms; README | Record 90s demo video (Loom/OBS); write submission copy | Omega final review against success criteria |

## Risk Mitigation

| Risk | Mitigation |
|---|---|
| ClickHouse Cloud signup is slow / requires CC | `docker compose up clickhouse` self-hosted fallback ready in first 15 min |
| LLM API rate limits / latency ruins live demo | Pre-compute classifications for scripted attacks; live demo uses cache |
| Synthetic data feels fake to judges | Frame explicitly: "200-agent fleet simulation; production trajectory 5M events/day" |
| NL query box hallucinates SQL | Constrain to curated templates; LLM picks template + fills params, never writes raw SQL live |
| One person finishes their track early | Cross-pollinate — Person A helps UI, Person B helps thresholds |
| Eval recall <0.85 | Add 2 more attack variants to datasets; rerun Claw-Evals |

## Submission Checklist

- [ ] Public GitHub repo (this one)
- [ ] `make demo` works on a clean machine in <60s
- [ ] 90-second demo video (Loom or YouTube unlisted) — lead with the attack
- [ ] Submission copy: 3-sentence "what we built," explicit ClickHouse usage, team names + emails
- [ ] Screenshot of dashboard mid-attack for submission thumbnail
- [ ] ClickHouse credits / signup email captured

## Stretch Goals (only if finished by 3:30 PM)

- Drop-in Python SDK: `from sentinel import track; track(agent_id, event)`
- Slack/Discord webhook for critical alerts
- ClickHouse-vs-Postgres latency comparison view (explicitly demonstrates prize criteria)
- Real LLM app integration (use Sentinel SDK on a small LangChain demo)
