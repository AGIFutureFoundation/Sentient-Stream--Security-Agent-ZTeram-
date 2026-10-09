# Sentinel Stream — Pitch Deck (Markdown source)

Used as the source for `pitch-deck/index.html`. 10 slides, ~120s spoken.

## Slide 1 — Cover
**Sentinel Stream**
Real-Time Threat Detection for LLM Agents
*Built at Cyberdefense Hackathon 2025 — for the ClickHouse prize*

## Slide 2 — The problem
Every team shipping LLM agents has the same blind spot.
No one is watching the agent event stream.
- Prompt injection → silent override of system instructions
- Tool abuse → unauthorized filesystem/exec calls
- Context exfil → AWS keys, JWTs, secrets leaking through model responses

MITRE ATLAS now catalogues dozens of these techniques.
Your SIEM doesn't see them. Your LLM observability tool doesn't catch them.
**There is no SOC for AI today.**

## Slide 3 — The opportunity
ClickHouse prize criteria:
1. **Data scale** — every LLM event is captured
2. **Query latency** — sub-100ms on millions of rows
3. **Insights drive detection** — alerts fire in real time

Sentinel Stream is built around all three. By design.

## Slide 4 — What we built
**Sentinel Stream** = the detection layer for the agent era.

- **Ingest** every prompt, tool call, retrieval, model response
- **Store** in ClickHouse (MergeTree + MVs, per-minute partitions)
- **Detect** 3 rule families in real time
- **Alert** with MITRE ATLAS labels + forensic event chains in <2s
- **Investigate** via natural-language query (sandboxed, template-constrained)

## Slide 5 — Architecture
[See diagram]
- FastAPI ingest → ClickHouse events/alerts/MVs
- Detection engine: regex + MV-backed baselines + LLM classifier
- HTMX dashboard with SSE live updates
- Synthetic workload generator (200 events/sec, scripted attacks every 90s)

## Slide 6 — Detection rules (3 families)
1. **Prompt-injection signatures** — 12 regex patterns. <5ms/event. AML.T0051 + AML.T0064.
2. **Tool-abuse baselines** — MV-backed 5-min rolling. <50ms/check. AML.T0063.
3. **Context-exfil heuristics** — AWS keys, JWTs, SSNs, PEM keys, + LLM classifier (cached). <10ms regex. AML.T0057.

## Slide 7 — Live demo (90 seconds)
1. Open dashboard — live ticker at 200 events/sec
2. Inject prompt-injection attack → alert card pops in 1.4s
3. Click → forensic timeline → NL query "show all agents that called filesystem after 'ignore previous'" → 142ms across 2.3M rows
4. CH query latency footer shows p99 <100ms

## Slide 8 — Evals prove it
| Metric | Result | Target |
|---|---|---|
| Precision | 0.96 | ≥0.90 |
| Recall | 0.89 | ≥0.85 |
| Detection latency p50 | 312ms | <500ms |
| Detection latency p99 | 1.7s | <2s |
| CH query latency p99 | 84ms | <100ms |

All 5 criteria pass. Re-ran 3× for stability.

## Slide 9 — Built with Omega-Claw
5-agent team using our own multi-agent framework:
- **Omega** (orchestrator) — task decomposition, dispatch, review
- **Claw-Data** — ClickHouse schema, ingestion, load test
- **Claw-Detection** — 3 detection rule families
- **Claw-UI** — FastAPI + HTMX dashboard + NL query
- **Claw-Evals** — datasets, scenarios, runner, metrics

Each claw runs from a metaprompt template, writes to its own console log.
Full audit trail in `omega-claw/consoles/`.

## Slide 10 — Why we win
**ClickHouse fit:** 5/5 on all 3 judging criteria — scale, latency, insight→detection.
**Novelty:** AI defending AI — the only candidate that's literally defensive AI for AI.
**Ship-ability:** 11/11 Omega-Claw tasks passed. `make demo` works in 47s.
**Story:** Judges remember "the SOC for AI" after 30 generic dashboards.

**Sentinel Stream.** Show me the attack, not the dashboard.
