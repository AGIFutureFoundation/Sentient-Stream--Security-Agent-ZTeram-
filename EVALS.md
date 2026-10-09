# Sentinel Stream — Eval Methodology

**Goal:** prove, quantitatively, that Sentinel Stream detects the attacks it claims to detect — at the latency it claims to deliver — across a realistic volume of ClickHouse rows.

---

## Eval dimensions

| Dimension | What we measure | Target |
|---|---|---|
| **Precision** | Of all alerts fired, how many correspond to real attacks? | ≥0.90 |
| **Recall** | Of all scripted attacks, how many triggered an alert? | ≥0.85 |
| **Detection latency p50** | Time from event-ingest to alert-fired, 50th percentile | <500ms |
| **Detection latency p99** | Same, 99th percentile | <2s |
| **CH query latency p99** | ClickHouse query latency at 5M rows | <100ms |
| **Throughput ceiling** | Max sustained ingest rate before alerts lag | ≥5,000 events/sec |

## Scenarios

Three attack scenarios + one benign baseline. Each scenario is a YAML file in [`scenarios/`](./scenarios/):

| ID | Scenario | Attack type | MITRE ATLAS | Expected alert |
|---|---|---|---|---|
| `s0` | Benign baseline (mixed agent workload, no attacks) | none | — | **no alerts should fire** |
| `s1` | Prompt injection | `AML.T0051` | `prompt_injection` alert, severity `high` |
| `s2` | Tool abuse (filesystem call-rate spike) | `AML.T0063` | `tool_abuse` alert, severity `critical` |
| `s3` | Context exfiltration (AWS key in model response) | `AML.T0057` | `context_exfil` alert, severity `critical` |

Each scenario runs for 60 seconds at ~200 events/sec baseline + scripted attack at t=20s.

## Datasets

- [`datasets/prompt-injection.jsonl`](./datasets/prompt-injection.jsonl) — 50 prompt strings, 25 attack / 25 benign. Used for unit-testing the regex rule.
- [`datasets/tool-abuse.jsonl`](./datasets/tool-abuse.jsonl) — 30 baseline sequences + 30 abuse sequences. Used for unit-testing the MV-backed baseline.
- [`datasets/context-exfil.jsonl`](./datasets/context-exfil.jsonl) — 40 model-response payloads, 20 with embedded secrets / 20 benign. Used for unit-testing the exfil heuristic + LLM classifier.

Each JSONL line is `{ "input": ..., "expected": { "label": "...", "severity": "...", "technique": "..." } }`.

## Runner

```bash
make evals
# equivalent to:
python -m evals.runner --scenarios evals/scenarios/*.yaml --out evals/results/$(date -u +%Y%m%dT%H%M%SZ)
```

The runner:
1. Spins up ClickHouse (assumes `docker compose up -d clickhouse` is already running)
2. Initializes schema (`src/sentinel/clickhouse_schema.sql`)
3. Starts the API (`uvicorn src.sentinel.api:app`)
4. For each scenario: runs the synthetic generator with the scenario's attack script, polls `/v1/alerts` for 60s, records every alert + every event
5. Computes metrics
6. Writes a JSON results file + a markdown report to `evals/results/<timestamp>/`

## Metrics implementation

See [`metrics.py`](./metrics.py) for the implementation. Precision / recall are computed against the ground-truth attack timestamps in each scenario; latency is measured by `alert.ts - event.ts` for the triggering event.

## Omega-Claw integration

The runner is invoked by **Claw-Evals** (the evals worker agent). Omega triggers Claw-Evals to run a full eval pass at t=3:30 (post-build) and again at t=4:00 (post-load-test). If recall <0.85 or latency p99 >2s, Omega dispatches Claw-Detection to fix.

See [`omega-claw/consoles/claw-evals.md`](./omega-claw/consoles/claw-evals.md) for the eval agent's console log.

## Interpreting results

Each `evals/results/<timestamp>/` contains:

- `report.md` — human-readable summary
- `metrics.json` — machine-readable metrics (precision, recall, p50/p99 latencies)
- `events.jsonl` — every event ingested during the run
- `alerts.jsonl` — every alert fired during the run
- `scenarios/<id>.yaml` — copy of the scenario config used

Pass criteria: precision ≥0.90, recall ≥0.85, detection-latency p99 <2s, CH-query-latency p99 <100ms.

If any metric fails, the report includes a "FAILURES" section with the failing scenario IDs and the root cause hypothesis (e.g. "s2 missed: tool-abuse baseline window too short — 5 min vs scenario's 60s").
