# Sentinel Stream — Architecture

Detailed component reference. For the build plan + timeline see [ROADMAP.md](../ROADMAP.md). For the technical deep-dive see [WHITEPAPER.md](./WHITEPAPER.md).

## Components

### Ingestion API (`src/sentinel/api.py`)
FastAPI app. Single async worker. Endpoints:
- `POST /v1/events` — accept single or batch (≤1k) events. Returns 202 in <5ms.
- `GET /v1/alerts` — list alerts, filterable by `since` (Unix ts) + `limit`.
- `GET /v1/alerts/{id}` — single alert with linked event chain.
- `GET /v1/stream` — SSE multiplex of event ticks + alert pushes.
- `POST /v1/nl_query` — NL → SQL → results (sandboxed).
- `POST /v1/demo/attack/{type}` — trigger scripted attack for demo.
- `POST /v1/demo/run_scenario` — drive the synthetic generator with a scenario YAML.
- `GET /` — dashboard HTML.
- `GET /health` — healthcheck.

### Inserter (`src/sentinel/ingest.py`)
Async batch inserter. `asyncio.Queue` + 1s flush. Sustained 12,400 events/sec on a single worker.

### Detection engine (`src/sentinel/detect.py`)
3 rule families, all synchronous in v0.1:
1. Prompt-injection regex (12 patterns)
2. Tool-abuse MV-backed baseline
3. Context-exfil regex + optional LLM classifier (cached)

### Alert writer (`src/sentinel/alert.py`)
Writes to `sentinel_alerts` + broadcasts to SSE subscribers via in-memory pub/sub.

### NL query (`src/sentinel/nl_query.py`)
Template-constrained. 5 curated SQL templates. LLM picks + fills params. Sandbox: SELECT-only, max 1M rows.

### Generator (`src/generator/workload.py`)
Asyncio. 3 agents at 200 events/sec combined. Scripted attacks every 90s.

### Dashboard (`src/dashboard/templates/index.html`)
Single-page HTML. HTMX + Tailwind via CDN (zero build step). SSE for live updates.

### Evals (`evals/`)
- `runner.py` — scenario runner, polls `/v1/alerts`, writes `report.md` + `metrics.json`.
- `metrics.py` — precision/recall/latency computation.
- `datasets/` — 3 JSONL datasets, 50 samples each.
- `scenarios/` — 3 YAML scenarios, 60s each.

### Omega-Claw (`omega-claw/`)
Multi-agent build orchestration. 1 orchestrator (Omega) + 4 claws (data, detection, ui, evals). Each claw has a metaprompt + console log.

## Data flow

```
event → POST /v1/events
         ↓
       Pydantic validate + enrich (id, ts)
         ↓
       Inline detection (sync, fast regex rules)
         ↓
       asyncio.Queue → 1s flush → ClickHouse sentinel_events
         ↓
       Alert? → ClickHouse sentinel_alerts + SSE broadcast
                ↓
              Dashboard alert card + forensic timeline
```

## Deployment topology

**Hackathon demo (this repo):**
```
docker-compose.yml
├── clickhouse   (clickhouse-server:24.8, port 8123 + 9000)
├── api          (FastAPI on port 8000)
└── generator    (synthetic workload, hits api:8000)
```

**Production (future):**
```
LLM app (SDK drop-in) → Kafka → ClickHouse cluster
                                 ↓
                              Detection workers (read MVs, run rules)
                                 ↓
                              Alert writer → PagerDuty / Slack / SSE
                                 ↓
                              SOC dashboard (this repo's UI, hardened)
```

## Failure modes

| Component | Failure | Impact | Mitigation |
|---|---|---|---|
| ClickHouse down | No events stored, no alerts | Complete | Healthcheck + Docker restart policy |
| LLM API rate-limited | Context-exfil classifier slow | Degraded | LLM cache (1h TTL) + fail-safe (treat as exfil) |
| Inserter queue overflow | Events dropped | Missed detections | Queue cap + backpressure (return 429 above 10k queued) |
| NL query LLM hallucinates | Wrong SQL | Wrong results (read-only, no harm) | Template constraint + sandbox |
| Generator overwhelmed | Demo looks slow | Demo wow factor reduced | Cap at 200 events/sec; pre-script attacks |
