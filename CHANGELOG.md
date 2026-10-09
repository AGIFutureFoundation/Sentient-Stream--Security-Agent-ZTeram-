# Changelog

All notable changes to Sentinel Stream are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] — 2025-10-09

### Added — Self-evolving deep cybersecurity hive

- **Self-evolving detection engine** — observes unlabeled high-risk events, clusters them, proposes new detection rules via LLM, evaluates candidates against eval datasets, and activates passing rules. 7-layer safety pipeline (observation filtering, min cluster size, regex validation, eval gate, staging, activation control, kill switch). Immutable evolution ledger. `src/sentinel/evolution.py`
- **Model router** — routes LLM queries based on sensitivity. Defensive security research (malware analysis, CVE explanation, vuln scanning of owned code) routed to a model profile with a defensive-context system prompt that enables legitimate analysis while still refusing genuinely harmful requests. 3 profiles (general, security_research, code_analysis). `src/sentinel/model_router.py`
- **claw-vulnscanner agent** — scans code repositories for vulnerabilities. 15 static patterns (injection flaws, hardcoded secrets, crypto misuse, LLM-specific vulns) + LLM-assisted deep analysis on top suspicious files. Outputs findings with CWE, MITRE technique, and fix recommendations. `omega-claw/claw_vulnscanner.py`
- **claw-evolution agent** — the self-evolution claw. Manages the unlabeled event buffer, triggers proposal cycles, and coordinates with the detection engine for rule activation. `omega-claw/consoles/claw-evolution.md`
- **SELF_EVOLUTION.md** — full safety design document covering the 7-layer safety pipeline, threat model, production recommendations, and compliance mapping. `docs/SELF_EVOLUTION.md`
- **9 new API endpoints**: `/v1/evolution/stats`, `/v1/evolution/rules` (list), `/v1/evolution/rules/{id}` (detail), `/v1/evolution/propose` (manual trigger), `/v1/evolution/activate/{id}` (human approval), `/v1/evolution/retire/{id}` (kill switch), `/v1/evolution/history/{id}`, `/v1/research/query` (model routing), `/v1/research/profiles`, `/v1/vulnscan`

### Changed
- `omega-claw/agents.yaml` — added claw-vulnscanner + claw-evolution (now 7 claw agents total)
- Alert writer now feeds unlabeled high-risk events to the evolution engine
- README, CHANGELOG, Makefile updated for v0.5.0

### Total now
- Detection rules: 5 families + N evolved rules (grows over time)
- API endpoints: 26
- Omega-Claw agents: 7 (data, detection, ui, evals, pentest, vulnscanner, evolution)

## [0.4.0] — 2025-10-09

### Added — Enterprise layer
- **Omega-Claw Hive** — optimized multi-agent architecture with shared blackboard memory, parallel task execution, health monitoring + auto-restart, work stealing, sub-hive spawning. `omega-claw/hive.py`
- **RBAC** — role-based access control (viewer/analyst/responder/admin) + multi-tenancy via `X-API-Key` + `X-Tenant-ID` headers. `src/sentinel/rbac.py`
- **Immutable audit log** — hash-chained, append-only log for SOC 2 / ISO 27001 / GDPR compliance. Tamper-detectable via `verify()`. `src/sentinel/audit.py`
- **Prometheus metrics** — `/metrics` endpoint with counters, histograms, gauges for ingest rate, alert rate, CH latency, detection latency, hive state. `src/sentinel/metrics.py`
- **SOAR playbook engine** — YAML-defined auto-response playbooks. 7 built-in actions: slack_notify, pagerduty_alert, jira_create_ticket, isolate_agent, block_ip, webhook, log_only. 3 example playbooks shipped. `src/sentinel/soar.py` + `playbooks/`
- **Kubernetes deployment** — full manifests: 3-replica API deployment with HPA, ClickHouse StatefulSet, TLS ingress, PVCs, Secrets/ConfigMaps. `deploy/kubernetes/sentinel-stream.yaml`
- **Enterprise deployment guide** — 10-section guide covering architecture, RBAC, audit, SOAR, metrics, scaling, hardening. `docs/ENTERPRISE.md`
- **Bootstrap admin script** — `python -m sentinel.bootstrap-admin` creates the first admin user. `src/sentinel/bootstrap_admin.py`
- **5 new API endpoints**: `/metrics`, `/v1/soar/playbooks`, `/v1/soar/test`, `/v1/audit`, `/v1/audit/verify`, `/v1/hive/status`
- **3 SOAR playbooks**: context-exfil-critical, prompt-injection-high, tool-abuse-critical

### Changed
- Alert writer now triggers SOAR playbooks + records metrics + writes audit log on every alert
- `/health` endpoint reports version
- Detection rules → metrics → SOAR → audit → Slack pipeline fully integrated

## [0.3.0] — 2025-10-09

### Added
- **Belief-drift detector (rule 5)** — polls hacker-bob's belief engine via MCP bridge; fires `belief_drift` alert when residual exceeds Wilson-95% band. First detection rule that reasons about agent-internal state, not just I/O. `src/sentinel/detect.py`
- **Slack webhook notifier** — critical/high alerts POST to Slack incoming webhook. Async fire-and-forget; sync fallback when no event loop. Configurable via `SLACK_WEBHOOK_URL` + `SLACK_NOTIFY_SEVERITIES` env vars. `src/sentinel/alert.py`
- **Drop-in Python SDK** — `from sentinel_sdk import track, instrument_agent, agent_session`. Thread-safe batched sender, background flush every 1s, graceful degradation. LangChain + OpenAI SDK integration examples. `src/sentinel_sdk/`
- **ClickHouse-vs-Postgres benchmark** — 6 representative queries × 100 iterations against both databases. Explicitly demonstrates the ClickHouse prize criteria. `src/sentinel/benchmark.py` + `/v1/benchmark` endpoint
- **New API endpoints**: `GET /v1/events` (read), `POST /v1/admin/truncate` (dev), `GET /v1/benchmark`, `GET /v1/benchmark/report`, `POST /v1/belief_drift` (manual rule-5 trigger)
- **`make bob-health` + `make bob-tail` + `make omega-pentest`** Makefile targets

### Changed
- Whitepaper §3 expanded with rule families 4 (v0.2.0) + 5 (v0.3.0)
- README updated with v0.3.0 features section
- `.env.example` extended with `SLACK_WEBHOOK_URL`, `SLACK_NOTIFY_SEVERITIES`, `POSTGRES_*`, SDK config vars

## [0.2.0] — 2025-10-09

### Added
- **hacker-bob integration** — closes the build→attack→detect loop. `INTEGRATION.md`
- **claw-pentest agent** — 5th Omega-Claw claw, drives hacker-bob headlessly. `omega-claw/agents.yaml`
- **MCP bridge client** — Python ↔ Node JSON-RPC over subprocess stdio. `omega-claw/mcp_bridge.py`
- **`tail_bob_sessions()` ingester** — real CVE-graded offensive traffic flows into ClickHouse, replacing synthetic generator. `src/sentinel/ingest.py`
- **Rule family 4: untrusted-data envelope injection** — detects injection signatures inside `<<UNTRUSTED_DATA>>` envelopes. `src/sentinel/detect.py`
- **`from_asff()` adapter** — AWS Security Hub ASFF records → Sentinel Stream alerts. `src/sentinel/alert.py`
- **4th eval scenario** — `evals/scenarios/s4-real-cve-replay.yaml` + `evals/datasets/cve-replay.jsonl`
- **`scripts/push-to-github.sh`** — one-command GitHub push helper

## [0.1.0] — 2025-10-09

### Added
- Initial release. Built at Cyberdefense Hackathon 2025 (San Francisco).
- **Omega-Claw multi-agent framework** — 1 orchestrator (Omega) + 4 claws (data, detection, ui, evals), 5 metaprompt templates, 5 console logs as audit trail. `omega-claw/`
- **ClickHouse schema** — `sentinel_events` (MergeTree, per-minute partitions), `sentinel_alerts`, `sentinel_tool_calls_mv` (SummingMergeTree). `src/sentinel/clickhouse_schema.sql`
- **Async batch inserter** — `asyncio.Queue` + 1s flush, 12.4k events/sec sustained. `src/sentinel/ingest.py`
- **3-family detection engine** — prompt-injection signatures, tool-abuse baselines, context-exfil heuristics + LLM classifier. `src/sentinel/detect.py`
- **FastAPI app** — `/v1/events` ingest, `/v1/alerts` list, `/v1/stream` SSE, `/v1/nl_query` sandbox, `/v1/demo/attack/{type}` demo triggers. `src/sentinel/api.py`
- **HTMX dashboard** — live event ticker, alert cards with MITRE ATLAS labels, forensic timeline, NL query box. `src/dashboard/templates/index.html`
- **Synthetic workload generator** — 3 agents at 200 events/sec, scripted attacks every 90s. `src/generator/workload.py`
- **NL query sandbox** — 5 curated templates, LLM picks + fills params, never writes raw SQL. SELECT-only, 1M-row cap. `src/sentinel/nl_query.py`
- **Evals framework** — 3 JSONL datasets (150 samples), 3 YAML scenarios, runner + metrics. All 5 pass criteria met: precision 0.96, recall 0.89, p99 1.7s, CH p99 84ms. `evals/`
- **Pitch deck** — 10-slide standalone HTML deck. `pitch-deck/index.html`
- **2-min demo video artifact** — 5 synced scenes, play/pause controls, voiceover captions. `demo-video/index.html`
- **Whitepaper** — 8-section technical deep-dive. `docs/WHITEPAPER.md`
- **Heartbeat log** — 3 phase checkpoints (P1/P2/P3) with artifact verification. `HEARTBEAT.md`
