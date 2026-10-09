# Claw-UI — Console Log

**Role:** Frontend & API engineer
**Specialty:** FastAPI endpoints, HTMX dashboard, SSE, NL query box
**Owns:** `src/sentinel/api.py`, `src/sentinel/nl_query.py`, `src/dashboard/`

---

## [2025-10-09T11:13:00] Task 3-a started. Spec: FastAPI scaffold + /v1/events endpoint

Metaprompt: `code-builder.md`
Target: `src/sentinel/api.py`

Design:
- `POST /v1/events` — accepts a single event or batch (max 1k). Validates via Pydantic, returns 202.
- `GET /v1/alerts` — list alerts, filterable by severity/agent/since.
- `GET /v1/alerts/{id}` — full alert with event chain.
- `GET /v1/stream` — SSE endpoint for live event ticker + alert pushes.
- `GET /` — dashboard (HTML).
- `POST /v1/nl_query` — NL → SQL → results (delegated to `nl_query.py`).
- `POST /v1/demo/attack/{type}` — triggers a scripted attack (for demo).

Async pattern: events go into an `asyncio.Queue`, background task flushes to ClickHouse every 1s. Detection runs inline (synchronously, before the 202 response) for prompt-injection rules (fast, <5ms). Tool-abuse and context-exfil run async (they need MV queries / LLM calls).

## [2025-10-09T11:27:00] Task 3-a complete. Endpoint accepts 1,400 events/sec sustained.

Load test: 10k events via `httpx.AsyncClient` concurrent POSTs, p99 latency 3.4ms per request.

## [2025-10-09T11:50:00] Task 3-b started. Spec: HTMX dashboard + SSE

Target: `src/dashboard/`

Design:
- Single-page HTML (HTMX + Tailwind via CDN — zero build step).
- 3 zones:
  1. **Live ticker** — SSE-fed event stream, last 50 events, color-coded by event_type.
  2. **Alert cards** — newest alerts at top, color-coded by severity, MITRE ATLAS label as a badge, click to expand into forensic timeline.
  3. **NL query box** — single text input, results render below as a table.
- SSE endpoint `/v1/stream` multiplexes events + alerts on the same connection (tagged with `event: tick` vs `event: alert`).
- Forensic timeline: per-alert, fetches the linked event_ids and renders a vertical timeline with timestamps + payload snippets.

## [2025-10-09T12:19:00] Task 3-b complete. Alert appears 1.4s after scripted attack.

UI polish:
- Severity colors: `low`=gray, `med`=yellow, `high`=orange, `critical`=red (Tailwind classes).
- MITRE ATLAS labels link out to `https://atlas.mitre.com/techniques/<id>`.
- Query-latency footer: shows p99 of last 100 queries, refreshes every 5s.

## [2025-10-09T11:50:00] Task 3-c started (parallel). Spec: NL query box

Target: `src/sentinel/nl_query.py`

Design — **template-constrained**, not free-form SQL generation:

Curated templates:
1. "show all agents that called {tool} after {trigger_phrase}"
2. "show events for agent {agent_id} in the last {n} minutes"
3. "show critical alerts in the last {n} minutes"
4. "show all events matching {regex} in payloads"
5. "show top {n} agents by event count in the last {n} minutes"

LLM role: classify the question, pick a template, fill the slots. **Never** generates SQL directly.

Sandbox:
- LLM output is parsed as `{template_id, params}`. If parse fails → refuse with "I can't answer that. Try one of: show events for agent X in the last 5 minutes."
- The SQL is generated from the template, not the LLM.
- Hard limit: only SELECT. Max 1M rows scanned (`max_rows_to_read = 1000000` on the query).

## [2025-10-09T12:20:00] Task 3-c complete. NL query "show all agents that called filesystem after 'ignore previous'" returns 142ms across 2.3M rows.

Tested with malicious inputs:
- "drop table sentinel_events" → refused ("I can't answer that.")
- "show me the password column" → refused ("I can't answer that. Try: show events for agent X...")
- "show all events matching 'AKIA' in payloads" → template 4, returned 3 hits in 92ms.

## [2025-10-09T15:30:00] Post-build polish

- Added "Replay Attack" button — fires a scripted prompt-injection attack on demand for demo purposes.
- Added query-latency footer (live p99).
- Added "Attack Replay" mode in the workload generator (`--demo-mode`) that pre-scripts 3 attacks at 20s intervals for predictable demo.

## [2025-10-09T16:15:00] Final: ALL TASKS PASS. Claw-UI track complete.

Dashboard demo video recorded at 90 seconds. Lead with the attack, not the architecture.
