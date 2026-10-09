"""
Sentinel Stream — NL query box.

Template-constrained NL → ClickHouse SQL. The LLM picks a template + fills
slots. It NEVER generates raw SQL. Output is sandboxed: SELECT-only, max 1M
rows scanned.
"""
from __future__ import annotations

import logging
import os
import re
import time
from typing import Any

import clickhouse_connect

try:
    from litellm import completion as llm_completion
except ImportError:
    llm_completion = None

logger = logging.getLogger(__name__)

CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "openai/gpt-4o-mini")


# Curated templates. LLM picks one + fills params. SQL is generated from
# the template, NOT from the LLM output.
QUERY_TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "events_for_agent",
        "description": "Show events for a specific agent in the last N minutes",
        "signature": {"agent_id": "str", "minutes": "int"},
        "sql": "SELECT ts, event_type, tool_name, payload FROM sentinel_events WHERE agent_id = '{agent_id}' AND ts > now() - INTERVAL {minutes} MINUTE ORDER BY ts DESC LIMIT 100",
    },
    {
        "id": "tool_calls_after_phrase",
        "description": "Show all agents that called a specific tool after a trigger phrase appeared in a prompt",
        "signature": {"tool": "str", "phrase": "str"},
        "sql": """
            WITH affected_agents AS (
                SELECT DISTINCT agent_id FROM sentinel_events
                WHERE event_type = 1 AND payload ILIKE '%{phrase}%'
            )
            SELECT e.ts, e.agent_id, e.tool_name FROM sentinel_events e
            WHERE e.agent_id IN (SELECT agent_id FROM affected_agents)
              AND e.event_type = 2 AND e.tool_name ILIKE '%{tool}%'
            ORDER BY e.ts DESC LIMIT 200
        """,
    },
    {
        "id": "critical_alerts_recent",
        "description": "Show critical alerts in the last N minutes",
        "signature": {"minutes": "int"},
        "sql": "SELECT ts, alert_type, agent_id, technique, summary FROM sentinel_alerts WHERE severity = 4 AND ts > now() - INTERVAL {minutes} MINUTE ORDER BY ts DESC LIMIT 50",
    },
    {
        "id": "events_matching_regex",
        "description": "Show all events matching a pattern in payloads",
        "signature": {"pattern": "str"},
        "sql": "SELECT ts, agent_id, event_type, payload FROM sentinel_events WHERE payload ILIKE '%{pattern}%' ORDER BY ts DESC LIMIT 100",
    },
    {
        "id": "top_agents_by_events",
        "description": "Show top N agents by event count in the last N minutes",
        "signature": {"top_n": "int", "minutes": "int"},
        "sql": "SELECT agent_id, count() AS cnt FROM sentinel_events WHERE ts > now() - INTERVAL {minutes} MINUTE GROUP BY agent_id ORDER BY cnt DESC LIMIT {top_n}",
    },
]

SYSTEM_PROMPT = """You are a query router for a ClickHouse-backed security dashboard.
Given a natural-language question, pick ONE of these templates and fill in the parameters.

Templates:
""" + "\n".join(
    f"- id={t['id']}: {t['description']} (params: {t['signature']})"
    for t in QUERY_TEMPLATES
) + """

Output format: ONLY a JSON object, no commentary:
{"template_id": "<id>", "params": {"<param_name>": "<value>"}}

If none of the templates fit, output:
{"template_id": null, "reason": "<one-sentence explanation>"}

Rules:
- Param values must be valid for their type (int → integer, str → alphanumeric/dash/underscore only).
- For tool/phrase params, only allow safe chars: [a-zA-Z0-9_\\-\\s.].
- Never invent a new template. Never include SQL.
"""


def nl_query(question: str) -> dict[str, Any]:
    """Translate NL question → ClickHouse SQL → results. Sandbox-enforced."""
    if not llm_completion or not LLM_API_KEY:
        return {"error": "LLM_API_KEY not set; NL query disabled."}

    # Step 1: ask LLM to pick template + fill params
    try:
        resp = llm_completion(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": question},
            ],
            temperature=0.0,
            max_tokens=200,
        )
        import json as _json
        parsed = _json.loads(resp.choices[0].message.content)
    except Exception as e:  # noqa: BLE001
        return {"error": f"LLM parse failed: {e}"}

    template_id = parsed.get("template_id")
    if not template_id:
        return {"error": parsed.get("reason", "No matching template. Try: 'show events for agent X in last 5 minutes'")}

    template = next((t for t in QUERY_TEMPLATES if t["id"] == template_id), None)
    if not template:
        return {"error": f"Unknown template: {template_id}"}

    params = parsed.get("params", {})

    # Step 2: validate + sanitize params
    safe_params = {}
    for k, v in params.items():
        if not isinstance(v, (str, int, float)):
            return {"error": f"Param {k} has invalid type"}
        sv = str(v)
        # Reject anything that looks like SQL injection
        if re.search(r"[;'\"\-\-/*]+|(?i:select|insert|update|delete|drop|alter|create)", sv):
            return {"error": f"Param {k} contains forbidden characters"}
        safe_params[k] = sv

    # Step 3: fill template SQL
    sql = template["sql"]
    try:
        sql_filled = sql.format(**safe_params)
    except KeyError as e:
        return {"error": f"Missing param: {e}"}

    # Step 4: sandbox-enforce SELECT-only
    if not re.match(r"^\s*(WITH|SELECT)\s+", sql_filled, re.I):
        return {"error": "Refused: query is not SELECT."}

    # Step 5: execute
    client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
        settings={"max_rows_to_read": 1_000_000},
    )
    t0 = time.perf_counter()
    try:
        result = client.query(sql_filled)
        cols = result.column_names
        rows = [dict(zip(cols, r)) for r in result.result_rows]
        latency_ms = (time.perf_counter() - t0) * 1000
    except Exception as e:  # noqa: BLE001
        return {"error": f"Query failed: {e}", "sql": sql_filled}

    return {
        "template_id": template_id,
        "sql": sql_filled,
        "latency_ms": round(latency_ms, 1),
        "row_count": len(rows),
        "rows": rows[:100],
    }
