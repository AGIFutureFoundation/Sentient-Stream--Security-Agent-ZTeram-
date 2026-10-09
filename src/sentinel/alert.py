"""
Sentinel Stream — alert writer.

Persists Detection objects to sentinel_alerts in ClickHouse and pushes them
to an in-memory pub/sub for SSE subscribers. Critical alerts also fire a
Slack webhook (NEW in v0.3.0).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

import clickhouse_connect
import httpx

from sentinel.detect import Detection

logger = logging.getLogger(__name__)

CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
SLACK_NOTIFY_SEVERITIES = set(os.environ.get("SLACK_NOTIFY_SEVERITIES", "critical,high").split(","))

SEVERITY_MAP = {"low": 1, "med": 2, "high": 3, "critical": 4}


class AlertWriter:
    """Writes alerts to ClickHouse and broadcasts to SSE subscribers."""

    def __init__(self) -> None:
        self._client = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
            username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
        )
        self._subscribers: list[asyncio.Queue] = []

    def write(self, detection: Detection) -> dict[str, Any]:
        """Persist an alert + broadcast to all SSE subscribers. Returns the alert dict."""
        alert_dict = {
            "ts": _now_iso(),
            "alert_type": detection.alert_type,
            "severity": detection.severity,
            "agent_id": detection.agent_id,
            "event_ids": detection.event_ids,
            "technique": detection.technique,
            "summary": detection.summary,
            "evidence": detection.evidence,
            "ch_query_ms": detection.ch_query_ms,
        }
        # Insert
        try:
            self._client.insert(
                "sentinel_alerts",
                [[
                    alert_dict["ts"],
                    alert_dict["alert_type"],
                    SEVERITY_MAP.get(alert_dict["severity"], 1),
                    alert_dict["agent_id"],
                    alert_dict["event_ids"],
                    alert_dict["technique"],
                    alert_dict["summary"],
                    alert_dict["evidence"],
                    alert_dict["ch_query_ms"],
                ]],
                column_names=[
                    "ts", "alert_type", "severity", "agent_id",
                    "event_ids", "technique", "summary", "evidence", "ch_query_ms",
                ],
            )
        except Exception as e:  # noqa: BLE001
            logger.error("Alert insert failed: %s", e)

        # Broadcast to SSE subscribers
        for q in list(self._subscribers):
            try:
                q.put_nowait(alert_dict)
            except asyncio.QueueFull:
                logger.warning("SSE queue full; dropping alert")

        # NEW (v0.3.0): fire Slack webhook for critical/high alerts
        if SLACK_WEBHOOK_URL and alert_dict["severity"] in SLACK_NOTIFY_SEVERITIES:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(_send_slack(alert_dict))
            except RuntimeError:
                # no event loop running — fire synchronously in a thread
                import threading
                threading.Thread(target=_send_slack_sync, args=(alert_dict,), daemon=True).start()

        # NEW (v0.4.0): record metrics
        try:
            from sentinel.metrics import record_alert_fired
            record_alert_fired(alert_dict["alert_type"], alert_dict["severity"])
        except Exception:
            pass  # metrics optional

        # NEW (v0.4.0): trigger SOAR playbooks
        try:
            from sentinel.soar import get_engine as get_soar
            get_soar().on_alert(alert_dict)
        except Exception as e:  # noqa: BLE001
            logger.debug("SOAR evaluation failed (non-fatal): %s", e)

        # NEW (v0.4.0): audit log the alert
        try:
            from sentinel.audit import get_audit
            get_audit().append(
                actor="detection-engine",
                action=f"alert.{alert_dict['alert_type']}",
                tenant_id="default",
                resource=f"alert:{alert_dict.get('agent_id', 'unknown')}",
                details={"severity": alert_dict["severity"], "technique": alert_dict.get("technique", "")},
            )
        except Exception:
            pass

        return alert_dict

    def subscribe(self) -> asyncio.Queue:
        """Subscribe to alert pushes. Returns a Queue that will receive alert dicts."""
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        if q in self._subscribers:
            self._subscribers.remove(q)

    def list_alerts(self, since: float | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """List alerts, optionally filtered by Unix timestamp."""
        query = "SELECT ts, alert_type, severity, agent_id, technique, summary FROM sentinel_alerts"
        params: dict[str, Any] = {}
        if since:
            query += " WHERE ts > toDateTime(%(since)s)"
            params["since"] = since
        query += " ORDER BY ts DESC LIMIT %(limit)s"
        params["limit"] = limit
        try:
            result = self._client.query(query, parameters=params)
        except Exception as e:  # noqa: BLE001
            logger.error("list_alerts query failed: %s", e)
            return []
        alerts = []
        for row in result.result_rows:
            alerts.append({
                "ts": str(row[0]),
                "alert_type": row[1],
                "severity": _severity_name(row[2]),
                "agent_id": row[3],
                "technique": row[4],
                "summary": row[5],
            })
        return alerts


def _now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _severity_name(sev_id: int) -> str:
    return {1: "low", 2: "med", 3: "high", 4: "critical"}.get(sev_id, "unknown")


# --- NEW: ASFF adapter (hacker-bob integration) ---------------------------
# See INTEGRATION.md §6. hacker-bob's bob_export_security_hub_finding tool
# emits AWS Security Hub ASFF records. This adapter converts them to
# Sentinel Stream alerts so the SOC dashboard can render hacker-bob findings
# alongside native detection alerts.

_ASFF_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "med",
    "LOW": "low",
    "INFORMATIONAL": "low",
}


def from_asff(asff_record: dict[str, Any]) -> dict[str, Any]:
    """Convert an AWS Security Hub ASFF record to a Sentinel Stream alert dict.

    ASFF schema reference:
    https://docs.aws.amazon.com/securityhub/latest/userguide/asff-schema.html

    Sentinel Stream alerts have shape:
        { ts, alert_type, severity, agent_id, event_ids, technique, summary, evidence }

    The ASFF record's FindingProviderFields are preserved under the 'asff_raw'
    key for full provenance traceability.
    """
    severity_label = (
        asff_record.get("Severity", {}).get("Label", "INFORMATIONAL")
        if isinstance(asff_record.get("Severity"), dict)
        else "INFORMATIONAL"
    )
    severity = _ASFF_SEVERITY_MAP.get(str(severity_label).upper(), "low")

    # Map ASFF Types (e.g. "TTP/Initial Access") to MITRE ATLAS techniques
    # where possible. ASFF uses ATT&CK tactics/techniques; we map known
    # LLM-agent-relevant types to ATLAS. Unknown types default to AML.T0051
    # (prompt injection) since hacker-bob findings are by definition about
    # the agent surface.
    types = asff_record.get("Types", []) or ["TTP/prompt-injection"]
    technique = _map_asff_type_to_atlas(types[0] if types else "")

    return {
        "ts": asff_record.get("CreatedAt") or _now_iso(),
        "alert_type": "hacker_bob_finding",
        "severity": severity,
        "agent_id": "bob:" + (asff_record.get("Id", "unknown")[:24]),
        "event_ids": [],  # ASFF doesn't carry linked event IDs; filled by ingestion layer
        "technique": technique,
        "summary": asff_record.get("Title", "hacker-bob finding"),
        "evidence": asff_record.get("Description", ""),
        "asff_raw": asff_record,  # preserve full provenance
        "source": "hacker-bob",
    }


def _map_asff_type_to_atlas(asff_type: str) -> str:
    """Best-effort map of ASFF Types → MITRE ATLAS technique IDs.
    Falls back to AML.T0051 (Prompt Injection) for unmapped types since
    hacker-bob's surface is the LLM agent."""
    mapping = {
        "TTP/Initial Access": "AML.T0051",
        "TTP/Execution": "AML.T0063",
        "TTP/Exfiltration": "AML.T0057",
        "TTP/Discovery": "AML.T0051",
        "TTP/Defense Evasion": "AML.T0064",
        "TTP/prompt-injection": "AML.T0051",
        "TTP/jailbreak": "AML.T0064",
        "TTP/tool-abuse": "AML.T0063",
        "TTP/context-exfil": "AML.T0057",
        "TTP/supply-chain": "AML.T0063",
    }
    return mapping.get(asff_type, "AML.T0051")


# --- NEW (v0.3.0): Slack webhook notifier ----------------------------------

async def _send_slack(alert: dict[str, Any]) -> None:
    """POST an alert to Slack via incoming webhook. Async, fire-and-forget."""
    if not SLACK_WEBHOOK_URL:
        return
    severity = alert.get("severity", "low")
    color = {"critical": "#ef4444", "high": "#f97316", "med": "#eab308", "low": "#6b7280"}.get(severity, "#6b7280")
    technique = alert.get("technique", "")
    atlas_link = f"https://atlas.mitre.com/techniques/{technique}" if technique else ""
    payload = {
        "attachments": [
            {
                "color": color,
                "title": f"🚨 Sentinel Stream — {severity.upper()} alert",
                "fields": [
                    {"title": "Type", "value": alert.get("alert_type", ""), "short": True},
                    {"title": "Severity", "value": severity, "short": True},
                    {"title": "Agent", "value": alert.get("agent_id", ""), "short": True},
                    {"title": "Technique", "value": f"<{atlas_link}|{technique}>" if atlas_link else "", "short": True},
                    {"title": "Summary", "value": alert.get("summary", "")[:500], "short": False},
                ],
                "footer": "Sentinel Stream v0.3.0",
                "ts": __import__("time").time(),
            }
        ]
    }
    try:
        async with httpx.AsyncClient() as client:
            await client.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
    except httpx.HTTPError as e:
        logger.warning("Slack webhook failed: %s", e)


def _send_slack_sync(alert: dict[str, Any]) -> None:
    """Sync wrapper for _send_slack, used when no event loop is running."""
    if not SLACK_WEBHOOK_URL:
        return
    try:
        with httpx.Client() as client:
            severity = alert.get("severity", "low")
            color = {"critical": "#ef4444", "high": "#f97316", "med": "#eab308", "low": "#6b7280"}.get(severity, "#6b7280")
            client.post(
                SLACK_WEBHOOK_URL,
                json={
                    "attachments": [{
                        "color": color,
                        "title": f"Sentinel Stream — {severity.upper()} alert",
                        "text": alert.get("summary", "")[:500],
                        "footer": "Sentinel Stream v0.3.0",
                    }]
                },
                timeout=5,
            )
    except Exception as e:  # noqa: BLE001
        logger.warning("Slack sync webhook failed: %s", e)


# Singleton
_writer: AlertWriter | None = None


def get_writer() -> AlertWriter:
    global _writer
    if _writer is None:
        _writer = AlertWriter()
    return _writer
