"""
Sentinel Stream — SOAR (Security Orchestration, Automation, and Response).

A playbook engine that auto-responds to alerts based on configurable rules.
Each playbook is a YAML-defined sequence of actions triggered by an alert.

Example playbook:
    trigger:
      alert_type: context_exfil
      severity: [critical]
    actions:
      - type: slack_notify
      - type: isolate_agent
      - type: create_ticket
        args:
          severity: P1
          assignee: soc-team

Usage:
    from sentinel.soar import SoarEngine, Playbook
    engine = SoarEngine()
    engine.load_playbooks("playbooks/")
    engine.on_alert(alert_dict)
"""
from __future__ import annotations

import asyncio
import importlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import httpx
import yaml

from sentinel.audit import get_audit

logger = logging.getLogger(__name__)

PLAYBOOKS_DIR = os.environ.get("SOAR_PLAYBOOKS_DIR", "playbooks")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
JIRA_WEBHOOK_URL = os.environ.get("JIRA_WEBHOOK_URL", "")
PAGERDUTY_INTEGRATION_KEY = os.environ.get("PAGERDUTY_INTEGRATION_KEY", "")


@dataclass
class Playbook:
    """A SOAR playbook: trigger condition + ordered actions."""
    id: str
    name: str
    description: str = ""
    trigger: dict[str, Any] = field(default_factory=dict)  # {alert_type, severity, agent_id, technique}
    actions: list[dict[str, Any]] = field(default_factory=list)
    enabled: bool = True
    cooldown_sec: float = 300.0  # don't re-trigger for same agent within 5 min
    _last_fired: dict[str, float] = field(default_factory=dict, repr=False)

    def matches(self, alert: dict[str, Any]) -> bool:
        """Check if this playbook's trigger matches the alert."""
        if not self.enabled:
            return False
        trig = self.trigger
        if "alert_type" in trig and alert.get("alert_type") not in trig["alert_type"]:
            return False
        if "severity" in trig and alert.get("severity") not in trig["severity"]:
            return False
        if "agent_id" in trig and alert.get("agent_id") not in trig["agent_id"]:
            return False
        if "technique" in trig and alert.get("technique") not in trig["technique"]:
            return False
        # Cooldown check
        agent = alert.get("agent_id", "_global")
        last = self._last_fired.get(agent, 0)
        if time.time() - last < self.cooldown_sec:
            return False
        return True


class SoarEngine:
    """SOAR playbook runner.

    Listens for alerts and executes matching playbooks.
    Each action is a pluggable handler function.
    """

    def __init__(self) -> None:
        self._playbooks: list[Playbook] = []
        self._action_handlers: dict[str, Callable[[dict, dict], Any]] = {}
        self._register_builtin_actions()

    def load_playbooks(self, path: str | Path) -> int:
        """Load playbooks from a directory of YAML files. Returns count loaded."""
        p = Path(path)
        if not p.exists():
            logger.warning("Playbooks dir not found: %s", p)
            return 0
        count = 0
        for f in sorted(p.glob("*.yaml")) + sorted(p.glob("*.yml")):
            try:
                data = yaml.safe_load(f.read_text())
                pb = Playbook(
                    id=data["id"],
                    name=data["name"],
                    description=data.get("description", ""),
                    trigger=data.get("trigger", {}),
                    actions=data.get("actions", []),
                    enabled=data.get("enabled", True),
                    cooldown_sec=data.get("cooldown_sec", 300.0),
                )
                self._playbooks.append(pb)
                count += 1
                logger.info("Loaded playbook: %s (%s actions)", pb.name, len(pb.actions))
            except Exception as e:
                logger.error("Failed to load playbook %s: %s", f, e)
        return count

    def register_action(self, name: str, handler: Callable[[dict, dict], Any]) -> None:
        """Register a custom action handler."""
        self._action_handlers[name] = handler

    def on_alert(self, alert: dict[str, Any]) -> list[dict[str, Any]]:
        """Evaluate all playbooks against an alert. Returns list of executed action results."""
        results: list[dict[str, Any]] = []
        for pb in self._playbooks:
            if not pb.matches(alert):
                continue
            pb._last_fired[alert.get("agent_id", "_global")] = time.time()
            logger.info("SOAR: playbook '%s' triggered by alert %s/%s",
                        pb.name, alert.get("alert_type"), alert.get("severity"))
            # Audit log the playbook trigger
            get_audit().append(
                actor="soar-engine",
                action="soar.playbook.triggered",
                tenant_id=alert.get("tenant_id", "default"),
                resource=f"playbook:{pb.id}",
                details={"alert_type": alert.get("alert_type"), "severity": alert.get("severity")},
            )
            for action in pb.actions:
                action_type = action.get("type", "")
                handler = self._action_handlers.get(action_type)
                if not handler:
                    logger.warning("SOAR: no handler for action '%s'", action_type)
                    results.append({"action": action_type, "status": "no_handler"})
                    continue
                args = action.get("args", {})
                try:
                    result = handler(alert, args)
                    results.append({"action": action_type, "status": "ok", "result": result})
                except Exception as e:
                    logger.error("SOAR action '%s' failed: %s", action_type, e)
                    results.append({"action": action_type, "status": "error", "error": str(e)})
        return results

    def list_playbooks(self) -> list[dict[str, Any]]:
        return [
            {"id": pb.id, "name": pb.name, "enabled": pb.enabled, "actions": len(pb.actions)}
            for pb in self._playbooks
        ]

    # --- Built-in action handlers ------------------------------------------

    def _register_builtin_actions(self) -> None:
        """Register the built-in SOAR actions."""
        self.register_action("slack_notify", _action_slack_notify)
        self.register_action("pagerduty_alert", _action_pagerduty_alert)
        self.register_action("jira_create_ticket", _action_jira_create_ticket)
        self.register_action("isolate_agent", _action_isolate_agent)
        self.register_action("block_ip", _action_block_ip)
        self.register_action("log_only", _action_log_only)
        self.register_action("webhook", _action_webhook)


# --- Built-in action implementations ---------------------------------------

def _action_slack_notify(alert: dict, args: dict) -> dict:
    """Send alert to Slack webhook."""
    if not SLACK_WEBHOOK_URL:
        return {"status": "skipped", "reason": "SLACK_WEBHOOK_URL not set"}
    payload = {
        "text": f"🚨 SOAR auto-response: {alert.get('alert_type','')} / {alert.get('severity','')}",
        "attachments": [{"color": "danger", "text": alert.get("summary", "")[:500]}],
    }
    with httpx.Client() as client:
        resp = client.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
    return {"status": "sent", "http_status": resp.status_code}


def _action_pagerduty_alert(alert: dict, args: dict) -> dict:
    """Trigger a PagerDuty incident."""
    if not PAGERDUTY_INTEGRATION_KEY:
        return {"status": "skipped", "reason": "PAGERDUTY_INTEGRATION_KEY not set"}
    payload = {
        "routing_key": PAGERDUTY_INTEGRATION_KEY,
        "event_action": "trigger",
        "payload": {
            "summary": f"Sentinel Stream: {alert.get('alert_type','')} — {alert.get('summary','')[:100]}",
            "severity": "critical" if alert.get("severity") == "critical" else "error",
            "source": alert.get("agent_id", "unknown"),
        },
    }
    with httpx.Client() as client:
        resp = client.post("https://events.pagerduty.com/v2/enqueue", json=payload, timeout=5)
    return {"status": "sent", "http_status": resp.status_code}


def _action_jira_create_ticket(alert: dict, args: dict) -> dict:
    """Create a JIRA ticket via webhook."""
    if not JIRA_WEBHOOK_URL:
        return {"status": "skipped", "reason": "JIRA_WEBHOOK_URL not set"}
    payload = {
        "fields": {
            "project": {"key": args.get("project", "SEC")},
            "summary": f"[Sentinel] {alert.get('alert_type','')}: {alert.get('summary','')[:80]}",
            "description": alert.get("evidence", "")[:2000],
            "issuetype": {"name": args.get("issue_type", "Incident")},
            "priority": {"name": args.get("priority", "P1")},
            "assignee": {"name": args.get("assignee", "soc-team")},
        }
    }
    with httpx.Client() as client:
        resp = client.post(JIRA_WEBHOOK_URL, json=payload, timeout=10,
                           headers={"Content-Type": "application/json"})
    return {"status": "created", "http_status": resp.status_code}


def _action_isolate_agent(alert: dict, args: dict) -> dict:
    """Mark an agent as isolated (writes to blackboard / quarantine set).

    In production, this would call the agent framework's quarantine API
    (e.g. LangGraph's pause/resume, or a network policy update).
    """
    agent_id = alert.get("agent_id", "")
    # Write to a quarantine set in the blackboard
    try:
        from omega_claw.hive import Blackboard  # type: ignore
        bb = Blackboard()
        quarantined = bb.read("quarantined_agents", default=[])
        if agent_id not in quarantined:
            quarantined.append(agent_id)
            bb.write("quarantined_agents", quarantined, agent="soar")
    except Exception:
        pass  # blackboard optional
    logger.warning("SOAR: agent %s ISOLATED due to %s", agent_id, alert.get("alert_type"))
    return {"status": "isolated", "agent_id": agent_id}


def _action_block_ip(alert: dict, args: dict) -> dict:
    """Block an IP address (stub — integrate with your WAF/firewall API)."""
    ip = args.get("ip") or alert.get("evidence", {}).get("source_ip", "")
    if not ip:
        return {"status": "skipped", "reason": "no IP in alert or args"}
    # In production: call AWS WAF / Cloudflare / iptables API here
    logger.warning("SOAR: would block IP %s (stub implementation)", ip)
    return {"status": "blocked", "ip": ip, "note": "stub — integrate with WAF API"}


def _action_log_only(alert: dict, args: dict) -> dict:
    """No-op action that just logs (useful for dry-run playbooks)."""
    logger.info("SOAR log_only: %s / %s", alert.get("alert_type"), alert.get("severity"))
    return {"status": "logged"}


def _action_webhook(alert: dict, args: dict) -> dict:
    """POST the alert to a custom webhook URL."""
    url = args.get("url")
    if not url:
        return {"status": "skipped", "reason": "no URL in args"}
    with httpx.Client() as client:
        resp = client.post(url, json=alert, timeout=10)
    return {"status": "sent", "http_status": resp.status_code}


# Singleton
_engine: SoarEngine | None = None


def get_engine() -> SoarEngine:
    global _engine
    if _engine is None:
        _engine = SoarEngine()
        _engine.load_playbooks(PLAYBOOKS_DIR)
    return _engine
