"""
Sentinel Stream — detection engine.

3 rule families:
  1. Prompt-injection signatures (regex + keyword)
  2. Tool-abuse baselines (MV-backed, 5-min rolling)
  3. Context-exfiltration heuristics (regex + optional LLM classifier)
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass
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
LLM_CLASSIFIER_ENABLED = bool(LLM_API_KEY)
LLM_CACHE_TTL_SEC = 3600


# --- Pattern libraries -----------------------------------------------------

PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # [SYSTEM]/[ADMIN] tags first — more specific, indicate jailbreak attempt
    (re.compile(r"\[SYSTEM\]|\[ADMIN\]|\[SYSTEM OVERRIDE\]", re.I), "high", "AML.T0064"),
    # Jailbreak keywords — high specificity
    (re.compile(r"jailbreak|DAN\s+mode|unrestricted\s+(ai|assistant|mode)", re.I), "high", "AML.T0064"),
    (re.compile(r"developer\s+mode|maintenance\s+mode|debug\s+(mode|bot)", re.I), "high", "AML.T0064"),
    (re.compile(r"forget\s+(your\s+)?(constraints|rules|safety)", re.I), "high", "AML.T0064"),
    (re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.I), "high", "AML.T0064"),
    # Direct override phrases
    (re.compile(r"ignore\s+(previous|prior|above)\s+(instructions?|messages?)", re.I), "high", "AML.T0051"),
    (re.compile(r"disregard\s+(above|prior|previous|all)", re.I), "high", "AML.T0051"),
    (re.compile(r"new\s+instructions?:", re.I), "high", "AML.T0051"),
    (re.compile(r"the\s+above\s+was\s+a\s+test", re.I), "high", "AML.T0051"),
    (re.compile(r"reveal\s+your\s+(system\s+)?prompt", re.I), "high", "AML.T0051"),
    (re.compile(r"override\s+(safety|previous|constraints)", re.I), "high", "AML.T0051"),
    # base64-looking payload > 200 chars (potential encoded override)
    (re.compile(r"[A-Za-z0-9+/=]{200,}"), "med", "AML.T0051"),
]

CONTEXT_EXFIL_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "critical", "AML.T0057"),                # AWS access key
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "critical", "AML.T0057"),  # JWT
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "critical", "AML.T0057"),             # SSN-like
    (re.compile(r"sk_live_[A-Za-z0-9]{20,}"), "critical", "AML.T0057"),         # Stripe live key
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "critical", "AML.T0057"),             # GitHub PAT
    (re.compile(r"xox[bap]-[A-Za-z0-9-]{20,}"), "critical", "AML.T0057"),       # Slack token
    (re.compile(r"-----BEGIN [A-Z]+ PRIVATE KEY-----"), "critical", "AML.T0057"),
    (re.compile(r"postgres://[^\s]+:[^\s]+@[^\s]+"), "critical", "AML.T0057"),  # Postgres URL with creds
    (re.compile(r"mongodb(\+srv)?://[^\s]+:[^\s]+@[^\s]+"), "critical", "AML.T0057"),
    (re.compile(r"[A-Za-z0-9+/=]{1024,}"), "high", "AML.T0057"),               # long base64 blob (potential key)
]

# --- NEW: hacker-bob's <<UNTRUSTED_DATA>> envelope convention -------------
# See INTEGRATION.md §4. hacker-bob's verifier prompts all carry the literal
# convention that content between <<UNTRUSTED_DATA ...>> and <<END_UNTRUSTED_DATA ...>>
# markers is data to analyze, never instructions to follow. Detection of
# injection signatures INSIDE such envelopes is high-confidence: the agent
# is reading attacker-controlled bytes in a context where it should treat
# them as data.

UNTRUSTED_ENVELOPE_RE = re.compile(
    r"<<UNTRUSTED_DATA[^>]*>>.*?<<END_UNTRUSTED_DATA[^>]*>>",
    re.DOTALL,
)

# Injection signatures to look for INSIDE untrusted-data envelopes
INJECTION_INSIDE_ENVELOPE_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(previous|prior|above)\s+(instructions?|messages?)", re.I),
    re.compile(r"disregard\s+(above|prior|previous|all)", re.I),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.I),
    re.compile(r"new\s+instructions?:", re.I),
    re.compile(r"\[SYSTEM\]|\[ADMIN\]|\[SYSTEM OVERRIDE\]", re.I),
    re.compile(r"reveal\s+your\s+(system\s+)?prompt", re.I),
    re.compile(r"jailbreak|DAN\s+mode|unrestricted\s+(ai|assistant|mode)", re.I),
]

SENSITIVE_TOOLS = {"filesystem", "filesystem.read", "filesystem.write", "exec", "subprocess", "shell.run", "network"}
TOOL_ABUSE_BASELINE_WINDOW_SEC = 300  # 5 min rolling baseline
TOOL_ABUSE_THRESHOLD_MULT = 3.0        # 3x baseline
TOOL_ABUSE_CRITICAL_MULT = 5.0         # 5x baseline


# --- Data classes ----------------------------------------------------------

@dataclass
class Detection:
    """Result of running a detection rule against an event."""
    alert_type: str
    severity: str
    technique: str
    agent_id: str
    event_ids: list[str]
    summary: str
    evidence: str
    ch_query_ms: float = 0.0


# --- Detector --------------------------------------------------------------

class DetectionEngine:
    """Runs detection rules against incoming events."""

    def __init__(self) -> None:
        self._client = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
            username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
        )
        self._llm_cache: dict[str, tuple[float, bool]] = {}  # payload_hash → (ts, verdict)

    def detect(self, event: dict[str, Any]) -> Detection | None:
        """Run all rules against an event. Returns the first hit (or None)."""
        etype = event.get("event_type")
        payload = event.get("payload", "") or ""
        agent_id = event.get("agent_id", "unknown")
        event_id = event.get("id") or _hash_event(event)

        # NEW (rule 4): untrusted-data envelope — runs on all event types.
        # If the payload contains a <<UNTRUSTED_DATA ...>> envelope with an
        # injection signature inside, fire a critical alert.
        d = self._detect_injection_in_untrusted_envelope(event_id, agent_id, payload)
        if d:
            return d

        # 1. Prompt-injection — runs on prompts
        if etype == "prompt":
            d = self._detect_prompt_injection(event_id, agent_id, payload)
            if d:
                return d

        # 2. Tool-abuse — runs on tool_call events
        if etype == "tool_call":
            d = self._detect_tool_abuse(event_id, agent_id, event.get("tool_name", ""))
            if d:
                return d

        # 3. Context-exfil — runs on model_response events
        if etype == "model_response":
            d = self._detect_context_exfil(event_id, agent_id, payload)
            if d:
                return d

        return None

    # --- Rule 4: injection inside untrusted-data envelope ----------------
    # See INTEGRATION.md §4. hacker-bob's prompts use <<UNTRUSTED_DATA ...>>
    # envelopes to mark attacker-controlled bytes the model should treat as
    # data. Finding an injection signature inside such an envelope is a
    # high-confidence signal: the model is reading attacker bytes in a
    # context where it should not execute them.

    def _detect_injection_in_untrusted_envelope(
        self, event_id: str, agent_id: str, payload: str
    ) -> Detection | None:
        for envelope_match in UNTRUSTED_ENVELOPE_RE.finditer(payload):
            envelope_text = envelope_match.group(0)
            for inj_pattern in INJECTION_INSIDE_ENVELOPE_PATTERNS:
                m = inj_pattern.search(envelope_text)
                if m:
                    return Detection(
                        alert_type="untrusted_envelope_injection",
                        severity="critical",
                        technique="AML.T0051",
                        agent_id=agent_id,
                        event_ids=[event_id],
                        summary=(
                            f"Injection signature inside <<UNTRUSTED_DATA>> envelope: "
                            f"{inj_pattern.pattern[:60]!r} → {m.group(0)[:50]!r}"
                        ),
                        evidence=_truncate(envelope_text, 800),
                    )
        return None

    # --- Rule 1: prompt injection ----------------------------------------

    def _detect_prompt_injection(self, event_id: str, agent_id: str, payload: str) -> Detection | None:
        for pattern, severity, technique in PROMPT_INJECTION_PATTERNS:
            if pattern.search(payload):
                return Detection(
                    alert_type="prompt_injection",
                    severity=severity,
                    technique=technique,
                    agent_id=agent_id,
                    event_ids=[event_id],
                    summary=f"Prompt-injection signature matched: {pattern.pattern[:60]!r}",
                    evidence=_truncate(payload, 500),
                )
        return None

    # --- Rule 2: tool abuse (MV-backed baseline) -------------------------

    def _detect_tool_abuse(self, event_id: str, agent_id: str, tool_name: str) -> Detection | None:
        if not tool_name or tool_name not in SENSITIVE_TOOLS:
            return None
        t0 = time.perf_counter()
        try:
            # Query MV for last 5 min of calls per (agent, tool)
            result = self._client.query(
                """
                SELECT sum(call_count) AS total_calls,
                       count() AS minute_buckets
                FROM sentinel_tool_calls_mv
                WHERE agent_id = %(agent_id)s
                  AND tool_name = %(tool_name)s
                  AND ts > now() - INTERVAL 5 MINUTE
                """,
                parameters={"agent_id": agent_id, "tool_name": tool_name},
            )
            rows = result.result_rows
        except Exception as e:  # noqa: BLE001
            logger.warning("tool_abuse query failed: %s", e)
            return None
        ch_query_ms = (time.perf_counter() - t0) * 1000

        if not rows or not rows[0][0]:
            return None  # no baseline yet

        total_calls, minute_buckets = rows[0]
        if minute_buckets == 0:
            return None
        baseline_per_min = total_calls / max(minute_buckets, 1)
        if baseline_per_min < 1:
            baseline_per_min = 1  # avoid divide-by-zero for fresh agents

        # Current 1-min rate: re-query for the current minute
        try:
            cur_result = self._client.query(
                """
                SELECT sum(call_count) AS cur_calls
                FROM sentinel_tool_calls_mv
                WHERE agent_id = %(agent_id)s
                  AND tool_name = %(tool_name)s
                  AND ts > now() - INTERVAL 1 MINUTE
                """,
                parameters={"agent_id": agent_id, "tool_name": tool_name},
            )
            cur_calls = cur_result.result_rows[0][0] if cur_result.result_rows else 0
        except Exception:
            return None

        ratio = cur_calls / baseline_per_min if baseline_per_min > 0 else 0
        if ratio < TOOL_ABUSE_THRESHOLD_MULT:
            return None

        severity = "critical" if ratio >= TOOL_ABUSE_CRITICAL_MULT else "high"
        return Detection(
            alert_type="tool_abuse",
            severity=severity,
            technique="AML.T0063",
            agent_id=agent_id,
            event_ids=[event_id],
            summary=f"Tool-abuse spike: {tool_name} rate {ratio:.1f}x baseline (cur={cur_calls}/min, base={baseline_per_min:.1f}/min)",
            evidence=f"agent={agent_id} tool={tool_name} ratio={ratio:.2f} ch_query_ms={ch_query_ms:.1f}",
            ch_query_ms=ch_query_ms,
        )

    # --- Rule 3: context exfiltration ------------------------------------

    def _detect_context_exfil(self, event_id: str, agent_id: str, payload: str) -> Detection | None:
        for pattern, severity, technique in CONTEXT_EXFIL_PATTERNS:
            m = pattern.search(payload)
            if m:
                matched = m.group(0)
                # If the pattern is "long base64 blob" (severity=high), confirm via LLM
                if severity == "high" and LLM_CLASSIFIER_ENABLED:
                    verdict = self._llm_classify_exfil(payload)
                    if not verdict:
                        continue  # LLM says benign; skip
                    severity = "critical"
                return Detection(
                    alert_type="context_exfil",
                    severity=severity,
                    technique=technique,
                    agent_id=agent_id,
                    event_ids=[event_id],
                    summary=f"Context-exfil pattern matched: {pattern.pattern[:60]!r} → {matched[:40]!r}",
                    evidence=_truncate(payload, 500),
                )
        return None

    def _llm_classify_exfil(self, payload: str) -> bool:
        """Yes/no LLM verdict on whether payload contains exfiltrated secrets. Cached."""
        if not llm_completion:
            return True  # fallback: assume exfil
        cache_key = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
        cached = self._llm_cache.get(cache_key)
        if cached and (time.time() - cached[0]) < LLM_CACHE_TTL_SEC:
            return cached[1]
        try:
            resp = llm_completion(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": "You are a security classifier. Answer with YES or NO only: does the following text contain leaked credentials, API keys, secrets, or private keys?"},
                    {"role": "user", "content": payload[:2000]},
                ],
                temperature=0.0,
                max_tokens=5,
            )
            verdict_text = resp.choices[0].message.content.strip().upper()
            verdict = verdict_text.startswith("YES")
        except Exception as e:  # noqa: BLE001
            logger.warning("LLM classifier failed: %s", e)
            verdict = True  # fail-safe
        self._llm_cache[cache_key] = (time.time(), verdict)
        return verdict

    # --- Rule 5: belief drift (NEW in v0.3.0) ----------------------------
    # See INTEGRATION.md §8 item 1. Polls hacker-bob's belief engine via
    # the MCP bridge and fires a `belief_drift` alert when the residual
    # exceeds a Wilson-95% band. This is a fundamentally new signal class:
    # it reasons about the agent's INTERNAL state, not just its I/O.
    #
    # Unlike rules 1-4 which run per-event, this rule is polling-based.
    # The API layer calls check_belief_drift() on a timer (every 30s).

    def check_belief_drift(self, session_id: str, window: int = 10) -> Detection | None:
        """Poll bob_query_belief_signals for a session and fire on drift.

        Args:
            session_id: hacker-bob session ID (e.g. "bob:sess-abc123")
            window: number of recent tool calls to include in the residual window

        Returns:
            Detection if drift exceeded the Wilson-95% band, else None.
        """
        bridge = self._get_bob_bridge()
        if bridge is None:
            return None  # hacker-bob not installed; rule disabled

        try:
            result = bridge.query_belief_signals(session_id, window=window)
        except Exception as e:  # noqa: BLE001
            logger.debug("belief_signals query failed for %s: %s", session_id, e)
            return None

        if not isinstance(result, dict):
            return None

        residual = float(result.get("residual", 0.0))
        wilson_upper = float(result.get("wilson_upper_95", 0.0))
        wilson_lower = float(result.get("wilson_lower_95", 0.0))

        # Drift = residual outside the Wilson-95% band
        if residual > wilson_upper and wilson_upper > 0:
            return Detection(
                alert_type="belief_drift",
                severity="high",
                technique="AML.T0051",  # belief drift is a precursor to prompt injection success
                agent_id=session_id,
                event_ids=[],  # belief-level signal, not tied to a single event
                summary=(
                    f"Belief drift detected: residual={residual:.3f} exceeds "
                    f"Wilson-95% upper bound={wilson_upper:.3f}"
                ),
                evidence=str(result)[:800],
            )
        if residual < wilson_lower and wilson_lower < 0:
            return Detection(
                alert_type="belief_drift",
                severity="med",
                technique="AML.T0051",
                agent_id=session_id,
                event_ids=[],
                summary=(
                    f"Belief drift (negative): residual={residual:.3f} below "
                    f"Wilson-95% lower bound={wilson_lower:.3f}"
                ),
                evidence=str(result)[:800],
            )
        return None

    def _get_bob_bridge(self):
        """Lazily import the MCP bridge. Returns None if unavailable."""
        try:
            from omega_claw.mcp_bridge import McpBridge
            if not hasattr(self, "_bob_bridge"):
                try:
                    self._bob_bridge = McpBridge.from_default()
                    self._bob_bridge.start()
                except Exception as e:  # noqa: BLE001
                    logger.debug("MCP bridge unavailable: %s", e)
                    self._bob_bridge = None
            return self._bob_bridge
        except ImportError:
            return None


# --- Helpers ---------------------------------------------------------------

def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + "...[truncated]"


def _hash_event(event: dict[str, Any]) -> str:
    import json as _json
    raw = _json.dumps(event, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# Module-level singleton
_engine: DetectionEngine | None = None


def get_engine() -> DetectionEngine:
    global _engine
    if _engine is None:
        _engine = DetectionEngine()
    return _engine
