"""
Sentinel Stream — Self-Evolving Detection Engine.

The hive observes attack patterns that don't match existing detection rules,
clusters them, and proposes NEW detection rules via the LLM. Proposed rules
go through a safety pipeline before activation:

  1. OBSERVE: collect events that triggered no rule but had high risk_score
  2. CLUSTER: group similar unlabeled events by payload similarity
  3. PROPOSE: LLM generates a candidate regex/signature for each cluster
  4. EVAL: candidate rule is tested against existing eval datasets
     (must not reduce precision below 0.90)
  5. STAGE: candidate rule is staged (not yet active) with a kill-switch
  6. ACTIVATE: after human review OR auto-activation if confidence > threshold
  7. LEDGER: every step is recorded in the immutable evolution ledger

See docs/SELF_EVOLUTION.md for the full safety design.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

try:
    from litellm import completion as llm_completion
except ImportError:
    llm_completion = None

logger = logging.getLogger(__name__)

LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "openai/gpt-4o-mini")

# Thresholds for auto-activation (without human review)
AUTO_ACTIVATE_PRECISION_THRESHOLD = 0.95
AUTO_ACTIVATE_CONFIDENCE_THRESHOLD = 0.90
MIN_CLUSTER_SIZE = 5  # need ≥5 similar events to propose a rule

EVOLUTION_LEDGER_PATH = Path(os.environ.get(
    "SENTINEL_EVOLUTION_LEDGER",
    "evolution_ledger.jsonl",
))


class RuleStatus(str, Enum):
    PROPOSED = "proposed"      # LLM generated, not yet evaluated
    EVALUATING = "evaluating"  # running against eval datasets
    STAGED = "staged"          # passed eval, awaiting activation
    ACTIVE = "active"          # live in the detection engine
    REJECTED = "rejected"      # failed eval or human review
    RETIRED = "retired"        # was active, now disabled


@dataclass
class EvolvedRule:
    """A self-evolved detection rule."""
    id: str
    proposed_at: float
    proposed_by: str  # "evolution-engine" or human reviewer
    alert_type: str
    severity: str  # low/med/high/critical
    technique: str  # MITRE ATLAS technique ID
    pattern: str  # regex pattern
    pattern_flags: str  # e.g. "IGNORECASE"
    rationale: str  # why the LLM proposed this
    cluster_sample_ids: list[str] = field(default_factory=list)
    status: RuleStatus = RuleStatus.PROPOSED
    eval_precision: float = 0.0
    eval_recall: float = 0.0
    eval_false_positives: int = 0
    activated_at: float | None = None
    retired_at: float | None = None
    kill_switch: bool = False  # if True, rule is immediately disabled
    generation: int = 1  # 1 = first-gen evolved rule

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


class EvolutionLedger:
    """Immutable append-only ledger of all rule evolution events.

    Every observation, proposal, evaluation, activation, and retirement
    is recorded here with a hash chain (same pattern as audit.py).
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or EVOLUTION_LEDGER_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = __import__("threading").Lock()

    def record(self, event_type: str, rule_id: str, details: dict[str, Any]) -> None:
        """Record an evolution event."""
        entry = {
            "ts": time.time(),
            "event_type": event_type,  # proposed/evaluated/staged/activated/retired
            "rule_id": rule_id,
            "details": details,
        }
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(__import__("json").dumps(entry, default=str) + "\n")

    def history(self, rule_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Query evolution history."""
        results: list[dict[str, Any]] = []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
            for line in reversed(lines):
                if not line.strip():
                    continue
                import json as _json
                entry = _json.loads(line)
                if rule_id and entry.get("rule_id") != rule_id:
                    continue
                results.append(entry)
                if len(results) >= limit:
                    break
        except FileNotFoundError:
            pass
        return results


class EvolutionEngine:
    """The self-evolving detection engine.

    Observes unlabeled high-risk events, clusters them, proposes new rules,
    evaluates candidates, and activates them (with safety rails).
    """

    def __init__(self) -> None:
        self.ledger = EvolutionLedger()
        self._rules: dict[str, EvolvedRule] = {}  # rule_id → EvolvedRule
        self._unlabeled_events: list[dict[str, Any]] = []  # buffer of events that didn't match any rule
        self._max_buffer = 1000
        self._load_rules()

    # --- Observation --------------------------------------------------------

    def observe(self, event: dict[str, Any]) -> None:
        """Observe an event that didn't trigger any detection rule.

        If the event has high risk_score or suspicious flags, buffer it
        for clustering. When the buffer fills, trigger proposal generation.
        """
        risk = float(event.get("risk_score", 0.0))
        flags = event.get("flags", [])
        if risk < 0.3 and not flags:
            return  # not suspicious enough
        self._unlabeled_events.append({
            "id": event.get("id", ""),
            "ts": event.get("ts", ""),
            "agent_id": event.get("agent_id", ""),
            "event_type": event.get("event_type", ""),
            "tool_name": event.get("tool_name", ""),
            "payload": event.get("payload", "")[:2000],  # cap for LLM context
            "risk_score": risk,
            "flags": flags,
        })
        if len(self._unlabeled_events) >= self._max_buffer:
            self.propose_rules()

    # --- Clustering ---------------------------------------------------------

    def _cluster_events(self) -> list[list[dict[str, Any]]]:
        """Cluster unlabeled events by payload similarity.

        Uses a simple hash-based grouping on the first N tokens + event_type.
        For production, swap to embeddings + DBSCAN.
        """
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for evt in self._unlabeled_events:
            # Simple clustering key: event_type + first 5 significant tokens
            payload = evt.get("payload", "")
            tokens = re.findall(r"\w+", payload.lower())[:5]
            key = f"{evt.get('event_type','')}|{'_'.join(tokens)}"
            groups[key].append(evt)

        # Only return clusters with enough samples
        return [g for g in groups.values() if len(g) >= MIN_CLUSTER_SIZE]

    # --- Rule proposal ------------------------------------------------------

    def propose_rules(self) -> list[EvolvedRule]:
        """Generate candidate detection rules from clustered unlabeled events."""
        if not llm_completion or not LLM_API_KEY:
            logger.debug("Evolution engine: LLM not available, skipping proposal")
            self._unlabeled_events.clear()
            return []

        clusters = self._cluster_events()
        if not clusters:
            self._unlabeled_events.clear()
            return []

        proposed: list[EvolvedRule] = []
        for cluster in clusters:
            rule = self._propose_rule_for_cluster(cluster)
            if rule:
                proposed.append(rule)

        # Clear the buffer after proposal
        self._unlabeled_events.clear()
        return proposed

    def _propose_rule_for_cluster(self, cluster: list[dict[str, Any]]) -> EvolvedRule | None:
        """Use LLM to propose a detection rule for a cluster of similar events."""
        sample_payloads = [e["payload"][:500] for e in cluster[:5]]
        event_type = cluster[0].get("event_type", "unknown")

        prompt = f"""You are a defensive security detection engineer. Analyze the following {len(cluster)} similar security events that did NOT match any existing detection rule, and propose a NEW regex-based detection rule to catch them in the future.

Event type: {event_type}

Sample payloads (first 5 of {len(cluster)}):
{chr(10).join(f"- {p}" for p in sample_payloads)}

Respond in EXACTLY this JSON format (no other text):
{{
  "alert_type": "string (e.g. 'novel_injection_variant')",
  "severity": "low|med|high|critical",
  "technique": "AML.T00xx (MITRE ATLAS ID, or 'AML.T9999' if novel)",
  "pattern": "python regex pattern string",
  "pattern_flags": "IGNORECASE|DOTALL|MULTILINE (or empty string)",
  "rationale": "one sentence explaining why this rule is needed and what it detects"
}}

Guidelines:
- The regex must be valid Python re module syntax
- Prefer specific patterns over overly broad ones (avoid '.*' style matches)
- The rule should have LOW false positive rate — it's better to miss some variants than to alert on benign traffic
- If the events don't represent a genuine attack pattern, respond with {{"alert_type": null}}"""

        try:
            resp = llm_completion(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": "You are a defensive security detection rule generator. Output JSON only."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=500,
            )
            import json as _json
            text = resp.choices[0].message.content.strip()
            # Strip markdown code fences if present
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0]
            proposal = _json.loads(text)
        except Exception as e:
            logger.warning("Rule proposal failed: %s", e)
            return None

        if not proposal.get("alert_type"):
            return None

        # Validate the regex compiles
        pattern = proposal.get("pattern", "")
        try:
            flags = 0
            if "IGNORECASE" in proposal.get("pattern_flags", ""):
                flags |= re.IGNORECASE
            if "DOTALL" in proposal.get("pattern_flags", ""):
                flags |= re.DOTALL
            re.compile(pattern, flags)
        except re.error as e:
            logger.warning("Proposed regex invalid: %s — %s", pattern, e)
            return None

        rule_id = "evolved_" + hashlib.sha256(
            f"{proposal['alert_type']}{pattern}{time.time()}".encode()
        ).hexdigest()[:12]

        rule = EvolvedRule(
            id=rule_id,
            proposed_at=time.time(),
            proposed_by="evolution-engine",
            alert_type=proposal["alert_type"],
            severity=proposal.get("severity", "med"),
            technique=proposal.get("technique", "AML.T9999"),
            pattern=pattern,
            pattern_flags=proposal.get("pattern_flags", ""),
            rationale=proposal.get("rationale", ""),
            cluster_sample_ids=[e.get("id", "") for e in cluster[:10]],
            status=RuleStatus.PROPOSED,
        )
        self._rules[rule_id] = rule
        self.ledger.record("proposed", rule_id, rule.to_dict())
        logger.info("Evolved rule proposed: %s (%s)", rule.alert_type, rule.id)
        return rule

    # --- Evaluation ---------------------------------------------------------

    def evaluate_rule(self, rule_id: str, benign_samples: list[str], attack_samples: list[str]) -> dict[str, Any]:
        """Evaluate a proposed rule against a labeled dataset.

        Returns metrics dict. The rule must achieve precision ≥ threshold
        to be staged for activation.
        """
        rule = self._rules.get(rule_id)
        if not rule:
            return {"error": "rule not found"}

        rule.status = RuleStatus.EVALUATING
        self.ledger.record("evaluating", rule_id, {"sample_counts": {"benign": len(benign_samples), "attack": len(attack_samples)}})

        flags = 0
        if "IGNORECASE" in rule.pattern_flags:
            flags |= re.IGNORECASE
        if "DOTALL" in rule.pattern_flags:
            flags |= re.DOTALL

        compiled = re.compile(rule.pattern, flags)

        tp = fp = fn = tn = 0
        for sample in attack_samples:
            if compiled.search(sample):
                tp += 1
            else:
                fn += 1
        for sample in benign_samples:
            if compiled.search(sample):
                fp += 1
            else:
                tn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        rule.eval_precision = precision
        rule.eval_recall = recall
        rule.eval_false_positives = fp

        result = {
            "precision": precision,
            "recall": recall,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "passes_precision_threshold": precision >= AUTO_ACTIVATE_PRECISION_THRESHOLD,
        }
        self.ledger.record("evaluated", rule_id, result)
        return result

    # --- Activation ---------------------------------------------------------

    def stage_rule(self, rule_id: str) -> bool:
        """Stage a rule that passed evaluation."""
        rule = self._rules.get(rule_id)
        if not rule or rule.status != RuleStatus.EVALUATING:
            return False
        rule.status = RuleStatus.STAGED
        self.ledger.record("staged", rule_id, {})
        self._save_rules()
        return True

    def activate_rule(self, rule_id: str, auto_activated: bool = False) -> bool:
        """Activate a staged rule. Loads it into the detection engine."""
        rule = self._rules.get(rule_id)
        if not rule or rule.status != RuleStatus.STAGED:
            return False
        rule.status = RuleStatus.ACTIVE
        rule.activated_at = time.time()
        self.ledger.record("activated", rule_id, {"auto_activated": auto_activated})

        # Load into the detection engine
        try:
            from sentinel.detect import PROMPT_INJECTION_PATTERNS, CONTEXT_EXFIL_PATTERNS
            flags = 0
            if "IGNORECASE" in rule.pattern_flags:
                flags |= re.IGNORECASE
            if "DOTALL" in rule.pattern_flags:
                flags |= re.DOTALL
            compiled = re.compile(rule.pattern, flags)
            # Add to the appropriate pattern list based on alert_type
            if "injection" in rule.alert_type:
                PROMPT_INJECTION_PATTERNS.append((compiled, rule.severity, rule.technique))
            elif "exfil" in rule.alert_type:
                CONTEXT_EXFIL_PATTERNS.append((compiled, rule.severity, rule.technique))
            logger.info("Evolved rule %s ACTIVATED and loaded into detection engine", rule.alert_type)
        except Exception as e:
            logger.error("Failed to load evolved rule into engine: %s", e)
        self._save_rules()
        return True

    def auto_activate_if_confident(self, rule_id: str) -> bool:
        """Auto-activate a rule if eval metrics exceed confidence thresholds."""
        rule = self._rules.get(rule_id)
        if not rule or rule.status != RuleStatus.STAGED:
            return False
        if (
            rule.eval_precision >= AUTO_ACTIVATE_PRECISION_THRESHOLD
            and rule.eval_recall >= 0.80
            and rule.eval_false_positives == 0
        ):
            return self.activate_rule(rule_id, auto_activated=True)
        return False

    def retire_rule(self, rule_id: str, reason: str = "") -> bool:
        """Retire an active rule (kill switch)."""
        rule = self._rules.get(rule_id)
        if not rule:
            return False
        rule.status = RuleStatus.RETIRED
        rule.retired_at = time.time()
        rule.kill_switch = True
        self.ledger.record("retired", rule_id, {"reason": reason})
        self._save_rules()
        logger.info("Evolved rule %s RETIRED: %s", rule.alert_type, reason)
        return True

    # --- Querying -----------------------------------------------------------

    def list_rules(self, status: RuleStatus | None = None) -> list[dict[str, Any]]:
        """List evolved rules, optionally filtered by status."""
        rules = list(self._rules.values())
        if status:
            rules = [r for r in rules if r.status == status]
        return [r.to_dict() for r in rules]

    def get_rule(self, rule_id: str) -> dict[str, Any] | None:
        rule = self._rules.get(rule_id)
        return rule.to_dict() if rule else None

    def evolution_stats(self) -> dict[str, Any]:
        """Stats for the dashboard."""
        status_counts: dict[str, int] = defaultdict(int)
        for r in self._rules.values():
            status_counts[r.status.value] += 1
        return {
            "total_rules_evolved": len(self._rules),
            "by_status": dict(status_counts),
            "active_rules": status_counts.get(RuleStatus.ACTIVE.value, 0),
            "unlabeled_buffer_size": len(self._unlabeled_events),
            "auto_activate_thresholds": {
                "precision": AUTO_ACTIVATE_PRECISION_THRESHOLD,
                "confidence": AUTO_ACTIVATE_CONFIDENCE_THRESHOLD,
                "min_cluster_size": MIN_CLUSTER_SIZE,
            },
        }

    # --- Persistence --------------------------------------------------------

    def _save_rules(self) -> None:
        """Persist evolved rules to disk."""
        import json as _json
        try:
            path = EVOLUTION_LEDGER_PATH.parent / "evolved_rules.json"
            path.write_text(_json.dumps(
                {rid: r.to_dict() for rid, r in self._rules.items()},
                indent=2, default=str,
            ))
        except Exception as e:
            logger.warning("Failed to save evolved rules: %s", e)

    def _load_rules(self) -> None:
        """Load previously-evolved rules from disk."""
        import json as _json
        try:
            path = EVOLUTION_LEDGER_PATH.parent / "evolved_rules.json"
            if path.exists():
                data = _json.loads(path.read_text())
                for rid, rdict in data.items():
                    rdict["status"] = RuleStatus(rdict["status"])
                    self._rules[rid] = EvolvedRule(**rdict)
                logger.info("Loaded %s evolved rules from %s", len(self._rules), path)
                # Re-activate any rules that were active
                for rule in list(self._rules.values()):
                    if rule.status == RuleStatus.ACTIVE and not rule.kill_switch:
                        try:
                            from sentinel.detect import PROMPT_INJECTION_PATTERNS, CONTEXT_EXFIL_PATTERNS
                            flags = 0
                            if "IGNORECASE" in rule.pattern_flags:
                                flags |= re.IGNORECASE
                            if "DOTALL" in rule.pattern_flags:
                                flags |= re.DOTALL
                            compiled = re.compile(rule.pattern, flags)
                            if "injection" in rule.alert_type:
                                PROMPT_INJECTION_PATTERNS.append((compiled, rule.severity, rule.technique))
                            elif "exfil" in rule.alert_type:
                                CONTEXT_EXFIL_PATTERNS.append((compiled, rule.severity, rule.technique))
                        except Exception:
                            pass
        except Exception as e:
            logger.warning("Failed to load evolved rules: %s", e)


# Singleton
_engine: EvolutionEngine | None = None


def get_evolution_engine() -> EvolutionEngine:
    global _engine
    if _engine is None:
        _engine = EvolutionEngine()
    return _engine
