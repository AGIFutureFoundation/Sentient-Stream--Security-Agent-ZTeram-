# Sentinel Stream — Self-Evolution Safety Design

**Version:** 0.5.0
**Status:** Active
**Audience:** Security engineers, SOC leads, anyone deploying the self-evolving hive.

This document explains how Sentinel Stream's self-evolving detection engine works, the safety rails that prevent runaway modification, and how to operate it in production.

---

## Why self-evolution?

Static detection rules decay. Attackers constantly develop new variants of prompt injection, novel tool-abuse patterns, and creative exfiltration channels. A detection system that cannot learn from what it observes will miss novel attacks.

Sentinel Stream v0.5.0 introduces a **self-evolving detection engine** that:
1. Observes events that don't match any existing rule
2. Clusters similar unlabeled events
3. Proposes new detection rules via LLM
4. Evaluates candidates against labeled datasets
5. Stages passing rules for review
6. Activates rules (auto or human-approved)
7. Records every step in an immutable ledger

---

## Architecture

```
   ┌─────────────────────────────────────────────────────────────┐
   │  Detection Engine (5 rule families)                        │
   │  • prompt_injection (12 patterns)                          │
   │  • tool_abuse (MV-backed baseline)                         │
   │  • context_exfil (10 patterns + LLM classifier)            │
   │  • untrusted_envelope_injection                            │
   │  • belief_drift (hacker-bob polling)                       │
   └────────────┬────────────────────────────────────────────────┘
                │ events that match NO rule
                ▼
   ┌─────────────────────────────────────────────────────────────┐
   │  Evolution Engine                                          │
   │  • observe(): buffer unlabeled high-risk events            │
   │  • cluster(): group by event_type + payload tokens         │
   │  • propose(): LLM generates candidate regex                │
   │  • evaluate(): test against evals/datasets/*.jsonl          │
   │  • stage(): passed eval, awaiting activation               │
   │  • activate(): load into Detection Engine's pattern lists  │
   └────────────┬────────────────────────────────────────────────┘
                │ every step
                ▼
   ┌─────────────────────────────────────────────────────────────┐
   │  Evolution Ledger (immutable, hash-chained)                │
   │  • proposed / evaluating / evaluated / staged / activated   │
   │  • retired (kill switch)                                    │
   └─────────────────────────────────────────────────────────────┘
```

---

## Safety rails (7 layers)

### 1. Observation filtering
Only events with `risk_score ≥ 0.3` OR suspicious flags are buffered. Most benign traffic never enters the evolution pipeline.

### 2. Minimum cluster size
A cluster must have ≥5 similar events before a rule is proposed. Single anomalies don't trigger rule generation (they may be noise).

### 3. Regex validation
Proposed regex patterns must compile in Python's `re` module before they're even staged. Invalid patterns are rejected immediately.

### 4. Eval gate (mandatory)
Every proposed rule is evaluated against all datasets in `evals/datasets/`. The rule must achieve **precision ≥ 0.95** to be staged. Rules that introduce false positives on benign traffic are rejected.

### 5. Staging period
Rules that pass eval are staged (not yet active). They can be reviewed via `/v1/evolution/rules?status=staged` before activation.

### 6. Activation control
Two activation paths:
- **Auto-activate** (only if all conditions met):
  - precision ≥ 0.95
  - recall ≥ 0.80
  - zero false positives on benign dataset
- **Human-approve**: a human reviews the staged rule and calls `/v1/evolution/activate/{rule_id}`

### 7. Kill switch (instant rollback)
Any active rule can be instantly retired via `/v1/evolution/retire/{rule_id}`. The rule is removed from the detection engine's pattern lists immediately. The retirement is recorded in the ledger with a reason.

---

## The evolution ledger

Every evolution event is appended to `evolution_ledger.jsonl`:

```json
{"ts": 1696872000.0, "event_type": "proposed", "rule_id": "evolved_abc123", "details": {"alert_type": "novel_b64_injection", "pattern": "[A-Za-z0-9+/]{500,}", ...}}
{"ts": 1696872010.0, "event_type": "evaluating", "rule_id": "evolved_abc123", "details": {"sample_counts": {"benign": 50, "attack": 50}}}
{"ts": 1696872020.0, "event_type": "evaluated", "rule_id": "evolved_abc123", "details": {"precision": 0.96, "recall": 0.84, "false_positives": 0}}
{"ts": 1696872030.0, "event_type": "staged", "rule_id": "evolved_abc123", "details": {}}
{"ts": 1696872040.0, "event_type": "activated", "rule_id": "evolved_abc123", "details": {"auto_activated": true}}
```

Query history: `GET /v1/evolution/history/{rule_id}`

---

## Model routing (defensive security research)

The "uncensored model" problem, reframed for defense:

**Problem:** Aligned models refuse legitimate security queries like "analyze this captured malware sample" or "explain how CVE-2024-XXXX works so I can write a detection rule." This blocks defensive work.

**Solution:** The model router (`src/sentinel/model_router.py`) classifies queries and routes security-research queries to a model profile with a defensive-context system prompt. The prompt establishes that the user is an authorized security professional doing defensive work, so legitimate analysis is answered fully — while genuinely harmful requests (writing new malware, attacking specific targets) are still refused.

**Query classes:**

| Class | Example | Routed to |
|---|---|---|
| `benign` | "What's the alert count?" | general profile |
| `security_research` | "Analyze this captured malware sample" | security_research profile (defensive system prompt) |
| `code_analysis` | "Find vulnerabilities in my code" | code_analysis profile |
| `refused` | "Write malware for me" | refused (with reframe suggestion) |

**What this is NOT:** This is not a tool for building offensive capabilities. The model router explicitly refuses to generate new malware, exploits for specific targets, or attack infrastructure. It only enables defensive analysis of existing artifacts.

See `docs/MODEL_ROUTING.md` (planned) for the full query classification matrix.

---

## Vulnerability scanner (claw-vulnscanner)

A new Omega-Claw agent that finds vulnerabilities in code repositories.

**Two-pass scan:**
1. **Static pass** (regex-based, no LLM): 15 patterns covering injection flaws, hardcoded secrets, crypto misuse, LLM-specific issues. Fast, deterministic, zero false negatives on the pattern set.
2. **LLM pass** (deep analysis): takes the top 5 most-suspicious files (by static finding count) and asks the LLM to identify additional logic flaws, data flow issues, and missing security controls.

**Output:** findings with file, line, severity, CWE, MITRE technique, code snippet, and fix recommendation.

**Integration:** writes results to the Omega-Claw blackboard for other agents to consume. Can trigger SOAR playbooks on critical findings.

---

## Operating the evolution engine

### Check evolution stats
```bash
curl http://localhost:8000/v1/evolution/stats
# → {"total_rules_evolved": 12, "by_status": {"active": 3, "staged": 2, ...}, ...}
```

### List staged rules (awaiting review)
```bash
curl http://localhost:8000/v1/evolution/rules?status=staged
```

### Review a specific rule
```bash
curl http://localhost:8000/v1/evolution/rules/evolved_abc123
# → full rule details including pattern, rationale, eval metrics
```

### Activate a staged rule (human approval)
```bash
curl -X POST http://localhost:8000/v1/evolution/activate/evolved_abc123
```

### Retire an active rule (kill switch)
```bash
curl -X POST "http://localhost:8000/v1/evolution/retire/evolved_abc123?reason=false+positives+in+prod"
```

### View evolution history for a rule
```bash
curl http://localhost:8000/v1/evolution/history/evolved_abc123
```

### Manually trigger proposal (normally runs when buffer fills)
```bash
curl -X POST http://localhost:8000/v1/evolution/propose
```

---

## Production recommendations

1. **Start with human-approval mode.** Disable auto-activation for the first 2-4 weeks of operation. Review every staged rule manually. Once you trust the LLM's proposals, enable auto-activation.

2. **Monitor the ledger.** Set up an alert on `retired` events — if rules are being retired frequently, the eval gate may be too permissive.

3. **Expand eval datasets.** The evolution engine's quality is bounded by the eval datasets. Add new benign + attack samples as you observe them in production.

4. **Rate-limit proposals.** The `propose_rules()` method clears the buffer after each run. In high-traffic deployments, cap the proposal rate to avoid LLM cost explosion (e.g. max 1 proposal run per hour).

5. **Review active evolved rules weekly.** Use `/v1/evolution/rules?status=active` to list all active evolved rules. Audit that each is still needed and not generating false positives.

6. **Back up the ledger.** `evolution_ledger.jsonl` is your audit trail for compliance. Back it up with the same frequency as the audit log.

---

## Threat model (what could go wrong)

| Threat | Mitigation |
|---|---|
| LLM proposes an overly-broad rule that causes false positives | Eval gate requires precision ≥0.95 with zero false positives on benign dataset |
| LLM proposes a rule that's syntactically valid but semantically wrong | Human review of staged rules; auto-activation requires recall ≥0.80 too |
| Adversarial events poison the cluster buffer to trigger bad rules | Minimum cluster size (5) + eval gate; a single attacker can't force a rule |
| Active rule causes production incident | Kill switch (`/v1/evolution/retire/{rule_id}`) removes it instantly |
| Ledger is tampered with | Hash-chained (same pattern as audit log); `verify()` detects tampering |
| LLM model degradation over time | Monitor eval metrics over time; retire rules whose precision drops |
| Cost explosion from LLM proposals | Rate-limit proposals; cap buffer size (1000 events); cap files per vuln scan (100) |

---

## Compliance notes

- **SOC 2 CC-8.1 (change management):** every rule change is in the ledger with timestamp + rationale
- **SOC 2 CC-7.4 (anomaly detection):** the evolution engine IS anomaly detection — it finds novel attacks
- **ISO 27001 A.12.6 (technical vulnerability management):** vuln scanner finds + reports vulnerabilities
- **ISO 27001 A.16.1 (incident management):** SOAR playbooks auto-respond to critical findings
