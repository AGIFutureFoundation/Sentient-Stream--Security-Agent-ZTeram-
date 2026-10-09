# Sentinel Stream — Enterprise Deployment Guide

**Version:** 0.4.0
**Audience:** Platform engineers, SREs, SOC leads deploying Sentinel Stream in production.

This guide covers everything needed to go from a fresh clone to a production deployment with RBAC, audit logging, SOAR playbooks, and Kubernetes scaling.

---

## 1. Architecture overview

```
                    ┌─────────────────────────────────────────────────┐
                    │  Ingress (TLS, rate-limited)                     │
                    │  sentinel.example.com                            │
                    └────────────────────┬────────────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────────────┐
                    │  Sentinel API (3-20 replicas, HPA)              │
                    │  • FastAPI + RBAC + audit log                    │
                    │  • 5 detection rules                             │
                    │  • SOAR engine + Prometheus metrics              │
                    │  • NL query sandbox                              │
                    └────────┬───────────────────────────┬───────────┘
                             │                           │
                    ┌────────▼────────┐         ┌────────▼────────────┐
                    │  ClickHouse      │         │  PVC (audit log +    │
                    │  StatefulSet     │         │  RBAC users)        │
                    │  100Gi SSD       │         │  10Gi                │
                    └────────┬─────────┘         └─────────────────────┘
                             │
                    ┌────────▼────────────────────────────────────────┐
                    │  Omega-Claw Hive (sidecar or separate deployment)│
                    │  • 5+ claw agents                                │
                    │  • Shared blackboard                             │
                    │  • Parallel task execution                       │
                    │  • hacker-bob MCP bridge                         │
                    └─────────────────────────────────────────────────┘
```

---

## 2. Prerequisites

- **Kubernetes 1.28+** (EKS, GKE, AKS, or self-hosted)
- **ClickHouse 24.8+** (self-hosted StatefulSet or ClickHouse Cloud)
- **cert-manager** (for TLS certificate issuance)
- **nginx-ingress-controller** (or equivalent)
- **Prometheus + Grafana** (for metrics scraping)
- **Python 3.12+** (for SDK + local development)

---

## 3. Quick deploy (Kubernetes)

```bash
# 1. Clone + build
git clone https://github.com/YOUR_ORG/sentinel-stream.git
cd sentinel-stream
docker build -t your-registry/sentinel-stream:v0.4.0 .

# 2. Create namespace + secrets
kubectl create namespace sentinel-stream
kubectl create secret generic sentinel-secrets \
  --from-literal=CLICKHOUSE_PASSWORD=... \
  --from-literal=LLM_API_KEY=sk-... \
  --from-literal=SLACK_WEBHOOK_URL=https://hooks.slack.com/... \
  --from-literal=PAGERDUTY_INTEGRATION_KEY=... \
  --from-literal=SENTINEL_API_KEY_PEPPER=$(openssl rand -hex 32) \
  -n sentinel-stream

# 3. Apply manifests
kubectl apply -f deploy/kubernetes/sentinel-stream.yaml

# 4. Wait for rollout
kubectl rollout status deployment/sentinel-api -n sentinel-stream

# 5. Create first admin user
kubectl exec -it deployment/sentinel-api -n sentinel-stream -- \
  python -m sentinel.bootstrap-admin --user-id admin --tenant-id default --name "SOC Admin"
# → prints API key (save it — shown once)

# 6. Verify
curl -H "X-API-Key: ssk_..." http://sentinel.example.com/health
```

---

## 4. RBAC (Role-Based Access Control)

### Roles

| Role | Permissions | Use case |
|---|---|---|
| `viewer` | read alerts, events, dashboard, metrics | SOC dashboards on wall displays |
| `analyst` | viewer + acknowledge alerts, run NL queries, read benchmarks | L1/L2 SOC analysts |
| `responder` | analyst + close alerts, run SOAR playbooks, trigger belief-drift | L2/L3 SOC responders |
| `admin` | responder + truncate tables, manage users, config | SOC team leads, platform admins |

### Creating users

```python
from sentinel.rbac import get_rbac, Role

rbac = get_rbac()
api_key = rbac.create_user(
    user_id="analyst-alice",
    role=Role.ANALYST,
    tenant_id="tenant-acme",
    name="Alice Chen",
    email="alice@acme.com",
)
print(f"API key (save once): {api_key}")
```

### API authentication

All requests must include `X-API-Key` header:
```bash
curl -H "X-API-Key: ssk_..." -H "X-Tenant-ID: tenant-acme" \
  https://sentinel.example.com/v1/alerts
```

### Multi-tenancy

- Each user is bound to a `tenant_id` at creation
- All queries are automatically filtered: `WHERE app_id = '<tenant_id>'`
- Users cannot access other tenants' data
- The `X-Tenant-ID` header is validated against the user's tenant

---

## 5. Audit log (compliance)

Every privileged action is appended to an immutable, hash-chained log at `/data/audit.log.jsonl`.

**Compliance mapping:**
- SOC 2 CC-7.3 (monitoring) — every alert ack/close logged
- SOC 2 CC-6.1 (logical access) — every user create/revoke logged
- ISO 27001 A.12.4 (event logging) — every truncate, SOAR run, config change logged
- GDPR Art. 30 (records) — actor, action, timestamp, resource for every event

**Verify integrity:**
```python
from sentinel.audit import get_audit
is_valid, violations = get_audit().verify()
print(f"Audit log valid: {is_valid}")
if not is_valid:
    for v in violations:
        print(f"  ✗ {v}")
```

**Query audit log:**
```python
entries = get_audit().query(actor="analyst-alice", action="alert.acknowledge", limit=50)
for e in entries:
    print(f"[{e.ts}] {e.actor} {e.action} on {e.resource}")
```

---

## 6. SOAR playbooks

Playbooks auto-respond to alerts. Configured as YAML in `playbooks/`.

### Built-in actions

| Action | Description | Requires env var |
|---|---|---|
| `slack_notify` | Post alert to Slack channel | `SLACK_WEBHOOK_URL` |
| `pagerduty_alert` | Trigger PagerDuty incident | `PAGERDUTY_INTEGRATION_KEY` |
| `jira_create_ticket` | Create JIRA incident | `JIRA_WEBHOOK_URL` |
| `isolate_agent` | Mark agent as quarantined in blackboard | — |
| `block_ip` | Block IP (stub — integrate with your WAF) | — |
| `webhook` | POST alert to a custom URL | args.url |
| `log_only` | No-op (useful for dry-run) | — |

### Custom actions

```python
from sentinel.soar import get_engine

def my_custom_action(alert: dict, args: dict) -> dict:
    # Your logic here
    return {"status": "ok"}

get_engine().register_action("my_action", my_custom_action)
```

### Playbook format

See `playbooks/context-exfil-critical.yaml` for a full example. Key fields:
- `trigger`: which alerts fire this playbook (alert_type, severity, technique, agent_id)
- `actions`: ordered list of action dicts
- `cooldown_sec`: don't re-trigger for same agent within N seconds
- `enabled`: set to false to disable without deleting

---

## 7. Prometheus metrics

The `/metrics` endpoint exposes:

| Metric | Type | Labels |
|---|---|---|
| `sentinel_events_ingested_total` | counter | agent_id, event_type |
| `sentinel_alerts_fired_total` | counter | alert_type, severity |
| `sentinel_clickhouse_query_latency_ms` | histogram | query |
| `sentinel_detection_latency_ms` | histogram | rule |
| `sentinel_nl_query_total` | counter | template_id |
| `sentinel_active_agents` | gauge | — |
| `sentinel_hive_tasks` | gauge | status |

### Grafana dashboard

Import `deploy/grafana/sentinel-stream-dashboard.json` (create from the metrics above). Key panels:
- Events/sec ingest rate
- Alerts/sec by severity
- CH query latency p50/p99
- Detection latency by rule
- SOAR playbook trigger rate

---

## 8. Omega-Claw Hive

The hive is the multi-agent orchestration layer. In production, it runs as a sidecar or separate deployment.

### Key concepts

- **Blackboard**: shared key-value store for inter-agent communication (persisted to disk)
- **Parallel execution**: tasks with met dependencies run concurrently (up to `max_workers`)
- **Health monitoring**: background thread checks agent heartbeats every 30s
- **Auto-restart**: unhealthy agents are restarted automatically
- **Work stealing**: idle agents steal tasks from busy ones (if `enable_work_stealing=True`)

### Configuration

```python
from omega_claw.hive import Hive, HiveConfig

hive = Hive(HiveConfig(
    max_workers=10,                     # parallel task slots
    blackboard_path=Path("/data/blackboard.json"),
    health_check_interval_sec=30.0,
    task_timeout_sec=300.0,
    enable_work_stealing=True,
    enable_auto_restart=True,
    max_retries=2,
))
```

### Observability

```python
status = hive.status()
# → { agents: {...}, tasks: {...}, blackboard_keys: N, total_tasks: N, uptime_sec: N }
```

---

## 9. Security hardening checklist

- [ ] Set `SENTINEL_API_KEY_PEPPER` to a random 32-byte hex value
- [ ] Enable TLS on the ingress (cert-manager + Let's Encrypt)
- [ ] Configure rate limiting on the ingress (100 req/min per IP)
- [ ] Set up network policies to restrict ClickHouse access to the API namespace only
- [ ] Enable ClickHouse authentication (set a real password)
- [ ] Configure the audit log PVC for append-only (WORM) if your storage supports it
- [ ] Set up log forwarding to your SIEM (Splunk, Elastic, Datadog)
- [ ] Configure Prometheus to scrape `/metrics` every 15s
- [ ] Set up alerting on: ingest rate drop, alert rate spike, CH latency p99 > 100ms, hive unhealthy agents > 0
- [ ] Rotate API keys quarterly (revoke + create new)
- [ ] Review audit log integrity weekly (`get_audit().verify()`)
- [ ] Enable SSO/OIDC if integrating with enterprise IdP (not in v0.4.0 — roadmap)

---

## 10. Scaling

| Component | Scale strategy | Target |
|---|---|---|
| Sentinel API | HPA on CPU + memory | 3-20 replicas |
| ClickHouse | Vertical (bigger instance) + read replicas | 1 writer + N readers |
| Omega-Claw hive | Increase `max_workers` | 1 hive pod per 5 agents |
| Audit log PVC | Size for retention, rotate weekly | 10Gi per replica, 7-day retention |

**Throughput targets (production):**
- 50,000 events/sec sustained ingest
- < 100ms p99 ClickHouse query latency at 100M rows
- < 2s p99 detection latency
- 99.9% uptime SLA
