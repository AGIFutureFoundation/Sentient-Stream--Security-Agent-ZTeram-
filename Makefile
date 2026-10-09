.PHONY: help demo up down logs schema ingest evals clean test lint format

help: ## Show this help
        @grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

demo: up ## Full demo: spin up ClickHouse + API + generator, open dashboard
        @echo "==> Dashboard: http://localhost:8000"
        @echo "==> ClickHouse UI: http://localhost:8123/play"
        @echo "==> Trigger attack: curl -X POST http://localhost:8000/v1/demo/attack/prompt_injection"

up: ## Start all services (ClickHouse + API + generator)
        docker compose up -d --build
        @echo "Waiting for ClickHouse to be healthy..."
        @timeout 60 sh -c 'until docker compose ps clickhouse | grep -q healthy; do sleep 2; done' || true

down: ## Stop all services
        docker compose down

logs: ## Tail logs from all services
        docker compose logs -f --tail=100

schema: ## Apply ClickHouse schema directly (via clickhouse-client)
        docker compose exec clickhouse clickhouse-client --queries-file /docker-entrypoint-initdb.d/01-schema.sql

ingest: ## Run synthetic workload generator locally against dockerized ClickHouse
        python -m src.generator.workload --duration 60 --rate 200

evals: ## Run full eval suite
        @mkdir -p evals/results
        @timestamp=$$(date -u +%Y%m%dT%H%M%SZ) && \
        python -m evals.runner \
                --scenarios evals/scenarios/*.yaml \
                --out evals/results/$$timestamp
        @echo "==> Results: evals/results/$$(ls -1t evals/results | head -1)/report.md"

clean: ## Remove all containers + volumes
        docker compose down -v
        rm -rf evals/results/

test: ## Run unit tests
        pytest tests/ -v

lint: ## Lint
        ruff check src/ evals/ omega-claw/ tests/

format: ## Format
        ruff format src/ evals/ omega-claw/ tests/

omega: ## Run the Omega-Claw orchestrator (meta-prompt the build)
        python -m omega_claw.run --plan ROADMAP.md

omega-evals: ## Have Omega run only the evals track
        python -m omega_claw.run --track evals

omega-pentest: ## Run the pentest track (drives hacker-bob against built artifacts)
        python -m omega_claw.run --track claw-pentest

bob-health: ## Check hacker-bob install readiness
        python -c "from omega_claw.mcp_bridge import health_check; import json; print(json.dumps(health_check(), indent=2))"

bob-tail: ## Tail hacker-bob session-events into ClickHouse
        python -c "import asyncio; from sentinel.ingest import tail_bob_sessions; n = asyncio.run(tail_bob_sessions()); print(f'{n} events ingested')"

# NEW (v0.4.0): Enterprise targets
bootstrap-admin: ## Create first admin user
        python -m sentinel.bootstrap-admin --user-id admin --tenant-id default --name "SOC Admin"

soar-test: ## Test SOAR playbook with a synthetic alert
        curl -s -X POST "http://localhost:8000/v1/soar/test?alert_type=context_exfil&severity=critical&agent_id=test-agent" | python -m json.tool

audit-verify: ## Verify audit log integrity (SOC 2 compliance)
        curl -s http://localhost:8000/v1/audit/verify | python -m json.tool

hive-status: ## Check Omega-Claw hive status
        curl -s http://localhost:8000/v1/hive/status | python -m json.tool

metrics: ## Scrape Prometheus metrics
        curl -s http://localhost:8000/metrics | head -30

k8s-deploy: ## Deploy to Kubernetes (requires kubectl configured)
        kubectl apply -f deploy/kubernetes/sentinel-stream.yaml

k8s-status: ## Check K8s deployment status
        kubectl get all -n sentinel-stream

# NEW (v0.5.0): Self-evolution + vuln scanning
evolve-stats: ## Check self-evolution engine stats
        curl -s http://localhost:8000/v1/evolution/stats | python -m json.tool

evolve-propose: ## Manually trigger rule proposal
        curl -s -X POST http://localhost:8000/v1/evolution/propose | python -m json.tool

evolve-staged: ## List staged rules awaiting review
        curl -s "http://localhost:8000/v1/evolution/rules?status=staged" | python -m json.tool

evolve-active: ## List active evolved rules
        curl -s "http://localhost:8000/v1/evolution/rules?status=active" | python -m json.tool

vulnscan: ## Scan the Sentinel Stream repo itself for vulns
        curl -s -X POST "http://localhost:8000/v1/vulnscan?target=." | python -m json.tool

research-query: ## Test the model router with a defensive research query
        curl -s -X POST "http://localhost:8000/v1/research/query?query=explain%20how%20CVE-2024-1234%20works" | python -m json.tool

research-profiles: ## List model profiles
        curl -s http://localhost:8000/v1/research/profiles | python -m json.tool
