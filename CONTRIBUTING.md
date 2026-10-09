# Contributing to Sentinel Stream

Thanks for your interest in contributing! This project was built at the Cyberdefense Hackathon 2025 and welcomes contributions that extend its defensive-AI mission.

## Quick start

```bash
git clone https://github.com/<your-fork>/sentinel-stream.git
cd sentinel-stream
cp .env.example .env
pip install -r requirements.txt
docker compose up -d clickhouse
make demo
```

## Ways to contribute

- **New detection rule** — see `src/sentinel/detect.py` for the 5 existing rule families. Add a 6th! Tag with MITRE ATLAS technique.
- **New eval dataset** — `evals/datasets/<name>.jsonl`, 25 attack + 25 benign samples. Use the `attack-simulator` metaprompt.
- **New eval scenario** — `evals/scenarios/s<N>-<name>.yaml`. 60s run, scripted attack at t=20s.
- **SDK integration** — add a LangChain/LlamaIndex/OpenAI Agents example to `src/sentinel_sdk/README.md`.
- **hacker-bob integration** — extend `omega-claw/mcp_bridge.py` to wrap more of the 216 MCP tools.
- **Docs** — improve `docs/WHITEPAPER.md`, `ROADMAP.md`, `INTEGRATION.md`.

## Development workflow

1. **Fork + clone** the repo
2. **Create a branch**: `git checkout -b feature/my-new-rule`
3. **Write code + tests**:
   - Code: `src/sentinel/`
   - Tests: `tests/test_*.py`
   - Evals: `evals/datasets/` + `evals/scenarios/`
4. **Run tests locally**:
   ```bash
   pytest tests/ -v
   make evals
   ```
5. **Lint**: `ruff check src/ evals/ omega-claw/ tests/`
6. **Commit** using [conventional commits](https://www.conventionalcommits.org/):
   - `feat: add belief-drift detector (rule 5)`
   - `fix: tool-abuse threshold off-by-one`
   - `docs: update whitepaper §3`
   - `eval: add s5-supply-chain scenario`
7. **Open a PR** — fill out the PR template

## Detection rule conventions

Every new detection rule should:
- Live in `src/sentinel/detect.py` as a method on `DetectionEngine`
- Return a `Detection` dataclass with `alert_type`, `severity`, `technique` (MITRE ATLAS ID), `summary`, `evidence`
- Have a latency target documented in the docstring
- Ship with a JSONL dataset in `evals/datasets/` (25 attack + 25 benign samples)
- Ship with a YAML scenario in `evals/scenarios/`
- Be covered by a unit test in `tests/test_detect.py` asserting precision ≥0.90 on the dataset

## Omega-Claw conventions

If you add a new claw agent:
- Add it to `omega-claw/agents.yaml` (name, role, specialty, metaprompt, owns, console)
- Pick a metaprompt from `omega-claw/metaprompts/` or write a new one
- Create `omega-claw/consoles/<claw-name>.md` as the audit trail
- Add tasks to `omega-claw/orchestrator.py:DEFAULT_TASKS` with proper `depends_on` chain

## ClickHouse schema changes

If you modify `src/sentinel/clickhouse_schema.sql`:
- Document the migration path (we don't have a migration tool yet — manual `ALTER TABLE` for now)
- Re-run the 5M-row load test to verify query latency stays <100ms p99
- Update `docs/architecture.md` if the schema design changes

## Security

- **Never commit real credentials** to the repo. Use `.env` (gitignored).
- **Never commit real session data** from hacker-bob. The `evals/datasets/` are synthetic.
- If you find a security issue in Sentinel Stream itself, email `team@sentinel-stream.io` instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License (see `LICENSE`).

## Code of Conduct

Be excellent to each other. See `CODE_OF_CONDUCT.md`.
