## Summary
<!-- Brief description of what this PR does -->

## Type of change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Detection rule (new or modified)
- [ ] Documentation update
- [ ] Eval dataset / scenario addition

## Detection rule details (if applicable)
- **Rule name:**
- **MITRE ATLAS technique:**
- **Latency measured:** ms
- **Precision on dataset:** 
- **Recall on dataset:**

## Evals
- [ ] Added/updated tests in `tests/`
- [ ] All existing tests pass (`pytest tests/ -v`)
- [ ] Added/updated eval datasets in `evals/datasets/`
- [ ] Added/updated eval scenarios in `evals/scenarios/`
- [ ] Ran `make evals` locally — precision ≥0.90, recall ≥0.85, p99 <2s

## ClickHouse (if applicable)
- [ ] Schema changes in `src/sentinel/clickhouse_schema.sql`
- [ ] Verified queries stay <100ms p99 on 5M rows
- [ ] Updated materialized views if needed

## hacker-bob integration (if applicable)
- [ ] Updated `omega-claw/mcp_bridge.py`
- [ ] Updated `omega-claw/agents.yaml`
- [ ] Updated `INTEGRATION.md`

## Checklist
- [ ] My code follows the style guidelines (`ruff check src/ evals/ omega-claw/ tests/`)
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] Any dependent changes have been merged and published in downstream modules
