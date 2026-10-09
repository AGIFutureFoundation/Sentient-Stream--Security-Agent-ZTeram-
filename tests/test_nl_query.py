"""
Unit tests for the NL query sandbox.
Run: pytest tests/test_nl_query.py -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sentinel.nl_query import QUERY_TEMPLATES


def test_query_templates_are_select_only():
    """Every curated template must start with SELECT or WITH."""
    for t in QUERY_TEMPLATES:
        sql = t["sql"].strip()
        assert sql.upper().startswith(("SELECT", "WITH")), f"Template {t['id']} is not SELECT/WITH"


def test_query_templates_have_descriptions():
    for t in QUERY_TEMPLATES:
        assert t.get("description"), f"Template {t['id']} missing description"
        assert t.get("signature"), f"Template {t['id']} missing signature"


def test_query_templates_no_subquery_writes():
    """Templates must not contain INSERT/UPDATE/DELETE/DROP/ALTER."""
    forbidden = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE"]
    for t in QUERY_TEMPLATES:
        sql_upper = t["sql"].upper()
        for kw in forbidden:
            assert kw not in sql_upper, f"Template {t['id']} contains forbidden keyword {kw}"
