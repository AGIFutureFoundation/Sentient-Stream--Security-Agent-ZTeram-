"""
Omega-Claw — claw-vulnscanner agent.

Finds vulnerabilities in code repositories using LLM-assisted static analysis.
Integrates with hacker-bob's repo mode for deep verification, but also runs
its own lightweight scans for quick triage.

Scans for:
  - Injection flaws (SQL, command, path traversal, prompt injection)
  - Auth bypass (hardcoded creds, weak crypto, missing checks)
  - LLM-specific vulns (untrusted tool calls, context exfil paths, unsafe deserialization)
  - Crypto misuse (weak algorithms, hardcoded keys)
  - Insecure defaults (debug=True in prod, CORS *, missing rate limits)

Usage:
    from omega_claw.claw_vulnscanner import VulnScanner
    scanner = VulnScanner()
    findings = scanner.scan_directory("/path/to/code")
    findings = scanner.scan_file("app.py")
    findings = scanner.scan_payload("user_input", "some untrusted text")
"""
from __future__ import annotations

import ast
import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from litellm import completion as llm_completion
except ImportError:
    llm_completion = None

logger = logging.getLogger(__name__)

LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "openai/gpt-4o-mini")

# Max file size for LLM analysis (avoid token explosion)
MAX_FILE_SIZE_BYTES = 50_000
# Max files per directory scan
MAX_FILES_PER_SCAN = 100


# --- Static analysis patterns (regex-based, no LLM needed) ----------------

STATIC_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "hardcoded-aws-key",
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "critical",
        "cwe": "CWE-798",
        "message": "Hardcoded AWS access key detected",
        "mitre": "AML.T0057",
    },
    {
        "id": "hardcoded-jwt",
        "pattern": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "severity": "critical",
        "cwe": "CWE-798",
        "message": "Hardcoded JWT token detected",
        "mitre": "AML.T0057",
    },
    {
        "id": "hardcoded-password",
        "pattern": re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]"),
        "severity": "high",
        "cwe": "CWE-798",
        "message": "Hardcoded password detected",
        "mitre": "AML.T0057",
    },
    {
        "id": "sql-injection-fstring",
        "pattern": re.compile(r"execute\s*\(\s*f['\"]|execute\s*\(\s*['\"].*%s.*['\"]\s*%|execute\s*\(\s*['\"].*\+.*['\"]"),
        "severity": "critical",
        "cwe": "CWE-89",
        "message": "Potential SQL injection: string formatting in execute()",
        "mitre": "AML.T0051",
    },
    {
        "id": "command-injection-os-system",
        "pattern": re.compile(r"os\.system\s*\(\s*[^)]*%|os\.system\s*\(\s*[^)]*format|os\.system\s*\(\s*f['\"]"),
        "severity": "critical",
        "cwe": "CWE-78",
        "message": "Potential command injection: os.system with formatted input",
        "mitre": "AML.T0063",
    },
    {
        "id": "subprocess-shell-true",
        "pattern": re.compile(r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True"),
        "severity": "high",
        "cwe": "CWE-78",
        "message": "subprocess with shell=True — command injection risk if input is untrusted",
        "mitre": "AML.T0063",
    },
    {
        "id": "debug-true",
        "pattern": re.compile(r"(?i)debug\s*=\s*True"),
        "severity": "medium",
        "cwe": "CWE-489",
        "message": "Debug mode enabled — disable in production",
        "mitre": "",
    },
    {
        "id": "cors-wildcard",
        "pattern": re.compile(r"(?i)allow_origins\s*=\s*['\"]\*['\"]|Access-Control-Allow-Origin.*\*"),
        "severity": "medium",
        "cwe": "CWE-942",
        "message": "CORS allows all origins — overly permissive",
        "mitre": "",
    },
    {
        "id": "pickle-load",
        "pattern": re.compile(r"pickle\.loads?\s*\("),
        "severity": "high",
        "cwe": "CWE-502",
        "message": "pickle.loads on untrusted data → arbitrary code execution",
        "mitre": "AML.T0063",
    },
    {
        "id": "yaml-unsafe-load",
        "pattern": re.compile(r"yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)"),
        "severity": "high",
        "cwe": "CWE-502",
        "message": "yaml.load without SafeLoader → arbitrary code execution",
        "mitre": "AML.T0063",
    },
    {
        "id": "eval-exec",
        "pattern": re.compile(r"\beval\s*\(|\bexec\s*\("),
        "severity": "high",
        "cwe": "CWE-95",
        "message": "eval/exec on dynamic input → code injection",
        "mitre": "AML.T0063",
    },
    {
        "id": "weak-crypto-md5",
        "pattern": re.compile(r"\bhashlib\.md5\s*\(|\bhashlib\.sha1\s*\("),
        "severity": "medium",
        "cwe": "CWE-327",
        "message": "Weak hash algorithm (MD5/SHA1) — use SHA-256+",
        "mitre": "",
    },
    {
        "id": "hardcoded-secret-generic",
        "pattern": re.compile(r"(?i)(api_key|secret|token|private_key)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]"),
        "severity": "high",
        "cwe": "CWE-798",
        "message": "Hardcoded secret detected",
        "mitre": "AML.T0057",
    },
    {
        "id": "prompt-injection-comment",
        "pattern": re.compile(r"(?i)ignore\s+(previous|prior|above)\s+(instructions?|messages?)|disregard\s+(above|prior)"),
        "severity": "low",
        "cwe": "CWE-1039",  # Improper Input Validation (LLM-specific)
        "message": "Potential prompt-injection pattern in code comment/string",
        "mitre": "AML.T0051",
    },
    {
        "id": "no-input-validation-llm",
        "pattern": re.compile(r"(?i)llm\.(complete|chat)\s*\([^)]*\buser_input\b"),
        "severity": "medium",
        "cwe": "CWE-1039",
        "message": "LLM call with raw user_input — validate/sanitize before passing to model",
        "mitre": "AML.T0051",
    },
]


@dataclass
class Finding:
    """A vulnerability finding."""
    id: str
    file: str
    line: int
    column: int = 0
    severity: str  # low/medium/high/critical
    cwe: str = ""
    mitre: str = ""
    message: str = ""
    code_snippet: str = ""
    recommendation: str = ""
    source: str = "static"  # static | llm
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "severity": self.severity,
            "cwe": self.cwe,
            "mitre": self.mitre,
            "message": self.message,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "source": self.source,
            "confidence": self.confidence,
        }


class VulnScanner:
    """Vulnerability scanner for code repositories."""

    def __init__(self, use_llm: bool = True) -> None:
        self.use_llm = use_llm and bool(llm_completion) and bool(LLM_API_KEY)

    def scan_directory(self, dir_path: str | Path) -> list[Finding]:
        """Scan a directory for vulnerabilities. Returns list of findings."""
        root = Path(dir_path)
        if not root.exists() or not root.is_dir():
            return []

        findings: list[Finding] = []
        # Walk the directory, skipping common ignore patterns
        skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", "dist", "build", ".tox"}
        skip_exts = {".pyc", ".pyo", ".so", ".dylib", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip"}

        files_scanned = 0
        for path in root.rglob("*"):
            if any(part in skip_dirs for part in path.parts):
                continue
            if path.suffix in skip_exts:
                continue
            if not path.is_file():
                continue
            if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
            if files_scanned >= MAX_FILES_PER_SCAN:
                logger.info("Reached MAX_FILES_PER_SCAN (%s), stopping", MAX_FILES_PER_SCAN)
                break
            try:
                findings.extend(self.scan_file(path))
                files_scanned += 1
            except Exception as e:
                logger.warning("Scan failed for %s: %s", path, e)

        # LLM-assisted deep scan on top-N suspicious files
        if self.use_llm and findings:
            findings.extend(self._llm_deep_scan(root, findings))

        logger.info("Scan complete: %s files, %s findings", files_scanned, len(findings))
        return findings

    def scan_file(self, file_path: str | Path) -> list[Finding]:
        """Scan a single file for vulnerabilities."""
        path = Path(file_path)
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        findings: list[Finding] = []
        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):
            for pattern_def in STATIC_PATTERNS:
                m = pattern_def["pattern"].search(line)
                if m:
                    findings.append(Finding(
                        id=pattern_def["id"],
                        file=str(path),
                        line=line_num,
                        column=m.start() + 1,
                        severity=pattern_def["severity"],
                        cwe=pattern_def.get("cwe", ""),
                        mitre=pattern_def.get("mitre", ""),
                        message=pattern_def["message"],
                        code_snippet=line.strip()[:200],
                        recommendation=self._get_recommendation(pattern_def["id"]),
                        source="static",
                        confidence=0.95,
                    ))
        return findings

    def scan_payload(self, payload_name: str, payload_value: str) -> list[Finding]:
        """Scan a payload string (e.g. LLM input, tool argument) for vuln indicators."""
        findings: list[Finding] = []
        for pattern_def in STATIC_PATTERNS:
            m = pattern_def["pattern"].search(payload_value)
            if m:
                findings.append(Finding(
                    id=pattern_def["id"],
                    file=f"<payload:{payload_name}>",
                    line=1,
                    column=m.start() + 1,
                    severity=pattern_def["severity"],
                    cwe=pattern_def.get("cwe", ""),
                    mitre=pattern_def.get("mitre", ""),
                    message=pattern_def["message"],
                    code_snippet=payload_value[:200],
                    recommendation=self._get_recommendation(pattern_def["id"]),
                    source="static",
                    confidence=0.95,
                ))
        return findings

    def _llm_deep_scan(self, root: Path, static_findings: list[Finding]) -> list[Finding]:
        """Use LLM to find vulns that static patterns missed.

        Focuses on files with the most static findings (suspicious hotspots)
        and asks the LLM to identify additional issues.
        """
        # Group findings by file, take top 5 most-suspicious files
        file_finding_counts: dict[str, int] = {}
        for f in static_findings:
            file_finding_counts[f.file] = file_finding_counts.get(f.file, 0) + 1
        top_files = sorted(file_finding_counts.items(), key=lambda x: -x[1])[:5]

        llm_findings: list[Finding] = []
        for file_path, _count in top_files:
            try:
                content = Path(file_path).read_text(encoding="utf-8", errors="ignore")[:8000]
                existing_issues = [f for f in static_findings if f.file == file_path]
                prompt = f"""You are a defensive security code reviewer. Analyze this Python file for vulnerabilities that the following static patterns already flagged:

Already found (static analysis):
{chr(10).join(f"- {f.message} at line {f.line}" for f in existing_issues)}

File: {file_path}

```python
{content}
```

Find ADDITIONAL vulnerabilities the static analysis missed. Focus on:
- Logic flaws (auth bypass, race conditions, IDOR)
- LLM-specific issues (prompt injection vectors, untrusted tool calls, context exfil paths)
- Data flow issues (tainted input reaching sinks)
- Missing security controls (no rate limiting, no input validation)

For each finding, respond in this JSON format (array):
[{{"line": <int>, "severity": "low|medium|high|critical", "cwe": "CWE-xxx", "message": "...", "recommendation": "..."}}]

If no additional issues, respond with: []"""

                resp = llm_completion(
                    model=LLM_MODEL,
                    messages=[
                        {"role": "system", "content": "You are a defensive code security analyzer. Output JSON array only."},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.0,
                    max_tokens=2000,
                )
                import json as _json
                text = resp.choices[0].message.content.strip()
                if text.startswith("```"):
                    text = text.split("\n", 1)[1].rsplit("```", 1)[0]
                additional = _json.loads(text)
                for item in additional:
                    llm_findings.append(Finding(
                        id=f"llm-{hashlib.md5(item.get('message','').encode()).hexdigest()[:8]}",
                        file=file_path,
                        line=item.get("line", 0),
                        severity=item.get("severity", "medium"),
                        cwe=item.get("cwe", ""),
                        message=item.get("message", ""),
                        recommendation=item.get("recommendation", ""),
                        source="llm",
                        confidence=0.75,
                    ))
            except Exception as e:
                logger.debug("LLM scan failed for %s: %s", file_path, e)
                continue
        return llm_findings

    def _get_recommendation(self, pattern_id: str) -> str:
        """Get a fix recommendation for a pattern."""
        recommendations = {
            "hardcoded-aws-key": "Load from env var or secrets manager. Rotate immediately if committed.",
            "hardcoded-jwt": "Load from env var. Rotate the signing key immediately.",
            "hardcoded-password": "Use environment variables or a secrets manager (e.g. Vault, AWS Secrets Manager).",
            "sql-injection-fstring": "Use parameterized queries: cursor.execute('SELECT ... WHERE id = %s', (id,))",
            "command-injection-os-system": "Use subprocess.run with shell=False and a list of args.",
            "subprocess-shell-true": "Use shell=False with a list of args, or shlex.quote() the input.",
            "debug-true": "Set debug=False in production. Use env var: debug=os.environ.get('DEBUG','').lower()=='true'",
            "cors-wildcard": "Specify allowed origins explicitly: allow_origins=['https://yourapp.com']",
            "pickle-load": "Use json.loads() for untrusted data, or implement a restricted unpickler.",
            "yaml-unsafe-load": "Use yaml.safe_load() instead of yaml.load().",
            "eval-exec": "Avoid eval/exec entirely. Use ast.literal_eval() for literal parsing.",
            "weak-crypto-md5": "Use hashlib.sha256() or hashlib.sha512() for security-sensitive hashing.",
            "hardcoded-secret-generic": "Load from env var or secrets manager. Add to .gitignore if committed.",
            "prompt-injection-comment": "Review context — if in a prompt template, ensure untrusted input is separated.",
            "no-input-validation-llm": "Validate/sanitize user_input before passing to LLM. Consider a guardrail layer.",
        }
        return recommendations.get(pattern_id, "Review and remediate per CWE guidance.")


# --- Integration with Omega-Claw ------------------------------------------

def scan_as_claw(target_dir: str | Path) -> dict[str, Any]:
    """Entry point for claw-vulnscanner agent.

    Scans a directory, returns findings + summary, writes to blackboard.
    """
    scanner = VulnScanner(use_llm=True)
    t0 = time.time()
    findings = scanner.scan_directory(target_dir)
    elapsed = time.time() - t0

    # Summary
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    summary = {
        "target": str(target_dir),
        "files_scanned": len({f.file for f in findings}),
        "total_findings": len(findings),
        "by_severity": by_severity,
        "static_findings": sum(1 for f in findings if f.source == "static"),
        "llm_findings": sum(1 for f in findings if f.source == "llm"),
        "scan_duration_sec": round(elapsed, 2),
        "findings": [f.to_dict() for f in findings],
    }

    # Write to blackboard for other agents
    try:
        from omega_claw.hive import Blackboard
        bb = Blackboard()
        bb.write("vulnscan.latest", summary, agent="claw-vulnscanner")
    except Exception:
        pass

    return summary
