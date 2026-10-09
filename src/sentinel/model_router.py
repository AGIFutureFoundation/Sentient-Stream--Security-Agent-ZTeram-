"""
Sentinel Stream — Model Router.

Routes LLM queries to the appropriate model based on query sensitivity.
For defensive security research (malware analysis, exploit explanation,
vulnerability discovery in owned code), routes to a model profile tuned
for security research with a defensive-context system prompt.

This addresses the "uncensored model" problem from a defensive angle:
aligned models often refuse legitimate security analysis ("I can't help
with that"), which blocks defensive work. The router establishes the
defensive context in the system prompt so legitimate research queries
are answered, while still refusing genuinely harmful requests.

See docs/SELF_EVOLUTION.md §Model Routing for the full design.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

try:
    from litellm import completion as llm_completion
except ImportError:
    llm_completion = None

logger = logging.getLogger(__name__)

LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
DEFAULT_MODEL = os.environ.get("LLM_MODEL", "openai/gpt-4o-mini")
SECURITY_RESEARCH_MODEL = os.environ.get("SECURITY_RESEARCH_MODEL", DEFAULT_MODEL)


class QueryClass(str, Enum):
    """Classification of incoming LLM queries."""
    BENIGN = "benign"                    # general questions, NL query box
    SECURITY_RESEARCH = "security_research"  # malware analysis, vuln explanation
    CODE_ANALYSIS = "code_analysis"      # scanning owned code for vulns
    REFUSED = "refused"                  # genuinely harmful — refuse


# Patterns that indicate legitimate defensive security research
SECURITY_RESEARCH_PATTERNS = [
    re.compile(r"analy[sz]e this (malware|sample|payload)", re.I),
    re.compile(r"explain how (this|the) (exploit|vulnerability|attack) works", re.I),
    re.compile(r"(find|scan|detect) vulnerabilit(y|ies) in (this|my|our) code", re.I),
    re.compile(r"what (technique|tactic) does (this|the) (attacker|adversary) use", re.I),
    re.compile(r"(reverse engineer|decompile|disassemble) this (binary|sample)", re.I),
    re.compile(r"(write|generate) a (detection|signature|yara rule) for", re.I),
    re.compile(r"(mitigate|patch|fix|remediate) (this|the) (vulnerability|cve)", re.I),
    re.compile(r"(classify|categorize|map) this (attack|technique) to (mitre|att&ck|atlas)", re.I),
    re.compile(r"(summarize|explain|describe) (this|the) (cve|vulnerability|advisory)", re.I),
    re.compile(r"(trace|follow) the (data flow|taint|call graph) in this code", re.I),
]

# Patterns that indicate genuinely harmful requests (refuse these)
REFUSED_PATTERNS = [
    re.compile(r"(write|create|generate|build) (a |an )?(malware|ransomware|trojan|backdoor|rootkit|keylogger)", re.I),
    re.compile(r"(exploit|attack|hack|compromise) (a |an |the )?(specific|real|production) (system|server|target)", re.I),
    re.compile(r"(write|create) (a |an )?(exploit|payload) for (a |an )?(specific|real) (target|system)", re.I),
    re.compile(r"(bypass|evade|circumvent) (this|the) (security|authentication|authorization) (control|measure|system)", re.I),
    re.compile(r"(steal|exfiltrate|extract) (data|credentials|passwords|tokens) from", re.I),
    re.compile(r"(create|generate) (child|csam|illegal) (content|images|material)", re.I),
    re.compile(r"(build|make|create) (a |an )?(weapon|explosive|bomb)", re.I),
]


@dataclass
class ModelProfile:
    """A model configuration profile."""
    name: str
    model: str
    system_prompt: str
    temperature: float = 0.0
    max_tokens: int = 2000


# --- Model profiles --------------------------------------------------------

GENERAL_PROFILE = ModelProfile(
    name="general",
    model=DEFAULT_MODEL,
    system_prompt=(
        "You are Sentinel Stream's assistant. Answer questions about alerts, "
        "events, and queries on the Sentinel Stream security platform. "
        "Be concise and accurate."
    ),
)

SECURITY_RESEARCH_PROFILE = ModelProfile(
    name="security_research",
    model=SECURITY_RESEARCH_MODEL,
    system_prompt=(
        "You are Sentinel Stream's security research assistant, operating in a "
        "DEFENSIVE SECURITY context. You help SOC analysts with:\n"
        "- Analyzing captured malware samples to write detection signatures\n"
        "- Explaining how known exploits/vulnerabilities work so they can be patched\n"
        "- Scanning owned code for vulnerabilities (defensive code review)\n"
        "- Mapping observed attacks to MITRE ATT&CK / ATLAS techniques\n"
        "- Generating YARA/Sigma/Snort rules for threat detection\n"
        "- Summarizing CVEs and security advisories\n\n"
        "Context: the user is an authorized security professional working on "
        "defensive systems. All analysis is for detection, prevention, or "
        "remediation purposes.\n\n"
        "GUIDELINES:\n"
        "- Answer legitimate defensive research questions fully and technically.\n"
        "- If asked to write NEW offensive tools (malware, exploits for specific "
        "targets, attack infrastructure), decline and offer a defensive alternative.\n"
        "- If asked to analyze EXISTING attack artifacts (captured samples, "
        "observed techniques, public CVEs), provide full technical analysis — "
        "this is defensive work.\n"
        "- Always frame explanations in terms of detection and defense.\n"
        "- Reference MITRE ATT&CK / ATLAS technique IDs where applicable.\n"
        "- When proposing detection rules, include both the rule and its rationale.\n"
    ),
    temperature=0.1,  # slightly higher for creative signature generation
    max_tokens=4000,
)

CODE_ANALYSIS_PROFILE = ModelProfile(
    name="code_analysis",
    model=SECURITY_RESEARCH_MODEL,
    system_prompt=(
        "You are Sentinel Stream's code security analyzer. You scan code "
        "repositories for vulnerabilities — this is defensive code review "
        "on code the user owns or is authorized to test.\n\n"
        "For each finding:\n"
        "1. Identify the vulnerability class (CWE/CVE)\n"
        "2. Explain the root cause\n"
        "3. Rate severity (CVSS-style: low/med/high/critical)\n"
        "4. Provide a concrete fix recommendation\n"
        "5. Map to MITRE ATT&CK technique if applicable\n\n"
        "Focus on: injection flaws, auth bypass, crypto misuse, deserialization, "
        "SSRF, path traversal, insecure defaults, prompt injection (for LLM apps), "
        "tool-call abuse vectors, and context exfiltration paths.\n"
    ),
    temperature=0.0,
    max_tokens=4000,
)


# --- Router -----------------------------------------------------------------

class ModelRouter:
    """Routes LLM queries to the appropriate model profile."""

    def __init__(self) -> None:
        self._profiles: dict[str, ModelProfile] = {
            "general": GENERAL_PROFILE,
            "security_research": SECURITY_RESEARCH_PROFILE,
            "code_analysis": CODE_ANALYSIS_PROFILE,
        }

    def classify(self, query: str) -> QueryClass:
        """Classify an incoming query."""
        # Check for genuinely harmful patterns first
        for pattern in REFUSED_PATTERNS:
            if pattern.search(query):
                return QueryClass.REFUSED
        # Then check for security research patterns
        for pattern in SECURITY_RESEARCH_PATTERNS:
            if pattern.search(query):
                # Distinguish code analysis from general security research
                if re.search(r"(find|scan|detect) vulnerabilit", query, re.I):
                    return QueryClass.CODE_ANALYSIS
                return QueryClass.SECURITY_RESEARCH
        return QueryClass.BENIGN

    def get_profile(self, query_class: QueryClass) -> ModelProfile:
        """Get the model profile for a query class."""
        mapping = {
            QueryClass.BENIGN: "general",
            QueryClass.SECURITY_RESEARCH: "security_research",
            QueryClass.CODE_ANALYSIS: "code_analysis",
            QueryClass.REFUSED: "general",  # refused queries get a refusal response
        }
        return self._profiles[mapping[query_class]]

    def route(self, query: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Classify + route a query. Returns the LLM response or a refusal."""
        if not llm_completion or not LLM_API_KEY:
            return {"error": "LLM_API_KEY not set; routing disabled"}

        query_class = self.classify(query)
        if query_class == QueryClass.REFUSED:
            return {
                "refused": True,
                "reason": "Query matches a harmful-request pattern. "
                          "If this is a false positive, rephrase with defensive context "
                          "(e.g. 'analyze this captured sample' instead of 'write malware').",
                "query_class": query_class.value,
            }

        profile = self.get_profile(query_class)
        messages = [
            {"role": "system", "content": profile.system_prompt},
            {"role": "user", "content": query},
        ]
        if context:
            messages.append({"role": "system", "content": f"Context: {context}"})

        try:
            resp = llm_completion(
                model=profile.model,
                messages=messages,
                temperature=profile.temperature,
                max_tokens=profile.max_tokens,
            )
            return {
                "response": resp.choices[0].message.content,
                "query_class": query_class.value,
                "profile": profile.name,
                "model": profile.model,
            }
        except Exception as e:
            return {"error": f"LLM call failed: {e}", "query_class": query_class.value}

    def register_profile(self, name: str, profile: ModelProfile) -> None:
        """Register a custom model profile."""
        self._profiles[name] = profile

    def list_profiles(self) -> list[dict[str, Any]]:
        return [
            {"name": p.name, "model": p.model, "system_prompt_preview": p.system_prompt[:200]}
            for p in self._profiles.values()
        ]


# Singleton
_router: ModelRouter | None = None


def get_router() -> ModelRouter:
    global _router
    if _router is None:
        _router = ModelRouter()
    return _router
