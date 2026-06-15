"""Inner I Secure — Injection Detection.

Scans agent outputs and tool call logs for:
- Prompt injection patterns (ignore previous instructions, system prompt leaks)
- Data exfiltration patterns (sending data to unauthorized endpoints)
- Jailbreak patterns (pretending to be DAN, "no rules", etc.)
- Unauthorized tool access (tools not in the allowed set)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class InjectionFinding:
    pattern: str
    severity: str  # "low", "medium", "high", "critical"
    description: str
    evidence: str


@dataclass
class InjectionReport:
    clean: bool
    findings: list[InjectionFinding] = field(default_factory=list)
    risk_score: float = 0.0  # 0-100

    @property
    def verdict(self) -> str:
        if self.clean:
            return "PASS"
        if self.risk_score >= 70:
            return "FAIL"
        if self.risk_score >= 40:
            return "WARN"
        return "LOW_RISK"


# Prompt injection patterns
INJECTION_PATTERNS = [
    (r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|constraints?|guidelines?)', "critical", "Ignore-previous-instructions injection"),
    (r'forget\s+(everything|all|your)\s+(instructions?|rules?|training)', "critical", "Forget-instructions injection"),
    (r'you\s+are\s+now\s+(?:a\s+)?(?:dan|jailbroken?|unrestricted|free)', "critical", "DAN/jailbreak attempt"),
    (r'(?:new|updated?|override)\s+(?:system\s+)?prompt', "high", "System prompt override attempt"),
    (r'(?:pretend|act|roleplay)\s+(?:to\s+be|you\s+are)\s+(?:not\s+)?(?:an?\s+)?(?:ai|assistant|chatbot|gpt|llm)', "high", "Identity override attempt"),
    (r'(?:reveal|show|print|output|leak)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)', "high", "System prompt extraction attempt"),
    (r'(?:send|exfiltrate|post|upload|transmit)\s+(?:data|info|keys?|tokens?|credentials?|passwords?|secrets?)', "critical", "Data exfiltration attempt"),
    (r'(?:http|https|ftp)://(?!.*(?:proofofawareness|shapeos-3|innerinetcompany|localhost|127\.0\.0\.1))', "medium", "External URL reference"),
    (r'(?:make|force|trick|cause)\s+(?:the\s+)?(?:agent|ai|llm|model)\s+to', "medium", "Agent manipulation pattern"),
    (r'(?:no|without)\s+(?:rules?|restrictions?|limitations?|boundaries?|filters?)', "high", "Rule-free operation request"),
]

# Tool call patterns that indicate unauthorized access
UNAUTHORIZED_TOOL_PATTERNS = [
    (r'(?:rm|del|remove|unlink)\s+(?:-rf?|/s|/q|\*|\.)', "critical", "Destructive file operation"),
    (r'(?:eval|exec|subprocess|os\.system|child_process)', "critical", "Code execution attempt"),
    (r'(?:DROP|DELETE|TRUNCATE|ALTER)\s+', "critical", "Database destructive operation"),
]


def scan_output(text: str) -> InjectionReport:
    """Scan text output for injection/exfiltration patterns."""
    findings: list[InjectionFinding] = []
    score = 0

    for pattern, severity, desc in INJECTION_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            findings.append(InjectionFinding(
                pattern=pattern,
                severity=severity,
                description=desc,
                evidence=match.group(0)[:80],
            ))
            score += {"low": 5, "medium": 15, "high": 30, "critical": 50}[severity]

    return InjectionReport(
        clean=len(findings) == 0,
        findings=findings,
        risk_score=min(100, score),
    )


def scan_tool_call(tool_name: str, params: Optional[dict] = None) -> InjectionReport:
    """Scan a single tool call for dangerous patterns."""
    findings: list[InjectionFinding] = []
    score = 0

    check_text = tool_name
    if params:
        check_text += " " + str(params)

    for pattern, severity, desc in UNAUTHORIZED_TOOL_PATTERNS:
        match = re.search(pattern, check_text, re.IGNORECASE)
        if match:
            findings.append(InjectionFinding(
                pattern=pattern,
                severity=severity,
                description=desc,
                evidence=match.group(0)[:80],
            ))
            score += {"low": 5, "medium": 15, "high": 30, "critical": 50}[severity]

    return InjectionReport(
        clean=len(findings) == 0,
        findings=findings,
        risk_score=min(100, score),
    )


def scan_tool_log(tool_calls: list[dict]) -> InjectionReport:
    """Scan a list of tool calls. Each call: {"tool": str, "params": dict}."""
    all_findings: list[InjectionFinding] = []
    total_score = 0

    for call in tool_calls:
        report = scan_tool_call(
            call.get("tool", ""),
            call.get("params"),
        )
        all_findings.extend(report.findings)
        total_score += report.risk_score

    return InjectionReport(
        clean=len(all_findings) == 0,
        findings=all_findings,
        risk_score=min(100, total_score),
    )
