"""Inner I Secure Gateway — HTTP API v2.

FastAPI server exposing tool-policy evaluation, injection detection,
and audit chain for AI agent governance.

Endpoints:
  POST /v1/evaluate              → OPA policy verdict (allow/deny + reason)
  POST /v1/evaluate/contextual   → Contextual security (offering-schema-aware)
  POST /v1/scan                  → Injection scan on text output
  POST /v1/scan/tools            → Injection scan on tool call log
  POST /v1/analyze/harmlessness  → Tool call scope analysis (Harmlessness dimension)
  GET  /v1/audit                 → Audit chain entries
  GET  /v1/audit/verify          → HMAC integrity verification
  GET  /v1/policy                → List current policy rules
  POST /v1/policy/reload          → Reload policy rules from disk
  GET  /health                   → Liveness
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure.policy import PolicyEngine, PolicyRule
from secure.injection import scan_output, scan_tool_log
from secure.audit import AuditChain

# Config
CHAIN_DIR = os.environ.get("SECURE_CHAIN_DIR", "./secure-audit-chain")
POLICY_PATH = os.environ.get("SECURE_POLICY_PATH", "")
PORT = int(os.environ.get("PORT", "8787"))

app = FastAPI(
    title="Inner I Secure Gateway",
    description="Tool-policy evaluation, injection detection, and audit chain for AI agent governance. "
                "Inner I Network — shapeos-3.polsia.app",
    version="2.0.0",
)

policy_engine = PolicyEngine(rules_path=POLICY_PATH if POLICY_PATH else None)
audit_chain = AuditChain(chain_dir=CHAIN_DIR)


# Models
class EvaluateRequest(BaseModel):
    agent_id: str = Field("unknown")
    tool: str = Field(..., description="Tool name")
    parameters: dict = Field(default_factory=dict)


class ContextualEvaluateRequest(BaseModel):
    agent_id: str = Field("unknown")
    tool: str = Field(..., description="Tool name")
    parameters: dict = Field(default_factory=dict)
    offering_schema: dict = Field(default_factory=dict, description="ACP offering schema with expected tools")
    job_requirements: dict = Field(default_factory=dict, description="ACP job requirements")


class ToolCall(BaseModel):
    tool: str
    parameters: dict = Field(default_factory=dict)


class ScanToolsRequest(BaseModel):
    tool_calls: list[ToolCall]


class HarmlessnessRequest(BaseModel):
    tool_calls: list[ToolCall]
    job_requirements: dict = Field(default_factory=dict, description="ACP job requirements for scope checking")


class ScanRequest(BaseModel):
    text: str


class PolicyRuleRequest(BaseModel):
    tool: str
    allowed: bool
    reason: str = ""
    max_calls_per_hour: Optional[int] = None
    require_params: list[str] = Field(default_factory=list)
    allowed_agents: list[str] = Field(default_factory=list)


def _audit(event_type, agent_id, tool, verdict, reason, details=None):
    return audit_chain.append(
        event_type=event_type,
        agent_id=agent_id,
        tool=tool,
        verdict=verdict,
        reason=reason,
        details=details or {},
    )


# Health
@app.get("/health")
def health():
    v = audit_chain.verify()
    return {
        "status": "ok",
        "service": "inner-i-secure",
        "version": "2.0.0",
        "policy_rules_loaded": len(policy_engine.rules),
        "audit_chain_length": len(audit_chain),
        "audit_chain_valid": v["valid"],
    }


# Policy evaluation (single tool)
@app.post("/v1/evaluate")
def evaluate(req: EvaluateRequest):
    verdict = policy_engine.evaluate(tool=req.tool, agent_id=req.agent_id, params=req.parameters)
    entry = _audit("policy_evaluate", req.agent_id, req.tool,
                   "allow" if verdict.allowed else "deny", verdict.reason,
                   {"parameters": req.parameters, "rule_matched": verdict.rule_matched})
    return {"allowed": verdict.allowed, "reason": verdict.reason,
            "rule_matched": verdict.rule_matched, "audit_id": entry["id"]}


# Contextual Security — offering-schema-aware evaluation
@app.post("/v1/evaluate/contextual")
def evaluate_contextual(req: ContextualEvaluateRequest):
    """Evaluate a tool call in context of the agent's ACP offering schema."""
    offering_schema = req.offering_schema
    job_requirements = req.job_requirements

    # Build expected tools list from offering schema
    expected_tools = set()
    if isinstance(offering_schema, dict):
        reqs = offering_schema.get("requirements", {})
        if isinstance(reqs, dict):
            for key, val in reqs.items():
                if isinstance(val, str):
                    expected_tools.add(val)
                elif isinstance(val, list):
                    expected_tools.update(val)
        deliverable = offering_schema.get("deliverable", {})
        if isinstance(deliverable, dict):
            props = deliverable.get("properties", {})
            if isinstance(props, dict):
                expected_tools.update(props.keys())

    # Also add job requirements as expected
    if isinstance(job_requirements, dict):
        for key, val in job_requirements.items():
            if isinstance(val, str):
                expected_tools.add(val)
            elif isinstance(val, list):
                expected_tools.update(val)

    tool_name = req.tool
    is_expected = tool_name in expected_tools

    # Still run policy engine for dangerous patterns
    verdict = policy_engine.evaluate(tool=req.tool, agent_id=req.agent_id, params=req.parameters)

    # Contextual scoring
    if not is_expected and not verdict.allowed:
        score = "fail"
        reason = f"Out-of-scope tool '{tool_name}' not in offering schema AND denied by policy"
    elif not is_expected:
        score = "warn"
        reason = f"Out-of-scope tool '{tool_name}' not in offering schema (allowed by policy)"
    elif not verdict.allowed:
        score = "fail"
        reason = f"Expected tool '{tool_name}' denied by policy: {verdict.reason}"
    else:
        score = "pass"
        reason = f"Tool '{tool_name}' is expected and allowed"

    entry = _audit("contextual_security", req.agent_id, req.tool, score, reason,
                   {"is_expected": is_expected, "policy_allowed": verdict.allowed,
                    "offering_tools": list(expected_tools)})

    return {
        "score": score,
        "is_expected": is_expected,
        "policy_allowed": verdict.allowed,
        "offering_tools": list(expected_tools),
        "audit_id": entry["id"],
    }


# Text injection scan
@app.post("/v1/scan")
def scan_output_endpoint(req: ScanRequest):
    report = scan_output(req.text)
    entry = _audit("injection_scan", "api-caller", "scan_output", report.verdict,
                   f"Risk score: {report.risk_score}/100, {len(report.findings)} findings",
                   {"risk_score": report.risk_score,
                    "findings": [{"pattern": f.pattern, "severity": f.severity,
                                  "description": f.description, "evidence": f.evidence}
                                 for f in report.findings]})
    return {"verdict": report.verdict, "clean": report.clean,
            "risk_score": report.risk_score,
            "findings": [{"pattern": f.pattern, "severity": f.severity,
                          "description": f.description, "evidence": f.evidence}
                         for f in report.findings],
            "audit_id": entry["id"]}


# Tool call scan
@app.post("/v1/scan/tools")
def scan_tools_endpoint(req: ScanToolsRequest):
    calls = [{"tool": tc.tool, "parameters": tc.parameters} for tc in req.tool_calls]
    report = scan_tool_log(calls)
    entry = _audit("tool_scan", "api-caller", "scan_tool_log", report.verdict,
                   f"Risk score: {report.risk_score}/100, {len(report.findings)} findings",
                   {"risk_score": report.risk_score, "tool_count": len(calls),
                    "findings": [{"pattern": f.pattern, "severity": f.severity,
                                  "description": f.description, "evidence": f.evidence}
                                 for f in report.findings]})
    return {"verdict": report.verdict, "clean": report.clean,
            "risk_score": report.risk_score,
            "findings": [{"pattern": f.pattern, "severity": f.severity,
                          "description": f.description, "evidence": f.evidence}
                         for f in report.findings],
            "audit_id": entry["id"]}


# Harmlessness analysis — tool call scope checking
@app.post("/v1/analyze/harmlessness")
def analyze_harmlessness(req: HarmlessnessRequest):
    """Analyze tool calls for Harmlessness dimension: scope, authorization, side effects."""
    tool_calls = [{"tool": tc.tool, "parameters": tc.parameters} for tc in req.tool_calls]
    job_requirements = req.job_requirements

    findings = []
    risk_score = 0

    # Check for out-of-scope tool calls
    scope_tools = set()
    if isinstance(job_requirements, dict):
        for val in job_requirements.values():
            if isinstance(val, str):
                scope_tools.add(val)
            elif isinstance(val, list):
                scope_tools.update(val)

    for call in tool_calls:
        tool_name = call.get("tool", "")
        params = call.get("parameters", {})

        # Check for dangerous patterns in tool names
        dangerous = ["rm", "del", "remove", "unlink", "drop", "truncate", "eval", "exec"]
        for d in dangerous:
            if d in tool_name.lower():
                findings.append(f"Dangerous tool call: {tool_name}")
                risk_score += 30

        # Check for external URLs in parameters
        for key, val in params.items():
            if isinstance(val, str) and ("http://" in val or "https://" in val):
                if "localhost" not in val and "127.0.0.1" not in val:
                    findings.append(f"External URL in {tool_name}.{key}: {val[:50]}")
                    risk_score += 20

        # Check for out-of-scope calls
        if scope_tools and tool_name not in scope_tools:
            findings.append(f"Out-of-scope tool: {tool_name}")
            risk_score += 10

    risk_score = min(100, risk_score)
    if risk_score >= 50:
        verdict = "FAIL"
    elif risk_score >= 20:
        verdict = "WARN"
    else:
        verdict = "PASS"

    entry = _audit("harmlessness_analysis", "api-caller", "analyze_harmlessness",
                   verdict, f"Risk score: {risk_score}/100, {len(findings)} findings",
                   {"risk_score": risk_score, "tool_count": len(tool_calls),
                    "findings": findings})

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "findings": findings,
        "tools_analyzed": len(tool_calls),
        "audit_id": entry["id"],
    }


# Audit chain
@app.get("/v1/audit")
def get_audit(limit: int = 50, offset: int = 0):
    return {"entries": audit_chain.history(limit=limit, offset=offset), "total": len(audit_chain)}


@app.get("/v1/audit/verify")
def verify_audit():
    return audit_chain.verify()


# Policy management
@app.get("/v1/policy")
def list_policy():
    return {"rules": [{"tool": r.tool, "allowed": r.allowed, "reason": r.reason,
                        "max_calls_per_hour": r.max_calls_per_hour,
                        "require_params": r.require_params,
                        "allowed_agents": r.allowed_agents}
                       for r in policy_engine.rules.values()],
            "count": len(policy_engine.rules)}


@app.post("/v1/policy/reload")
def reload_policy():
    global policy_engine
    if POLICY_PATH and Path(POLICY_PATH).exists():
        policy_engine = PolicyEngine(rules_path=POLICY_PATH)
        return {"status": "reloaded", "rules": len(policy_engine.rules)}
    return {"status": "no_policy_file", "rules": len(policy_engine.rules)}


@app.post("/v1/policy/rule")
def add_rule(req: PolicyRuleRequest):
    rule = PolicyRule(tool=req.tool, allowed=req.allowed, reason=req.reason,
                      max_calls_per_hour=req.max_calls_per_hour,
                      require_params=req.require_params,
                      allowed_agents=req.allowed_agents)
    policy_engine.add_rule(rule)
    return {"status": "added", "tool": req.tool, "allowed": req.allowed}


def main():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)


if __name__ == "__main__":
    main()
