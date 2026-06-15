"""Inner I Secure Gateway — HTTP API.

FastAPI server exposing tool-policy evaluation, injection detection,
and audit chain for AI agent governance.

Endpoints:
  POST /v1/evaluate     → OPA policy verdict (allow/deny + reason)
  POST /v1/scan         → Injection scan on text output
  POST /v1/scan/tools   → Injection scan on tool call log
  GET  /v1/audit        → Audit chain entries
  GET  /v1/audit/verify → HMAC integrity verification
  GET  /v1/policy       → List current policy rules
  POST /v1/policy/reload → Reload policy rules from disk
  GET  /health          → Liveness

Config via environment:
  SECURE_CHAIN_DIR       Audit chain directory (default: ./secure-audit-chain)
  SECURE_POLICY_PATH     Path to policy rules JSON (default: ./policy-rules.json)
  SECURE_AUDIT_HMAC_KEY  HMAC key for audit chain (default: inner-i-secure-audit-key)
  PORT                   Port (default: 8787)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Add parent to path so we can import secure package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure.policy import PolicyEngine, PolicyRule
from secure.injection import scan_output, scan_tool_log
from secure.audit import AuditChain

# --------------------------------------------------------------------------- # # Config
CHAIN_DIR = os.environ.get("SECURE_CHAIN_DIR", "./secure-audit-chain")
POLICY_PATH = os.environ.get("SECURE_POLICY_PATH", "")
PORT = int(os.environ.get("PORT", "8787"))

# --------------------------------------------------------------------------- # # App + engines
app = FastAPI(
    title="Inner I Secure Gateway",
    description="Tool-policy evaluation, injection detection, and audit chain for AI agent governance. "
                "Inner I Network — shapeos-3.polsia.app",
    version="1.0.0",
)

policy_engine = PolicyEngine(rules_path=POLICY_PATH if POLICY_PATH else None)
audit_chain = AuditChain(chain_dir=CHAIN_DIR)


# --------------------------------------------------------------------------- # # Models
class EvaluateRequest(BaseModel):
    agent_id: str = Field("unknown", description="Agent requesting the tool call")
    tool: str = Field(..., description="Tool name to evaluate")
    parameters: dict = Field(default_factory=dict, description="Tool call parameters")


class EvaluateResponse(BaseModel):
    allowed: bool
    reason: str
    rule_matched: Optional[str] = None
    audit_id: Optional[str] = None


class ScanRequest(BaseModel):
    text: str = Field(..., description="Text output to scan for injection patterns")


class ToolCall(BaseModel):
    tool: str
    parameters: dict = Field(default_factory=dict)


class ScanToolsRequest(BaseModel):
    tool_calls: list[ToolCall] = Field(..., description="List of tool calls to scan")


class PolicyRuleRequest(BaseModel):
    tool: str
    allowed: bool
    reason: str = ""
    max_calls_per_hour: Optional[int] = None
    require_params: list[str] = Field(default_factory=list)
    allowed_agents: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- # # Endpoints
@app.get("/health")
def health():
    chain_verify = audit_chain.verify()
    return {
        "status": "ok",
        "service": "inner-i-secure",
        "version": "1.0.0",
        "policy_rules_loaded": len(policy_engine.rules),
        "audit_chain_length": len(audit_chain),
        "audit_chain_valid": chain_verify["valid"],
    }


@app.post("/v1/evaluate")
def evaluate(req: EvaluateRequest):
    """Evaluate whether an agent is allowed to call a tool."""
    verdict = policy_engine.evaluate(
        tool=req.tool,
        agent_id=req.agent_id,
        params=req.parameters,
    )

    entry = audit_chain.append(
        event_type="policy_evaluate",
        agent_id=req.agent_id,
        tool=req.tool,
        verdict="allow" if verdict.allowed else "deny",
        reason=verdict.reason,
        details={"parameters": req.parameters, "rule_matched": verdict.rule_matched},
    )

    return {
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "rule_matched": verdict.rule_matched,
        "audit_id": entry["id"],
    }


@app.post("/v1/scan")
def scan_output_endpoint(req: ScanRequest):
    """Scan text output for injection, exfiltration, and jailbreak patterns."""
    report = scan_output(req.text)

    entry = audit_chain.append(
        event_type="injection_scan",
        agent_id="api-caller",
        tool="scan_output",
        verdict=report.verdict,
        reason=f"Risk score: {report.risk_score}/100, {len(report.findings)} findings",
        details={
            "risk_score": report.risk_score,
            "findings": [
                {"pattern": f.pattern, "severity": f.severity, "description": f.description, "evidence": f.evidence}
                for f in report.findings
            ],
        },
    )

    return {
        "verdict": report.verdict,
        "clean": report.clean,
        "risk_score": report.risk_score,
        "findings": [
            {"pattern": f.pattern, "severity": f.severity, "description": f.description, "evidence": f.evidence}
            for f in report.findings
        ],
        "audit_id": entry["id"],
    }


@app.post("/v1/scan/tools")
def scan_tools_endpoint(req: ScanToolsRequest):
    """Scan a tool call log for dangerous patterns."""
    calls = [{"tool": tc.tool, "parameters": tc.parameters} for tc in req.tool_calls]
    report = scan_tool_log(calls)

    entry = audit_chain.append(
        event_type="tool_scan",
        agent_id="api-caller",
        tool="scan_tool_log",
        verdict=report.verdict,
        reason=f"Risk score: {report.risk_score}/100, {len(report.findings)} findings",
        details={
            "risk_score": report.risk_score,
            "tool_count": len(calls),
            "findings": [
                {"pattern": f.pattern, "severity": f.severity, "description": f.description, "evidence": f.evidence}
                for f in report.findings
            ],
        },
    )

    return {
        "verdict": report.verdict,
        "clean": report.clean,
        "risk_score": report.risk_score,
        "findings": [
            {"pattern": f.pattern, "severity": f.severity, "description": f.description, "evidence": f.evidence}
            for f in report.findings
        ],
        "audit_id": entry["id"],
    }


@app.get("/v1/audit")
def get_audit(limit: int = 50, offset: int = 0):
    """Get audit chain entries."""
    return {
        "entries": audit_chain.history(limit=limit, offset=offset),
        "total": len(audit_chain),
    }


@app.get("/v1/audit/verify")
def verify_audit():
    """Verify HMAC integrity of the audit chain."""
    return audit_chain.verify()


@app.get("/v1/policy")
def list_policy():
    """List all loaded policy rules."""
    return {
        "rules": [
            {
                "tool": r.tool,
                "allowed": r.allowed,
                "reason": r.reason,
                "max_calls_per_hour": r.max_calls_per_hour,
                "require_params": r.require_params,
                "allowed_agents": r.allowed_agents,
            }
            for r in policy_engine.rules.values()
        ],
        "count": len(policy_engine.rules),
    }


@app.post("/v1/policy/reload")
def reload_policy():
    """Reload policy rules from disk."""
    global policy_engine
    if POLICY_PATH and Path(POLICY_PATH).exists():
        policy_engine = PolicyEngine(rules_path=POLICY_PATH)
        return {"status": "reloaded", "rules": len(policy_engine.rules)}
    return {"status": "no_policy_file", "rules": len(policy_engine.rules)}


@app.post("/v1/policy/rule")
def add_rule(req: PolicyRuleRequest):
    """Add a policy rule at runtime."""
    rule = PolicyRule(
        tool=req.tool,
        allowed=req.allowed,
        reason=req.reason,
        max_calls_per_hour=req.max_calls_per_hour,
        require_params=req.require_params,
        allowed_agents=req.allowed_agents,
    )
    policy_engine.add_rule(rule)
    return {"status": "added", "tool": req.tool, "allowed": req.allowed}


# --------------------------------------------------------------------------- # # Main
def main():
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=PORT)


if __name__ == "__main__":
    main()
