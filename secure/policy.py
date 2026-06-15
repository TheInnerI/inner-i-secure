"""Inner I Secure — Tool Policy Engine.

OPA-inspired policy evaluation for AI agent tool calls.
Fail-closed: if no rule matches, deny.

Policy rules are loaded from a JSON file at startup.
Each rule maps a tool name to an allow/deny + optional conditions.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class PolicyRule:
    tool: str
    allowed: bool
    reason: str = ""
    max_calls_per_hour: Optional[int] = None
    require_params: list[str] = field(default_factory=list)
    allowed_agents: list[str] = field(default_factory=list)  # empty = all agents


@dataclass
class PolicyVerdict:
    allowed: bool
    reason: str
    rule_matched: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


class PolicyEngine:
    def __init__(self, rules_path: Optional[str] = None):
        self.rules: dict[str, PolicyRule] = {}
        self._call_log: dict[str, list[float]] = {}  # tool -> [timestamps]
        if rules_path and Path(rules_path).exists():
            self._load_rules(rules_path)

    def _load_rules(self, path: str):
        with open(path) as f:
            data = json.load(f)
        for entry in data.get("rules", []):
            rule = PolicyRule(
                tool=entry["tool"],
                allowed=entry.get("allowed", False),
                reason=entry.get("reason", ""),
                max_calls_per_hour=entry.get("max_calls_per_hour"),
                require_params=entry.get("require_params", []),
                allowed_agents=entry.get("allowed_agents", []),
            )
            self.rules[rule.tool] = rule

    def add_rule(self, rule: PolicyRule):
        self.rules[rule.tool] = rule

    def evaluate(
        self,
        tool: str,
        agent_id: str = "unknown",
        params: Optional[dict] = None,
    ) -> PolicyVerdict:
        """Evaluate whether agent_id is allowed to call tool with params."""
        params = params or {}

        rule = self.rules.get(tool)
        if not rule:
            return PolicyVerdict(
                allowed=False,
                reason=f'No matching rule for tool "{tool}" — fail-closed default',
                rule_matched=None,
            )

        # Agent restriction
        if rule.allowed_agents and agent_id not in rule.allowed_agents:
            return PolicyVerdict(
                allowed=False,
                reason=f'Agent "{agent_id}" not in allowlist for tool "{tool}"',
                rule_matched=tool,
            )

        # Rate limit check
        if rule.max_calls_per_hour is not None:
            key = f"{agent_id}:{tool}"
            now = time.time()
            window = self._call_log.setdefault(key, [])
            # Prune old entries
            window[:] = [t for t in window if now - t < 3600]
            if len(window) >= rule.max_calls_per_hour:
                return PolicyVerdict(
                    allowed=False,
                    reason=f'Rate limit exceeded for tool "{tool}": {rule.max_calls_per_hour}/hr',
                    rule_matched=tool,
                )

        # Required params check
        for req_param in rule.require_params:
            if req_param not in params:
                return PolicyVerdict(
                    allowed=False,
                    reason=f'Missing required parameter "{req_param}" for tool "{tool}"',
                    rule_matched=tool,
                )

        # Log the call
        if rule.allowed:
            key = f"{agent_id}:{tool}"
            self._call_log.setdefault(key, []).append(time.time())

        return PolicyVerdict(
            allowed=rule.allowed,
            reason=rule.reason or ("Allowed" if rule.allowed else "Denied by policy"),
            rule_matched=tool,
        )
