"""Inner I Secure — Audit Chain.

Append-only audit log with HMAC integrity verification.
Records every policy evaluation and injection scan.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from pathlib import Path
from typing import Optional


DEFAULT_CHAIN_DIR = "./secure-audit-chain"
HMAC_KEY_ENV = "SECURE_AUDIT_HMAC_KEY"


class AuditChain:
    def __init__(self, chain_dir: str = DEFAULT_CHAIN_DIR):
        self.chain_dir = Path(chain_dir)
        self.chain_dir.mkdir(parents=True, exist_ok=True)
        self.chain_file = self.chain_dir / "audit-chain.jsonl"
        self._hmac_key = os.environ.get(HMAC_KEY_ENV, "inner-i-secure-audit-key").encode()

    def _hash_entry(self, entry: dict) -> str:
        canonical = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        return hmac.new(self._hmac_key, canonical.encode(), hashlib.sha256).hexdigest()

    def append(
        self,
        event_type: str,
        agent_id: str,
        tool: str,
        verdict: str,
        reason: str,
        details: Optional[dict] = None,
    ) -> dict:
        entry = {
            "id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "event_type": event_type,
            "agent_id": agent_id,
            "tool": tool,
            "verdict": verdict,
            "reason": reason,
            "details": details or {},
        }
        entry["hmac"] = self._hash_entry(entry)

        with open(self.chain_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

        return entry

    def history(self, limit: int = 100, offset: int = 0) -> list[dict]:
        if not self.chain_file.exists():
            return []
        entries = []
        with open(self.chain_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return entries[-offset - limit: len(entries) - offset] if offset else entries[-limit:]

    def verify(self) -> dict:
        if not self.chain_file.exists():
            return {"valid": True, "entries": 0, "tampered": 0}
        valid = 0
        tampered = 0
        with open(self.chain_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    stored_hmac = entry.pop("hmac", "")
                    expected = self._hash_entry(entry)
                    entry["hmac"] = stored_hmac
                    if hmac.compare_digest(stored_hmac, expected):
                        valid += 1
                    else:
                        tampered += 1
                except (json.JSONDecodeError, KeyError):
                    tampered += 1
        return {
            "valid": tampered == 0,
            "entries": valid + tampered,
            "tampered": tampered,
        }

    def __len__(self) -> int:
        if not self.chain_file.exists():
            return 0
        count = 0
        with open(self.chain_file) as f:
            for line in f:
                if line.strip():
                    count += 1
        return count
