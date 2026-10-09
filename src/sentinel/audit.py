"""
Sentinel Stream — immutable hash-chained audit log.

Every privileged action (alert ack, truncate, user create, SOAR run) is
appended to an append-only, hash-chained log. Each entry's hash includes
the previous entry's hash, making tampering detectable.

Compliance: SOC 2 CC-7.3, ISO 27001 A.12.4, GDPR Art. 30.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

AUDIT_LOG_PATH = Path(os.environ.get(
    "SENTINEL_AUDIT_LOG",
    "audit.log.jsonl",
))
GENESIS_HASH = "0" * 64


@dataclass
class AuditEntry:
    """A single audit log entry. Hash-chained to the previous entry."""
    seq: int                        # monotonically increasing sequence number
    ts: float                       # Unix timestamp
    actor: str                      # user_id or "system"
    action: str                      # e.g. "alert.acknowledge", "admin.truncate"
    tenant_id: str
    resource: str                    # e.g. "alert:abc123"
    details: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    entry_hash: str = ""

    def compute_hash(self) -> str:
        """Compute the SHA-256 hash of this entry (including prev_hash)."""
        payload = {
            "seq": self.seq,
            "ts": self.ts,
            "actor": self.actor,
            "action": self.action,
            "tenant_id": self.tenant_id,
            "resource": self.resource,
            "details": self.details,
            "prev_hash": self.prev_hash,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


class AuditLog:
    """Append-only hash-chained audit log.

    Backed by a JSONL file. Each line is a JSON-encoded AuditEntry.
    The chain is verified by re-computing hashes on read.

    Tamper detection: if any entry's recomputed hash doesn't match its
    stored hash, or if a prev_hash doesn't match the previous entry's hash,
    verification fails.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else AUDIT_LOG_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = __import__("threading").Lock()
        self._seq = self._get_next_seq()
        self._prev_hash = self._get_last_hash()

    def append(
        self,
        actor: str,
        action: str,
        tenant_id: str,
        resource: str,
        details: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Append a new audit entry. Returns the entry with its hash."""
        entry = AuditEntry(
            seq=self._seq,
            ts=time.time(),
            actor=actor,
            action=action,
            tenant_id=tenant_id,
            resource=resource,
            details=details or {},
            prev_hash=self._prev_hash,
        )
        entry.entry_hash = entry.compute_hash()
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(entry), default=str) + "\n")
            self._seq += 1
            self._prev_hash = entry.entry_hash
        logger.debug("Audit: %s by %s on %s", action, actor, resource)
        return entry

    def verify(self) -> tuple[bool, list[str]]:
        """Verify the integrity of the entire audit log.

        Returns (is_valid, list_of_violations).
        """
        violations: list[str] = []
        prev_hash = GENESIS_HASH
        expected_seq = 0
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                data = json.loads(line)
                entry = AuditEntry(**data)
                if entry.seq != expected_seq:
                    violations.append(f"Seq gap at line {expected_seq}: got {entry.seq}")
                if entry.prev_hash != prev_hash:
                    violations.append(f"Chain break at seq {entry.seq}: prev_hash mismatch")
                recomputed = entry.compute_hash()
                if recomputed != entry.entry_hash:
                    violations.append(f"Hash mismatch at seq {entry.seq}")
                prev_hash = entry.entry_hash
                expected_seq += 1
        except Exception as e:
            violations.append(f"Read error: {e}")
        return (len(violations) == 0, violations)

    def query(
        self,
        actor: str | None = None,
        action: str | None = None,
        tenant_id: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Query audit log entries with filters."""
        results: list[AuditEntry] = []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
            for line in reversed(lines):  # most recent first
                if not line.strip():
                    continue
                data = json.loads(line)
                entry = AuditEntry(**data)
                if actor and entry.actor != actor:
                    continue
                if action and not entry.action.startswith(action):
                    continue
                if tenant_id and entry.tenant_id != tenant_id:
                    continue
                if since and entry.ts < since:
                    continue
                results.append(entry)
                if len(results) >= limit:
                    break
        except Exception as e:
            logger.warning("Audit query failed: %s", e)
        return results

    def _get_next_seq(self) -> int:
        """Get the next sequence number by counting existing entries."""
        try:
            count = sum(1 for _ in self.path.open(encoding="utf-8") if _.strip())
            return count
        except FileNotFoundError:
            return 0

    def _get_last_hash(self) -> str:
        """Get the hash of the last entry in the log."""
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
            for line in reversed(lines):
                if line.strip():
                    data = json.loads(line)
                    return data.get("entry_hash", GENESIS_HASH)
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning("Failed to read last audit hash: %s", e)
        return GENESIS_HASH


# Singleton
_audit: AuditLog | None = None


def get_audit() -> AuditLog:
    global _audit
    if _audit is None:
        _audit = AuditLog()
    return _audit
