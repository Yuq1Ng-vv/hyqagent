"""observability/audit_trail.py — ESAA decision trail with SHA-256 chain verification.

ESAA = Evidence → System proposes → Agent decides → Audit trail records.

Each :class:`AuditEntry` carries the decision metadata plus a *chain_hash*
that links it to the previous entry, forming an immutable log.  Recomputing
the chain from scratch and comparing hashes detects tampering.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ── Audit entry ────────────────────────────────────────────────────────────────


@dataclass
class AuditEntry:
    """A single ESAA decision record.

    Each entry has a *chain_hash* that commits to the entry content *and*
    the previous entry's hash — forming a SHA-256 linked list.
    """

    sequence: int
    timestamp: str  # ISO 8601 in UTC
    phase: str
    event: str  # e.g. "hypothesis_confirmed", "validator_rejected", "adversarial_overturned"
    hypothesis_id: str
    actor: str  # model name or "L1-validator" / "adversarial-reviewer"
    decision: str  # confirmed | rejected | overturned | upheld
    evidence_hash: str = ""  # SHA-256 of raw evidence (or "" when absent)
    chain_hash: str = ""  # filled by AuditTrail after the previous entry
    metadata: dict[str, Any] = field(default_factory=dict)


# ── AuditTrail ─────────────────────────────────────────────────────────────────


class AuditTrail:
    """Immutable decision trail backed by SHA-256 chaining.

    Usage::

        trail = AuditTrail(session_id="audit-001")
        e1 = trail.record("hypothesis_confirmed", "validation", "h-1",
                          "L2-claude", "confirmed", evidence="...")
        e2 = trail.record("adversarial_upheld", "adversarial_review", "h-1",
                          "adversarial-opus", "upheld")
        assert trail.verify_chain()      # True
        trail.export_jsonl()             # writes to disk
    """

    def __init__(
        self, session_id: str, output_path: str | Path | None = None
    ) -> None:
        self._session_id = session_id
        self._entries: list[AuditEntry] = []
        self._output_path = Path(output_path) if output_path else None

    # ── Recording ──────────────────────────────────────────────────────────

    def record(
        self,
        event: str,
        phase: str,
        hypothesis_id: str,
        actor: str,
        decision: str,
        evidence: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Append a decision to the trail and return the new entry."""
        seq = len(self._entries) + 1
        prev_hash = self._entries[-1].chain_hash if self._entries else ""

        evidence_hash = (
            hashlib.sha256(evidence.encode("utf-8")).hexdigest()
            if evidence
            else ""
        )

        entry = AuditEntry(
            sequence=seq,
            timestamp=datetime.now(UTC).isoformat(),
            phase=phase,
            event=event,
            hypothesis_id=hypothesis_id,
            actor=actor,
            decision=decision,
            evidence_hash=evidence_hash,
            metadata=dict(metadata or {}),
        )

        # Chain: hash(this entry's content + previous chain hash)
        payload = self._canonical_payload(entry, prev_hash)
        entry.chain_hash = hashlib.sha256(payload).hexdigest()
        self._entries.append(entry)
        return entry

    # ── Verification ───────────────────────────────────────────────────────

    def verify_chain(self) -> bool:
        """Recompute every chain hash and check for tampering.

        Returns ``True`` if the entire chain is intact.
        """
        prev_hash = ""
        for entry in self._entries:
            payload = self._canonical_payload(entry, prev_hash)
            expected = hashlib.sha256(payload).hexdigest()
            if entry.chain_hash != expected:
                return False
            prev_hash = entry.chain_hash
        return True

    # ── Export ─────────────────────────────────────────────────────────────

    def export_jsonl(self, path: str | Path | None = None) -> Path:
        """Write the audit trail as newline-delimited JSON.

        If *path* is not provided, writes to ``<output_path>/audit-<session_id>.jsonl``
        or falls back to ``./audit-<session_id>.jsonl``.
        """
        target = Path(path) if path else self._resolve_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            for entry in self._entries:
                fh.write(json.dumps(self._entry_to_dict(entry), ensure_ascii=False))
                fh.write("\n")
        return target

    # ── Properties ─────────────────────────────────────────────────────────

    @property
    def entries(self) -> list[AuditEntry]:
        """Return a copy of all entries."""
        return list(self._entries)

    @property
    def session_id(self) -> str:
        """The audit session identifier."""
        return self._session_id

    # ── Internal helpers ───────────────────────────────────────────────────

    @staticmethod
    def _canonical_payload(entry: AuditEntry, prev_hash: str) -> bytes:
        """Deterministic binary payload for hashing."""
        # Deliberately exclude chain_hash itself from the digest input
        # so the chain hash can be verified by re-computation.
        fields = (
            f"{entry.sequence}|{entry.timestamp}|{entry.phase}|{entry.event}|"
            f"{entry.hypothesis_id}|{entry.actor}|{entry.decision}|"
            f"{entry.evidence_hash}|{json.dumps(entry.metadata, sort_keys=True)}|"
            f"{prev_hash}"
        )
        return fields.encode("utf-8")

    @staticmethod
    def _entry_to_dict(entry: AuditEntry) -> dict[str, Any]:
        """Serialize an AuditEntry to a plain dict (for JSONL export)."""
        return {
            "session_id": "",  # set by caller if needed
            "sequence": entry.sequence,
            "timestamp": entry.timestamp,
            "phase": entry.phase,
            "event": entry.event,
            "hypothesis_id": entry.hypothesis_id,
            "actor": entry.actor,
            "decision": entry.decision,
            "evidence_hash": entry.evidence_hash,
            "chain_hash": entry.chain_hash,
            "metadata": entry.metadata,
        }

    def _resolve_path(self) -> Path:
        if self._output_path:
            return self._output_path / f"audit-{self._session_id}.jsonl"
        return Path(f"audit-{self._session_id}.jsonl")
