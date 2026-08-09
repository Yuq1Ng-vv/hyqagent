"""Tests for observability/audit_trail.py — AuditEntry, AuditTrail, chain verification."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from hyqagent.observability.audit_trail import AuditEntry, AuditTrail


class TestAuditEntry:
    def test_defaults(self) -> None:
        entry = AuditEntry(
            sequence=1, timestamp="2026-01-01T00:00:00Z",
            phase="test", event="hypothesis_confirmed",
            hypothesis_id="h-1", actor="L1",
            decision="confirmed",
        )
        assert entry.evidence_hash == ""
        assert entry.chain_hash == ""
        assert entry.metadata == {}

    def test_full_fields(self) -> None:
        entry = AuditEntry(
            sequence=2,
            timestamp="2026-01-01T00:00:01Z",
            phase="validation",
            event="validator_rejected",
            hypothesis_id="h-2",
            actor="L2-sonnet",
            decision="rejected",
            evidence_hash="abc123",
            chain_hash="def456",
            metadata={"confidence": 0.5},
        )
        assert entry.sequence == 2
        assert entry.evidence_hash == "abc123"
        assert entry.chain_hash == "def456"
        assert entry.metadata["confidence"] == 0.5


class TestAuditTrail:
    def test_empty_trail_verifies(self) -> None:
        trail = AuditTrail(session_id="test")
        assert trail.verify_chain() is True
        assert trail.entries == []

    def test_record_returns_entry(self) -> None:
        trail = AuditTrail(session_id="test")
        entry = trail.record(
            event="hypothesis_confirmed",
            phase="validation",
            hypothesis_id="h-1",
            actor="L1-validator",
            decision="confirmed",
            evidence="user input passed to SQL query",
        )
        assert entry.sequence == 1
        assert entry.hypothesis_id == "h-1"
        assert entry.chain_hash != ""
        assert entry.evidence_hash != ""

    def test_chain_is_verified(self) -> None:
        trail = AuditTrail(session_id="test")
        trail.record("e1", "p1", "h-1", "L1", "confirmed")
        trail.record("e2", "p2", "h-2", "L2", "rejected")
        trail.record("e3", "p3", "h-3", "adversarial", "overturned")
        assert trail.verify_chain() is True
        assert len(trail.entries) == 3

    def test_chain_tampering_detected(self) -> None:
        trail = AuditTrail(session_id="test")
        e1 = trail.record("e1", "p1", "h-1", "L1", "confirmed")
        trail.record("e2", "p2", "h-2", "L2", "rejected")

        # Tamper: change a decision in the middle entry
        e1.decision = "changed"  # type: ignore[misc]

        assert trail.verify_chain() is False

    def test_export_jsonl(self) -> None:
        trail = AuditTrail(session_id="test")
        trail.record("e1", "p1", "h-1", "L1", "confirmed")
        trail.record("e2", "p2", "h-2", "L2", "rejected")

        with tempfile.TemporaryDirectory() as tmpdir:
            path = trail.export_jsonl(Path(tmpdir) / "audit.jsonl")
            lines = path.read_text().strip().split("\n")
            assert len(lines) == 2
            for line in lines:
                obj = json.loads(line)
                assert "sequence" in obj
                assert "chain_hash" in obj

    def test_export_jsonl_default_path(self) -> None:
        trail = AuditTrail(session_id="sess-xyz")
        trail.record("e", "p", "h-1", "actor", "confirmed")
        path = trail.export_jsonl()
        assert path.name == "audit-sess-xyz.jsonl"
        # Cleanup
        path.unlink(missing_ok=True)

    def test_entries_are_copies(self) -> None:
        trail = AuditTrail(session_id="test")
        trail.record("e1", "p1", "h-1", "L1", "confirmed")
        entries = trail.entries
        entries.pop()
        assert len(trail.entries) == 1  # Original unchanged

    def test_metadata_preserved(self) -> None:
        trail = AuditTrail(session_id="test")
        trail.record(
            "e1", "p1", "h-1", "L1", "confirmed",
            metadata={"cost_usd": 0.005, "latency_ms": 300},
        )
        # Re-fetch to get canonical copy
        stored = trail.entries[-1]
        assert stored.metadata["cost_usd"] == 0.005
        assert stored.metadata["latency_ms"] == 300

    def test_session_id_property(self) -> None:
        trail = AuditTrail(session_id="audit-42")
        assert trail.session_id == "audit-42"

    def test_output_path_constructor(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            trail = AuditTrail(session_id="s", output_path=tmpdir)
            path = trail.export_jsonl()
            assert str(path).startswith(tmpdir)
