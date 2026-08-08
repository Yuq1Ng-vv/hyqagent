"""Tests for session/manager.py — SQLite session CRUD + finding persistence."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from hyqagent.core.protocols import (
    CodeLocation,
    FindingSeverity,
    HypothesisStatus,
    VulnerabilityHypothesis,
)
from hyqagent.session.manager import SessionManager


@pytest.fixture
def mgr() -> SessionManager:
    """Return a SessionManager pointed at a temp database."""
    db = Path(tempfile.mkdtemp()) / "test.db"
    return SessionManager(db)


class TestSessionCRUD:
    @pytest.mark.asyncio
    async def test_save_and_get(self, mgr: SessionManager) -> None:
        sid = await mgr.save_session({"project_path": "/tmp/x", "language": "python"})
        s = await mgr.get_session(sid)
        assert s is not None
        assert s["language"] == "python"
        assert s["status"] == "running"

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, mgr: SessionManager) -> None:
        s = await mgr.get_session("does-not-exist")
        assert s is None

    @pytest.mark.asyncio
    async def test_list_sessions(self, mgr: SessionManager) -> None:
        await mgr.save_session({"project_path": "/tmp/a", "language": "js"})
        await mgr.save_session({"project_path": "/tmp/b", "language": "java"})
        sessions = await mgr.list_sessions()
        assert len(sessions) == 2

    @pytest.mark.asyncio
    async def test_update_status(self, mgr: SessionManager) -> None:
        sid = await mgr.save_session({"project_path": "/tmp/x"})
        await mgr.update_session_status(sid, "paused")
        s = await mgr.get_session(sid)
        assert s and s["status"] == "paused"


class TestFindingCRUD:
    def _make_hyp(self, **kwargs: object) -> VulnerabilityHypothesis:
        defaults: dict[str, object] = {
            "id": "hyp-001",
            "title": "Test Vuln",
            "vuln_type": "sql_injection",
            "severity": FindingSeverity.HIGH,
            "confidence": 0.8,
            "status": HypothesisStatus.PROPOSED,
            "source": CodeLocation("a.py", 1, 1, "f"),
            "sink": CodeLocation("a.py", 2, 2, "f"),
            "cwe_id": "CWE-89",
            "description": "Test",
        }
        defaults.update(kwargs)
        return VulnerabilityHypothesis(**defaults)  # type: ignore[arg-type]

    @pytest.mark.asyncio
    async def test_save_and_get_finding(self, mgr: SessionManager) -> None:
        sid = await mgr.save_session({"project_path": "/tmp/x"})
        hyp = self._make_hyp()
        fid = await mgr.save_finding(sid, hyp)
        assert fid == "hyp-001"

        findings = await mgr.get_findings(sid)
        assert len(findings) == 1
        assert findings[0].id == "hyp-001"
        assert findings[0].vuln_type == "sql_injection"

    @pytest.mark.asyncio
    async def test_filter_by_severity(self, mgr: SessionManager) -> None:
        sid = await mgr.save_session({"project_path": "/tmp/x"})
        await mgr.save_finding(sid, self._make_hyp(id="h1", severity=FindingSeverity.HIGH))
        await mgr.save_finding(sid, self._make_hyp(id="h2", severity=FindingSeverity.LOW))

        high = await mgr.get_findings(sid, severity=FindingSeverity.HIGH)
        low = await mgr.get_findings(sid, severity=FindingSeverity.LOW)
        assert len(high) == 1
        assert len(low) == 1

    @pytest.mark.asyncio
    async def test_update_hypothesis_status(self, mgr: SessionManager) -> None:
        sid = await mgr.save_session({"project_path": "/tmp/x"})
        await mgr.save_finding(sid, self._make_hyp())
        await mgr.update_hypothesis_status("hyp-001", HypothesisStatus.CONFIRMED, 0.95)

        findings = await mgr.get_findings(sid)
        assert findings[0].status == HypothesisStatus.CONFIRMED
        assert findings[0].confidence == 0.95

    @pytest.mark.asyncio
    async def test_finding_count(self, mgr: SessionManager) -> None:
        sid = await mgr.save_session({"project_path": "/tmp/x"})
        assert await mgr.get_finding_count(sid) == 0
        await mgr.save_finding(sid, self._make_hyp(id="h1"))
        await mgr.save_finding(sid, self._make_hyp(id="h2"))
        assert await mgr.get_finding_count(sid) == 2

    @pytest.mark.asyncio
    async def test_source_sink_roundtrip(self, mgr: SessionManager) -> None:
        """Source/sink CodeLocation should round-trip through SQLite."""
        sid = await mgr.save_session({"project_path": "/tmp/x"})
        hyp = self._make_hyp(
            source=CodeLocation("src/app.py", 15, 18, "login"),
            sink=CodeLocation("src/db.py", 42, 42, "execute"),
        )
        await mgr.save_finding(sid, hyp)
        findings = await mgr.get_findings(sid)
        f = findings[0]
        assert f.source is not None
        assert f.source.file_path == "src/app.py"
        assert f.source.start_line == 15
        assert f.sink is not None
        assert f.sink.file_path == "src/db.py"

    @pytest.mark.asyncio
    async def test_belief_tracking(self, mgr: SessionManager) -> None:
        sid = await mgr.save_session({"project_path": "/tmp/x"})
        hyp = self._make_hyp()
        await mgr.save_finding(sid, hyp)
        # Should not raise
        await mgr.record_belief_update("hyp-001", 0.8, 0.95, 0.98, "L1+L2 confirm")
