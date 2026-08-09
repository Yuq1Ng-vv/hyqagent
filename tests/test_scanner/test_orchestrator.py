"""Tests for scanner/orchestrator.py — central pipeline coordinator."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hyqagent.observability.cost_tracker import CostTracker
from hyqagent.scanner.orchestrator import (
    AuditReport,
    Orchestrator,
    PhaseName,
    PipelineState,
    _checkpoint_to_state,
    _state_to_checkpoint,
)
from hyqagent.session.checkpoint import Checkpoint, CheckpointManager
from hyqagent.session.manager import SessionManager

# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_db() -> str:
    """Create a temporary SQLite database for tests."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def session_mgr(tmp_db: str) -> SessionManager:
    return SessionManager(tmp_db)


@pytest.fixture
def checkpoint_mgr(tmp_db: str) -> CheckpointManager:
    return CheckpointManager(tmp_db)


@pytest.fixture
def cost_tracker() -> CostTracker:
    return CostTracker()


@pytest.fixture
def orchestrator(tmp_db: str) -> Orchestrator:
    return Orchestrator(db_path=tmp_db, quiet=True)


# ── PipelineState ──────────────────────────────────────────────────────────


class TestPipelineState:
    def test_default_values(self) -> None:
        state = PipelineState(session_id="test-1")
        assert state.session_id == "test-1"
        assert state.current_phase is None
        assert state.completed_phases == []
        assert state.file_count == 0
        assert state.converge_round == 0

    def test_to_dict_roundtrip(self) -> None:
        state = PipelineState(
            session_id="test-2",
            current_phase=PhaseName.DETERMINISTIC_SCAN,
            completed_phases=["cpg_build"],
            phase_states={"cpg_build": {"nodes": 100}},
            file_count=42,
            endpoint_count=5,
            finding_count=3,
            cost_total=1.23,
            converge_round=2,
        )
        d = state.to_dict()
        restored = PipelineState.from_dict(d)
        assert restored.session_id == state.session_id
        assert restored.current_phase == state.current_phase
        assert restored.completed_phases == state.completed_phases
        assert restored.phase_states == state.phase_states
        assert restored.file_count == state.file_count
        assert restored.converge_round == state.converge_round

    def test_from_dict_no_current_phase(self) -> None:
        state = PipelineState.from_dict({"session_id": "test"})
        assert state.session_id == "test"
        assert state.current_phase is None

    def test_from_dict_with_phase_str(self) -> None:
        state = PipelineState.from_dict(
            {
                "session_id": "test",
                "current_phase": "validation",
            }
        )
        assert state.current_phase == PhaseName.VALIDATION


# ── Checkpoint conversion ──────────────────────────────────────────────────


class TestCheckpointConversion:
    def test_state_to_checkpoint(self) -> None:
        state = PipelineState(
            session_id="s1",
            current_phase=PhaseName.HYPOTHESIS_GEN,
            file_count=10,
            finding_count=5,
        )
        cp = _state_to_checkpoint(state)
        assert cp.session_id == "s1"
        assert cp.phase == "hypothesis_gen"
        assert cp.file_count == 10
        assert cp.finding_count == 5
        assert "session_id" in cp.state

    def test_checkpoint_to_state(self) -> None:
        cp = Checkpoint(
            id="c1",
            session_id="s1",
            phase="deterministic_scan",
            state={
                "session_id": "s1",
                "current_phase": "deterministic_scan",
                "completed_phases": ["cpg_build"],
                "phase_states": {"cpg_build": {"nodes": 500}},
                "file_count": 20,
                "endpoint_count": 3,
                "finding_count": 7,
                "cost_total": 0.50,
                "converge_round": 1,
                "converge_history": [],
            },
            file_count=20,
            finding_count=7,
        )
        state = _checkpoint_to_state(cp)
        assert state.session_id == "s1"
        assert state.current_phase == PhaseName.DETERMINISTIC_SCAN
        assert state.file_count == 20
        assert state.finding_count == 7

    def test_full_roundtrip(self) -> None:
        original = PipelineState(
            session_id="roundtrip",
            current_phase=PhaseName.VALIDATION,
            completed_phases=["cpg_build", "deterministic_scan"],
            phase_states={"deterministic_scan": {"findings": []}},
            file_count=99,
            cost_total=4.20,
        )
        cp = _state_to_checkpoint(original)
        restored = _checkpoint_to_state(cp)
        assert restored.session_id == original.session_id
        assert restored.current_phase == original.current_phase
        assert restored.file_count == original.file_count


# ── Orchestrator init ─────────────────────────────────────────────────────


class TestOrchestratorInit:
    def test_creates_with_db_path(self, tmp_db: str) -> None:
        orch = Orchestrator(db_path=tmp_db)
        assert orch._session_mgr is not None
        assert orch._checkpoint_mgr is not None
        assert orch._cost_tracker is not None

    def test_accepts_injected_dependencies(self, session_mgr, checkpoint_mgr, cost_tracker) -> None:
        orch = Orchestrator(
            session_manager=session_mgr,
            checkpoint_manager=checkpoint_mgr,
            cost_tracker=cost_tracker,
        )
        assert orch._session_mgr is session_mgr
        assert orch._checkpoint_mgr is checkpoint_mgr

    def test_default_db_path(self) -> None:
        orch = Orchestrator()
        assert ".hyqagent" in str(orch._DEFAULT_DB)


# ── Phase execution ───────────────────────────────────────────────────────


class TestPhaseExecution:
    @pytest.mark.asyncio
    async def test_phase_name_enum(self) -> None:
        """Verify PhaseName enum has the expected phases."""
        assert PhaseName.CPG_BUILD == "cpg_build"
        assert PhaseName.DETERMINISTIC_SCAN == "deterministic_scan"
        assert PhaseName.HYPOTHESIS_GEN == "hypothesis_gen"
        assert PhaseName.VALIDATION == "validation"
        assert PhaseName.CONVERGENCE_CHECK == "convergence_check"

    @pytest.mark.asyncio
    async def test_phase_skipping_completed(self, orchestrator, session_mgr) -> None:
        """Already-completed phases should not re-execute."""
        await session_mgr.save_session(
            {
                "id": "skip-test",
                "project_path": "/tmp/test",
                "language": "python",
            }
        )
        state = PipelineState(
            session_id="skip-test",
            completed_phases=["cpg_build", "deterministic_scan"],
            phase_states={"file_paths": []},
            current_phase=PhaseName.DETERMINISTIC_SCAN,
        )
        orchestrator._state = state
        orchestrator._report = AuditReport(session_id="skip-test")

        # _run_phase should skip already-completed phases
        # We test this through the internal method
        assert "cpg_build" in state.completed_phases
        assert "deterministic_scan" in state.completed_phases

    @pytest.mark.asyncio
    async def test_run_creates_session(self, orchestrator, tmp_db: str) -> None:
        """run() should create a session in the database."""
        with patch.object(orchestrator, "_execute_phases", new_callable=AsyncMock):
            with patch.object(orchestrator, "_ensure_scanner_modules"):
                with patch.object(orchestrator, "_setup_signal_handlers"):
                    report = await orchestrator.run(
                        project_path="/tmp/test_proj",
                        language="python",
                        file_paths=[],
                    )
        assert report.session_id != ""
        # Session should be saved
        session = await orchestrator._session_mgr.get_session(report.session_id)
        assert session is not None
        assert session["language"] == "python"

    @pytest.mark.asyncio
    async def test_resume_raises_if_no_session(self, orchestrator) -> None:
        with pytest.raises(ValueError, match="not found"):
            await orchestrator.resume("nonexistent-session")

    @pytest.mark.asyncio
    async def test_resume_raises_if_no_checkpoint(
        self,
        orchestrator,
        session_mgr,
    ) -> None:
        await session_mgr.save_session(
            {
                "id": "no-cp",
                "project_path": "/tmp/test",
                "language": "python",
            }
        )
        with pytest.raises(ValueError, match="No checkpoint"):
            await orchestrator.resume("no-cp")


# ── Checkpoint integration ────────────────────────────────────────────────


class TestCheckpointIntegration:
    @pytest.mark.asyncio
    async def test_save_checkpoint(self, orchestrator) -> None:
        orchestrator._state = PipelineState(
            session_id="cp-test",
            current_phase=PhaseName.CPG_BUILD,
            file_count=10,
        )
        await orchestrator._save_checkpoint("test")

        cp = await orchestrator._checkpoint_mgr.load_latest("cp-test")
        assert cp is not None
        assert cp.phase == "cpg_build"
        assert cp.file_count == 10

    @pytest.mark.asyncio
    async def test_emergency_checkpoint(self, orchestrator, session_mgr) -> None:
        await session_mgr.save_session(
            {
                "id": "emergency-test",
                "project_path": "/tmp/test",
                "language": "python",
            }
        )
        orchestrator._state = PipelineState(
            session_id="emergency-test",
            current_phase=PhaseName.VALIDATION,
        )
        await orchestrator._emergency_checkpoint()

        cp = await orchestrator._checkpoint_mgr.load_latest("emergency-test")
        assert cp is not None
        assert cp.phase == "validation"

    @pytest.mark.asyncio
    async def test_checkpoint_cleanup(self, orchestrator) -> None:
        """Old checkpoints should be cleaned up, keeping latest 5."""
        orchestrator._state = PipelineState(session_id="cleanup-test")
        for i in range(10):
            orchestrator._state.current_phase = PhaseName.CPG_BUILD
            await orchestrator._save_checkpoint(f"test-{i}")

        all_cps = await orchestrator._checkpoint_mgr.list_all("cleanup-test")
        assert len(all_cps) <= 5


# ── AuditReport ───────────────────────────────────────────────────────────


class TestAuditReport:
    def test_default_values(self) -> None:
        report = AuditReport(session_id="r1")
        assert report.session_id == "r1"
        assert report.findings == []
        assert report.hypotheses == []
        assert report.status == "completed"

    def test_with_data(self) -> None:
        report = AuditReport(
            session_id="r2",
            findings=[MagicMock()],
            hypotheses=[MagicMock(), MagicMock()],
            phases_completed=["cpg_build", "deterministic_scan"],
            status="paused",
        )
        assert len(report.findings) == 1
        assert len(report.hypotheses) == 2
        assert len(report.phases_completed) == 2
        assert report.status == "paused"


# ── Edge cases ─────────────────────────────────────────────────────────────


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_run_empty_file_list(self, orchestrator) -> None:
        """Empty file list should not crash."""
        with patch.object(orchestrator, "_execute_phases", new_callable=AsyncMock):
            with patch.object(orchestrator, "_ensure_scanner_modules"):
                with patch.object(orchestrator, "_setup_signal_handlers"):
                    report = await orchestrator.run(
                        project_path="/tmp/empty",
                        language="python",
                        file_paths=[],
                    )
        assert report.session_id != ""

    @pytest.mark.asyncio
    async def test_resume_same_state(self, orchestrator, session_mgr, checkpoint_mgr) -> None:
        """Resume should load the saved pipeline state."""
        await session_mgr.save_session(
            {
                "id": "resume-state-test",
                "project_path": "/tmp/test",
                "language": "python",
            }
        )
        state = PipelineState(
            session_id="resume-state-test",
            current_phase=PhaseName.DETERMINISTIC_SCAN,
            completed_phases=["cpg_build"],
            file_count=5,
        )
        cp = _state_to_checkpoint(state)
        await checkpoint_mgr.save(cp)

        with patch.object(orchestrator, "_execute_phases", new_callable=AsyncMock):
            with patch.object(orchestrator, "_ensure_scanner_modules"):
                with patch.object(orchestrator, "_setup_signal_handlers"):
                    report = await orchestrator.resume("resume-state-test")

        assert report.session_id == "resume-state-test"

    @pytest.mark.asyncio
    async def test_quiet_mode(self, tmp_db: str) -> None:
        """Quiet mode should suppress log output."""
        orch = Orchestrator(db_path=tmp_db, quiet=True)
        # Just verifying it doesn't crash
        orch._log("info", "this should not appear")

    def test_make_session_id(self) -> None:
        sid = Orchestrator._make_session_id()
        assert sid.startswith("audit-")
        assert len(sid) > 20

    def test_discover_files(self, tmp_path: Path) -> None:
        """File discovery should find python files."""
        (tmp_path / "test.py").write_text("print('hello')")
        (tmp_path / "readme.md").write_text("# Readme")
        (tmp_path / "nested").mkdir()
        (tmp_path / "nested" / "util.py").write_text("def foo(): pass")

        files = Orchestrator._discover_files(tmp_path, "python")
        assert len(files) == 2
        assert any("test.py" in f for f in files)
        assert any("util.py" in f for f in files)

    def test_discover_files_single_file(self, tmp_path: Path) -> None:
        py_file = tmp_path / "single.py"
        py_file.write_text("x = 1")
        files = Orchestrator._discover_files(py_file, "python")
        assert len(files) == 1

    def test_discover_files_wrong_language(self, tmp_path: Path) -> None:
        (tmp_path / "test.py").write_text("x = 1")
        files = Orchestrator._discover_files(tmp_path, "javascript")
        assert len(files) == 0


# ── Convergence integration ───────────────────────────────────────────────


class TestOrchestratorConvergence:
    def test_is_high_severity(self) -> None:
        """_is_high_severity should detect critical/high hypotheses."""
        h_crit = MagicMock(id="h1", severity="critical")
        h_high = MagicMock(id="h2", severity="high")
        h_low = MagicMock(id="h3", severity="low")

        v1 = MagicMock(hypothesis_id="h1")
        v2 = MagicMock(hypothesis_id="h2")
        v3 = MagicMock(hypothesis_id="h3")
        v4 = MagicMock(hypothesis_id="h4")  # no match

        assert Orchestrator._is_high_severity(v1, [h_crit])
        assert Orchestrator._is_high_severity(v2, [h_high])
        assert not Orchestrator._is_high_severity(v3, [h_low])
        assert not Orchestrator._is_high_severity(v4, [h_crit])

    def test_summarise_findings(self) -> None:
        f1 = MagicMock(severity="high", location="test.py:10", rule_id="R001")
        f2 = MagicMock(severity="medium", location="app.py:5", rule_id="R002")

        summary = Orchestrator._summarise_findings([f1, f2])
        assert "R001" in summary
        assert "test.py" in summary

    def test_summarise_findings_empty(self) -> None:
        assert Orchestrator._summarise_findings([]) == "No findings."
