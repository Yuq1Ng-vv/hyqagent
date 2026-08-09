"""scanner/orchestrator.py — Central pipeline coordinator for HyqAgent audits.

Ties together all Phase 2–4 scanner modules with:
- Phase-sequenced execution (CPG build → scan → hypotheses → validate → converge)
- Checkpoint save/restore at phase boundaries via :class:`CheckpointManager`
- Session persistence via :class:`SessionManager` (SQLite, not JSON)
- Convergence detection loop (hypothesis gen → validation → check → repeat)
- Signal handling (SIGTERM graceful shutdown, SIGUSR1 manual checkpoint)
- Resume from last checkpoint

See DESIGN-IMPLEMENTATION.md §4 and LONG-RUNNING-AGENT-ARCHITECTURE.md.
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import networkx as nx
import structlog

from hyqagent.observability.cost_tracker import CostSummary, CostTracker
from hyqagent.scanner.convergence import (
    ConvergenceMonitor,
    ConvergenceReport,
    ConvergenceSnapshot,
    ConvergenceThresholds,
)
from hyqagent.session.checkpoint import Checkpoint, CheckpointManager
from hyqagent.session.manager import SessionManager

if TYPE_CHECKING:
    from hyqagent.cpg.query import CPGQuery
    from hyqagent.cpg.taint_loader import TaintRuleLoader

logger = structlog.get_logger(__name__)

# ── Phase enum ────────────────────────────────────────────────────────────────


class PhaseName(StrEnum):
    """Fixed pipeline phases. Each phase has a known input/output contract."""

    CPG_BUILD = "cpg_build"
    DETERMINISTIC_SCAN = "deterministic_scan"
    ATTACK_SURFACE_MAP = "attack_surface_map"
    HYPOTHESIS_GEN = "hypothesis_gen"
    VALIDATION = "validation"
    ADVERSARIAL_REVIEW = "adversarial_review"
    SATURATION_SCAN = "saturation_scan"
    REVERSE_SINK = "reverse_sink"
    BLIND_SCAN = "blind_scan"
    COVERAGE_AUDIT = "coverage_audit"
    COMPLETENESS_CRITIC = "completeness_critic"
    CONVERGENCE_CHECK = "convergence_check"


# Phase sequence for --deep mode.  Convergence loop wraps HYPOTHESIS_GEN
# through CONVERGENCE_CHECK.
DEEP_PHASES: list[PhaseName] = [
    PhaseName.CPG_BUILD,
    PhaseName.DETERMINISTIC_SCAN,
    PhaseName.ATTACK_SURFACE_MAP,
    PhaseName.HYPOTHESIS_GEN,
    PhaseName.VALIDATION,
    PhaseName.ADVERSARIAL_REVIEW,
    PhaseName.SATURATION_SCAN,
    PhaseName.REVERSE_SINK,
    PhaseName.BLIND_SCAN,
    PhaseName.COVERAGE_AUDIT,
    PhaseName.COMPLETENESS_CRITIC,
    PhaseName.CONVERGENCE_CHECK,
]

# Phases that participate in the convergence loop body.
_CONVERGE_BODY: list[PhaseName] = [
    PhaseName.HYPOTHESIS_GEN,
    PhaseName.VALIDATION,
    PhaseName.ADVERSARIAL_REVIEW,
    PhaseName.SATURATION_SCAN,
    PhaseName.REVERSE_SINK,
    PhaseName.BLIND_SCAN,
    PhaseName.COVERAGE_AUDIT,
    PhaseName.CONVERGENCE_CHECK,
]

# ── Pipeline state ────────────────────────────────────────────────────────────


@dataclass
class PipelineState:
    """Serialisable snapshot of orchestrator progress — saved as checkpoint."""

    session_id: str
    current_phase: PhaseName | None = None
    completed_phases: list[str] = field(default_factory=list)
    phase_states: dict[str, Any] = field(default_factory=dict)
    file_count: int = 0
    endpoint_count: int = 0
    finding_count: int = 0
    cost_total: float = 0.0
    converge_round: int = 0
    converge_history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize pipeline state to a JSON-safe dictionary."""
        return {
            "session_id": self.session_id,
            "current_phase": self.current_phase.value if self.current_phase else None,
            "completed_phases": self.completed_phases,
            "phase_states": self.phase_states,
            "file_count": self.file_count,
            "endpoint_count": self.endpoint_count,
            "finding_count": self.finding_count,
            "cost_total": self.cost_total,
            "converge_round": self.converge_round,
            "converge_history": self.converge_history,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PipelineState:
        """Reconstitute pipeline state from a serialized dictionary."""
        cur = d.get("current_phase")
        return cls(
            session_id=d["session_id"],
            current_phase=PhaseName(cur) if cur else None,
            completed_phases=d.get("completed_phases", []),
            phase_states=d.get("phase_states", {}),
            file_count=d.get("file_count", 0),
            endpoint_count=d.get("endpoint_count", 0),
            finding_count=d.get("finding_count", 0),
            cost_total=d.get("cost_total", 0.0),
            converge_round=d.get("converge_round", 0),
            converge_history=d.get("converge_history", []),
        )


def _state_to_checkpoint(state: PipelineState) -> Checkpoint:
    """Convert PipelineState to a Checkpoint for persistence."""
    return Checkpoint(
        id="",
        session_id=state.session_id,
        phase=state.current_phase.value if state.current_phase else "init",
        state=state.to_dict(),
        file_count=state.file_count,
        endpoint_count=state.endpoint_count,
        finding_count=state.finding_count,
        cost_total=state.cost_total,
        created_at=datetime.now(UTC).isoformat(),
    )


def _checkpoint_to_state(cp: Checkpoint) -> PipelineState:
    """Reconstitute PipelineState from a persisted Checkpoint."""
    return PipelineState.from_dict(cp.state)


# ── Audit report ──────────────────────────────────────────────────────────────


@dataclass
class AuditReport:
    """Unified output of an audit run — aggregates results from all phases."""

    session_id: str
    findings: list[Any] = field(default_factory=list)  # Finding objects
    hypotheses: list[Any] = field(default_factory=list)  # Hypothesis objects
    validations: list[Any] = field(default_factory=list)  # ValidationResult objects
    annotated_paths: list[Any] = field(default_factory=list)  # AnnotatedPath objects
    coverage_audit: Any = None  # CoverageAuditResult
    completeness_review: dict[str, Any] | None = None
    convergence: ConvergenceReport | None = None
    cost_summary: CostSummary = field(default_factory=CostSummary)
    scan_duration_ms: int = 0
    phases_completed: list[str] = field(default_factory=list)
    status: str = "completed"  # completed | paused | failed


# ── Orchestrator ──────────────────────────────────────────────────────────────


class Orchestrator:
    """Central pipeline coordinator.

    Owns session/checkpoint/cost/convergence infrastructure.
    Receives scanner modules via dependency injection.

    Usage::

        orch = Orchestrator(
            session_manager=SessionManager(db_path),
            checkpoint_manager=CheckpointManager(db_path),
            cost_tracker=CostTracker(),
            query=cpq_query,
            taint_loader=taint_loader,
            # ... scanner modules created externally ...
        )
        report = await orch.run(project_path="/path/to/project", language="python")
        # or: report = await orch.resume(session_id="audit-20260809-...")
    """

    # The default database path under ~/.hyqagent/
    _DEFAULT_DB = Path.home() / ".hyqagent" / "sessions.db"

    def __init__(
        self,
        *,
        # ── Infrastructure (owned) ──
        session_manager: SessionManager | None = None,
        checkpoint_manager: CheckpointManager | None = None,
        cost_tracker: CostTracker | None = None,
        convergence_thresholds: ConvergenceThresholds | None = None,
        # ── CPG layer (injected) ──
        query: CPGQuery | None = None,
        taint_loader: TaintRuleLoader | None = None,
        # ── Scanner modules (injected) ──
        deterministic_scanner: Any = None,
        hypothesis_generator: Any = None,
        validator: Any = None,
        path_annotator: Any = None,
        mapper: Any = None,
        coverage_auditor_class: Any = None,
        completeness_critic: Any = None,
        adversarial_reviewer: Any = None,
        saturation_scanner: Any = None,
        reverse_sink_analyzer: Any = None,
        blind_scan_reviewer: Any = None,
        # ── Observability (injected) ──
        observability: Any = None,  # ObservabilityManager
        # ── LLM layer (injected) ──
        cheap_provider: Any = None,
        mid_provider: Any = None,
        strong_provider: Any = None,
        router: Any = None,
        # ── Config ──
        quiet: bool = False,
        db_path: str | Path | None = None,
    ) -> None:
        db = str(db_path or self._DEFAULT_DB)

        self._session_mgr = session_manager or SessionManager(db)
        self._checkpoint_mgr = checkpoint_manager or CheckpointManager(db)
        self._cost_tracker = cost_tracker or CostTracker()
        self._obs_manager = observability  # Optional[ObservabilityManager]

        # Injected scanner modules
        self._query = query
        self._taint_loader = taint_loader
        self._deterministic_scanner = deterministic_scanner
        self._hypothesis_gen = hypothesis_generator
        self._validator = validator
        self._path_annotator = path_annotator
        self._mapper = mapper
        self._coverage_auditor_class = coverage_auditor_class
        self._completeness_critic = completeness_critic
        self._adversarial_reviewer = adversarial_reviewer
        self._saturation_scanner = saturation_scanner
        self._reverse_sink_analyzer = reverse_sink_analyzer
        self._blind_scan_reviewer = blind_scan_reviewer

        # LLM
        self._cheap = cheap_provider
        self._mid = mid_provider
        self._strong = strong_provider
        self._router = router

        # Convergence
        self._convergence = ConvergenceMonitor(convergence_thresholds)

        # State
        self._quiet = quiet
        self._state: PipelineState | None = None
        self._report: AuditReport | None = None
        self._periodic_task: asyncio.Task[None] | None = None
        self._shutdown_requested = False

    # ── Public API ────────────────────────────────────────────────────────

    async def run(
        self,
        project_path: str | Path,
        language: str,
        *,
        file_paths: list[str] | None = None,
        session_id: str | None = None,
    ) -> AuditReport:
        """Execute a full audit pipeline from start to finish.

        Args:
            project_path: Root directory of the project to audit.
            language: Programming language (python | javascript | java).
            file_paths: Explicit file list.  If None, discovered from *project_path*.
            session_id: Override auto-generated session ID.

        Returns:
            Aggregated :class:`AuditReport`.

        """
        target = Path(project_path).resolve()
        self._log("", f"Starting {language} audit of {target}")

        # ── Session ──────────────────────────────────────────────────
        sid = session_id or self._make_session_id()
        await self._session_mgr.save_session(
            {
                "id": sid,
                "project_path": str(target),
                "language": language,
                "status": "running",
            }
        )
        self._state = PipelineState(session_id=sid)

        # ── File discovery ───────────────────────────────────────────
        if file_paths is None:
            file_paths = self._discover_files(target, language)
        self._state.file_count = len(file_paths)
        self._state.phase_states["file_paths"] = file_paths

        self._log("info", f"Session {sid} — {len(file_paths)} files")

        # ── Build scanner modules if not injected ────────────────────
        self._ensure_scanner_modules(target, file_paths, language)

        # ── Signal handlers ──────────────────────────────────────────
        self._setup_signal_handlers()

        # ── Run phases ───────────────────────────────────────────────
        self._report = AuditReport(session_id=sid)
        start = time.monotonic()

        try:
            await self._execute_phases()
        except _ShutdownSignal:
            self._log("warn", "Shutdown requested — checkpoint saved.")
            self._report.status = "paused"
        except Exception:
            logger.exception("Audit pipeline failed")
            self._report.status = "failed"
            await self._save_checkpoint("error")
            raise

        self._report.scan_duration_ms = int((time.monotonic() - start) * 1000)
        self._report.cost_summary = self._cost_tracker.summary()
        self._report.phases_completed = list(self._state.completed_phases)

        # Update Prometheus budget gauge
        if self._obs_manager and self._obs_manager._metrics is not None:
            try:
                self._obs_manager._metrics.set_budget_spent(
                    self._cost_tracker.total_cost()
                )
            except Exception:
                pass

        # ── Finalise session ─────────────────────────────────────────
        await self._session_mgr.update_session_status(sid, self._report.status)

        self._log(
            "info",
            f"Audit {sid} {self._report.status} in {self._report.scan_duration_ms}ms — "
            f"{len(self._report.findings)} findings, {len(self._report.hypotheses)} hypotheses, "
            f"${self._report.cost_summary.total_cost:.4f} total cost",
        )
        return self._report

    async def resume(self, session_id: str) -> AuditReport:
        """Resume an audit from its most recent checkpoint.

        Args:
            session_id: The session ID to resume (from a previous ``run()``).

        Returns:
            Aggregated :class:`AuditReport` starting from the last checkpoint.

        Raises:
            ValueError: If the session or checkpoint cannot be found.

        """
        session = await self._session_mgr.get_session(session_id)
        if session is None:
            raise ValueError(f"Session '{session_id}' not found.")

        cp = await self._checkpoint_mgr.load_latest(session_id)
        if cp is None:
            raise ValueError(f"No checkpoint found for session '{session_id}'.")

        self._state = _checkpoint_to_state(cp)
        language = session.get("language", "")
        target = Path(session.get("project_path", "."))
        file_paths = self._state.phase_states.get("file_paths", [])
        if not file_paths:
            file_paths = self._discover_files(target, language)

        self._log(
            "info",
            f"Resuming session {session_id} from phase "
            f"'{self._state.current_phase}' "
            f"(completed: {self._state.completed_phases})",
        )

        # Rebuild scanner modules
        self._ensure_scanner_modules(target, file_paths, language)

        # Restore convergence state
        for hist in self._state.converge_history:
            self._convergence.update(ConvergenceSnapshot(**hist))

        # Rebuild report from saved state
        self._report = AuditReport(session_id=session_id)
        self._report.findings = self._state.phase_states.get("findings", [])
        self._report.hypotheses = self._state.phase_states.get("hypotheses", [])
        self._report.validations = self._state.phase_states.get("validations", [])
        self._report.annotated_paths = self._state.phase_states.get("annotated_paths", [])

        await self._session_mgr.update_session_status(session_id, "running")
        self._setup_signal_handlers()
        start = time.monotonic()

        try:
            await self._execute_phases()
        except _ShutdownSignal:
            self._report.status = "paused"
        except Exception:
            logger.exception("Resume pipeline failed")
            self._report.status = "failed"
            await self._save_checkpoint("error")
            raise

        self._report.scan_duration_ms = int((time.monotonic() - start) * 1000)
        self._report.cost_summary = self._cost_tracker.summary()
        self._report.phases_completed = list(self._state.completed_phases)

        if self._obs_manager and self._obs_manager._metrics is not None:
            try:
                self._obs_manager._metrics.set_budget_spent(
                    self._cost_tracker.total_cost()
                )
            except Exception:
                pass

        await self._session_mgr.update_session_status(session_id, self._report.status)
        return self._report

    # ── Phase execution engine ────────────────────────────────────────────

    async def _execute_phases(self) -> None:
        """Run phases in order, skipping already-completed ones, with convergence loop."""
        state = self._state
        assert state is not None

        # Find the starting index
        completed = set(state.completed_phases)

        # Pre-convergence-loop phases: run once, in order
        pre_loop = [
            PhaseName.CPG_BUILD,
            PhaseName.DETERMINISTIC_SCAN,
            PhaseName.ATTACK_SURFACE_MAP,
        ]

        for phase in pre_loop:
            if phase.value in completed:
                continue
            await self._run_phase(phase)

        # ── Convergence loop ──────────────────────────────────────────
        max_rounds = self._convergence._thresholds.max_rounds
        for round_num in range(1, max_rounds + 1):
            if self._shutdown_requested:
                raise _ShutdownSignal()

            state.converge_round = round_num

            # HYPOTHESIS_GEN
            if PhaseName.HYPOTHESIS_GEN.value not in completed:
                await self._run_phase(PhaseName.HYPOTHESIS_GEN)

            # VALIDATION
            if PhaseName.VALIDATION.value not in completed:
                await self._run_phase(PhaseName.VALIDATION)

            # ADVERSARIAL_REVIEW — attacker-lens review of rejected hypotheses
            if PhaseName.ADVERSARIAL_REVIEW.value not in completed:
                await self._run_phase(PhaseName.ADVERSARIAL_REVIEW)

            # SATURATION_SCAN — expand CPG call graph from confirmed sinks
            if PhaseName.SATURATION_SCAN.value not in completed:
                await self._run_phase(PhaseName.SATURATION_SCAN)

            # REVERSE_SINK — reverse BFS from sinks to unrecognised sources
            if PhaseName.REVERSE_SINK.value not in completed:
                await self._run_phase(PhaseName.REVERSE_SINK)

            # BLIND_SCAN — LLM reviews endpoints for pattern-blind issues
            if PhaseName.BLIND_SCAN.value not in completed:
                await self._run_phase(PhaseName.BLIND_SCAN)

            # COVERAGE_AUDIT
            if PhaseName.COVERAGE_AUDIT.value not in completed:
                await self._run_phase(PhaseName.COVERAGE_AUDIT)

            # CONVERGENCE_CHECK
            await self._run_phase(PhaseName.CONVERGENCE_CHECK)

            conv_report = self._report.convergence if self._report else None
            if conv_report and conv_report.converged:
                self._log("info", f"Converged at round {round_num}!")
                break

            # Clear completed flags for loop phases to allow re-entry
            for p in _CONVERGE_BODY:
                completed.discard(p.value)

            if conv_report and conv_report.recommendation == "escalate_to_human":
                self._log("warn", conv_report.escalate_reason)
                break

        # ── Post-loop: COMPLETENESS_CRITIC (runs once after convergence) ──
        if PhaseName.COMPLETENESS_CRITIC.value not in completed:
            await self._run_phase(PhaseName.COMPLETENESS_CRITIC)

    async def _run_phase(self, phase: PhaseName) -> None:
        """Execute a single phase, save checkpoint, and mark completed."""
        state = self._state
        assert state is not None

        state.current_phase = phase
        self._log("phase", f"Phase: {phase.value}")

        method = getattr(self, f"_phase_{phase.value}", None)
        if method is None:
            self._log("warn", f"No handler for phase '{phase.value}' — skipping.")
        else:
            await method(state)

        state.completed_phases.append(phase.value)
        await self._save_checkpoint("phase_complete")

    # ── Phase implementations ────────────────────────────────────────────

    async def _phase_cpg_build(self, state: PipelineState) -> None:
        """Build CPG graph from source files."""
        file_paths: list[str] = state.phase_states.get("file_paths", [])
        if not file_paths or not self._taint_loader:
            return

        from hyqagent.cpg.graph import CPGGraphBuilder
        from hyqagent.cpg.parser import Parser

        parser = Parser()
        builder = CPGGraphBuilder(parser, taint_loader=self._taint_loader)
        for fp in file_paths:
            with contextlib.suppress(Exception):
                builder.add_file(fp)

        from hyqagent.cpg.query import CPGQuery

        self._query = CPGQuery(builder.graph)
        state.phase_states["graph_nodes"] = builder.graph.number_of_nodes()
        state.phase_states["graph_edges"] = builder.graph.number_of_edges()

    async def _phase_deterministic_scan(self, state: PipelineState) -> None:
        """Run deterministic scanner (Phase 2)."""
        if self._deterministic_scanner is None:
            return
        file_paths: list[str] = state.phase_states.get("file_paths", [])
        language = state.phase_states.get("language", "")
        if not language:
            # Try to recover from session
            session = await self._session_mgr.get_session(state.session_id)
            language = session.get("language", "") if session else ""

        result = self._deterministic_scanner.scan_all(file_paths, language)
        state.finding_count = len(result.findings)
        state.phase_states["findings"] = result.findings
        state.phase_states["annotated_paths"] = result.annotated_paths
        if self._report:
            self._report.findings = result.findings
            self._report.annotated_paths = result.annotated_paths

    async def _phase_attack_surface_map(self, state: PipelineState) -> None:
        """Map attack surface from framework-extracted endpoints."""
        if self._mapper is None:
            return
        # Collect endpoints from frameworks
        endpoints: list[Any] = []
        for fw in getattr(self._deterministic_scanner, "_frameworks", []) or []:
            try:
                endpoints.extend(fw.extract_endpoints() or [])
            except Exception:
                pass

        if not endpoints:
            return

        surface, phase3 = self._mapper.map_endpoints(endpoints, max_for_phase3=50)
        state.endpoint_count = surface.total_endpoints
        state.phase_states["attack_surface"] = surface
        state.phase_states["phase3_targets"] = phase3

    async def _phase_hypothesis_gen(self, state: PipelineState) -> None:
        """Generate LLM hypotheses from annotated paths AND seed feedback.

        Seeds come from two sources:
        - ``saturation_seeds`` — function names adjacent to confirmed vulns
        - ``reverse_sink_result`` — sinks connected to unrecognised sources
        """
        annotated = state.phase_states.get("annotated_paths", [])
        if self._hypothesis_gen is None:
            return

        hypotheses: list[Any] = []

        # ── Primary: hypotheses from annotated paths ────────────────────
        if annotated:
            hypotheses = await self._hypothesis_gen.generate(annotated)

        # ── Seed feedback: saturation seeds + reverse sink discoveries ──
        seeds: list[str] = state.phase_states.get("saturation_seeds", []) or []
        reverse_result = state.phase_states.get("reverse_sink_result")
        discoveries: list[dict[str, Any]] = []
        if reverse_result is not None:
            for d in getattr(reverse_result, "discoveries", []) or []:
                discoveries.append({
                    "sink_name": getattr(d, "sink_name", ""),
                    "sink_file": getattr(d, "sink_file", ""),
                    "sink_line": getattr(d, "sink_line", 0),
                    "source_names": getattr(d, "source_names", []) or [],
                    "taint_category": getattr(d, "taint_category", ""),
                    "confidence": getattr(d, "confidence", "medium"),
                })

        if seeds or discoveries:
            self._log(
                "info",
                f"Seed feedback: {len(seeds)} saturation seeds, "
                f"{len(discoveries)} reverse-sink discoveries",
            )
            try:
                seed_hyps = await self._hypothesis_gen.generate_from_seeds(
                    seed_functions=list(seeds),
                    sink_discoveries=discoveries if discoveries else None,
                )
                hypotheses.extend(seed_hyps)
                self._log(
                    "info",
                    f"Seed feedback produced {len(seed_hyps)} new hypotheses",
                )
            except Exception:
                logger.warning("Seed feedback hypothesis generation failed — skipping.")

        state.phase_states["hypotheses"] = hypotheses
        if self._report:
            self._report.hypotheses = hypotheses

    async def _phase_validation(self, state: PipelineState) -> None:
        """Validate hypotheses (L1 deterministic + L2 LLM)."""
        hypotheses = state.phase_states.get("hypotheses", [])
        if not hypotheses or self._validator is None:
            return

        validations: list[Any] = []
        for h in hypotheses:
            try:
                l1, l2 = await self._validator.validate(h)
                validations.append(l1)
                if l2:
                    validations.append(l2)
            except Exception:
                logger.warning("Validation failed for hypothesis", id=getattr(h, "id", "?"))

        state.phase_states["validations"] = validations
        if self._report:
            self._report.validations = validations

    async def _phase_adversarial_review(self, state: PipelineState) -> None:
        """Adversarial review of rejected hypotheses — attacker's lens.

        An independent model re-examines hypotheses the validator rejected,
        systematically probing for bypasses.  Implements "提出者 ≠ 裁决者".
        """
        if self._adversarial_reviewer is None:
            return

        hypotheses = state.phase_states.get("hypotheses", [])
        validations = state.phase_states.get("validations", [])
        mode = state.phase_states.get("mode", "deep")

        if mode == "quick":
            return

        # Build hypothesis lookup
        hyp_map: dict[str, Any] = {}
        for h in hypotheses:
            hid = getattr(h, "id", "")
            if hid:
                hyp_map[hid] = h

        # Filter: only REJECTED validations with matching hypotheses
        rejected: list[tuple[Any, Any]] = []
        for v in validations:
            vid = getattr(v, "hypothesis_id", "")
            if getattr(v, "verdict", "") == "rejected" and vid in hyp_map:
                # Mode filter: standard mode only reviews HIGH+ severity
                if mode == "standard":
                    h = hyp_map[vid]
                    sev = getattr(h, "severity", "")
                    conf = getattr(h, "confidence", 0.0)
                    if sev not in ("critical", "high") or conf <= 0.4:
                        continue
                rejected.append((hyp_map[vid], v))

        if not rejected:
            self._log("info", f"Adversarial review: no eligible rejections (mode={mode})")
            return

        self._log(
            "phase",
            f"Adversarial review: {len(rejected)} rejected hypotheses to review",
        )

        try:
            results = await self._adversarial_reviewer.review(rejected)
        except Exception:
            logger.warning("Adversarial review failed — skipping.")
            return

        state.phase_states["adversarial_reviews"] = results

        # Track overturned rejections as new confirmed validations
        overturned = 0
        for r in results:
            if r.review_verdict == "overturned":
                from hyqagent.scanner.validator import ValidationResult

                state.phase_states.setdefault("validations", []).append(
                    ValidationResult(
                        hypothesis_id=r.hypothesis_id,
                        verdict="confirmed",
                        confidence=r.confidence,
                        validation_type="adversarial_review",
                        reasoning=r.reasoning,
                        model=r.model,
                    )
                )
                overturned += 1

        self._log(
            "info",
            f"Adversarial review: {len(results)} reviewed, {overturned} overturned",
        )

    async def _phase_saturation_scan(self, state: PipelineState) -> None:
        """Saturation scanning — expand attack surface from confirmed vulns.

        Uses confirmed findings (via validation + adversarial review) as
        seeds to discover adjacent code in the CPG call graph.  Purely
        graph-based — no LLM cost.
        """
        if self._saturation_scanner is None:
            return

        mode = state.phase_states.get("mode", "deep")
        if mode == "quick":
            return

        from hyqagent.scanner.saturation import confirmed_from_state

        confirmed = confirmed_from_state(state)
        if not confirmed:
            self._log("info", "Saturation scan: no confirmed findings to seed from")
            return

        self._log(
            "phase",
            f"Saturation scan: expanding from {len(confirmed)} confirmed findings",
        )

        try:
            result = await self._saturation_scanner.scan(confirmed)
        except Exception:
            logger.warning("Saturation scan failed — skipping.")
            return

        state.phase_states["saturation_result"] = result
        state.phase_states["saturation_seeds"] = result.seed_functions

        self._log(
            "info",
            result.reasoning,
        )

        # ── Feed new functions into convergence ─────────────────────────
        # Saturation-discovered functions that haven't been analyzed yet
        # extend the endpoint count → convergence requires more rounds.
        new_funcs = result.total_seeds_generated
        if new_funcs > 0:
            state.endpoint_count += new_funcs

    async def _phase_reverse_sink(self, state: PipelineState) -> None:
        """Reverse sink analysis (通道3) — trace from sinks to unrecognised sources.

        Zero-LLM, pure CPG graph traversal.
        """
        if self._reverse_sink_analyzer is None:
            return

        mode = state.phase_states.get("mode", "deep")
        if mode == "quick":
            return

        annotated = state.phase_states.get("annotated_paths", [])
        session = await self._session_mgr.get_session(state.session_id)
        language = session.get("language", "") if session else ""

        self._log(
            "phase",
            f"Reverse sink: analysing {len(annotated)} annotated paths (lang={language})",
        )

        try:
            result = await self._reverse_sink_analyzer.analyse(
                annotated_paths=annotated,
                language=language,
            )
        except Exception:
            logger.warning("Reverse sink analysis failed — skipping.")
            return

        state.phase_states["reverse_sink_result"] = result

        self._log(
            "info",
            f"Reverse sink: {len(result.discoveries)} new discovery/ies "
            f"({result.total_labeled} labelled, {result.total_unlabeled} unlabelled)",
        )

        # New discoveries extend the attack surface → increment endpoint count
        # to push convergence EC metric higher and trigger more rounds.
        new_discoveries = len(result.discoveries)
        if new_discoveries > 0:
            state.endpoint_count += new_discoveries

    async def _phase_blind_scan(self, state: PipelineState) -> None:
        """Blind-scan LLM channel (通道2).

        Ask an LLM what pattern-based scanners would miss at endpoints
        without source→sink coverage.
        """
        if self._blind_scan_reviewer is None:
            return

        mode = state.phase_states.get("mode", "deep")
        if mode == "quick":
            return

        from hyqagent.scanner.blind_scan import exposed_endpoints_from_state

        exposed = exposed_endpoints_from_state(state)
        if not exposed:
            self._log("info", "Blind scan: no exposed endpoints to review.")
            return

        session = await self._session_mgr.get_session(state.session_id)
        language = session.get("language", "") if session else ""

        self._log(
            "phase",
            f"Blind scan: reviewing {len(exposed)} exposed endpoint(s)",
        )

        try:
            result = await self._blind_scan_reviewer.review(
                endpoints=exposed,
                language=language,
            )
        except Exception:
            logger.warning("Blind scan LLM call failed — skipping.")
            return

        state.phase_states["blind_scan_result"] = result

        self._log(
            "info",
            f"Blind scan: {len(result.findings)} potential issue(s) found "
            f"across {result.endpoints_reviewed} endpoint(s)",
        )

        # Each blind-scan finding may reflect a new vulnerability class →
        # increment finding count for convergence metrics.
        new_findings = len(result.findings)
        if new_findings > 0:
            state.finding_count += new_findings

    async def _phase_coverage_audit(self, state: PipelineState) -> None:
        """Differential coverage audit (zero-LLM)."""
        if self._coverage_auditor_class is None or self._query is None:
            return
        annotated = state.phase_states.get("annotated_paths", [])
        language = ""
        session = await self._session_mgr.get_session(state.session_id)
        if session:
            language = session.get("language", "")

        auditor = self._coverage_auditor_class(
            self._query,
            annotated,
            language=language,
        )
        audit_result = auditor.audit()
        state.phase_states["coverage_audit"] = audit_result
        if self._report:
            self._report.coverage_audit = audit_result

    async def _phase_completeness_critic(self, state: PipelineState) -> None:
        """Post-audit completeness review (LLM)."""
        if self._completeness_critic is None:
            return
        findings = state.phase_states.get("findings", [])
        hypotheses = state.phase_states.get("hypotheses", [])
        coverage_audit = state.phase_states.get("coverage_audit")
        language = ""
        session = await self._session_mgr.get_session(state.session_id)
        if session:
            language = session.get("language", "")

        try:
            critic_report = await self._completeness_critic.review(
                project_summary="",
                findings_summary=self._summarise_findings(findings),
                hypotheses=[
                    {
                        "id": getattr(h, "id", ""),
                        "vuln_type": getattr(h, "vuln_type", ""),
                        "severity": getattr(h, "severity", ""),
                    }
                    for h in hypotheses
                ],
                coverage={"coverage_pct": getattr(coverage_audit, "coverage_pct", 0.0)},
                language=language,
            )
            if self._report:
                self._report.completeness_review = {
                    "overall": critic_report.overall_assessment,
                    "missed_classes": critic_report.missed_vuln_classes,
                    "recommendations": critic_report.recommendations,
                }
        except Exception:
            logger.warning("Completeness critic failed — skipping.")

    async def _phase_convergence_check(self, state: PipelineState) -> None:
        """Evaluate convergence metrics from the latest round."""
        validations = state.phase_states.get("validations", [])
        hypotheses = state.phase_states.get("hypotheses", [])
        attack_surface = state.phase_states.get("attack_surface")

        # Count new HIGH+ confirmed findings this round
        new_high = sum(
            1
            for v in validations
            if getattr(v, "verdict", "") == "confirmed" and self._is_high_severity(v, hypotheses)
        )

        # Endpoint coverage
        endpoints_analyzed = state.endpoint_count
        total_endpoints = getattr(attack_surface, "total_endpoints", 0) or state.endpoint_count or 1

        # Risk-weighted coverage (simplified: all analyzed endpoints count fully)
        risk_analyzed = float(endpoints_analyzed)
        risk_total = float(max(total_endpoints, endpoints_analyzed))

        # CWE coverage
        cwe_covered: set[str] = set()
        for h in hypotheses:
            cwe = getattr(h, "cwe_id", "")
            if cwe:
                cwe_covered.add(cwe)
        for v in validations:
            cwe = getattr(v, "cwe_id", "")
            if cwe:
                cwe_covered.add(cwe)
        # Target CWE classes from taint rules
        target_cwe: set[str] = set()
        if self._taint_loader:
            for rule in getattr(self._taint_loader, "rules", []):
                cwe = getattr(rule, "cwe_id", "") or rule.get("cwe_id", "")
                if cwe:
                    target_cwe.add(cwe)

        # ── Dual-perspective findings for Chao2 estimator ────────
        # Perspective A: hypothesis IDs from the generator (validator-confirmed)
        perspective_a: set[str] = {
            getattr(h, "id", "") for h in hypotheses if getattr(h, "id", "")
        }
        # Perspective B: hypothesis IDs overturned by adversarial review
        adversarial_results = state.phase_states.get("adversarial_reviews", [])
        perspective_b: set[str] = {
            getattr(ar, "hypothesis_id", "")
            for ar in adversarial_results
            if getattr(ar, "review_verdict", "") == "overturned"
        }
        # Merge blind-scan discovered endpoints into perspective B
        # (they represent findings from an independent "lens")
        blind_scan = state.phase_states.get("blind_scan_result")
        if blind_scan is not None:
            for bf in getattr(blind_scan, "findings", []) or []:
                ep = getattr(bf, "endpoint", "")
                if ep:
                    perspective_b.add(f"blind:{ep}")

        snapshot = ConvergenceSnapshot(
            round=state.converge_round,
            new_high_findings=new_high,
            endpoints_analyzed=endpoints_analyzed,
            total_endpoints=total_endpoints,
            risk_score_analyzed=risk_analyzed,
            risk_score_total=risk_total,
            cwe_classes_covered=cwe_covered,
            total_cwe_classes=target_cwe,
            perspective_a_findings=perspective_a,
            perspective_b_findings=perspective_b,
        )
        report = self._convergence.update(snapshot)
        state.converge_history.append(
            {
                "round": snapshot.round,
                "new_high_findings": snapshot.new_high_findings,
                "endpoints_analyzed": snapshot.endpoints_analyzed,
                "total_endpoints": snapshot.total_endpoints,
                "risk_score_analyzed": snapshot.risk_score_analyzed,
                "risk_score_total": snapshot.risk_score_total,
                "cwe_classes_covered": list(snapshot.cwe_classes_covered),
                "total_cwe_classes": list(snapshot.total_cwe_classes),
            }
        )
        state.phase_states["convergence_report"] = report
        if self._report:
            self._report.convergence = report
        self._log("info", report.summary)

    # ── Checkpoint management ────────────────────────────────────────────

    async def _save_checkpoint(self, trigger: str) -> None:
        """Persist current pipeline state."""
        if self._state is None:
            return
        cp = _state_to_checkpoint(self._state)
        await self._checkpoint_mgr.save(cp)

        # Clean up old checkpoints (keep latest 5)
        with contextlib.suppress(Exception):
            await self._checkpoint_mgr.delete_old(self._state.session_id, keep_latest=5)

        self._log("debug", f"Checkpoint saved [trigger={trigger}]")

    async def _emergency_checkpoint(self) -> None:
        """Save checkpoint and mark session as paused (called on SIGTERM)."""
        if self._state is None:
            return
        await self._save_checkpoint("sigterm")
        await self._session_mgr.update_session_status(self._state.session_id, "paused")
        self._log("warn", "Emergency checkpoint saved — session paused.")

    # ── Signal handling ──────────────────────────────────────────────────

    def _setup_signal_handlers(self) -> None:
        """Register OS signal handlers for graceful shutdown."""
        try:
            loop = asyncio.get_running_loop()
            loop.add_signal_handler(signal.SIGTERM, self._on_sigterm)
            loop.add_signal_handler(signal.SIGUSR1, self._on_sigusr1)
        except NotImplementedError:
            # Windows does not support add_signal_handler
            self._log("debug", "Signal handlers not available on this platform.")

    def _on_sigterm(self) -> None:
        """SIGTERM received — trigger graceful shutdown."""
        self._shutdown_requested = True
        asyncio.ensure_future(self._emergency_checkpoint())

    def _on_sigusr1(self) -> None:
        """SIGUSR1 received — manual checkpoint trigger."""
        asyncio.ensure_future(self._save_checkpoint("sigusr1"))

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _make_session_id() -> str:
        ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        return f"audit-{ts}-{uuid.uuid4().hex[:6]}"

    @staticmethod
    def _discover_files(target: Path, language: str) -> list[str]:
        _EXT = {
            "python": {".py"},
            "javascript": {".js", ".mjs", ".cjs", ".jsx"},
            "java": {".java"},
        }
        exts = _EXT.get(language, set())
        if target.is_file():
            return [str(target)] if target.suffix in exts else []
        return sorted(str(p) for p in target.rglob("*") if p.suffix in exts and p.is_file())

    def _ensure_scanner_modules(
        self,
        target: Path,
        file_paths: list[str],
        language: str,
    ) -> None:
        """Build scanner modules from scratch if not injected via DI."""
        if self._query is not None and self._deterministic_scanner is not None:
            return  # Already fully wired

        # ── CPG layer ──────────────────────────────────────────────────
        if self._query is None:
            from hyqagent.cpg.graph import CPGGraphBuilder
            from hyqagent.cpg.parser import Parser
            from hyqagent.cpg.taint_loader import TaintRuleLoader

            if self._taint_loader is None:
                self._taint_loader = TaintRuleLoader()

            parser = Parser()
            builder = CPGGraphBuilder(parser, taint_loader=self._taint_loader)
            for fp in file_paths:
                with contextlib.suppress(Exception):
                    builder.add_file(fp)

            from hyqagent.cpg.query import CPGQuery

            self._query = CPGQuery(builder.graph)

        if self._taint_loader is None:
            from hyqagent.cpg.taint_loader import TaintRuleLoader

            self._taint_loader = TaintRuleLoader()

        # ── Annotator ──────────────────────────────────────────────────
        if self._path_annotator is None:
            from hyqagent.cpg.discovery import SinkDiscoverer, SourceCompletenessChecker
            from hyqagent.scanner.annotator import PathAnnotator

            graph = getattr(self._query, "_graph", None)
            sink_disc = SinkDiscoverer(graph, self._taint_loader)  # type: ignore[arg-type]
            src_check = SourceCompletenessChecker(graph, self._taint_loader)  # type: ignore[arg-type]
            self._path_annotator = PathAnnotator(
                self._query,
                self._taint_loader,
                sink_disc,
                src_check,
            )

        # ── Coverage tracker ───────────────────────────────────────────
        tracker = None
        try:
            from hyqagent.cpg.coverage import CoverageTracker

            graph = getattr(self._query, "_graph", None)
            if graph is not None:
                tracker = CoverageTracker(graph)
        except Exception:
            pass

        # ── Framework extractors ───────────────────────────────────────
        frameworks: list[Any] = []
        try:
            from hyqagent.cpg.parser import Parser as CPGParser

            cpg_parser = CPGParser(languages=[language])
            if language == "python":
                from hyqagent.cpg.frameworks.django import DjangoExtractor
                from hyqagent.cpg.frameworks.fastapi import FastAPIExtractor
                from hyqagent.cpg.frameworks.flask import FlaskExtractor

                frameworks = [
                    FlaskExtractor(cpg_parser),
                    DjangoExtractor(cpg_parser),
                    FastAPIExtractor(cpg_parser),
                ]
            elif language == "javascript":
                from hyqagent.cpg.frameworks.express import ExpressExtractor

                frameworks = [ExpressExtractor(cpg_parser)]
            elif language == "java":
                from hyqagent.cpg.frameworks.jaxrs import JaxRsExtractor
                from hyqagent.cpg.frameworks.spring import SpringExtractor

                frameworks = [SpringExtractor(cpg_parser), JaxRsExtractor(cpg_parser)]
        except Exception:
            pass

        # ── Deterministic scanner ──────────────────────────────────────
        if self._deterministic_scanner is None:
            from hyqagent.scanner.deterministic import DeterministicScanner

            self._deterministic_scanner = DeterministicScanner(
                graph=getattr(self._query, "_graph", None) or nx.MultiDiGraph(),
                query=self._query,
                taint_loader=self._taint_loader,
                annotator=self._path_annotator,
                frameworks=frameworks,
                tracker=tracker,
            )

        # ── Mapper ─────────────────────────────────────────────────────
        if self._mapper is None:
            from hyqagent.scanner.mapper import AttackSurfaceMapper

            self._mapper = AttackSurfaceMapper()

        # ── Coverage auditor ───────────────────────────────────────────
        if self._coverage_auditor_class is None:
            from hyqagent.scanner.coverage_auditor import CoverageAuditor

            self._coverage_auditor_class = CoverageAuditor

        # ── LLM providers ──────────────────────────────────────────────
        if self._cheap is None or self._mid is None:
            from hyqagent.api.config import HyqAgentConfig
            from hyqagent.models.providers.anthropic_provider import (
                AnthropicProvider,
                ProviderConfig,
            )
            from hyqagent.models.router import ModelRouter

            cfg = HyqAgentConfig()
            if self._cheap is None:
                try:
                    self._cheap = AnthropicProvider(
                        ProviderConfig(
                            api_key=cfg.deepseek_key,
                            base_url=cfg.deepseek_base_url,
                        ),
                        max_retries=cfg.llm_max_retries,
                        timeout_seconds=cfg.llm_timeout_seconds,
                    )
                except Exception:
                    self._cheap = None

            if self._mid is None:
                try:
                    self._mid = AnthropicProvider(
                        ProviderConfig(api_key=cfg.anthropic_key, base_url=None),
                        max_retries=cfg.llm_max_retries,
                        timeout_seconds=cfg.llm_timeout_seconds,
                    )
                except Exception:
                    self._mid = self._cheap  # Fallback

            if self._strong is None:
                self._strong = self._mid

            if self._router is None and self._cheap is not None:
                self._router = ModelRouter(
                    providers={"deepseek": self._cheap, "anthropic": self._mid},
                    cheap_model=cfg.cheap_model,
                    mid_model=cfg.mid_model,
                    strong_model=cfg.strong_model,
                )

        # ── Hypothesis generator ───────────────────────────────────────
        if self._hypothesis_gen is None and self._router is not None:
            from hyqagent.scanner.hypothesis import HypothesisGenerator
            from hyqagent.scanner.nudge import NudgeConfig, NudgeLoop

            nudge = NudgeLoop(NudgeConfig(max_turns=5))
            self._hypothesis_gen = HypothesisGenerator(
                query=self._query,
                router=self._router,
                cheap_provider=self._cheap,
                mid_provider=self._mid,
                strong_provider=self._strong,
                language=language,
                nudge_loop=nudge,
            )

        # ── Validator ──────────────────────────────────────────────────
        if self._validator is None and self._router is not None:
            from hyqagent.scanner.nudge import NudgeConfig, NudgeLoop
            from hyqagent.scanner.validator import Validator

            nudge = NudgeLoop(NudgeConfig(max_turns=5))
            self._validator = Validator(
                query=self._query,
                taint_loader=self._taint_loader,
                router=self._router,
                mid_provider=self._mid,
                strong_provider=self._strong,
                language=language,
                nudge_loop=nudge,
            )

        # ── Completeness critic ────────────────────────────────────────
        if self._completeness_critic is None and self._mid is not None:
            from hyqagent.api.config import HyqAgentConfig
            from hyqagent.scanner.completeness import CompletenessCritic

            cfg = HyqAgentConfig()
            self._completeness_critic = CompletenessCritic(
                self._mid,
                cfg.mid_model,
            )

        # ── Adversarial reviewer ─────────────────────────────────────────
        if self._adversarial_reviewer is None and self._strong is not None:
            from hyqagent.api.config import HyqAgentConfig
            from hyqagent.scanner.adversarial import AdversarialReviewer
            from hyqagent.scanner.nudge import NudgeConfig, NudgeLoop

            cfg = HyqAgentConfig()
            nudge = NudgeLoop(NudgeConfig(max_turns=3))
            self._adversarial_reviewer = AdversarialReviewer(
                provider=self._strong,
                model=cfg.strong_model,
                nudge_loop=nudge,
            )

        # ── Saturation scanner ──────────────────────────────────────────
        if self._saturation_scanner is None and self._query is not None:
            from hyqagent.scanner.saturation import SaturationScanner

            self._saturation_scanner = SaturationScanner(
                cpg_query=self._query,
                max_rounds=4,
            )

        # ── Reverse sink analyser (通道3, zero-LLM) ──────────────────────
        if self._reverse_sink_analyzer is None and self._query is not None:
            from hyqagent.scanner.reverse_sink import ReverseSinkAnalyzer

            self._reverse_sink_analyzer = ReverseSinkAnalyzer(
                cpg_query=self._query,
                max_depth=15,
            )

        # ── Blind scan reviewer (通道2, LLM-based) ──────────────────────
        if self._blind_scan_reviewer is None and self._mid is not None:
            from hyqagent.api.config import HyqAgentConfig
            from hyqagent.scanner.blind_scan import BlindScanReviewer

            cfg = HyqAgentConfig()
            self._blind_scan_reviewer = BlindScanReviewer(
                provider=self._mid,
                model=cfg.mid_model,
            )

        # ── Observability ──────────────────────────────────────────────────
        if self._obs_manager is None:
            from hyqagent.observability.metrics import PrometheusMetrics
            from hyqagent.observability.tracer import ObservabilityManager

            self._obs_manager = ObservabilityManager(
                cost_tracker=self._cost_tracker,
                metrics=PrometheusMetrics(),
                audit_trail=None,  # created per-session in run()
                session_id="",
            )

        # Wire the on_call_complete callback into each LLM provider so
        # every generate() call feeds CostTracker + Prometheus.
        _obs_cb = self._obs_manager.record_llm_call
        for _prov in (self._cheap, self._mid, self._strong):
            if _prov is not None and getattr(_prov, "_on_call_complete", None) is None:
                try:
                    _prov._on_call_complete = _obs_cb
                except Exception:
                    pass

    @staticmethod
    def _summarise_findings(findings: list[Any]) -> str:
        if not findings:
            return "No findings."
        lines = []
        for f in findings[:15]:
            sev = getattr(f, "severity", "?")
            loc = getattr(f, "location", getattr(f, "file_path", "?"))
            rule = getattr(f, "rule_id", getattr(f, "rule", "?"))
            lines.append(f"- [{sev}] {rule} at {loc}")
        if len(findings) > 15:
            lines.append(f"... and {len(findings) - 15} more")
        return "\n".join(lines)

    @staticmethod
    def _is_high_severity(validation: Any, hypotheses: list[Any]) -> bool:
        """Check whether a validation result corresponds to a HIGH+ severity hypothesis."""
        hid = getattr(validation, "hypothesis_id", "")
        for h in hypotheses:
            if getattr(h, "id", "") == hid:
                sev = getattr(h, "severity", "")
                return sev in ("critical", "high")
        return False

    def _log(self, level: str, message: str) -> None:
        """Conditional logging — suppressed when *quiet* is True."""
        if self._quiet:
            return
        if level == "phase":
            logger.info(message)
        elif level == "warn":
            logger.warning(message)
        elif level == "error":
            logger.error(message)
        elif level == "debug":
            logger.debug(message)
        else:
            logger.info(message)


# ── Internal ──────────────────────────────────────────────────────────────────


class _ShutdownSignal(Exception):
    """Raised when SIGTERM is received during pipeline execution."""

    pass
