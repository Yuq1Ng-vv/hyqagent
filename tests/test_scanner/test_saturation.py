"""Tests for scanner/saturation.py — SaturationScanner, seed extraction, graph traversal."""

from __future__ import annotations

from unittest.mock import MagicMock

import networkx as nx

from hyqagent.scanner.saturation import (
    SaturationResult,
    SaturationScanner,
    SeedPoint,
    _find_callers,
    _find_callees,
    _resolve_function_at,
    confirmed_from_state,
)


# ── SeedPoint ────────────────────────────────────────────────────────────────


class TestSeedPoint:
    def test_defaults(self) -> None:
        s = SeedPoint(function_name="do_query", file_path="app.py")
        assert s.function_name == "do_query"
        assert s.file_path == "app.py"
        assert s.reason == ""
        assert s.source_finding_id == ""
        assert s.source_sink == ""

    def test_all_fields(self) -> None:
        s = SeedPoint(
            function_name="handle_login",
            file_path="auth.py",
            reason="caller_of_sink",
            source_finding_id="hyp-001",
            source_sink="execute_sql",
        )
        assert s.reason == "caller_of_sink"
        assert s.source_sink == "execute_sql"


# ── SaturationResult ─────────────────────────────────────────────────────────


class TestSaturationResult:
    def test_defaults(self) -> None:
        r = SaturationResult()
        assert r.rounds_completed == 0
        assert r.total_seeds_generated == 0
        assert r.seeds_per_round == []
        assert r.seed_functions == []
        assert r.reasoning == ""

    def test_with_data(self) -> None:
        r = SaturationResult(
            rounds_completed=3,
            total_seeds_generated=12,
            seeds_per_round=[5, 4, 3],
            seed_functions=["f1", "f2", "f3"],
            reasoning="Done.",
        )
        assert r.rounds_completed == 3
        assert r.total_seeds_generated == 12
        assert len(r.seeds_per_round) == 3


# ── Graph traversal helpers ──────────────────────────────────────────────────


def _build_call_graph() -> nx.MultiDiGraph:
    """Build a minimal CPG-like call graph for testing.

    Topology:
        main --> sanitize --> do_query --> execute_sql
                upload_file --> do_query   (shared callee)
    """
    g = nx.MultiDiGraph()

    def add_func(name: str, file_path: str, start: int, end: int) -> str:
        nid = f"fn::{name}"
        g.add_node(
            nid,
            node_type="function",
            name=name,
            file_path=file_path,
            start_line=start,
            end_line=end,
        )
        return nid

    def add_call(caller: str, callee: str) -> None:
        cs_id = f"cs::{caller}->{callee}"
        g.add_node(cs_id, node_type="_call_site")
        g.add_edge(f"fn::{caller}", cs_id, edge_type="CALLS")
        g.add_edge(cs_id, f"fn::{callee}", edge_type="CALLS")

    add_func("main", "app.py", 1, 30)
    add_func("sanitize", "app.py", 32, 50)
    add_func("do_query", "db.py", 10, 40)
    add_func("execute_sql", "db.py", 42, 60)
    add_func("upload_file", "upload.py", 1, 25)

    add_call("main", "sanitize")
    add_call("sanitize", "do_query")
    add_call("do_query", "execute_sql")
    add_call("upload_file", "do_query")

    return g


class TestGraphTraversal:
    @classmethod
    def setup_class(cls) -> None:
        cls.graph = _build_call_graph()

    def test_resolve_function_at_exact_match(self) -> None:
        name = _resolve_function_at(self.graph, "db.py", 45)  # inside execute_sql
        assert name == "execute_sql"

    def test_resolve_function_at_boundary(self) -> None:
        name = _resolve_function_at(self.graph, "db.py", 42)  # start_line of execute_sql
        assert name == "execute_sql"

    def test_resolve_function_at_no_match_file(self) -> None:
        name = _resolve_function_at(self.graph, "nonexistent.py", 10)
        assert name is None

    def test_resolve_function_at_no_match_line(self) -> None:
        name = _resolve_function_at(self.graph, "app.py", 999)
        assert name is None

    def test_find_callers_single(self) -> None:
        callers = _find_callers(self.graph, "execute_sql")
        caller_names = {c[0] for c in callers}
        assert "do_query" in caller_names

    def test_find_callers_multiple(self) -> None:
        callers = _find_callers(self.graph, "do_query")
        caller_names = {c[0] for c in callers}
        assert "sanitize" in caller_names
        assert "upload_file" in caller_names
        assert len(caller_names) == 2

    def test_find_callers_none(self) -> None:
        callers = _find_callers(self.graph, "main")
        assert len(callers) == 0

    def test_find_callees_single(self) -> None:
        callees = _find_callees(self.graph, "main")
        callee_names = {c[0] for c in callees}
        assert "sanitize" in callee_names

    def test_find_callees_none(self) -> None:
        callees = _find_callees(self.graph, "execute_sql")
        assert len(callees) == 0


# ── SaturationScanner ────────────────────────────────────────────────────────

def _mock_cpg_query(graph: nx.MultiDiGraph) -> MagicMock:
    q = MagicMock()
    q._graph = graph
    return q


def _mock_hypothesis(**overrides: object) -> MagicMock:
    defaults: dict[str, object] = {
        "id": "hyp-001",
        "sink_location": "db.py:45",  # execute_sql
        "vuln_type": "sql_injection",
        "severity": "high",
    }
    defaults.update(overrides)
    return MagicMock(**defaults)


def _mock_validation(**overrides: object) -> MagicMock:
    defaults: dict[str, object] = {
        "hypothesis_id": "hyp-001",
        "verdict": "confirmed",
        "confidence": 0.90,
    }
    defaults.update(overrides)
    return MagicMock(**defaults)


class TestSaturationScannerConstruction:
    def test_constructor(self) -> None:
        q = _mock_cpg_query(nx.MultiDiGraph())
        scanner = SaturationScanner(cpg_query=q, max_rounds=3)
        assert scanner._max_rounds == 3

    def test_default_max_rounds(self) -> None:
        q = _mock_cpg_query(nx.MultiDiGraph())
        scanner = SaturationScanner(cpg_query=q)
        assert scanner._max_rounds == 4


class TestSaturationScannerScan:
    graph = _build_call_graph()

    async def test_empty_confirmed(self) -> None:
        q = _mock_cpg_query(self.graph)
        scanner = SaturationScanner(cpg_query=q)
        result = await scanner.scan([])
        assert result.rounds_completed == 0

    async def test_no_graph(self) -> None:
        q = MagicMock()
        del q._graph  # ensure AttributeError
        scanner = SaturationScanner(cpg_query=q)
        h = _mock_hypothesis()
        v = _mock_validation()
        result = await scanner.scan([(h, v)])
        assert result.rounds_completed == 0

    async def test_extracts_seeds_from_sink(self) -> None:
        """Confirmed finding at execute_sql → seeds = do_query (caller)."""
        q = _mock_cpg_query(self.graph)
        scanner = SaturationScanner(cpg_query=q, max_rounds=2)
        h = _mock_hypothesis(sink_location="db.py:45")  # execute_sql
        v = _mock_validation()

        result = await scanner.scan([(h, v)])

        # Round 0: 1 seed (do_query calls execute_sql)
        # execute_sql has no callees
        assert result.rounds_completed >= 1
        assert result.total_seeds_generated >= 1
        assert "do_query" in result.seed_functions

    async def test_multiple_rounds_expand(self) -> None:
        """Multi-round: sql → do_query → sanitize + upload_file."""
        q = _mock_cpg_query(self.graph)
        scanner = SaturationScanner(cpg_query=q, max_rounds=3)
        h = _mock_hypothesis(sink_location="db.py:45")  # execute_sql
        v = _mock_validation()

        result = await scanner.scan([(h, v)])

        # Round 1: do_query (caller of execute_sql)
        # Round 2: sanitize + upload_file (callers of do_query)
        # Round 3: main (caller of sanitize)
        assert result.rounds_completed >= 2
        all_funcs = set(result.seed_functions)
        assert "do_query" in all_funcs
        assert "sanitize" in all_funcs or "upload_file" in all_funcs

    async def test_dedup_across_rounds(self) -> None:
        """Same function discovered from multiple paths → counted once."""
        q = _mock_cpg_query(self.graph)
        scanner = SaturationScanner(cpg_query=q, max_rounds=3)
        # Two confirmed findings both pointing at do_query (same sink)
        h1 = _mock_hypothesis(id="h1", sink_location="db.py:25")  # do_query
        h2 = _mock_hypothesis(id="h2", sink_location="db.py:25")  # do_query
        v1 = _mock_validation(hypothesis_id="h1")
        v2 = _mock_validation(hypothesis_id="h2")

        result = await scanner.scan([(h1, v1), (h2, v2)])

        # sanitize and upload_file appear only once despite 2 confirmations
        assert len(result.seed_functions) == len(set(result.seed_functions))

    async def test_seeds_per_round_populated(self) -> None:
        q = _mock_cpg_query(self.graph)
        scanner = SaturationScanner(cpg_query=q, max_rounds=2)
        h = _mock_hypothesis(sink_location="db.py:45")
        v = _mock_validation()

        result = await scanner.scan([(h, v)])

        assert len(result.seeds_per_round) >= 2  # round 0 + round 1
        assert result.seeds_per_round[0] > 0  # initial seeds


class TestSaturationScannerEdgeCases:
    async def test_unresolvable_location(self) -> None:
        """Location that doesn't match any function → no seeds."""
        q = _mock_cpg_query(_build_call_graph())
        scanner = SaturationScanner(cpg_query=q)
        h = _mock_hypothesis(sink_location="unknown.py:999")
        v = _mock_validation()

        result = await scanner.scan([(h, v)])
        assert result.rounds_completed == 0
        assert result.total_seeds_generated == 0

    async def test_invalid_location_format(self) -> None:
        q = _mock_cpg_query(_build_call_graph())
        scanner = SaturationScanner(cpg_query=q)
        h = _mock_hypothesis(sink_location="not-a-location")
        v = _mock_validation()

        result = await scanner.scan([(h, v)])
        assert result.rounds_completed == 0

    async def test_mixed_confirmed_and_rejected(self) -> None:
        """Only confirmed findings produce seeds."""
        q = _mock_cpg_query(_build_call_graph())
        scanner = SaturationScanner(cpg_query=q)
        h_confirmed = _mock_hypothesis(id="hc", sink_location="db.py:45")
        v_confirmed = _mock_validation(hypothesis_id="hc", verdict="confirmed")
        h_rejected = _mock_hypothesis(id="hr", sink_location="db.py:45")
        v_rejected = _mock_validation(hypothesis_id="hr", verdict="rejected")

        result = await scanner.scan([(h_confirmed, v_confirmed), (h_rejected, v_rejected)])
        # Should still produce seeds from the confirmed one
        assert result.total_seeds_generated >= 1


# ── confirmed_from_state ─────────────────────────────────────────────────────


class TestConfirmedFromState:
    def test_extracts_confirmed(self) -> None:
        state = MagicMock()
        state.phase_states = {
            "hypotheses": [
                _mock_hypothesis(id="h1"),
                _mock_hypothesis(id="h2"),
            ],
            "validations": [
                _mock_validation(hypothesis_id="h1", verdict="confirmed"),
                _mock_validation(hypothesis_id="h2", verdict="rejected"),
            ],
        }
        confirmed = confirmed_from_state(state)
        assert len(confirmed) == 1
        assert getattr(confirmed[0][0], "id", "") == "h1"

    def test_empty_state(self) -> None:
        state = MagicMock()
        state.phase_states = {}
        confirmed = confirmed_from_state(state)
        assert confirmed == []

    def test_dedup_by_hypothesis_id(self) -> None:
        """Multiple validations for the same hypothesis → only one pair."""
        state = MagicMock()
        state.phase_states = {
            "hypotheses": [_mock_hypothesis(id="h1")],
            "validations": [
                _mock_validation(hypothesis_id="h1", verdict="confirmed"),
                _mock_validation(
                    hypothesis_id="h1",
                    verdict="confirmed",
                    validation_type="adversarial_review",
                ),
            ],
        }
        confirmed = confirmed_from_state(state)
        assert len(confirmed) == 1

    def test_adversarial_overturned_are_confirmed(self) -> None:
        """Validation with validation_type='adversarial_review' and verdict='confirmed'."""
        state = MagicMock()
        state.phase_states = {
            "hypotheses": [_mock_hypothesis(id="h-ar")],
            "validations": [
                _mock_validation(
                    hypothesis_id="h-ar",
                    verdict="confirmed",
                    validation_type="adversarial_review",
                ),
            ],
        }
        confirmed = confirmed_from_state(state)
        assert len(confirmed) == 1


# ── Orchestrator phase integration ──────────────────────────────────────────


class TestPhaseSaturationScan:
    async def test_skips_when_no_scanner(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        state = PipelineState(
            session_id="test-sat",
            current_phase=PhaseName.SATURATION_SCAN,
        )
        orch = Orchestrator()  # no saturation_scanner
        await orch._phase_saturation_scan(state)
        assert "saturation_result" not in state.phase_states

    async def test_skips_quick_mode(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        q = _mock_cpg_query(_build_call_graph())
        scanner = SaturationScanner(cpg_query=q)
        orch = Orchestrator(saturation_scanner=scanner)

        state = PipelineState(
            session_id="test-sat-q",
            current_phase=PhaseName.SATURATION_SCAN,
        )
        state.phase_states["mode"] = "quick"
        state.phase_states["hypotheses"] = [_mock_hypothesis(id="h1", sink_location="db.py:45")]
        state.phase_states["validations"] = [_mock_validation(hypothesis_id="h1")]

        await orch._phase_saturation_scan(state)
        assert "saturation_result" not in state.phase_states

    async def test_skips_when_no_confirmed(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        q = _mock_cpg_query(_build_call_graph())
        scanner = SaturationScanner(cpg_query=q)
        orch = Orchestrator(saturation_scanner=scanner)

        state = PipelineState(
            session_id="test-sat-nc",
            current_phase=PhaseName.SATURATION_SCAN,
        )
        state.phase_states["hypotheses"] = []
        state.phase_states["validations"] = []

        await orch._phase_saturation_scan(state)
        assert "saturation_result" not in state.phase_states

    async def test_stores_result_and_seeds(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        q = _mock_cpg_query(_build_call_graph())
        scanner = SaturationScanner(cpg_query=q, max_rounds=2)
        orch = Orchestrator(saturation_scanner=scanner)

        state = PipelineState(
            session_id="test-sat-ok",
            current_phase=PhaseName.SATURATION_SCAN,
        )
        state.phase_states["hypotheses"] = [
            _mock_hypothesis(id="h1", sink_location="db.py:45")
        ]
        state.phase_states["validations"] = [
            _mock_validation(hypothesis_id="h1", verdict="confirmed")
        ]

        await orch._phase_saturation_scan(state)

        assert "saturation_result" in state.phase_states
        assert "saturation_seeds" in state.phase_states
        result = state.phase_states["saturation_result"]
        assert isinstance(result, SaturationResult)
        assert result.rounds_completed >= 1

    async def test_updates_endpoint_count(self) -> None:
        """New functions discovered → endpoint_count increases → convergence delayed."""
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        q = _mock_cpg_query(_build_call_graph())
        scanner = SaturationScanner(cpg_query=q, max_rounds=2)
        orch = Orchestrator(saturation_scanner=scanner)

        state = PipelineState(
            session_id="test-sat-ec",
            current_phase=PhaseName.SATURATION_SCAN,
        )
        state.phase_states["hypotheses"] = [
            _mock_hypothesis(id="h1", sink_location="db.py:45")
        ]
        state.phase_states["validations"] = [
            _mock_validation(hypothesis_id="h1", verdict="confirmed")
        ]
        old_ec = state.endpoint_count

        await orch._phase_saturation_scan(state)

        assert state.endpoint_count > old_ec
