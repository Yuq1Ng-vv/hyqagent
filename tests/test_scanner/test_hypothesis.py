"""Tests for scanner/hypothesis.py — generate_from_seeds, seed feedback loop."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import networkx as nx

from hyqagent.scanner.hypothesis import HypothesisGenerator

# ── Helpers ───────────────────────────────────────────────────────────────────


def _build_seed_graph() -> nx.MultiDiGraph:
    """Build a minimal CPG graph with function nodes for seed testing."""
    g = nx.MultiDiGraph()
    g.add_node("f1", node_type="function", name="do_query",
               file_path="app.py", start_line=10, end_line=25,
               source="def do_query(sql):\n    return db.execute(sql)")
    g.add_node(
        "f2", node_type="function", name="handle_upload",
        file_path="upload.py", start_line=5, end_line=30,
        source=(
            "def handle_upload(file):\n"
            "    name = file.filename\n"
            "    os.system(f'touch {name}')"
        ),
    )
    g.add_node("f3", node_type="function", name="helper",
               file_path="app.py", start_line=30, end_line=32,
               source="")  # empty source → test fallback
    return g


def _mock_query(graph: nx.MultiDiGraph) -> MagicMock:
    q = MagicMock()
    q._graph = graph
    return q


def _mock_router() -> MagicMock:
    r = MagicMock()
    r.CHEAP_SPEC.model_id = "cheap-model"
    return r


def _mock_provider(response: dict) -> MagicMock:
    p = MagicMock()
    p.generate_structured = AsyncMock(return_value=response)
    return p


# ── _read_function_source ─────────────────────────────────────────────────────


class TestReadFunctionSource:
    def test_finds_function_and_returns_markdown(self) -> None:
        g = _build_seed_graph()
        q = _mock_query(g)
        gen = HypothesisGenerator(
            query=q, router=_mock_router(),
            cheap_provider=_mock_provider({}),
            mid_provider=_mock_provider({}),
            strong_provider=_mock_provider({}),
            language="python",
        )
        md = gen._read_function_source("do_query", g)
        assert md is not None
        assert "do_query" in md
        assert "app.py" in md
        assert "def do_query" in md
        assert "```python" in md

    def test_returns_none_for_unknown_function(self) -> None:
        g = _build_seed_graph()
        q = _mock_query(g)
        gen = HypothesisGenerator(
            query=q, router=_mock_router(),
            cheap_provider=_mock_provider({}),
            mid_provider=_mock_provider({}),
            strong_provider=_mock_provider({}),
            language="python",
        )
        assert gen._read_function_source("nonexistent", g) is None

    def test_skips_empty_source(self) -> None:
        """Function with empty source → None (no code block generated)."""
        g = _build_seed_graph()
        q = _mock_query(g)
        gen = HypothesisGenerator(
            query=q, router=_mock_router(),
            cheap_provider=_mock_provider({}),
            mid_provider=_mock_provider({}),
            strong_provider=_mock_provider({}),
            language="python",
        )
        # f3 has empty source
        assert gen._read_function_source("helper", g) is None

    def test_truncates_long_sources(self) -> None:
        g = nx.MultiDiGraph()
        long_src = "x = 1\n" * 2000  # ~14000 chars
        g.add_node("big", node_type="function", name="big_func",
                   file_path="big.py", source=long_src)
        q = _mock_query(g)
        gen = HypothesisGenerator(
            query=q, router=_mock_router(),
            cheap_provider=_mock_provider({}),
            mid_provider=_mock_provider({}),
            strong_provider=_mock_provider({}),
            language="python",
        )
        md = gen._read_function_source("big_func", g)
        assert md is not None
        # Truncated to 1500 chars
        assert len(md) < 2000


# ── generate_from_seeds ───────────────────────────────────────────────────────


class TestGenerateFromSeeds:
    async def test_empty_inputs_returns_empty(self) -> None:
        gen = HypothesisGenerator(
            query=_mock_query(nx.MultiDiGraph()),
            router=_mock_router(),
            cheap_provider=_mock_provider({}),
            mid_provider=_mock_provider({}),
            strong_provider=_mock_provider({}),
            language="python",
        )
        result = await gen.generate_from_seeds([], None)
        assert result == []

    async def test_generates_from_seed_functions(self) -> None:
        g = _build_seed_graph()
        cheap = _mock_provider({"hypotheses": [
            {"vuln_type": "sql_injection", "severity": "high",
             "title": "SQLi in do_query",
             "description": "Direct SQL execution without parameterisation.",
             "confidence": 0.9, "cwe_id": "CWE-89",
             "source_location": "app.py:10",
             "sink_location": "app.py:11",
             "sanitizer_exists": False},
        ]})
        gen = HypothesisGenerator(
            query=_mock_query(g),
            router=_mock_router(),
            cheap_provider=cheap,
            mid_provider=_mock_provider({}),
            strong_provider=_mock_provider({}),
            language="python",
        )
        result = await gen.generate_from_seeds(["do_query"])
        assert len(result) == 1
        h = result[0]
        assert h.vuln_type == "sql_injection"
        assert h.severity == "high"

    async def test_generates_from_sink_discoveries(self) -> None:
        g = nx.MultiDiGraph()
        cheap = _mock_provider({"hypotheses": [
            {"vuln_type": "command_injection", "severity": "critical",
             "title": "Command injection in handle_upload",
             "description": "Unsanitised filename passed to os.system.",
             "confidence": 0.85, "cwe_id": "CWE-78",
             "source_location": "upload.py:5",
             "sink_location": "upload.py:7",
             "sanitizer_exists": False},
        ]})
        gen = HypothesisGenerator(
            query=_mock_query(g),
            router=_mock_router(),
            cheap_provider=cheap,
            mid_provider=_mock_provider({}),
            strong_provider=_mock_provider({}),
            language="python",
        )
        discoveries = [
            {"sink_name": "os.system", "sink_file": "upload.py",
             "sink_line": 7, "source_names": ["file.filename"],
             "taint_category": "", "confidence": "high"},
        ]
        result = await gen.generate_from_seeds(
            seed_functions=[],
            sink_discoveries=discoveries,
        )
        assert len(result) == 1
        assert result[0].vuln_type == "command_injection"

    async def test_merge_seeds_and_discoveries(self) -> None:
        """Both seed functions AND sink discoveries produce merged hypotheses."""
        g = _build_seed_graph()
        cheap = _mock_provider({"hypotheses": [
            {"vuln_type": "sql_injection", "severity": "high",
             "title": "SQLi",
             "description": "desc.",
             "confidence": 0.8, "cwe_id": "CWE-89",
             "source_location": "app.py:10",
             "sink_location": "app.py:11",
             "sanitizer_exists": False},
        ]})
        gen = HypothesisGenerator(
            query=_mock_query(g),
            router=_mock_router(),
            cheap_provider=cheap,
            mid_provider=_mock_provider({}),
            strong_provider=_mock_provider({}),
            language="python",
        )
        result = await gen.generate_from_seeds(
            seed_functions=["do_query"],
            sink_discoveries=[{"sink_name": "exec", "sink_file": "a.py",
                                "sink_line": 1, "source_names": [],
                                "taint_category": "", "confidence": "low"}],
        )
        assert len(result) == 1  # single LLM call returns 1 hypothesis

    async def test_llm_failure_returns_empty(self) -> None:
        g = _build_seed_graph()
        cheap = MagicMock()
        cheap.generate_structured = AsyncMock(
            side_effect=RuntimeError("API error"))
        gen = HypothesisGenerator(
            query=_mock_query(g),
            router=_mock_router(),
            cheap_provider=cheap,
            mid_provider=_mock_provider({}),
            strong_provider=_mock_provider({}),
            language="python",
        )
        result = await gen.generate_from_seeds(["do_query"])
        assert result == []

    async def test_produces_multiple_hypotheses(self) -> None:
        g = _build_seed_graph()
        cheap = _mock_provider({"hypotheses": [
            {"vuln_type": "sql_injection", "severity": "high",
             "title": "SQLi", "description": "d1.",
             "confidence": 0.9, "cwe_id": "CWE-89",
             "source_location": "a.py:1", "sink_location": "a.py:2",
             "sanitizer_exists": False},
            {"vuln_type": "info_disclosure", "severity": "medium",
             "title": "Info leak", "description": "d2.",
             "confidence": 0.7, "cwe_id": "CWE-200",
             "source_location": "a.py:1", "sink_location": "a.py:2",
             "sanitizer_exists": False},
        ]})
        gen = HypothesisGenerator(
            query=_mock_query(g),
            router=_mock_router(),
            cheap_provider=cheap,
            mid_provider=_mock_provider({}),
            strong_provider=_mock_provider({}),
            language="python",
        )
        result = await gen.generate_from_seeds(["do_query"])
        assert len(result) == 2

    async def test_truncates_discoveries_at_15(self) -> None:
        """More than 15 discoveries → truncated to avoid prompt overflow."""
        g = nx.MultiDiGraph()
        cheap = _mock_provider({"hypotheses": []})
        gen = HypothesisGenerator(
            query=_mock_query(g),
            router=_mock_router(),
            cheap_provider=cheap,
            mid_provider=_mock_provider({}),
            strong_provider=_mock_provider({}),
            language="python",
        )
        discoveries = [
            {"sink_name": f"sink_{i}", "sink_file": "a.py",
             "sink_line": i, "source_names": ["x"],
             "taint_category": "", "confidence": "medium"}
            for i in range(25)
        ]
        # Should not raise — 25 discoveries truncated to 15
        result = await gen.generate_from_seeds(
            seed_functions=[], sink_discoveries=discoveries,
        )
        assert result == []


# ── Orchestrator phase integration ────────────────────────────────────────────


class TestPhaseHypothesisGenSeedFeedback:
    async def test_calls_generate_from_seeds_when_seeds_exist(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        gen = MagicMock()
        gen.generate = AsyncMock(return_value=[])
        gen.generate_from_seeds = AsyncMock(return_value=[])

        orch = Orchestrator(hypothesis_generator=gen)
        state = PipelineState(
            session_id="test-sf",
            current_phase=PhaseName.HYPOTHESIS_GEN,
        )
        state.phase_states["annotated_paths"] = []
        state.phase_states["saturation_seeds"] = ["do_query", "handle_upload"]

        await orch._phase_hypothesis_gen(state)

        gen.generate_from_seeds.assert_called_once()
        call_kwargs = gen.generate_from_seeds.call_args.kwargs
        assert "do_query" in call_kwargs["seed_functions"]

    async def test_calls_generate_from_seeds_with_discoveries(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        gen = MagicMock()
        gen.generate = AsyncMock(return_value=[])
        gen.generate_from_seeds = AsyncMock(return_value=[])

        from hyqagent.scanner.reverse_sink import ReverseSinkDiscovery, ReverseSinkResult

        orch = Orchestrator(hypothesis_generator=gen)
        state = PipelineState(
            session_id="test-sf-d",
            current_phase=PhaseName.HYPOTHESIS_GEN,
        )
        state.phase_states["annotated_paths"] = []
        disc = ReverseSinkDiscovery(
            sink_name="exec_cmd", sink_file="app.py",
            sink_line=42, sink_source="exec(cmd)",
            source_names=["stdin"], taint_category="",
            confidence="high",
        )
        state.phase_states["reverse_sink_result"] = ReverseSinkResult(
            total_sinks_checked=5, discoveries=[disc],
        )

        await orch._phase_hypothesis_gen(state)

        gen.generate_from_seeds.assert_called_once()
        call_kwargs = gen.generate_from_seeds.call_args.kwargs
        discoveries = call_kwargs["sink_discoveries"]
        assert len(discoveries) == 1
        assert discoveries[0]["sink_name"] == "exec_cmd"

    async def test_merges_seed_and_annotated_hypotheses(self) -> None:
        from hyqagent.scanner.hypothesis import Hypothesis
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        gen = MagicMock()
        gen.generate = AsyncMock(return_value=[
            Hypothesis(id="h-1", vuln_type="xss", severity="medium",
                       title="XSS", description="d",
                       confidence=0.7, cwe_id="CWE-79",
                       source_location="a.py:1", sink_location="a.py:2",
                       evidence="<script>", reasoning="user input in HTML"),
        ])
        gen.generate_from_seeds = AsyncMock(return_value=[
            Hypothesis(id="h-2", vuln_type="sql_injection", severity="high",
                       title="SQLi from seed", description="d",
                       confidence=0.85, cwe_id="CWE-89",
                       source_location="a.py:10", sink_location="a.py:11",
                       evidence="' OR 1=1", reasoning="parameterised"),
        ])

        orch = Orchestrator(hypothesis_generator=gen)
        state = PipelineState(
            session_id="test-sf-merge",
            current_phase=PhaseName.HYPOTHESIS_GEN,
        )
        state.phase_states["annotated_paths"] = [MagicMock()]
        state.phase_states["saturation_seeds"] = ["do_query"]

        await orch._phase_hypothesis_gen(state)

        hyps = state.phase_states.get("hypotheses", [])
        assert len(hyps) == 2
        vuln_types = {h.vuln_type for h in hyps}
        assert "xss" in vuln_types
        assert "sql_injection" in vuln_types

    async def test_no_seeds_skips_feedback(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        gen = MagicMock()
        gen.generate = AsyncMock(return_value=[])
        gen.generate_from_seeds = AsyncMock(return_value=[])

        orch = Orchestrator(hypothesis_generator=gen)
        state = PipelineState(
            session_id="test-sf-noseed",
            current_phase=PhaseName.HYPOTHESIS_GEN,
        )
        state.phase_states["annotated_paths"] = [MagicMock()]

        await orch._phase_hypothesis_gen(state)

        # generate_from_seeds should NOT be called when no seeds/discoveries
        gen.generate_from_seeds.assert_not_called()

    async def test_seed_feedback_failure_does_not_crash(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        gen = MagicMock()
        gen.generate = AsyncMock(return_value=[])
        gen.generate_from_seeds = AsyncMock(
            side_effect=RuntimeError("LLM down"))

        orch = Orchestrator(hypothesis_generator=gen)
        state = PipelineState(
            session_id="test-sf-fail",
            current_phase=PhaseName.HYPOTHESIS_GEN,
        )
        state.phase_states["annotated_paths"] = [MagicMock()]
        state.phase_states["saturation_seeds"] = ["f1"]

        # Should not raise
        await orch._phase_hypothesis_gen(state)

        # Annotated hypotheses should still be present (from gen.generate)
        assert "hypotheses" in state.phase_states
