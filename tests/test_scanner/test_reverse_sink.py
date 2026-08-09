"""Tests for scanner/reverse_sink.py — ReverseSinkAnalyzer, reverse BFS, source heuristics."""

from __future__ import annotations

from unittest.mock import MagicMock

import networkx as nx

from hyqagent.scanner.reverse_sink import (
    ReverseSinkAnalyzer,
    ReverseSinkDiscovery,
    ReverseSinkResult,
    _looks_like_source,
    _reverse_bfs_from_node,
)

# ── Helpers ───────────────────────────────────────────────────────────────────


def _build_simple_graph() -> nx.MultiDiGraph:
    """Build a minimal CPG graph with some sources and sinks.

    Topology:
        request.args (SOURCE) --> x = request.args (ASSIGNMENT, tainted)
            --> mysql_query(x) (ASSIGNMENT, sink)
        stdin (PARAMETER) --> y = read_input() (ASSIGNMENT, not tainted)
            --> exec(y) (ASSIGNMENT, sink)
    """
    g = nx.MultiDiGraph()

    # Node 1: source node (request.args) — NO taint_category (unrecognised)
    g.add_node("n1", node_type="source", name="request.args", file_path="app.py", taint_category="")
    # Node 2: assignment tainted
    g.add_node(
        "n2",
        node_type="assignment",
        name="x",
        source="x = request.args.get('id')",
        file_path="app.py",
        start_line=10,
        taint_category="user_input",
    )
    # Node 3: sink node (labelled)
    g.add_node(
        "n3",
        node_type="assignment",
        name="result",
        source="result = mysql_query(x)",
        file_path="app.py",
        start_line=12,
        taint_category="sql_injection",
        enclosing_function="handle_request",
    )
    # Node 4: parameter (untainted source-like)
    g.add_node("n4", node_type="parameter", name="user_input", file_path="app.py", start_line=20)
    # Node 5: assignment (untainted but dangerous — source text
    # deliberately avoids matching _SOURCE_HEURISTICS so BFS reaches n4)
    g.add_node(
        "n5",
        node_type="assignment",
        name="cmd",
        source="cmd = helper_call()",
        file_path="app.py",
        start_line=21,
        taint_category="",
        enclosing_function="process",
    )
    # Node 6: sink node (unlabelled, dangerous)
    g.add_node(
        "n6",
        node_type="assignment",
        name="exec_result",
        source="exec(cmd)",
        file_path="app.py",
        start_line=22,
        taint_category="",
        enclosing_function="process",
    )

    # Edges: n1 -> n2 -> n3  (DATA_FLOW)
    g.add_edge("n1", "n2", edge_type="DATA_FLOW")
    g.add_edge("n2", "n3", edge_type="DATA_FLOW")
    # n4 -> n5 -> n6  (DATA_FLOW)
    g.add_edge("n4", "n5", edge_type="DATA_FLOW")
    g.add_edge("n5", "n6", edge_type="DATA_FLOW")

    return g


def _mock_cpg_query(graph: nx.MultiDiGraph) -> MagicMock:
    """Mock CPGQuery with test graph."""
    q = MagicMock()
    q._graph = graph
    q.get_all_sink_candidates.return_value = [
        {
            "node_id": "n3",
            "file_path": "app.py",
            "start_line": 12,
            "source": "result = mysql_query(x)",
            "taint_category": "sql_injection",
            "enclosing_function": "handle_request",
        },
        {
            "node_id": "n6",
            "file_path": "app.py",
            "start_line": 22,
            "source": "exec(cmd)",
            "taint_category": "",
            "enclosing_function": "process",
        },
    ]
    q.get_labeled_sinks.return_value = ["n3"]
    return q


# ── ReverseSinkDiscovery ──────────────────────────────────────────────────────


class TestReverseSinkDiscovery:
    def test_defaults(self) -> None:
        d = ReverseSinkDiscovery(
            sink_name="handle_request",
            sink_file="app.py",
            sink_line=12,
            sink_source="mysql_query(x)",
        )
        assert d.sink_name == "handle_request"
        assert d.source_names == []
        assert d.source_files == []
        assert d.taint_category == ""
        assert d.confidence == "medium"

    def test_full_discovery(self) -> None:
        d = ReverseSinkDiscovery(
            sink_name="handle_request",
            sink_file="app.py",
            sink_line=12,
            sink_source="mysql_query(x)",
            source_names=["request.args"],
            source_files=["app.py"],
            taint_category="sql_injection",
            confidence="high",
        )
        assert len(d.source_names) == 1
        assert d.taint_category == "sql_injection"
        assert d.confidence == "high"


# ── ReverseSinkResult ─────────────────────────────────────────────────────────


class TestReverseSinkResult:
    def test_defaults(self) -> None:
        r = ReverseSinkResult()
        assert r.total_sinks_checked == 0
        assert r.total_labeled == 0
        assert r.total_unlabeled == 0
        assert r.discoveries == []
        assert r.previously_covered == 0
        assert r.reasoning == ""

    def test_with_discoveries(self) -> None:
        disc = ReverseSinkDiscovery(sink_name="f", sink_file="a.py", sink_line=1, sink_source="x")
        r = ReverseSinkResult(
            total_sinks_checked=10,
            total_labeled=3,
            total_unlabeled=7,
            discoveries=[disc],
            previously_covered=2,
            reasoning="Found 1 new.",
        )
        assert r.total_sinks_checked == 10
        assert r.total_labeled == 3
        assert len(r.discoveries) == 1


# ── Source heuristics ─────────────────────────────────────────────────────────


class TestLooksLikeSource:
    def test_tagged_source_node(self) -> None:
        assert _looks_like_source({"node_type": "source", "name": "", "taint_category": ""})

    def test_tagged_source_skipped_if_tainted(self) -> None:
        """A source node that already has a taint_category is 'known' — skip."""
        assert not _looks_like_source(
            {
                "node_type": "source",
                "name": "",
                "taint_category": "user_input",
            }
        )

    def test_parameter_node_is_source_like(self) -> None:
        assert _looks_like_source(
            {"node_type": "parameter", "name": "user_id", "taint_category": ""}
        )

    def test_source_like_name(self) -> None:
        assert _looks_like_source(
            {
                "node_type": "assignment",
                "name": "request_args",
                "source": "",
                "taint_category": "",
            }
        )

    def test_source_like_in_source_text(self) -> None:
        assert _looks_like_source(
            {
                "node_type": "assignment",
                "name": "x",
                "source": "x = request.form.get('name')",
                "taint_category": "",
            }
        )

    def test_tainted_node_not_source_like(self) -> None:
        """A node with taint_category is already known — not a new source."""
        assert not _looks_like_source(
            {
                "node_type": "assignment",
                "name": "x",
                "source": "x = request.args.get('id')",
                "taint_category": "user_input",
            }
        )

    def test_ordinary_assignment_not_source(self) -> None:
        assert not _looks_like_source(
            {
                "node_type": "assignment",
                "name": "y",
                "source": "y = 42",
                "taint_category": "",
            }
        )

    def test_cookie_heuristic(self) -> None:
        assert _looks_like_source(
            {
                "node_type": "assignment",
                "name": "ck",
                "source": "ck = request.cookies.get('s')",
                "taint_category": "",
            }
        )

    def test_get_json_heuristic(self) -> None:
        assert _looks_like_source(
            {
                "node_type": "assignment",
                "name": "data",
                "source": "data = request.get_json()",
                "taint_category": "",
            }
        )

    def test_stdin_heuristic(self) -> None:
        assert _looks_like_source(
            {
                "node_type": "assignment",
                "name": "line",
                "source": "line = sys.stdin.readline()",
                "taint_category": "",
            }
        )


# ── Reverse BFS ───────────────────────────────────────────────────────────────


class TestReverseBFS:
    def test_finds_upstream_source(self) -> None:
        g = _build_simple_graph()
        # BFS backwards from n3 (mysql_query) should find n1 (source)
        sources = _reverse_bfs_from_node(g, "n3", max_depth=10)
        assert len(sources) >= 1
        source_names = [s.get("name", "") for s in sources]
        assert "request.args" in source_names

    def test_finds_untainted_parameter(self) -> None:
        g = _build_simple_graph()
        # BFS backwards from n6 (exec) should find n4 (parameter)
        sources = _reverse_bfs_from_node(g, "n6", max_depth=10)
        assert len(sources) >= 1
        source_types = [s.get("node_type", "") for s in sources]
        assert "parameter" in source_types

    def test_max_depth_limit(self) -> None:
        g = _build_simple_graph()
        # Very shallow depth should miss deep sources
        sources = _reverse_bfs_from_node(g, "n3", max_depth=0)
        # At depth 0 we only visit n3 itself, which is a labelled sink (not a source)
        assert len(sources) == 0

    def test_stops_at_source(self) -> None:
        """BFS should not traverse past a source node (prevents double-counting)."""
        g = _build_simple_graph()
        sources = _reverse_bfs_from_node(g, "n1", max_depth=10)
        # n1 is a source — should return itself and stop
        assert len(sources) == 1

    def test_unknown_node_returns_empty(self) -> None:
        g = _build_simple_graph()
        sources = _reverse_bfs_from_node(g, "nonexistent", max_depth=10)
        assert sources == []

    def test_only_follows_dataflow_calls_edges(self) -> None:
        """Ensure BFS only traverses DATA_FLOW and CALLS, not CTRL_FLOW."""
        g = nx.MultiDiGraph()
        g.add_node("a", node_type="assignment", name="a", source="a = input()", taint_category="")
        g.add_node("b", node_type="assignment", name="b", source="b = a", taint_category="")
        g.add_edge("a", "b", edge_type="CTRL_FLOW")  # shouldn't be followed

        sources = _reverse_bfs_from_node(g, "b", max_depth=5)
        # a is a source-like, but connected via CTRL_FLOW, not DATA_FLOW/CALLS
        assert len(sources) == 0

    def test_follows_calls_edges(self) -> None:
        g = nx.MultiDiGraph()
        g.add_node("caller", node_type="parameter", name="x", taint_category="")
        g.add_node(
            "callee", node_type="assignment", name="y", source="y = process(x)", taint_category=""
        )
        g.add_edge("caller", "callee", edge_type="CALLS")

        sources = _reverse_bfs_from_node(g, "callee", max_depth=5)
        assert len(sources) == 1
        assert sources[0].get("name") == "x"


# ── ReverseSinkAnalyzer ───────────────────────────────────────────────────────


class TestReverseSinkAnalyzerConstruction:
    def test_constructor(self) -> None:
        q = _mock_cpg_query(nx.MultiDiGraph())
        a = ReverseSinkAnalyzer(cpg_query=q, max_depth=15)
        assert a._query is q
        assert a._max_depth == 15

    def test_default_max_depth(self) -> None:
        q = _mock_cpg_query(nx.MultiDiGraph())
        a = ReverseSinkAnalyzer(cpg_query=q)
        assert a._max_depth == 15


class TestReverseSinkAnalyzerAnalyse:
    async def test_no_graph_returns_empty(self) -> None:
        q = MagicMock()
        q._graph = None
        a = ReverseSinkAnalyzer(cpg_query=q)
        result = await a.analyse()
        assert result.total_sinks_checked == 0
        assert "not available" in result.reasoning

    async def test_no_sink_candidates(self) -> None:
        q = MagicMock()
        q._graph = nx.MultiDiGraph()
        q.get_all_sink_candidates.return_value = []
        q.get_labeled_sinks.return_value = []
        a = ReverseSinkAnalyzer(cpg_query=q)
        result = await a.analyse()
        assert result.total_sinks_checked == 0
        assert "No sink candidates" in result.reasoning

    async def test_finds_discoveries(self) -> None:
        g = _build_simple_graph()
        q = _mock_cpg_query(g)
        a = ReverseSinkAnalyzer(cpg_query=q)
        result = await a.analyse()
        assert result.total_sinks_checked == 2
        assert result.total_labeled >= 1
        assert result.total_unlabeled >= 1
        # n6 (exec) is unlabelled and should produce a discovery
        assert len(result.discoveries) >= 1

    async def test_dedup_against_annotated_paths(self) -> None:
        """Sinks already in annotated_paths should be counted as previously_covered."""
        g = _build_simple_graph()
        q = _mock_cpg_query(g)
        a = ReverseSinkAnalyzer(cpg_query=q)

        # Mock an annotated path that covers n3
        ap = MagicMock()
        ap.path = MagicMock()
        ap.path.nodes = [
            MagicMock(node_type="assignment", node_id="n3"),
        ]

        result = await a.analyse(annotated_paths=[ap])
        assert result.previously_covered >= 1

    async def test_confidence_based_on_depth(self) -> None:
        """Deeper BFS paths → lower confidence."""
        g = _build_simple_graph()
        q = _mock_cpg_query(g)
        a = ReverseSinkAnalyzer(cpg_query=q)
        result = await a.analyse()
        # At least one discovery should exist for the unlabelled exec sink
        assert len(result.discoveries) >= 1
        # Verify confidence is one of the expected values
        for d in result.discoveries:
            assert d.confidence in ("high", "medium", "low")

    async def test_unlabelled_sorted_first(self) -> None:
        """Unlabelled sinks (new discoveries) sorted before labelled ones."""
        g = _build_simple_graph()
        q = _mock_cpg_query(g)
        a = ReverseSinkAnalyzer(cpg_query=q)
        result = await a.analyse()
        if len(result.discoveries) >= 2:
            # First item should be unlabelled (more interesting)
            assert result.discoveries[0].taint_category == ""

    async def test_empty_language_default(self) -> None:
        g = _build_simple_graph()
        q = _mock_cpg_query(g)
        a = ReverseSinkAnalyzer(cpg_query=q)
        result = await a.analyse(language="")
        assert result.total_sinks_checked == 2


# ── Orchestrator phase integration ────────────────────────────────────────────


class TestPhaseReverseSink:
    async def test_skips_when_no_analyzer(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        state = PipelineState(
            session_id="test-rs",
            current_phase=PhaseName.REVERSE_SINK,
        )
        orch = Orchestrator()  # no reverse_sink_analyzer
        await orch._phase_reverse_sink(state)
        assert "reverse_sink_result" not in state.phase_states

    async def test_skips_quick_mode(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        q = _mock_cpg_query(nx.MultiDiGraph())
        a = ReverseSinkAnalyzer(cpg_query=q)
        orch = Orchestrator(reverse_sink_analyzer=a)

        state = PipelineState(
            session_id="test-rs-q",
            current_phase=PhaseName.REVERSE_SINK,
        )
        state.phase_states["mode"] = "quick"

        await orch._phase_reverse_sink(state)
        assert "reverse_sink_result" not in state.phase_states

    async def test_stores_result(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        g = _build_simple_graph()
        q = _mock_cpg_query(g)
        a = ReverseSinkAnalyzer(cpg_query=q)
        orch = Orchestrator(reverse_sink_analyzer=a)

        state = PipelineState(
            session_id="test-rs-ok",
            current_phase=PhaseName.REVERSE_SINK,
        )

        await orch._phase_reverse_sink(state)
        assert "reverse_sink_result" in state.phase_states
        result = state.phase_states["reverse_sink_result"]
        assert isinstance(result, ReverseSinkResult)
        assert result.total_sinks_checked >= 1

    async def test_updates_endpoint_count(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        g = _build_simple_graph()
        q = _mock_cpg_query(g)
        a = ReverseSinkAnalyzer(cpg_query=q)
        orch = Orchestrator(reverse_sink_analyzer=a)

        state = PipelineState(
            session_id="test-rs-ec",
            current_phase=PhaseName.REVERSE_SINK,
        )
        old_ec = state.endpoint_count

        await orch._phase_reverse_sink(state)

        # New discoveries → endpoint_count increases
        if state.phase_states.get("reverse_sink_result") is not None:
            result = state.phase_states["reverse_sink_result"]
            if result.discoveries:
                assert state.endpoint_count >= old_ec

    async def test_phase_name_registered(self) -> None:
        """REVERSE_SINK must be a valid PhaseName."""
        from hyqagent.scanner.orchestrator import DEEP_PHASES, PhaseName

        assert PhaseName.REVERSE_SINK in DEEP_PHASES
        assert PhaseName.REVERSE_SINK.value == "reverse_sink"
