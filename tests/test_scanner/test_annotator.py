"""Tests for scanner/annotator.py — PathAnnotator + CDG sanitizer verification."""

from __future__ import annotations

import networkx as nx

from hyqagent.cpg.graph import (
    EDGE_CTRL_FLOW,
    EDGE_DATA_FLOW,
    NODE_ASSIGNMENT,
    NODE_BASIC_BLOCK,
)
from hyqagent.cpg.query import CPGQuery, GraphNode, GraphPath
from hyqagent.scanner.annotator import (
    AnnotatedPath,
    PathAnnotator,
    PathLabel,
    SanitizerStatus,
)

# ── Stubs ──────────────────────────────────────────────────────────────────


class _FakeCategory:
    """Minimal category stub for rules_for()."""

    def __init__(self, sanitizers=None):
        self.sanitizers = sanitizers or []


class _FakeRules:
    """Minimal rules stub for rules_for()."""

    def __init__(self, sanitizers=None):
        self.categories = {
            "sql_injection": _FakeCategory(sanitizers=sanitizers or []),
        }


class _FakeTaintLoader:
    """Minimal stub for TaintRuleLoader."""

    def __init__(self, sources=None, sinks=None, sanitizers=None):
        self._sources = sources or []
        self._sinks = sinks or []
        self._sanitizers = sanitizers or ["html.escape", "int("]
        self.available_languages = ["python"]

    def all_sinks(self, language: str) -> list[str]:
        return list(self._sinks)

    def all_sources(self, language: str) -> list[str]:
        return list(self._sources)

    def match_source(self, language: str, text: str) -> str | None:
        for pat in self._sources:
            if pat.lower() in text.lower():
                return "sql_injection"
        return None

    def match_sink(self, language: str, text: str) -> str | None:
        for pat in self._sinks:
            if pat.lower() in text.lower():
                return "sql_injection"
        return None

    def rules_for(self, language: str):
        return _FakeRules(sanitizers=self._sanitizers)


class _FakeSinkDiscoverer:
    def discover_heuristic_sinks(self, language, score_threshold=60):
        return []

    def is_potentially_dangerous(self, node_id, language=""):
        return False, 0


class _FakeSourceChecker:
    def find_exposed_no_source(self):
        return []

    def find_uncovered_sinks(self, language):
        return []


# ── Helpers ────────────────────────────────────────────────────────────────


def _make_diamond_cfg_graph() -> nx.MultiDiGraph:
    """Build a diamond CFG with a sanitizer in one branch and a sink in the merge.

    CFG shape:
        entry ──► cond ──true──► sanitize_block ──► merge ──► exit
                      │                              ↑
                      └──false──► nosanitize_block ──┘

    The sanitize_block should be CD on 'cond'.
    The merge block should NOT be CD on 'cond' (it post-dominates cond).
    """
    g = nx.MultiDiGraph()

    # Basic blocks
    blocks = {
        "entry": ("entry", 1, 1),
        "cond": ("normal", 4, 5),
        "sanitize_block": ("normal", 7, 8),
        "nosanitize_block": ("normal", 10, 11),
        "merge": ("normal", 13, 14),
        "exit": ("exit", 16, 16),
    }

    for bid, (btype, start, end) in blocks.items():
        g.add_node(
            bid,
            node_type=NODE_BASIC_BLOCK,
            enclosing_function="handler",
            file_path="app.py",
            start_line=start,
            end_line=end,
            block_type=btype,
        )

    # CFG edges
    edges = [
        ("entry", "cond", "fallthrough"),
        ("cond", "sanitize_block", "branch_true"),
        ("cond", "nosanitize_block", "branch_false"),
        ("sanitize_block", "merge", "fallthrough"),
        ("nosanitize_block", "merge", "fallthrough"),
        ("merge", "exit", "fallthrough"),
    ]
    for src, dst, kind in edges:
        g.add_edge(src, dst, edge_type=EDGE_CTRL_FLOW, ctrl_type=kind)

    # Add a DATA_FLOW edge from function to entry (so CFG is "connected" to CPG)
    g.add_node("fn_handler", node_type="function", name="handler", file_path="app.py", start_line=1)
    g.add_edge("fn_handler", "entry", edge_type=EDGE_DATA_FLOW)

    return g


def _make_mini_taint_graph(with_sanitizer: bool = True) -> nx.MultiDiGraph:
    """Build a small graph with a source→sink data-flow path.

    Optionally includes a sanitizer node in the path.
    """
    g = nx.MultiDiGraph()

    # Source
    g.add_node(
        "src",
        node_type=NODE_ASSIGNMENT,
        file_path="app.py",
        enclosing_function="handler",
        start_line=2,
        source="request.args.get('id')",
        taint_category="sql_injection",
    )

    if with_sanitizer:
        # Sanitizer
        g.add_node(
            "san",
            node_type=NODE_ASSIGNMENT,
            file_path="app.py",
            enclosing_function="handler",
            start_line=8,
            source="int(user_input)",
            taint_category="sql_injection",
        )
        g.add_edge("src", "san", edge_type=EDGE_DATA_FLOW)
        g.add_edge("san", "sink", edge_type=EDGE_DATA_FLOW)
    else:
        g.add_edge("src", "sink", edge_type=EDGE_DATA_FLOW)

    # Sink
    g.add_node(
        "sink",
        node_type=NODE_ASSIGNMENT,
        file_path="app.py",
        enclosing_function="handler",
        start_line=12,
        source="cursor.execute(sql)",
        taint_category="sql_injection",
    )

    return g


# ── PathLabel enum ─────────────────────────────────────────────────────────


class TestPathLabel:
    def test_all_10_labels_present(self):
        """Ensure we define all 10 labels from the plan."""
        labels = list(PathLabel)
        assert len(labels) >= 10

    def test_label_uniqueness(self):
        values = [l.value for l in PathLabel]
        assert len(values) == len(set(values))


class TestSanitizerStatus:
    def test_status_values(self):
        statuses = list(SanitizerStatus)
        assert len(statuses) >= 4  # must_execute, conditional, dead_code, unknown


# ── PathAnnotator ──────────────────────────────────────────────────────────


class TestPathAnnotator:
    def test_annotate_empty_graph_returns_empty(self):
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        annotator = PathAnnotator(query, tl, _FakeSinkDiscoverer(), _FakeSourceChecker())
        result = annotator.annotate("python")
        assert isinstance(result, list)

    def test_label_path_confirmed_taint_no_sanitizer(self):
        g = _make_mini_taint_graph(with_sanitizer=False)
        query = CPGQuery(g)
        tl = _FakeTaintLoader(
            sources=["request.args.get"],
            sinks=[".execute("],
        )
        annotator = PathAnnotator(query, tl, _FakeSinkDiscoverer(), _FakeSourceChecker())

        # Build a path manually
        node1 = GraphNode(
            node_id="src",
            node_type="assignment",
            location="app.py:2",
            source="request.args.get('id')",
        )
        node2 = GraphNode(
            node_id="sink",
            node_type="assignment",
            location="app.py:12",
            source="cursor.execute(sql)",
        )
        path = GraphPath(nodes=[node1, node2], edges=["DATA_FLOW"])

        label = annotator._label_path(path, "python")
        assert label == PathLabel.CONFIRMED_TAINT

    def test_label_path_sanitized_without_cfg(self):
        """When a sanitizer is present but no CFG data exists, treat as
        CONDITIONAL_SANITIZED (conservative default).
        """
        g = _make_mini_taint_graph(with_sanitizer=True)
        query = CPGQuery(g)
        tl = _FakeTaintLoader(
            sources=["request.args.get"],
            sinks=[".execute("],
        )
        annotator = PathAnnotator(query, tl, _FakeSinkDiscoverer(), _FakeSourceChecker())

        node1 = GraphNode(
            node_id="src",
            node_type="assignment",
            location="app.py:2",
            source="request.args.get('id')",
        )
        node2 = GraphNode(
            node_id="san", node_type="assignment", location="app.py:8", source="int(user_input)"
        )
        node3 = GraphNode(
            node_id="sink",
            node_type="assignment",
            location="app.py:12",
            source="cursor.execute(sql)",
        )
        path = GraphPath(nodes=[node1, node2, node3], edges=["DATA_FLOW", "DATA_FLOW"])

        label = annotator._label_path(path, "python")
        # Without CFG, sanitizer verification returns UNKNOWN → CONDITIONAL_SANITIZED
        assert label == PathLabel.CONDITIONAL_SANITIZED

    def test_verify_sanitizer_dominance_with_diamond_cfg(self):
        """Diamond CFG: sanitizer is in the branch_true block.

        verify should detect that sanitize_block is CD on 'cond'.
        """
        g = _make_diamond_cfg_graph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        annotator = PathAnnotator(query, tl, _FakeSinkDiscoverer(), _FakeSourceChecker())

        # Build a path where the sanitizer is in sanitize_block (line 7-8)
        node1 = GraphNode(
            node_id="src",
            node_type="assignment",
            location="app.py:7",
            source="html.escape(user_input)",
        )
        node2 = GraphNode(
            node_id="sink",
            node_type="assignment",
            location="app.py:14",
            source="cursor.execute(sql)",
        )
        path = GraphPath(nodes=[node1, node2], edges=["DATA_FLOW"])

        status = annotator._verify_sanitizer_dominance(path, "python")
        assert status == SanitizerStatus.CONDITIONAL

    def test_verify_sanitizer_dominance_must_execute(self):
        """Linear CFG: sanitizer in a non-branch block → MUST_EXECUTE."""
        g = nx.MultiDiGraph()

        # Linear CFG: entry → sanitize → merge → exit (no branching)
        blocks = [
            ("entry", "entry", 1, 1),
            ("san_block", "normal", 3, 4),
            ("merge", "normal", 6, 7),
            ("exit", "exit", 9, 9),
        ]
        for bid, btype, start, end in blocks:
            g.add_node(
                bid,
                node_type=NODE_BASIC_BLOCK,
                enclosing_function="handler",
                file_path="app.py",
                start_line=start,
                end_line=end,
                block_type=btype,
            )

        edges = [
            ("entry", "san_block", "fallthrough"),
            ("san_block", "merge", "fallthrough"),
            ("merge", "exit", "fallthrough"),
        ]
        for src, dst, kind in edges:
            g.add_edge(src, dst, edge_type=EDGE_CTRL_FLOW, ctrl_type=kind)

        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        annotator = PathAnnotator(query, tl, _FakeSinkDiscoverer(), _FakeSourceChecker())

        node1 = GraphNode(
            node_id="src", node_type="assignment", location="app.py:4", source="int(user_input)"
        )
        node2 = GraphNode(
            node_id="sink",
            node_type="assignment",
            location="app.py:7",
            source="cursor.execute(sql)",
        )
        path = GraphPath(nodes=[node1, node2], edges=["DATA_FLOW"])

        status = annotator._verify_sanitizer_dominance(path, "python")
        assert status == SanitizerStatus.MUST_EXECUTE

    def test_verify_sanitizer_dominance_no_sanitizers_in_path(self):
        """When there are no sanitizer patterns on the path, return UNKNOWN."""
        g = _make_diamond_cfg_graph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        annotator = PathAnnotator(query, tl, _FakeSinkDiscoverer(), _FakeSourceChecker())

        # Nodes with source text that does NOT match any sanitizer pattern
        node1 = GraphNode(
            node_id="src",
            node_type="assignment",
            location="app.py:1",
            source="x = request.args.get('id')",
        )
        node2 = GraphNode(
            node_id="sink",
            node_type="assignment",
            location="app.py:14",
            source="result = cursor.fetchall()",
        )
        path = GraphPath(nodes=[node1, node2], edges=["DATA_FLOW"])

        status = annotator._verify_sanitizer_dominance(path, "python")
        # No sanitizer pattern found in either node → UNKNOWN
        assert status == SanitizerStatus.UNKNOWN

    def test_get_known_categories(self):
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        annotator = PathAnnotator(query, tl, _FakeSinkDiscoverer(), _FakeSourceChecker())
        cats = annotator._get_known_categories("python")
        assert isinstance(cats, list)


# ── AnnotatedPath dataclass ────────────────────────────────────────────────


class TestAnnotatedPath:
    def test_fields(self):
        node = GraphNode(node_id="n1")
        path = GraphPath(nodes=[node])
        ap = AnnotatedPath(path=path, label=PathLabel.CONFIRMED_TAINT)
        assert ap.label == PathLabel.CONFIRMED_TAINT
        assert ap.sanitizer_status is None
        assert ap.metadata == {}

    def test_with_sanitizer_status(self):
        node = GraphNode(node_id="n1")
        path = GraphPath(nodes=[node])
        ap = AnnotatedPath(
            path=path,
            label=PathLabel.SANITIZED_TAINT,
            sanitizer_status=SanitizerStatus.MUST_EXECUTE,
            metadata={"verified_by": "cdg"},
        )
        assert ap.sanitizer_status == SanitizerStatus.MUST_EXECUTE
        assert ap.metadata["verified_by"] == "cdg"
