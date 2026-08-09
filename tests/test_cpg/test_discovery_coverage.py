"""Tests for cpg/discovery.py and cpg/coverage.py."""

from __future__ import annotations

import networkx as nx

from hyqagent.cpg.coverage import _STRUCTURAL_BLIND_SPOTS, CoverageTracker
from hyqagent.cpg.discovery import (
    SinkDiscoverer,
    SourceCompletenessChecker,
)
from hyqagent.cpg.graph import EDGE_DATA_FLOW, NODE_ASSIGNMENT
from hyqagent.cpg.types import (
    BlindSpot,
    CoverageReport,
    ExposedEndpoint,
    HeuristicSink,
    UncoveredSink,
)

# ── Fixtures ──────────────────────────────────────────────────────────────


class _FakeTaintLoader:
    """Minimal stub that satisfies the TaintRuleLoader interface for tests."""

    def __init__(self, sources=None, sinks=None, sanitizers=None):
        self._sources = sources or []
        self._sinks = sinks or []
        self._sanitizers = sanitizers or []
        self.available_languages = ["python"]

    def all_sinks(self, language: str) -> list[str]:
        return list(self._sinks)

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
        return None


class _FakeEndpoint:
    """Minimal HttpEndpoint stub."""

    def __init__(self, route, handler_func, file_path, line, methods=None, auth_required=None):
        self.route = route
        self.handler_func = handler_func
        self.file_path = file_path
        self.line = line
        self.methods = methods or ["GET"]
        self.auth_required = auth_required


def _make_mini_graph() -> nx.MultiDiGraph:
    """Build a tiny CPG-like graph with assignments and data-flow edges."""
    g = nx.MultiDiGraph()

    # A source-labelled node (simulates request.args.get("id"))
    g.add_node(
        "src1",
        node_type=NODE_ASSIGNMENT,
        file_path="app.py",
        enclosing_function="handler1",
        start_line=10,
        source="request.args.get('id')",
        taint_category="sql_injection",
    )

    # A sink labelled node (simulates cursor.execute(...))
    g.add_node(
        "sink1",
        node_type=NODE_ASSIGNMENT,
        file_path="app.py",
        enclosing_function="handler1",
        start_line=12,
        source="cursor.execute(query)",
        taint_category="sql_injection",
    )

    # A DATA_FLOW edge from source to sink
    g.add_edge("src1", "sink1", edge_type=EDGE_DATA_FLOW)

    # An un-labelled but dangerous-looking node
    g.add_node(
        "unsafe1",
        node_type=NODE_ASSIGNMENT,
        file_path="app.py",
        enclosing_function="handler1",
        start_line=15,
        source="os.system(user_cmd)",
    )

    # An un-labelled harmless node
    g.add_node(
        "safe1",
        node_type=NODE_ASSIGNMENT,
        file_path="app.py",
        enclosing_function="handler1",
        start_line=18,
        source="logger.info('done')",
    )

    # A handler function node
    g.add_node(
        "fn1",
        node_type="function",
        file_path="app.py",
        name="handler1",
        start_line=8,
        source="@app.route('/users')\ndef handler1():",
    )

    return g


# ── SinkDiscoverer ──────────────────────────────────────────────────────


class TestSinkDiscoverer:
    def test_is_potentially_dangerous_detects_os_system(self):
        g = _make_mini_graph()
        tl = _FakeTaintLoader()
        sd = SinkDiscoverer(g, tl)

        dangerous, score = sd.is_potentially_dangerous("unsafe1")
        assert dangerous
        assert score >= 25  # os. module prefix

    def test_is_potentially_dangerous_scores_low_for_safe_call(self):
        g = _make_mini_graph()
        tl = _FakeTaintLoader()
        sd = SinkDiscoverer(g, tl)

        dangerous, score = sd.is_potentially_dangerous("safe1")
        # logger.info is not dangerous
        assert score < 40 or not dangerous

    def test_discover_heuristic_sinks_finds_unlabeled_dangerous(self):
        g = _make_mini_graph()
        tl = _FakeTaintLoader()
        sd = SinkDiscoverer(g, tl)

        sinks = sd.discover_heuristic_sinks("python", score_threshold=30)
        # unsafe1 should be found
        assert any(s.node_id == "unsafe1" for s in sinks)
        # safe1 should NOT
        assert not any(s.node_id == "safe1" for s in sinks)
        # src1 and sink1 are already labelled → skipped
        assert not any(s.node_id == "src1" for s in sinks)
        assert not any(s.node_id == "sink1" for s in sinks)

    def test_discover_heuristic_sinks_respects_threshold(self):
        g = _make_mini_graph()
        tl = _FakeTaintLoader()
        sd = SinkDiscoverer(g, tl)

        # Very high threshold — nothing should pass
        sinks = sd.discover_heuristic_sinks("python", score_threshold=95)
        assert len(sinks) == 0

    def test_match_keywords(self):
        g = _make_mini_graph()
        tl = _FakeTaintLoader()
        sd = SinkDiscoverer(g, tl)

        kws = sd._match_keywords("cursor.execute(sql_query)")
        assert "sql" in kws
        assert "execute" in kws

        kws = sd._match_keywords("print('hello')")
        assert len(kws) == 0


# ── SourceCompletenessChecker ────────────────────────────────────────────


class TestSourceCompletenessChecker:
    def test_find_exposed_no_source_returns_endpoints_without_source(self):
        g = _make_mini_graph()
        tl = _FakeTaintLoader(sources=["request.args.get"])
        checker = SourceCompletenessChecker(g, tl)

        ep = _FakeEndpoint("/users", "handler2", "app.py", 30)
        checker.set_endpoints([ep])

        exposed = checker.find_exposed_no_source()
        assert len(exposed) == 1
        assert exposed[0].handler_func == "handler2"
        assert "GET /users" in exposed[0].endpoint

    def test_find_exposed_no_source_skips_endpoints_with_source(self):
        g = _make_mini_graph()
        tl = _FakeTaintLoader(sources=["request.args.get"])
        checker = SourceCompletenessChecker(g, tl)

        # handler1 HAS src1 with taint_category
        ep = _FakeEndpoint("/users", "handler1", "app.py", 8)
        checker.set_endpoints([ep])

        exposed = checker.find_exposed_no_source()
        # handler1 has a source match → should NOT be exposed
        # But our _handler_has_source checks match_source which looks at source text
        # src1 has "request.args.get('id')" → matches "request.args.get"
        assert len(exposed) == 0

    def test_find_uncovered_sinks_returns_only_unlabeled(self):
        g = _make_mini_graph()
        tl = _FakeTaintLoader()
        checker = SourceCompletenessChecker(g, tl)

        uncovered = checker.find_uncovered_sinks("python")
        node_ids = {u.node_id for u in uncovered}
        # unsafe1 is un-labelled and has '(' → should appear
        assert "unsafe1" in node_ids
        # safe1 is un-labelled but has '(' → should appear
        assert "safe1" in node_ids
        # src1 and sink1 are taint-labelled → should NOT appear
        assert "src1" not in node_ids
        assert "sink1" not in node_ids


# ── CoverageTracker ──────────────────────────────────────────────────────


class TestCoverageTracker:
    def test_compute_coverage_empty(self):
        g = nx.MultiDiGraph()
        tracker = CoverageTracker(g)
        report = tracker.compute_coverage()
        assert isinstance(report, CoverageReport)
        assert report.endpoint_total == 0
        assert report.endpoint_coverage_ratio == 0.0
        assert report.sink_total == 0
        assert report.sink_coverage_ratio == 0.0
        # Structural blind spots are always present
        assert len(report.blind_spots) >= len(_STRUCTURAL_BLIND_SPOTS)

    def test_compute_coverage_with_endpoints_and_graph(self):
        g = _make_mini_graph()
        tracker = CoverageTracker(g)

        ep1 = _FakeEndpoint("/users", "handler1", "app.py", 8)
        ep2 = _FakeEndpoint("/admin", "handler2", "app.py", 30, auth_required=False)
        tracker.set_endpoints([ep1, ep2])

        report = tracker.compute_coverage()
        assert report.endpoint_total == 2
        assert report.endpoint_coverage_ratio >= 0.0
        # handler1 has a labelled node → analyzed count >= 1
        assert report.endpoint_analyzed >= 1

        # sink_total should count call-like assignments
        # src1 ("request.args.get('id')") has '(' → counts
        # sink1 ("cursor.execute(query)") has '(' → counts
        # unsafe1 ("os.system(user_cmd)") has '(' → counts
        # safe1 ("logger.info('done')") has '(' → counts
        assert report.sink_total >= 2
        # sink1 and src1 are labelled → labeled >= 2
        assert report.sink_labeled >= 2

    def test_blind_spot_manifest_includes_structural_gaps(self):
        g = nx.MultiDiGraph()
        tracker = CoverageTracker(g)
        manifest = tracker.generate_blind_spot_manifest()

        # Structural blind spots
        reasons = {bs.reason for bs in manifest}
        assert "idor_no_structural_signature" in reasons
        assert "business_logic_no_sink" in reasons

    def test_blind_spot_manifest_flags_missing_auth(self):
        g = _make_mini_graph()
        tracker = CoverageTracker(g)
        ep = _FakeEndpoint("/admin", "handler2", "app.py", 30, auth_required=False)
        tracker.set_endpoints([ep])
        manifest = tracker.generate_blind_spot_manifest()

        auth_spots = [bs for bs in manifest if "missing_auth" in bs.reason]
        assert len(auth_spots) >= 1
        assert "app.py" in auth_spots[0].location
        assert "admin" in auth_spots[0].recommendation

    def test_coverage_report_round_trip(self):
        g = _make_mini_graph()
        tracker = CoverageTracker(g)
        tracker.set_language("python")
        tracker.set_framework("Flask")
        tracker.set_active_categories({"sql_injection"})

        report = tracker.compute_coverage()
        # Should survive dataclass round-trip
        d = {
            "endpoint_total": report.endpoint_total,
            "endpoint_coverage_ratio": report.endpoint_coverage_ratio,
            "sink_total": report.sink_total,
            "sink_coverage_ratio": report.sink_coverage_ratio,
            "blind_spot_count": len(report.blind_spots),
        }
        assert isinstance(d["endpoint_total"], int)
        assert isinstance(d["sink_coverage_ratio"], float)


# ── Dataclass validation ─────────────────────────────────────────────────


class TestDiscoveryDataclasses:
    def test_heuristic_sink_defaults(self):
        hs = HeuristicSink(node_id="n1", file_path="a.py", line=42, expression="eval(x)")
        assert hs.score == 0
        assert hs.matched_keywords == []
        assert hs.reachable_from_source is False

    def test_exposed_endpoint_fields(self):
        ee = ExposedEndpoint(
            endpoint="GET /api/orders/:id",
            handler_func="get_order",
            file_path="orders.py",
            line=55,
        )
        assert ee.endpoint == "GET /api/orders/:id"
        assert ee.line == 55

    def test_uncovered_sink_fields(self):
        us = UncoveredSink(
            node_id="n3",
            file_path="a.py",
            line=100,
            expression="db.execute(sql)",
            reason="no_known_rule",
        )
        assert us.reason == "no_known_rule"

    def test_coverage_report_defaults(self):
        cr = CoverageReport()
        assert cr.endpoint_total == 0
        assert cr.blind_spots == []

    def test_blind_spot_defaults(self):
        bs = BlindSpot(location="x.py:1", reason="test")
        assert bs.severity == "medium"
        assert bs.recommendation == ""
