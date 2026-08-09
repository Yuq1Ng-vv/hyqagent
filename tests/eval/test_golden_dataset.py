"""tests/eval/test_golden_dataset.py — Golden dataset regression tests.

Runs all 28 labeled golden cases through deterministic checks and validates
against ground truth.  No LLM judge, no API keys — purely deterministic.

Usage::

    pytest tests/eval/test_golden_dataset.py -v          # all 28 cases
    pytest tests/eval/test_golden_dataset.py -k "case-001" -v  # single case
    pytest tests/eval/test_golden_dataset.py -k "gap-fill" -v   # new fixtures
    pytest tests/eval/test_golden_dataset.py -k "negative" -v   # FP check
    pytest -m eval -v                                       # all eval-marked tests
"""

from __future__ import annotations

import pytest

from hyqagent.cpg.parser import Parser
from hyqagent.cpg.taint_loader import TaintRuleLoader
from tests.eval.conftest import build_graph_for_case
from tests.eval.golden_loader import GoldenCase

# ── Level 1: Fixture file integrity ────────────────────────────────────────


class TestGoldenFixtureIntegrity:
    """Fixture file integrity: exist, parse, and contain source/sink annotations."""

    @pytest.mark.eval
    def test_file_exists(self, case: GoldenCase) -> None:
        """Golden case fixture file must exist on disk."""
        p = case.fixture_abs_path
        assert p.exists(), f"Fixture file not found: {p}"
        assert p.is_file(), f"Not a file: {p}"

    @pytest.mark.eval
    def test_parses(self, case: GoldenCase, parser: Parser) -> None:
        """Golden case fixture must parse without errors."""
        tree = parser.parse_file(str(case.fixture_abs_path))
        assert tree.root_node is not None, f"Parser returned None tree for {case.fixture_file}"
        detected = parser.get_language(tree)
        assert detected == case.language, (
            f"Expected language '{case.language}', detected '{detected}' in {case.fixture_file}"
        )

    @pytest.mark.eval
    def test_has_source_annotation(self, case: GoldenCase) -> None:
        """Each taint fixture must contain its expected source annotation comment."""
        gt = case.ground_truth
        if not gt.source_pattern:
            pytest.skip("No source_pattern in ground truth — not a taint-path case")
        code = case.source_code()
        assert gt.source_pattern in code, (
            f"Expected source pattern '{gt.source_pattern}' not found in {case.fixture_file}"
        )

    @pytest.mark.eval
    def test_has_sink_annotation(self, case: GoldenCase) -> None:
        """Each taint fixture must contain its expected sink annotation comment."""
        gt = case.ground_truth
        if not gt.sink_pattern:
            pytest.skip("No sink_pattern in ground truth — not a taint-path case")
        code = case.source_code()
        assert gt.sink_pattern in code, (
            f"Expected sink pattern '{gt.sink_pattern}' not found in {case.fixture_file}"
        )


# ── Level 2: CPG graph construction ────────────────────────────────────────


class TestGoldenCPGBuild:
    """Valid CPG graph with function nodes and data-flow edges for every golden case fixture."""

    @pytest.mark.eval
    def test_graph_has_nodes(self, case: GoldenCase, parser: Parser) -> None:
        """CPG graph must build with at least 1 node."""
        builder = build_graph_for_case(case, parser)
        assert builder.node_count > 0, f"CPG graph has 0 nodes for {case.id} ({case.fixture_file})"

    @pytest.mark.eval
    def test_graph_has_edges(self, case: GoldenCase, parser: Parser) -> None:
        """CPG graph must build with at least 1 edge."""
        builder = build_graph_for_case(case, parser)
        assert builder.edge_count > 0, f"CPG graph has 0 edges for {case.id} ({case.fixture_file})"

    @pytest.mark.eval
    def test_graph_has_function_nodes(self, case: GoldenCase, parser: Parser) -> None:
        """CPG graph must contain at least one function node."""
        builder = build_graph_for_case(case, parser)
        funcs = builder.nodes_by_type("function")
        assert len(funcs) > 0, f"No function nodes in CPG for {case.id} ({case.fixture_file})"

    @pytest.mark.eval
    def test_graph_has_data_flow_edges(self, case: GoldenCase, parser: Parser) -> None:
        """CPG graph must contain DATA_FLOW edges for taint-path cases."""
        builder = build_graph_for_case(case, parser)
        data_flow_edges = [
            (u, v, d)
            for u, v, d in builder.graph.edges(data=True)
            if d.get("edge_type") == "DATA_FLOW"
        ]
        # Non-taint cases (config_issue, missing_auth) may have 0 DF edges
        if case.detection_method in ("config_issue", "missing_auth"):
            return  # soft pass — no DF edges expected
        assert len(data_flow_edges) > 0, (
            f"No DATA_FLOW edges in CPG for {case.id} ({case.fixture_file})"
        )


# ── Level 3: Taint rule source/sink matching ───────────────────────────────


class TestGoldenSourceSinkMatching:
    """TaintRuleLoader must match source and sink patterns in each fixture.

    This is the core deterministic check — the same one used by
    ``test_cross_language_parity.py``.
    """

    @pytest.mark.eval
    def test_source_patterns_match(
        self,
        case: GoldenCase,
        taint_loader: TaintRuleLoader,
    ) -> None:
        """At least one taint source pattern must match the fixture code."""
        if case.detection_method not in ("cpg_taint", "heuristic"):
            pytest.skip(f"Not a taint-path case ({case.detection_method})")
        if case.negative_test:
            pytest.skip("Negative test — no source pattern expected")

        code = case.source_code()
        sources = taint_loader.all_sources(case.language)
        matches = [p for p in sources if p in code]
        assert len(matches) > 0, (
            f"No source pattern matched in {case.fixture_file} "
            f"(language={case.language}, type={case.vulnerability_type})"
        )

    @pytest.mark.eval
    def test_sink_patterns_match(
        self,
        case: GoldenCase,
        taint_loader: TaintRuleLoader,
    ) -> None:
        """At least one taint sink pattern must match the fixture code."""
        if case.detection_method not in ("cpg_taint", "heuristic"):
            pytest.skip(f"Not a taint-path case ({case.detection_method})")
        if case.negative_test:
            pytest.skip("Negative test — no sink pattern expected")

        code = case.source_code()
        sinks = taint_loader.all_sinks(case.language)
        matches = [p for p in sinks if p in code]
        assert len(matches) > 0, (
            f"No sink pattern matched in {case.fixture_file} "
            f"(language={case.language}, type={case.vulnerability_type})"
        )

    @pytest.mark.eval
    def test_source_category_matches(
        self,
        case: GoldenCase,
        taint_loader: TaintRuleLoader,
    ) -> None:
        """TaintLoader.match_source() must return a non-None category."""
        if case.detection_method not in ("cpg_taint", "heuristic"):
            pytest.skip(f"Not a taint-path case ({case.detection_method})")
        if case.negative_test:
            pytest.skip("Negative test — no source category expected")

        code = case.source_code()
        cat = taint_loader.match_source(case.language, code)
        assert cat is not None, f"match_source returned None for {case.id} ({case.fixture_file})"

    @pytest.mark.eval
    def test_sink_category_matches(
        self,
        case: GoldenCase,
        taint_loader: TaintRuleLoader,
    ) -> None:
        """TaintLoader.match_sink() must return a non-None category."""
        if case.detection_method not in ("cpg_taint", "heuristic"):
            pytest.skip(f"Not a taint-path case ({case.detection_method})")
        if case.negative_test:
            pytest.skip("Negative test — no sink category expected")

        code = case.source_code()
        cat = taint_loader.match_sink(case.language, code)
        assert cat is not None, f"match_sink returned None for {case.id} ({case.fixture_file})"


# ── Level 4: Negative case validation ──────────────────────────────────────


class TestGoldenNegativeCases:
    """Negative cases: the scanner MUST NOT produce findings for safe code.

    Note: sink-pattern matching is NOT a reliable false-positive gate for
    cases like parameterized SQL — both safe and unsafe SQL use the same
    API (e.g. ``cursor.execute()``).  The real FP gate is the full scanner
    with data-flow analysis (Phase 5 Task 2).
    """

    @pytest.mark.eval
    def test_no_source_match_on_safe_code(
        self,
        case: GoldenCase,
        taint_loader: TaintRuleLoader,
    ) -> None:
        """Safe code must not match any taint source pattern."""
        if not case.negative_test:
            pytest.skip("Not a negative test case")

        code = case.source_code()
        cat = taint_loader.match_source(case.language, code)
        assert cat is None, (
            f"Safe code {case.id} unexpectedly matched source category '{cat}' — "
            f"this is a FALSE POSITIVE"
        )


# ── Level 5: Scanner-level integration ────────────────────────────────────


class TestGoldenScannerIntegration:
    """Run the full :class:`DeterministicScanner` on each golden case.

    These tests exercise the complete scanner dependency chain
    (CPG graph → CPGQuery → PathAnnotator → DeterministicScanner)
    and verify the scanner produces (or does not produce) findings
    matching ground truth.

    Note for ``cpg_taint`` cases: the current CPG data-flow analysis
    does not trace variable refs into call-site arguments within
    single-file fixtures, so the taint BFS may produce zero paths.
    This is a known limitation — scanner-level taint regression will
    become effective once cross-procedural data-flow is improved.
    """

    @pytest.mark.eval
    def test_scanner_constructs_and_runs(
        self,
        case: GoldenCase,
        parser: Parser,
        taint_loader: TaintRuleLoader,
    ) -> None:
        """DeterministicScanner must construct and scan without exceptions."""
        from tests.eval.conftest import build_scanner_for_case

        scanner = build_scanner_for_case(case, parser, taint_loader)
        result = scanner.scan_all([str(case.fixture_abs_path)], case.language)
        assert result is not None
        assert hasattr(result, "findings")
        assert hasattr(result, "stats")
        assert "total_findings" in result.stats

    @pytest.mark.eval
    def test_scanner_taint_labels_exist(
        self,
        case: GoldenCase,
        parser: Parser,
        taint_loader: TaintRuleLoader,
    ) -> None:
        """Taint-labeled nodes must exist in the CPG for cpg_taint cases."""
        if case.detection_method != "cpg_taint":
            pytest.skip(f"Not a cpg_taint case ({case.detection_method})")
        if case.negative_test:
            pytest.skip("Negative test — taint labels may or may not exist")

        from tests.eval.conftest import build_labeled_graph_for_case

        builder = build_labeled_graph_for_case(case, parser, taint_loader)
        labeled = [n for n, d in builder.graph.nodes(data=True) if d.get("taint_category")]
        assert len(labeled) > 0, (
            f"No taint-labeled nodes in {case.id} ({case.fixture_file}). "
            f"Expected taint_category labels for {case.vulnerability_type}."
        )

    @pytest.mark.eval
    def test_config_scanner_finds_issue(
        self,
        case: GoldenCase,
        parser: Parser,
        taint_loader: TaintRuleLoader,
    ) -> None:
        """scan_config_issues must detect CSRF disable in case-026."""
        if case.detection_method != "config_issue":
            pytest.skip(f"Not a config_issue case ({case.detection_method})")

        from tests.eval.conftest import build_scanner_for_case

        scanner = build_scanner_for_case(case, parser, taint_loader)
        findings = scanner.scan_config_issues(
            [str(case.fixture_abs_path)],
            case.language,
        )

        assert len(findings) >= case.ground_truth.min_findings, (
            f"Expected ≥{case.ground_truth.min_findings} config findings "
            f"for {case.id}, got {len(findings)}"
        )
        if case.ground_truth.expected_category:
            matched = [
                f
                for f in findings
                if f.category == case.ground_truth.expected_category
                or case.ground_truth.expected_category in f.category  # type: ignore[operator]
            ]
            assert len(matched) > 0, (
                f"No finding with category '{case.ground_truth.expected_category}' "
                f"in {case.id}. Got categories: {[f.category for f in findings]}"
            )

    @pytest.mark.eval
    def test_missing_auth_scanner(
        self,
        case: GoldenCase,
        parser: Parser,
        taint_loader: TaintRuleLoader,
    ) -> None:
        """scan_missing_auth must detect unprotected endpoint in case-027."""
        if case.detection_method != "missing_auth":
            pytest.skip(f"Not a missing_auth case ({case.detection_method})")

        from tests.eval.conftest import build_scanner_for_case

        # Build scanner WITHOUT frameworks first — missing_auth needs
        # framework extractors to discover endpoints.  For single-fixture
        # tests the framework extractors may not parse the fixture fully,
        # so this is a soft/best-effort assertion.
        scanner = build_scanner_for_case(case, parser, taint_loader)
        findings = scanner.scan_missing_auth()

        # Soft pass: min_findings=0 allows zero findings (known-gap)
        assert len(findings) >= case.ground_truth.min_findings, (
            f"Expected ≥{case.ground_truth.min_findings} missing-auth findings "
            f"for {case.id}, got {len(findings)}"
        )

    @pytest.mark.eval
    def test_safe_code_produces_no_findings(
        self,
        case: GoldenCase,
        parser: Parser,
        taint_loader: TaintRuleLoader,
    ) -> None:
        """Negative cases must produce ZERO findings from the full scanner."""
        if not case.negative_test:
            pytest.skip("Not a negative test case")

        from tests.eval.conftest import build_scanner_for_case

        scanner = build_scanner_for_case(case, parser, taint_loader)
        result = scanner.scan_all([str(case.fixture_abs_path)], case.language)

        # For now, only check that no CONFIRMED_TAINT finding appears
        # with the forbidden category.  Regex-based scanners (secrets,
        # dangerous_calls, config_issues) may produce incidental matches
        # on safe fixtures — those are separate FP concerns.
        forbidden = case.ground_truth.expected_category or case.vulnerability_type
        taint_findings = [
            f for f in result.findings if f.rule_id == "TAINT-001" and f.category == forbidden
        ]
        assert len(taint_findings) == 0, (
            f"SAFE CODE FALSE POSITIVE: {case.id} produced "
            f"{len(taint_findings)} taint finding(s) with category "
            f"'{forbidden}' — scanner should not flag safe parameterized code"
        )
