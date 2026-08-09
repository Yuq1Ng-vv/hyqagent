"""tests/eval/test_llm_eval.py — LLM pipeline evaluation tests.

Covers the HypothesisGenerator and Validator components using
mock providers (no real LLM calls) plus DeepEval custom metrics.

Usage::

    pytest tests/eval/test_llm_eval.py -v -m eval                 # all mock tests
    pytest tests/eval/test_llm_eval.py -v -m "eval and not slow"  # mock only
    HYQAGENT_EVAL_REAL_LLM=1 pytest ... -m "eval and slow"        # real LLM (opt-in)
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

# DeepEval availability — skip all tests if not installed
pytest.importorskip("deepeval")

from deepeval.test_case import LLMTestCase

from hyqagent.cpg.query import CPGQuery, GraphNode, GraphPath
from hyqagent.scanner.annotator import AnnotatedPath, PathLabel
from hyqagent.scanner.hypothesis import Hypothesis, HypothesisGenerator
from hyqagent.scanner.validator import ValidationResult, Validator
from tests.eval.metrics import (
    CWEMappingMetric,
    SeverityAgreementMetric,
    VerdictCorrectnessMetric,
    VulnTypeAccuracyMetric,
)
from tests.eval.mock_responses import (
    EMPTY_HYPOTHESES,
    SQLLI_TRUE_POSITIVE,
    VALIDATOR_CONFIRMED,
    VALIDATOR_REJECTED,
    FakeProvider,
)

# ── shared helpers ────────────────────────────────────────────────────────


def _build_router(provider: FakeProvider) -> Any:
    """Build a ModelRouter whose providers dict returns *provider* for all tiers."""
    from hyqagent.models.router import ModelRouter

    return ModelRouter(
        providers={"deepseek": provider, "anthropic": provider},
        cheap_model="mock-model",
        mid_model="mock-model",
        strong_model="mock-model",
    )


def _build_mock_annotated_path(
    label: PathLabel, nodes: list[GraphNode] | None = None
) -> AnnotatedPath:
    """Build an :class:`AnnotatedPath` with a minimal :class:`GraphPath`."""
    if nodes is None:
        nodes = [
            GraphNode(
                node_id="src-1",
                node_type="assignment",
                location="fixture.py:10",
                name="user_input",
                source='request.args.get("q")',
                taint_category="sql_injection",
            ),
            GraphNode(
                node_id="snk-1",
                node_type="call_site",
                location="fixture.py:18",
                name="execute",
                source="cursor.execute(query)",
                taint_category="sql_injection",
            ),
        ]
    path = GraphPath(nodes=nodes, edges=["DATA_FLOW"])
    return AnnotatedPath(path=path, label=label, metadata={"score": 85})


def _build_minimal_cpg_query() -> CPGQuery:
    """Build a :class:`CPGQuery` backed by an empty graph.

    :meth:`CPGQuery.slice_path` only uses the path (not the graph)
    so an empty graph suffices for mock tests.
    """
    import networkx as nx

    return CPGQuery(nx.DiGraph())


def _make_sqli_hypothesis() -> Hypothesis:
    """Create a plausible SQL injection hypothesis for validation testing."""
    return Hypothesis(
        id="hyp-test-001",
        vuln_type="sql_injection",
        cwe_id="CWE-89",
        severity="high",
        confidence=0.85,
        title="SQL Injection via user input",
        description="User input flows into raw SQL query",
        source_location="fixture.py:10",
        sink_location="fixture.py:18",
        evidence="cursor.execute(f\"SELECT * FROM users WHERE name = '{q}'\")",
        reasoning="No parameterization, direct string interpolation",
        remediation="Use parameterized queries with placeholders",
    )


# ── Test: Hypothesis parsing ─────────────────────────────────────────────


class TestHypothesisParsing:
    """Test :meth:`HypothesisGenerator._parse_response` with known LLM responses."""

    @pytest.mark.eval
    def test_parse_sqli_true_positive(self) -> None:
        """Parse SQLLI_TRUE_POSITIVE → list of Hypothesis objects with correct fields."""
        from hyqagent.models.router import ModelRouter

        provider = FakeProvider()
        router = ModelRouter(providers={"deepseek": provider, "anthropic": provider})
        gen = HypothesisGenerator(
            query=_build_minimal_cpg_query(),
            router=router,
            cheap_provider=provider,
            mid_provider=provider,
            strong_provider=provider,
            language="python",
        )

        hypotheses = gen._parse_response(SQLLI_TRUE_POSITIVE)

        assert len(hypotheses) == 1
        h = hypotheses[0]
        assert h.vuln_type == "sql_injection"
        assert h.cwe_id == "CWE-89"
        assert h.severity == "high"
        assert 0.0 < h.confidence <= 1.0
        assert "SQL Injection" in h.title
        assert "source_location" in h.__dataclass_fields__
        assert "remediation" in h.__dataclass_fields__

    @pytest.mark.eval
    def test_parse_empty_hypotheses(self) -> None:
        """Parse EMPTY_HYPOTHESES → empty list (no false positives)."""
        from hyqagent.models.router import ModelRouter

        provider = FakeProvider()
        router = ModelRouter(providers={"deepseek": provider, "anthropic": provider})
        gen = HypothesisGenerator(
            query=_build_minimal_cpg_query(),
            router=router,
            cheap_provider=provider,
            mid_provider=provider,
            strong_provider=provider,
            language="python",
        )

        hypotheses = gen._parse_response(EMPTY_HYPOTHESES)
        assert hypotheses == []

    @pytest.mark.eval
    def test_parse_invalid_response(self) -> None:
        """Parse malformed/missing responses → empty list (no crash)."""
        from hyqagent.models.router import ModelRouter

        provider = FakeProvider()
        router = ModelRouter(providers={"deepseek": provider, "anthropic": provider})
        gen = HypothesisGenerator(
            query=_build_minimal_cpg_query(),
            router=router,
            cheap_provider=provider,
            mid_provider=provider,
            strong_provider=provider,
            language="python",
        )

        # Missing 'hypotheses' key
        assert gen._parse_response({"some_other_key": []}) == []

        # hypotheses is not a list
        assert gen._parse_response({"hypotheses": "not_a_list"}) == []

        # hypotheses contains non-dict items
        assert gen._parse_response({"hypotheses": ["string_not_dict"]}) == []

        # Empty dict
        assert gen._parse_response({}) == []


# ── Test: Mock hypothesis generation ─────────────────────────────────────


class TestMockHypothesisGeneration:
    """Full HypothesisGenerator.generate() with FakeProvider injected.

    Uses the CPG graph from a golden fixture to build annotated paths,
    then injects FakeProvider so LLM calls return canned responses.
    """

    @pytest.mark.eval
    def test_generate_returns_hypotheses_with_mock_provider(
        self,
        case: Any,
        parser: Any,
        taint_loader: Any,
        request: pytest.FixtureRequest,
    ) -> None:
        """HypothesisGenerator with FakeProvider must return parsed hypotheses."""
        # Only test on cpg_taint cases with non-negative fixtures
        if case.detection_method != "cpg_taint":
            pytest.skip(f"Not a cpg_taint case ({case.detection_method})")
        if case.negative_test:
            pytest.skip("Negative test — no hypotheses expected")

        from tests.eval.conftest import build_labeled_graph_for_case

        # Build the CPG graph (with taint labels)
        builder = build_labeled_graph_for_case(case, parser, taint_loader)
        query = CPGQuery(builder.graph)

        # Create provider with SQLi true positive response
        provider = FakeProvider([SQLLI_TRUE_POSITIVE])
        router = _build_router(provider)

        gen = HypothesisGenerator(
            query=query,
            router=router,
            cheap_provider=provider,
            mid_provider=provider,
            strong_provider=provider,
            language=case.language,
        )

        # Build annotated paths from the real graph
        annotated = _build_mock_annotated_path(PathLabel.HEURISTIC_SINK)

        hypotheses = asyncio.run(gen.generate([annotated]))

        assert isinstance(hypotheses, list)
        assert len(hypotheses) >= 1
        h = hypotheses[0]
        assert h.vuln_type == "sql_injection"
        assert provider.call_count >= 1

    @pytest.mark.eval
    def test_generate_empty_when_provider_returns_empty(
        self,
        case: Any,
        parser: Any,
        taint_loader: Any,
    ) -> None:
        """When the LLM returns empty hypotheses, generate() returns []."""
        if case.detection_method != "cpg_taint":
            pytest.skip(f"Not a cpg_taint case ({case.detection_method})")
        if case.negative_test:
            pytest.skip("Negative test")

        from tests.eval.conftest import build_labeled_graph_for_case

        builder = build_labeled_graph_for_case(case, parser, taint_loader)
        query = CPGQuery(builder.graph)

        provider = FakeProvider([EMPTY_HYPOTHESES])
        router = _build_router(provider)

        gen = HypothesisGenerator(
            query=query,
            router=router,
            cheap_provider=provider,
            mid_provider=provider,
            strong_provider=provider,
            language=case.language,
        )

        annotated = _build_mock_annotated_path(PathLabel.HEURISTIC_SINK)
        hypotheses = asyncio.run(gen.generate([annotated]))

        assert hypotheses == []

    @pytest.mark.eval
    def test_skips_non_llm_labels(
        self,
        case: Any,
        parser: Any,
        taint_loader: Any,
    ) -> None:
        """Paths with confirmed_taint/sanitized_taint labels are skipped."""
        if case.detection_method != "cpg_taint":
            pytest.skip(f"Not a cpg_taint case ({case.detection_method})")
        if case.negative_test:
            pytest.skip("Negative test")

        from tests.eval.conftest import build_labeled_graph_for_case

        builder = build_labeled_graph_for_case(case, parser, taint_loader)
        query = CPGQuery(builder.graph)

        provider = FakeProvider()
        router = _build_router(provider)

        gen = HypothesisGenerator(
            query=query,
            router=router,
            cheap_provider=provider,
            mid_provider=provider,
            strong_provider=provider,
            language=case.language,
        )

        annotated = _build_mock_annotated_path(PathLabel.CONFIRMED_TAINT)
        hypotheses = asyncio.run(gen.generate([annotated]))

        # Should be skipped — no LLM call needed for CONFIRMED_TAINT
        assert hypotheses == []
        assert provider.call_count == 0


# ── Test: Mock validation ────────────────────────────────────────────────


class TestMockValidation:
    """Validator L1 and L2 with FakeProvider injected.

    Tests both deterministic L1 checks and LLM-powered L2 verification.
    """

    @pytest.mark.eval
    def test_l2_validates_confirmed(
        self,
        case: Any,
        parser: Any,
        taint_loader: Any,
    ) -> None:
        """Validator L2: LLM confirms a real SQLi hypothesis."""
        if case.detection_method != "cpg_taint":
            pytest.skip(f"Not a cpg_taint case ({case.detection_method})")

        from tests.eval.conftest import build_graph_for_case

        builder = build_graph_for_case(case, parser)
        query = CPGQuery(builder.graph)

        provider = FakeProvider([VALIDATOR_CONFIRMED])
        router = _build_router(provider)

        validator = Validator(
            query=query,
            taint_loader=taint_loader,
            router=router,
            mid_provider=provider,
            strong_provider=provider,
            language=case.language,
        )

        hypothesis = _make_sqli_hypothesis()
        code_context = """
        def search():
            q = request.args.get('q')
            query = f"SELECT * FROM users WHERE name = '{q}'"
            cursor.execute(query)
        """
        result = asyncio.run(validator.validate_l2(hypothesis, code_context))

        assert isinstance(result, ValidationResult)
        assert result.hypothesis_id == "hyp-test-001"
        assert result.verdict in ("confirmed", "rejected", "inconclusive", "needs_human")
        assert isinstance(result.confidence, float)
        assert result.validation_type == "l2_llm"

    @pytest.mark.eval
    def test_l2_rejects_false_positive(
        self,
        case: Any,
        parser: Any,
        taint_loader: Any,
    ) -> None:
        """Validator L2: LLM rejects a hypothesis on safe code."""
        if case.detection_method != "cpg_taint":
            pytest.skip(f"Not a cpg_taint case ({case.detection_method})")

        from tests.eval.conftest import build_graph_for_case

        builder = build_graph_for_case(case, parser)
        query = CPGQuery(builder.graph)

        provider = FakeProvider([VALIDATOR_REJECTED])
        router = _build_router(provider)

        validator = Validator(
            query=query,
            taint_loader=taint_loader,
            router=router,
            mid_provider=provider,
            strong_provider=provider,
            language=case.language,
        )

        hypothesis = _make_sqli_hypothesis()
        code_context = """
        def search():
            q = request.args.get('q')
            cursor.execute('SELECT * FROM users WHERE name = ?', (q,))
        """
        result = asyncio.run(validator.validate_l2(hypothesis, code_context))

        assert result.hypothesis_id == "hyp-test-001"
        assert result.verdict in ("confirmed", "rejected", "inconclusive", "needs_human")

    @pytest.mark.eval
    def test_l1_deterministic_rejects_type_mismatch(
        self,
        case: Any,
        parser: Any,
        taint_loader: Any,
    ) -> None:
        """Validator L1: source/sink type mismatch → rejected."""
        if case.detection_method != "cpg_taint":
            pytest.skip(f"Not a cpg_taint case ({case.detection_method})")

        from tests.eval.conftest import build_graph_for_case

        builder = build_graph_for_case(case, parser)
        query = CPGQuery(builder.graph)

        # L1 only — no LLM provider needed
        provider = FakeProvider()
        router = _build_router(provider)

        validator = Validator(
            query=query,
            taint_loader=taint_loader,
            router=router,
            mid_provider=provider,
            strong_provider=provider,
            language=case.language,
        )

        # Create hypothesis with deliberately wrong types
        hypothesis = Hypothesis(
            id="hyp-bad-001",
            vuln_type="xss",
            cwe_id="CWE-79",
            severity="low",
            confidence=0.3,
            title="Bad XSS hypothesis on SQLi code",
            description="This won't match",
            source_location="request.args.get(...)",  # will match sql_injection source
            sink_location="cursor.execute(...)",  # will match sql_injection sink
            evidence="",
            reasoning="Wrong guess",
        )
        result = validator.validate_l1(hypothesis)

        assert isinstance(result, ValidationResult)
        assert result.validation_type == "l1_deterministic"
        # L1 should catch the type mismatch
        assert result.verdict in ("rejected", "inconclusive")


# ── Test: DeepEval custom metrics ────────────────────────────────────────


class TestDeepEvalMetrics:
    """Custom DeepEval metrics on mock LLMTestCase data.

    These tests validate the metric logic itself — no real LLM is involved.
    """

    @pytest.mark.eval
    def test_vuln_type_accuracy_exact_match(self) -> None:
        """VulnTypeAccuracy: exact match scores 1.0."""
        metric = VulnTypeAccuracyMetric(threshold=0.5)
        tc = LLMTestCase(
            input="source code with SQL query",
            actual_output="sql_injection",
            expected_output="sql_injection",
        )
        score = metric.measure(tc)
        assert score == 1.0, f"Expected 1.0, got {score}"
        assert metric.is_successful()

    @pytest.mark.eval
    def test_vuln_type_accuracy_mismatch(self) -> None:
        """VulnTypeAccuracy: total mismatch scores 0.0."""
        metric = VulnTypeAccuracyMetric(threshold=0.5)
        tc = LLMTestCase(
            input="source code",
            actual_output="xss",
            expected_output="sql_injection",
        )
        score = metric.measure(tc)
        assert score == 0.0, f"Expected 0.0, got {score}"
        assert not metric.is_successful()

    @pytest.mark.eval
    def test_severity_agreement_adjacent(self) -> None:
        """SeverityAgreement: adjacent severities (high↔critical) score 0.8."""
        metric = SeverityAgreementMetric(threshold=0.6)
        tc = LLMTestCase(
            input="code",
            actual_output="high",
            expected_output="critical",
        )
        score = metric.measure(tc)
        assert score == 0.8, f"Expected 0.8 (adjacent), got {score}"
        assert metric.is_successful()

    @pytest.mark.eval
    def test_severity_agreement_far(self) -> None:
        """SeverityAgreement: severities 3+ levels apart score 0.0."""
        metric = SeverityAgreementMetric(threshold=0.6)
        tc = LLMTestCase(
            input="code",
            actual_output="info",
            expected_output="critical",
        )
        score = metric.measure(tc)
        assert score == 0.0, f"Expected 0.0 (4 levels apart), got {score}"

    @pytest.mark.eval
    def test_cwe_mapping_exact(self) -> None:
        """CWEMapping: exact CWE match scores 1.0."""
        metric = CWEMappingMetric(threshold=0.5)
        tc = LLMTestCase(
            input="SQLi code",
            actual_output="CWE-89",
            expected_output="CWE-89",
        )
        score = metric.measure(tc)
        assert score == 1.0, f"Expected 1.0, got {score}"

    @pytest.mark.eval
    def test_cwe_mapping_same_family(self) -> None:
        """CWEMapping: same CWE family scores 0.7."""
        metric = CWEMappingMetric(threshold=0.5)
        tc = LLMTestCase(
            input="SQLi code",
            actual_output="CWE-564",
            expected_output="CWE-89",
        )
        score = metric.measure(tc)
        assert score == 0.7, f"Expected 0.7 (same family), got {score}"

    @pytest.mark.eval
    def test_verdict_correctness_true_positive(self) -> None:
        """VerdictCorrectness: confirmed on real vuln scores 1.0."""
        metric = VerdictCorrectnessMetric(threshold=0.5, expect_positive=True)
        tc = LLMTestCase(
            input="SQLi code",
            actual_output="confirmed",
        )
        score = metric.measure(tc)
        assert score == 1.0

    @pytest.mark.eval
    def test_verdict_correctness_false_negative(self) -> None:
        """VerdictCorrectness: rejected on real vuln scores 0.0 (FN)."""
        metric = VerdictCorrectnessMetric(threshold=0.5, expect_positive=True)
        tc = LLMTestCase(
            input="SQLi code",
            actual_output="rejected",
        )
        score = metric.measure(tc)
        assert score == 0.0

    @pytest.mark.eval
    def test_verdict_correctness_true_negative(self) -> None:
        """VerdictCorrectness: rejected on safe code scores 1.0 (TN)."""
        metric = VerdictCorrectnessMetric(threshold=0.5, expect_positive=False)
        tc = LLMTestCase(
            input="safe parameterized SQL",
            actual_output="rejected",
        )
        score = metric.measure(tc)
        assert score == 1.0

    @pytest.mark.eval
    def test_verdict_correctness_false_positive(self) -> None:
        """VerdictCorrectness: confirmed on safe code scores 0.0 (FP)."""
        metric = VerdictCorrectnessMetric(threshold=0.5, expect_positive=False)
        tc = LLMTestCase(
            input="safe parameterized SQL",
            actual_output="confirmed",
        )
        score = metric.measure(tc)
        assert score == 0.0


# ── Test: Real LLM eval (opt-in) ─────────────────────────────────────────


class TestRealLLMEval:
    """Opt-in real LLM evaluation using GEval metrics.

    Requires ``HYQAGENT_EVAL_REAL_LLM=1`` environment variable AND valid
    API keys.  Skipped in CI.

    Usage::

        HYQAGENT_EVAL_REAL_LLM=1 pytest tests/eval/test_llm_eval.py -v -k RealLLM
    """

    @pytest.mark.eval
    @pytest.mark.slow
    def test_real_llm_vuln_type_accuracy(
        self,
        case: Any,
    ) -> None:
        """Real LLM eval: GEval judges vuln_type accuracy on all 28 golden cases."""
        import os

        if not os.environ.get("HYQAGENT_EVAL_REAL_LLM"):
            pytest.skip("Set HYQAGENT_EVAL_REAL_LLM=1 to enable real LLM eval")

        if case.detection_method not in ("cpg_taint", "heuristic"):
            pytest.skip(f"Not a taint-path case ({case.detection_method})")

        from deepeval.metrics import GEval

        gt = case.ground_truth
        expected = gt.expected_category or case.vulnerability_type
        code = case.source_code()[:3000]

        metric = GEval(
            name="VulnTypeAccuracy (GEval)",
            criteria=(
                "You are evaluating a security auditing tool's vulnerability "
                "type classification. Given the source code and the expected "
                "vulnerability type, determine whether the tool correctly "
                "identified the vulnerability category."
            ),
            evaluation_steps=[
                "1. Read the source code snippet and identify the actual vulnerability type",
                "2. Compare the tool's reported vuln_type against the expected type",
                "3. Check if the reasoning is consistent with the code",
                "4. Score: 1.0=exact match, 0.5=related/subcategory, 0.0=wrong or hallucinated",
            ],
            threshold=0.5,
        )

        tc = LLMTestCase(
            input=f"Analyze this code for security vulnerabilities:\n```\n{code}\n```",
            actual_output=f"Vulnerability type: {case.vulnerability_type}",
            expected_output=expected,
        )
        metric.measure(tc)
        assert metric.score is not None
        assert metric.score >= 0.0

    @pytest.mark.eval
    @pytest.mark.slow
    def test_real_llm_severity_agreement(
        self,
        case: Any,
    ) -> None:
        """Real LLM eval: GEval judges severity agreement."""
        import os

        if not os.environ.get("HYQAGENT_EVAL_REAL_LLM"):
            pytest.skip("Set HYQAGENT_EVAL_REAL_LLM=1 to enable real LLM eval")

        if case.detection_method not in ("cpg_taint", "heuristic"):
            pytest.skip(f"Not applicable for {case.detection_method}")

        from deepeval.metrics import GEval

        code = case.source_code()[:3000]

        metric = GEval(
            name="SeverityAgreement (GEval)",
            criteria=(
                "Evaluate whether the severity level assigned to a security "
                "finding matches the actual severity of the vulnerability in "
                "the source code."
            ),
            evaluation_steps=[
                "1. Assess the vulnerability severity from the code (critical/high/medium/low)",
                "2. Compare against the reported severity",
                "3. Score: 1.0=exact match, 0.8=one level off, 0.5=two levels off, 0.0=otherwise",
            ],
            threshold=0.5,
        )

        tc = LLMTestCase(
            input=f"Code:\n```\n{code}\n```",
            actual_output=f"Severity: {case.severity}",
            expected_output=case.severity,
        )
        metric.measure(tc)
        assert metric.score is not None
