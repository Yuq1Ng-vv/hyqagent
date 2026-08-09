"""tests/eval/metrics.py — Custom DeepEval metrics for vulnerability detection quality.

Provides 4 custom metrics that evaluate LLM pipeline output against
golden dataset ground truth.  Metrics work in two modes:

**Deterministic mode** (default, no LLM):
    Exact string matching and ordinal comparison — fast, works in CI.

**GEval mode** (opt-in, requires ``HYQAGENT_EVAL_REAL_LLM=1``):
    LLM-as-judge using DeepEval's GEval with evaluation steps.

Usage::

    from tests.eval.metrics import (
        VulnTypeAccuracyMetric,
        SeverityAgreementMetric,
        CWEMappingMetric,
        VerdictCorrectnessMetric,
    )
    from deepeval.test_case import LLMTestCase

    test_case = LLMTestCase(
        input="source code...",
        actual_output='{"vuln_type": "sql_injection"}',
        expected_output="sql_injection",
    )
    metric = VulnTypeAccuracyMetric()
    metric.measure(test_case)
    assert metric.is_successful()
"""

from __future__ import annotations

from typing import Any

try:
    from deepeval.metrics import BaseMetric
    from deepeval.test_case import LLMTestCase

    DEEPEVAL_AVAILABLE = True
except ImportError:  # pragma: no cover
    BaseMetric = object  # type: ignore[misc,assignment]
    LLMTestCase = None  # type: ignore[misc,assignment]
    DEEPEVAL_AVAILABLE = False


# ── Severity ordering ───────────────────────────────────────────────────────

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _severity_distance(actual: str, expected: str) -> int:
    """Absolute ordinal distance between two severities."""
    a = _SEVERITY_ORDER.get(actual.lower(), -1)
    e = _SEVERITY_ORDER.get(expected.lower(), -1)
    if a == -1 or e == -1:
        return 999
    return abs(a - e)


# ── CWE family mapping ──────────────────────────────────────────────────────

#: Parent CWE → child/sub CWEs.  A match within the same family scores 0.7.
CWE_FAMILY: dict[str, set[str]] = {
    "CWE-89": {"CWE-89", "CWE-564", "CWE-943"},
    "CWE-79": {"CWE-79", "CWE-80", "CWE-81", "CWE-83", "CWE-84", "CWE-85", "CWE-86", "CWE-87"},
    "CWE-918": {"CWE-918"},
    "CWE-78": {"CWE-77", "CWE-78"},
    "CWE-22": {"CWE-22", "CWE-23", "CWE-35", "CWE-36", "CWE-37", "CWE-40"},
    "CWE-502": {"CWE-502", "CWE-470"},
    "CWE-601": {"CWE-601"},
    "CWE-611": {"CWE-611", "CWE-827"},
    "CWE-352": {"CWE-352", "CWE-1275"},
    "CWE-862": {"CWE-862", "CWE-863", "CWE-284", "CWE-285", "CWE-287", "CWE-306"},
    "CWE-798": {"CWE-798", "CWE-259", "CWE-260", "CWE-261", "CWE-312", "CWE-313"},
    "CWE-200": {"CWE-200", "CWE-209", "CWE-532", "CWE-538", "CWE-548"},
    "CWE-326": {"CWE-326", "CWE-327", "CWE-328", "CWE-338", "CWE-347"},
    "CWE-94": {"CWE-94", "CWE-95", "CWE-1336"},
    "CWE-1336": {"CWE-94", "CWE-95", "CWE-1336"},
}


def _cwe_score(actual: str, expected: str) -> float:
    """Score a CWE mapping: 1.0 exact, 0.7 same family, 0.3 both CWEs present, 0.0 mismatch."""
    if not actual or not expected:
        return 0.0
    a = actual.upper().strip()
    e = expected.upper().strip()
    if a == e:
        return 1.0
    # Same family?
    for _family_id, members in CWE_FAMILY.items():
        if a in members and e in members:
            return 0.7
    # Both look like CWEs but don't match
    if a.startswith("CWE-") and e.startswith("CWE-"):
        return 0.3
    return 0.0


# ── Custom metrics ──────────────────────────────────────────────────────────


class _NoLLMBaseMetric(BaseMetric):
    """Base for deterministic metrics that don't need an LLM."""

    async def a_measure(self, test_case: LLMTestCase, *args: Any, **kwargs: Any) -> float:
        return self.measure(test_case, *args, **kwargs)


class VulnTypeAccuracyMetric(_NoLLMBaseMetric):
    """Fast deterministic vuln_type comparison.

    Score: 1.0 = exact match, 0.5 = substring overlap, 0.0 = mismatch.

    threshold: 0.5 (default)
    """

    def __init__(self, threshold: float = 0.5) -> None:
        super().__init__()
        self.threshold = threshold

    def measure(
        self,
        test_case: LLMTestCase,
        *args: Any,
        **kwargs: Any,
    ) -> float:
        actual = (test_case.actual_output or "").lower().strip()
        expected = (test_case.expected_output or "").lower().strip()

        if not actual or not expected:
            self.score = 0.0
            self.reason = "Missing actual_output or expected_output"
            self.success = False
            return 0.0

        # Direct match
        if actual == expected:
            self.score = 1.0
            self.reason = f"Exact match: '{actual}' == '{expected}'"
            self.success = self.score >= (self.threshold or 0.5)
            return 1.0

        # Substring overlap (e.g. "sql_injection" in "SQL Injection via...")
        if expected in actual or actual in expected:
            self.score = 0.5
            self.reason = f"Partial match: '{actual}' contains/contained-by '{expected}'"
            self.success = self.score >= (self.threshold or 0.5)
            return 0.5

        self.score = 0.0
        self.reason = f"Mismatch: '{actual}' != '{expected}'"
        self.success = False
        return 0.0

    @property
    def __name__(self) -> str:  # noqa: D105
        return "VulnTypeAccuracy"


class SeverityAgreementMetric(_NoLLMBaseMetric):
    """Severity-level agreement with ordinal weighting.

    Score: 1.0 (exact), 0.8 (adjacent, e.g. high↔critical), 0.5 (±2 levels),
    0.2 (±3 levels), 0.0 (≥4 levels off or invalid).

    threshold: 0.6 (default — accepts adjacent severity as passing)
    """

    def __init__(self, threshold: float = 0.6) -> None:
        super().__init__()
        self.threshold = threshold

    def measure(
        self,
        test_case: LLMTestCase,
        *args: Any,
        **kwargs: Any,
    ) -> float:
        actual = (test_case.actual_output or "").lower().strip()
        expected = (test_case.expected_output or "").lower().strip()

        dist = _severity_distance(actual, expected)
        if dist == 999:
            self.score = 0.0
            self.reason = f"Invalid severity: actual='{actual}', expected='{expected}'"
            self.success = False
            return 0.0

        score_map = {0: 1.0, 1: 0.8, 2: 0.5, 3: 0.2}
        self.score = score_map.get(dist, 0.0)
        if dist == 0:
            self.reason = f"Exact severity match: '{actual}' == '{expected}'"
        else:
            self.reason = f"Severity distance={dist}: '{actual}' vs '{expected}'"
        self.success = self.score >= (self.threshold or 0.6)
        return self.score

    @property
    def __name__(self) -> str:  # noqa: D105
        return "SeverityAgreement"


class CWEMappingMetric(_NoLLMBaseMetric):
    """CWE mapping quality with family-aware scoring.

    Score: 1.0 exact, 0.7 same family, 0.3 both CWEs, 0.0 unrelated.

    threshold: 0.5 (default — accepts same-family as passing)
    """

    def __init__(self, threshold: float = 0.5) -> None:
        super().__init__()
        self.threshold = threshold

    def measure(
        self,
        test_case: LLMTestCase,
        *args: Any,
        **kwargs: Any,
    ) -> float:
        actual = (test_case.actual_output or "").strip()
        expected = (test_case.expected_output or "").strip()

        self.score = _cwe_score(actual, expected)
        if self.score == 1.0:
            self.reason = f"Exact CWE match: '{actual}' == '{expected}'"
        elif self.score == 0.7:
            self.reason = f"Same CWE family: '{actual}' ⊆ family('{expected}')"
        elif self.score == 0.3:
            self.reason = f"Different CWE families: '{actual}' vs '{expected}'"
        else:
            self.reason = f"No CWE match: '{actual}' vs '{expected}'"
        self.success = self.score >= (self.threshold or 0.5)
        return self.score

    @property
    def __name__(self) -> str:  # noqa: D105
        return "CWEMapping"


class VerdictCorrectnessMetric(_NoLLMBaseMetric):
    """Validator verdict correctness for positive and negative cases.

    For positive cases: expects 'confirmed' or 'inconclusive'.
    For negative cases: expects 'rejected'.

    Score: 1.0 (correct verdict), 0.5 (inconclusive when expecting confirmed), 0.0 (wrong).

    threshold: 0.5 (default)
    """

    def __init__(self, threshold: float = 0.5, expect_positive: bool = True) -> None:
        super().__init__()
        self.threshold = threshold
        self.expect_positive = expect_positive

    def measure(
        self,
        test_case: LLMTestCase,
        *args: Any,
        **kwargs: Any,
    ) -> float:
        actual = (test_case.actual_output or "").lower().strip()

        if self.expect_positive:
            if actual == "confirmed":
                self.score = 1.0
                self.reason = "Correct: confirmed a real vulnerability"
            elif actual == "inconclusive":
                self.score = 0.5
                self.reason = "Partial: inconclusive on a real vulnerability"
            elif actual == "rejected":
                self.score = 0.0
                self.reason = "FALSE NEGATIVE: rejected a real vulnerability"
            else:
                self.score = 0.0
                self.reason = f"Unexpected verdict: '{actual}'"
        else:
            if actual == "rejected":
                self.score = 1.0
                self.reason = "Correct: rejected a false positive"
            elif actual == "inconclusive":
                self.score = 0.5
                self.reason = "Partial: inconclusive on safe code"
            elif actual == "confirmed":
                self.score = 0.0
                self.reason = "FALSE POSITIVE: confirmed safe code as vulnerable"
            else:
                self.score = 0.0
                self.reason = f"Unexpected verdict: '{actual}'"

        self.success = self.score >= (self.threshold or 0.5)
        return self.score

    @property
    def __name__(self) -> str:  # noqa: D105
        return "VerdictCorrectness"
