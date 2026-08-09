"""Tests for scanner/validator.py — L1 deterministic validation logic.

L2 tests (LLM-powered) are in test_validator_integration.py and
require a running provider (marked slow).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from hyqagent.scanner.validator import (
    VALIDATOR_SCHEMA,
    ValidationResult,
    Validator,
    _build_validation_prompt,
)


class TestValidationResult:
    def test_defaults(self) -> None:
        result = ValidationResult(
            hypothesis_id="hyp-001",
            verdict="confirmed",
            confidence=0.85,
            validation_type="l1_deterministic",
            reasoning="All checks passed",
        )
        assert result.hypothesis_id == "hyp-001"
        assert result.verdict == "confirmed"
        assert result.confidence == 0.85
        assert result.evidence == []
        assert result.model == ""


class TestValidationPrompt:
    def test_basic_prompt(self) -> None:
        from hyqagent.scanner.hypothesis import Hypothesis

        hyp = Hypothesis(
            id="hyp-001",
            vuln_type="sql_injection",
            cwe_id="CWE-89",
            severity="high",
            confidence=0.9,
            title="SQL injection in login",
            description="User input flows into raw SQL query",
            source_location="app.py:15",
            sink_location="app.py:42",
            evidence='db.execute(f"SELECT * FROM users WHERE name={name}")',
            reasoning="No parameterization detected",
        )
        prompt = _build_validation_prompt(hyp, "def login(): ...")
        assert "sql_injection" in prompt
        assert "CWE-89" in prompt
        assert "app.py:15" in prompt
        assert "app.py:42" in prompt
        assert "def login()" in prompt

    def test_prompt_with_sanitizer_info(self) -> None:
        from hyqagent.scanner.hypothesis import Hypothesis

        hyp = Hypothesis(
            id="hyp-002",
            vuln_type="xss",
            cwe_id="CWE-79",
            severity="medium",
            confidence=0.7,
            title="XSS in comment",
            description="User comment rendered without escaping",
            source_location="views.py:20",
            sink_location="views.py:25",
            evidence="{{ comment }}",
            reasoning="Template may not auto-escape",
        )
        prompt = _build_validation_prompt(
            hyp, "def comment(): ...", sanitizer_info="jinja2 autoescape=True"
        )
        assert "jinja2 autoescape=True" in prompt


class TestValidatorSchema:
    def test_schema_structure(self) -> None:
        assert VALIDATOR_SCHEMA["name"] == "report_validation"
        props = VALIDATOR_SCHEMA["input_schema"]["properties"]
        assert "verdict" in props
        assert "confidence" in props
        assert "q1_reachability" in props
        assert "q5_judgment" in props
        assert "exploit_scenario" in props

    def test_verdict_valid_values(self) -> None:
        verdicts = VALIDATOR_SCHEMA["input_schema"]["properties"]["verdict"]["enum"]
        assert "confirmed" in verdicts
        assert "rejected" in verdicts
        assert "inconclusive" in verdicts
        assert "needs_human" in verdicts


class TestValidatorL1:
    """L1 deterministic validation tests — no LLM required."""

    @pytest.fixture
    def mock_taint_loader(self) -> MagicMock:
        tl = MagicMock()
        tl.match_all_sources.return_value = []
        tl.match_sink.return_value = None
        return tl

    @pytest.fixture
    def validator(self, mock_taint_loader: MagicMock) -> Validator:
        return Validator(
            query=MagicMock(),
            taint_loader=mock_taint_loader,
            router=MagicMock(),
            mid_provider=MagicMock(),
            strong_provider=MagicMock(),
            language="python",
        )

    def _make_hypothesis(self, **kwargs: object) -> object:
        from hyqagent.scanner.hypothesis import Hypothesis

        defaults: dict[str, object] = {
            "id": "hyp-test",
            "vuln_type": "sql_injection",
            "cwe_id": "CWE-89",
            "severity": "high",
            "confidence": 0.8,
            "title": "Test",
            "description": "Test desc",
            "source_location": "app.py:10",
            "sink_location": "app.py:50",
            "evidence": 'execute("SELECT ...")',
            "reasoning": "No sanitization",
        }
        defaults.update(kwargs)
        return Hypothesis(**defaults)  # type: ignore[arg-type]

    def test_l1_all_match_confirms(
        self, validator: Validator, mock_taint_loader: MagicMock
    ) -> None:
        """When source and sink types match, L1 confirms."""
        mock_taint_loader.match_all_sources.return_value = ["sql_injection"]
        mock_taint_loader.match_sink.return_value = "sql_injection"

        result = validator.validate_l1(self._make_hypothesis())
        assert result.verdict == "confirmed"
        assert result.validation_type == "l1_deterministic"
        assert result.confidence >= 0.8

    def test_l1_multiple_mismatches_reject(
        self, validator: Validator, mock_taint_loader: MagicMock
    ) -> None:
        """When both source and sink types mismatch, L1 rejects."""
        mock_taint_loader.match_all_sources.return_value = ["xss"]
        mock_taint_loader.match_sink.return_value = "command_injection"

        result = validator.validate_l1(self._make_hypothesis())
        assert result.verdict == "rejected"
        assert result.confidence < 0.5

    def test_l1_single_mismatch_inconclusive(
        self, validator: Validator, mock_taint_loader: MagicMock
    ) -> None:
        """Single mismatch → inconclusive (let L2 sort it out)."""
        mock_taint_loader.match_all_sources.return_value = ["xss"]
        mock_taint_loader.match_sink.return_value = "sql_injection"

        result = validator.validate_l1(self._make_hypothesis())
        assert result.verdict == "inconclusive"

    def test_l1_no_source_match_but_sink_matches(
        self, validator: Validator, mock_taint_loader: MagicMock
    ) -> None:
        """Source type unknown but sink matches → inconclusive."""
        mock_taint_loader.match_all_sources.return_value = []
        mock_taint_loader.match_sink.return_value = "sql_injection"

        result = validator.validate_l1(self._make_hypothesis())
        assert result.verdict == "confirmed"

    def test_l1_no_evidence_no_mismatch_ok(
        self, validator: Validator, mock_taint_loader: MagicMock
    ) -> None:
        """L1 should handle hypotheses without evidence gracefully."""
        hyp = self._make_hypothesis(evidence="")
        result = validator.validate_l1(hyp)
        assert result.verdict in ("confirmed", "inconclusive")

    def test_l1_evidence_tracking(self, validator: Validator, mock_taint_loader: MagicMock) -> None:
        """L1 should record evidence for each check."""
        mock_taint_loader.match_all_sources.return_value = ["sql_injection"]
        mock_taint_loader.match_sink.return_value = "sql_injection"

        result = validator.validate_l1(self._make_hypothesis())
        assert len(result.evidence) >= 2  # at least source + sink checks
