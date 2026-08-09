"""Tests for scanner/completeness.py — CompletenessCritic prompt building and schema."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from hyqagent.scanner.completeness import (
    CRITIC_SCHEMA,
    CompletenessCritic,
    CompletenessReport,
    build_critic_prompt,
)


class TestCompletenessReport:
    def test_defaults(self) -> None:
        report = CompletenessReport(overall_assessment="All good")
        assert report.overall_assessment == "All good"
        assert report.missed_vuln_classes == []
        assert report.recommendations == []


class TestCriticSchema:
    def test_schema_structure(self) -> None:
        assert CRITIC_SCHEMA["name"] == "report_completeness"
        props = CRITIC_SCHEMA["input_schema"]["properties"]
        assert "overall_assessment" in props
        assert "missed_vuln_classes" in props
        assert "skipped_code_paths" in props
        assert "questionable_assumptions" in props
        assert "framework_specific_blind_spots" in props
        assert "recommendations" in props

    def test_required_fields(self) -> None:
        required = CRITIC_SCHEMA["input_schema"]["required"]
        assert "overall_assessment" in required
        assert "missed_vuln_classes" in required
        assert "recommendations" in required


class TestBuildCriticPrompt:
    def test_minimal_prompt(self) -> None:
        prompt = build_critic_prompt(language="python")
        assert "python" in prompt
        assert "Completeness Review Questions" in prompt

    def test_prompt_with_findings(self) -> None:
        prompt = build_critic_prompt(
            findings_summary="- [HIGH] sql_injection at app.py:42",
            language="javascript",
        )
        assert "sql_injection" in prompt
        assert "javascript" in prompt

    def test_prompt_with_label_breakdown(self) -> None:
        prompt = build_critic_prompt(
            label_breakdown={"heuristic_sink": 5, "confirmed_taint": 10},
            language="python",
        )
        assert "heuristic_sink" in prompt
        assert "5 paths" in prompt
        assert "confirmed_taint" in prompt

    def test_prompt_with_coverage_data(self) -> None:
        prompt = build_critic_prompt(
            coverage={"total_endpoints": 20, "analyzed": 15},
            language="java",
        )
        assert "total_endpoints" in prompt
        assert "Coverage Summary" in prompt

    def test_prompt_includes_label_key_explanation(self) -> None:
        prompt = build_critic_prompt(
            label_breakdown={"heuristic_sink": 3},
        )
        assert "heuristic_sink" in prompt.lower()
        assert "couldn't classify" in prompt.lower()

    def test_prompt_includes_hypotheses(self) -> None:
        prompt = build_critic_prompt(
            hypotheses=[
                {
                    "severity": "high",
                    "vuln_type": "sql_injection",
                    "confidence": 0.9,
                    "title": "SQLi in login",
                },
            ],
        )
        assert "SQLi in login" in prompt

    def test_prompt_truncates_many_hypotheses(self) -> None:
        """Should not include more than 15 hypotheses in the prompt."""
        many = [
            {"severity": "low", "vuln_type": "xss", "confidence": 0.5, "title": f"XSS {i}"}
            for i in range(30)
        ]
        prompt = build_critic_prompt(hypotheses=many)
        # Should mention total count
        assert "30 total" in prompt
        # Should only show first 15
        assert "XSS 0" in prompt
        assert "XSS 29" not in prompt


class TestCompletenessCritic:
    def _make_mock_provider(self, return_value: dict | None = None) -> MagicMock:
        if return_value is None:
            return_value = {
                "overall_assessment": "The audit covered most SQL and XSS paths.",
                "missed_vuln_classes": ["IDOR", "SSRF", "business_logic"],
                "skipped_code_paths": [],
                "questionable_assumptions": ["Assumed ORM always parameterizes"],
                "framework_specific_blind_spots": ["Django raw() not checked"],
                "recommendations": [
                    "Check all Django raw() queryset calls",
                    "Add IDOR detection for order/user endpoints",
                ],
            }
        provider = MagicMock()
        provider.generate_structured = AsyncMock(return_value=return_value)
        return provider

    @pytest.mark.asyncio
    async def test_review_success(self) -> None:
        provider = self._make_mock_provider()
        critic = CompletenessCritic(provider, "claude-sonnet-5")

        report = await critic.review(
            project_summary="Flask e-commerce app",
            findings_summary="- [HIGH] SQL injection at orders.py:42",
            label_breakdown={"heuristic_sink": 5, "confirmed_taint": 10},
            language="python",
        )

        assert isinstance(report, CompletenessReport)
        assert len(report.missed_vuln_classes) > 0
        assert len(report.recommendations) > 0

    @pytest.mark.asyncio
    async def test_review_calls_provider_correctly(self) -> None:
        provider = self._make_mock_provider()
        critic = CompletenessCritic(provider, "claude-sonnet-5")

        await critic.review(language="python")

        # Verify provider was called with structured output
        call_kwargs = provider.generate_structured.call_args.kwargs
        assert call_kwargs["model"] == "claude-sonnet-5"
        assert call_kwargs["output_schema"] == CRITIC_SCHEMA
        assert "completeness" in call_kwargs["system"].lower()

    @pytest.mark.asyncio
    async def test_review_handles_provider_error(self) -> None:
        provider = MagicMock()
        provider.generate_structured = AsyncMock(side_effect=RuntimeError("API error"))
        critic = CompletenessCritic(provider, "test-model")

        report = await critic.review(language="python")
        assert "could not reach" in report.overall_assessment.lower()
        assert len(report.recommendations) > 0

    @pytest.mark.asyncio
    async def test_review_no_data_succeeds(self) -> None:
        provider = self._make_mock_provider()
        critic = CompletenessCritic(provider, "test-model")

        report = await critic.review()
        assert isinstance(report, CompletenessReport)
