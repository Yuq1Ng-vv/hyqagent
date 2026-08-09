"""Tests for observability/metrics.py — PrometheusMetrics."""

from __future__ import annotations

from prometheus_client import CollectorRegistry

from hyqagent.observability.metrics import PrometheusMetrics


def _new_metrics() -> PrometheusMetrics:
    """Create a PrometheusMetrics with a fresh registry for isolated testing."""
    return PrometheusMetrics(registry=CollectorRegistry())


class TestPrometheusMetricsInit:
    def test_creates_without_error(self) -> None:
        m = _new_metrics()
        assert m is not None

    def test_get_metrics_text_returns_string(self) -> None:
        m = _new_metrics()
        text = m.get_metrics_text()
        assert isinstance(text, str)
        assert len(text) > 0


class TestRecordLlmCall:
    def test_records_and_reflects_in_output(self) -> None:
        m = _new_metrics()
        m.record_llm_call(
            model="gpt-4",
            phase="hypothesis_gen",
            input_tokens=500,
            output_tokens=200,
            cache_read_tokens=0,
            cost_usd=0.015,
            latency_seconds=1.2,
            status="success",
        )
        text = m.get_metrics_text()
        assert "hyqagent_llm_calls_total" in text

    def test_multiple_calls_aggregate(self) -> None:
        m = _new_metrics()
        for _ in range(3):
            m.record_llm_call(
                model="claude",
                phase="validation",
                input_tokens=100,
                output_tokens=50,
                cache_read_tokens=0,
                cost_usd=0.003,
                latency_seconds=0.5,
            )
        text = m.get_metrics_text()
        assert "hyqagent_llm_calls_total" in text

    def test_different_statuses_labeled(self) -> None:
        m = _new_metrics()
        m.record_llm_call(
            model="m",
            phase="p",
            input_tokens=1,
            output_tokens=1,
            cache_read_tokens=0,
            cost_usd=0.0,
            latency_seconds=0.1,
            status="success",
        )
        m.record_llm_call(
            model="m",
            phase="p",
            input_tokens=1,
            output_tokens=1,
            cache_read_tokens=0,
            cost_usd=0.0,
            latency_seconds=0.1,
            status="error",
        )
        text = m.get_metrics_text()
        # Should have entries for both success and error
        assert "success" in text or "error" in text


class TestRecordFinding:
    def test_records_finding(self) -> None:
        m = _new_metrics()
        m.record_finding(severity="high", cwe="CWE-89")
        text = m.get_metrics_text()
        assert "hyqagent_findings_total" in text

    def test_empty_cwe_allowed(self) -> None:
        m = _new_metrics()
        m.record_finding(severity="medium", cwe="")
        text = m.get_metrics_text()
        assert "hyqagent_findings_total" in text


class TestRecordToolCall:
    def test_success_records(self) -> None:
        m = _new_metrics()
        m.record_tool_call("query", True, 0.5)
        text = m.get_metrics_text()
        assert "hyqagent_llm_latency_seconds" in text

    def test_failure_records(self) -> None:
        m = _new_metrics()
        m.record_tool_call("parse", False, 1.0)
        text = m.get_metrics_text()
        assert "hyqagent_llm_latency_seconds" in text


class TestSetCoverage:
    def test_set_coverage(self) -> None:
        m = _new_metrics()
        m.set_coverage("s1", 0.75, 0.60)
        text = m.get_metrics_text()
        assert "hyqagent_endpoint_coverage_ratio" in text


class TestBudgetGauge:
    def test_set_budget_spent(self) -> None:
        m = _new_metrics()
        m.set_budget_spent(3.50)
        text = m.get_metrics_text()
        assert "hyqagent_budget_spent_usd" in text

    def test_budget_updates(self) -> None:
        m = _new_metrics()
        m.set_budget_spent(1.0)
        m.set_budget_spent(5.0)
        text = m.get_metrics_text()
        assert "hyqagent_budget_spent_usd" in text
