"""Tests for observability/tracer.py — SpanEvent, ObservabilityManager."""

from __future__ import annotations

from unittest.mock import MagicMock

from hyqagent.observability.cost_tracker import CostTracker
from hyqagent.observability.tracer import ObservabilityManager, SpanEvent


class TestSpanEvent:
    def test_creation_defaults(self) -> None:
        s = SpanEvent(
            trace_id="trace-1",
            span_id="span-1",
            parent_span_id=None,
            name="test",
            start_time=100.0,
        )
        assert s.trace_id == "trace-1"
        assert s.span_id == "span-1"
        assert s.parent_span_id is None
        assert s.name == "test"
        assert s.end_time == 0.0
        assert s.attributes == {}

    def test_duration_zero_before_end(self) -> None:
        s = SpanEvent(
            trace_id="t1",
            span_id="s1",
            parent_span_id=None,
            name="x",
            start_time=200.0,
        )
        assert s.duration_ms == 0.0

    def test_duration_after_end(self) -> None:
        s = SpanEvent(
            trace_id="t1",
            span_id="s1",
            parent_span_id=None,
            name="x",
            start_time=100.0,
            end_time=101.5,
        )
        assert s.duration_ms == 1500.0

    def test_to_dict_basic(self) -> None:
        s = SpanEvent(
            trace_id="abc",
            span_id="def",
            parent_span_id=None,
            name="llm_call",
            start_time=100.0,
            end_time=101.0,
            attributes={"model": "sonnet"},
        )
        d = s.to_dict()
        assert d["trace_id"] == "abc"
        assert d["span_id"] == "def"
        assert "parent_span_id" not in d
        assert d["name"] == "llm_call"
        assert d["duration_ms"] == 1000.0
        assert d["attributes"]["model"] == "sonnet"

    def test_to_dict_with_parent(self) -> None:
        s = SpanEvent(
            trace_id="a",
            span_id="b",
            parent_span_id="c",
            name="child",
            start_time=1.0,
            end_time=2.0,
        )
        d = s.to_dict()
        assert d["parent_span_id"] == "c"

    def test_attributes_set_on_end(self) -> None:
        s = SpanEvent(
            trace_id="t1",
            span_id="s1",
            parent_span_id=None,
            name="tool",
            start_time=1.0,
        )
        s.end_time = 2.0
        s.attributes["status"] = "ok"
        assert s.duration_ms == 1000.0
        assert s.attributes["status"] == "ok"


class TestObservabilityManager:
    def test_start_end_span(self) -> None:
        obs = ObservabilityManager(session_id="test")
        span = obs.start_span("test_phase", attributes={"key": "val"})
        assert span.name == "test_phase"
        assert span.attributes["key"] == "val"
        assert span.trace_id is not None

        obs.end_span(span, status="done")
        assert span.end_time > 0
        assert span.attributes["status"] == "done"

    def test_nested_spans_share_trace_id(self) -> None:
        obs = ObservabilityManager(session_id="test")
        parent = obs.start_span("parent")
        child = obs.start_span("child", parent=parent)
        assert child.trace_id == parent.trace_id
        assert child.parent_span_id == parent.span_id

    def test_trace_id_cleared_on_flush(self) -> None:
        obs = ObservabilityManager(session_id="test")
        obs.start_span("span1")
        obs.flush()
        assert obs.spans == []
        # New span gets a new trace_id
        span2 = obs.start_span("span2")
        assert span2.trace_id is not None

    def test_record_llm_call_updates_cost_tracker(self) -> None:
        ct = CostTracker(max_budget=10.0)
        obs = ObservabilityManager(cost_tracker=ct, session_id="test")
        obs.record_llm_call(
            model="sonnet",
            phase="test-phase",
            input_tokens=1000,
            output_tokens=500,
            latency_ms=200.0,
            hypothesis_id="h-1",
        )
        assert ct.total_cost() > 0
        summary = ct.summary()
        assert summary.total_calls == 1

    def test_record_llm_call_with_metrics_delegates(self) -> None:
        mock_metrics = MagicMock()
        ct = CostTracker()
        obs = ObservabilityManager(
            cost_tracker=ct,
            metrics=mock_metrics,
            session_id="test",
        )
        obs.record_llm_call(
            model="claude",
            phase="hypothesis_gen",
            input_tokens=200,
            output_tokens=100,
            cache_read_tokens=50,
            latency_ms=1500.0,
            hypothesis_id="h-42",
            status="success",
        )
        mock_metrics.record_llm_call.assert_called_once()
        call = mock_metrics.record_llm_call.call_args
        assert call.kwargs["model"] == "claude"
        assert call.kwargs["phase"] == "hypothesis_gen"
        assert call.kwargs["input_tokens"] == 200
        assert call.kwargs["output_tokens"] == 100
        assert call.kwargs["status"] == "success"

    def test_metrics_failure_does_not_crash(self) -> None:
        mock_metrics = MagicMock()
        mock_metrics.record_llm_call.side_effect = RuntimeError("boom")
        obs = ObservabilityManager(
            metrics=mock_metrics,
            session_id="test",
        )
        # Should not raise
        obs.record_llm_call(
            model="m",
            phase="p",
            input_tokens=1,
            output_tokens=1,
        )
        obs.record_finding(severity="high", cwe="CWE-89")
        obs.record_tool_call("query", True, 0.1)
        obs.set_coverage("s1", 0.5, 0.3)

    def test_record_finding_delegates(self) -> None:
        mock_metrics = MagicMock()
        obs = ObservabilityManager(metrics=mock_metrics, session_id="test")
        obs.record_finding(severity="critical", cwe="CWE-78")
        mock_metrics.record_finding.assert_called_once_with(
            severity="critical",
            cwe="CWE-78",
        )

    def test_record_tool_call_delegates(self) -> None:
        mock_metrics = MagicMock()
        obs = ObservabilityManager(metrics=mock_metrics, session_id="test")
        obs.record_tool_call("cpg_query", True, 0.3)
        mock_metrics.record_tool_call.assert_called_once_with(
            tool_name="cpg_query",
            success=True,
            latency_seconds=0.3,
        )

    def test_set_coverage_delegates(self) -> None:
        mock_metrics = MagicMock()
        obs = ObservabilityManager(metrics=mock_metrics, session_id="test")
        obs.set_coverage("s1", 0.8, 0.7)
        mock_metrics.set_coverage.assert_called_once_with(
            session_id="s1",
            endpoint=0.8,
            risk_weighted=0.7,
        )

    def test_cost_tracker_accessible(self) -> None:
        ct = CostTracker()
        obs = ObservabilityManager(cost_tracker=ct)
        assert obs.cost_tracker is ct

    def test_default_cost_tracker_when_none(self) -> None:
        obs = ObservabilityManager()
        assert obs.cost_tracker is not None
        assert isinstance(obs.cost_tracker, CostTracker)
