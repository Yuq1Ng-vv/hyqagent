"""observability/tracer.py — ObservabilityManager: spans, cost, metrics, audit trail.

Coordinates :class:`CostTracker`, :class:`PrometheusMetrics`, and :class:`AuditTrail`
behind a single facade.  No external SDK dependency — spans are emitted as structured
JSON via *structlog*.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import structlog

from hyqagent.observability.cost_tracker import CostTracker

logger = structlog.get_logger(__name__)


# ── Span event ─────────────────────────────────────────────────────────────────


@dataclass
class SpanEvent:
    """A structured trace span — OTel-compatible JSON shape.

    Each span has a unique *trace_id* / *span_id* pair and optional
    *parent_span_id* for nesting.  Attributes carry domain data (model,
    phase, token counts, cost, status, …).
    """

    trace_id: str
    span_id: str
    parent_span_id: str | None
    name: str
    start_time: float
    end_time: float = 0.0
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ms(self) -> float:
        """Elapsed wall-clock time in milliseconds."""
        if self.end_time <= self.start_time:
            return 0.0
        return (self.end_time - self.start_time) * 1000

    def to_dict(self) -> dict[str, Any]:
        """OTel-compatible JSON representation."""
        d: dict[str, Any] = {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "name": self.name,
            "start_time_unix_nano": int(self.start_time * 1e9),
            "end_time_unix_nano": int(self.end_time * 1e9)
            if self.end_time
            else 0,
            "duration_ms": round(self.duration_ms, 3),
        }
        if self.parent_span_id:
            d["parent_span_id"] = self.parent_span_id
        if self.attributes:
            d["attributes"] = self.attributes
        return d


# ── ObservabilityManager ──────────────────────────────────────────────────────


class ObservabilityManager:
    """Central observability coordinator — no external SDK deps.

    Wraps :class:`CostTracker`, :class:`PrometheusMetrics`, and :class:`AuditTrail`.
    Emits structured span events via *structlog* so downstream consumers
    (log aggregators, SIEMs, local JSONL files) can ingest them.

    Typical usage::

        obs = ObservabilityManager(cost_tracker=CostTracker(),
                                    metrics=PrometheusMetrics(),
                                    audit_trail=AuditTrail("sess-1"),
                                    session_id="sess-1")
        span = obs.start_span("llm_call", attributes={"model": "claude-sonnet-5"})
        # … LLM call …
        obs.end_span(span, status="success", input_tokens=1200, output_tokens=300)
        obs.record_finding(severity="high", cwe="CWE-89")
    """

    def __init__(
        self,
        *,
        cost_tracker: CostTracker | None = None,
        metrics: Any = None,  # PrometheusMetrics  (lazy import to avoid circ)
        audit_trail: Any = None,  # AuditTrail
        session_id: str = "",
    ) -> None:
        self._cost_tracker = cost_tracker or CostTracker()
        self._metrics = metrics
        self._audit_trail = audit_trail
        self._session_id = session_id
        self._spans: list[SpanEvent] = []
        self._current_trace_id: str | None = None
        self._phase: str = ""

    # ── Span API ──────────────────────────────────────────────────────────

    def start_span(
        self,
        name: str,
        parent: SpanEvent | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> SpanEvent:
        """Begin a new span.  Returns the span for later :meth:`end_span`."""
        if self._current_trace_id is None:
            self._current_trace_id = uuid.uuid4().hex
        span = SpanEvent(
            trace_id=self._current_trace_id,
            span_id=uuid.uuid4().hex[:16],
            parent_span_id=parent.span_id if parent else None,
            name=name,
            start_time=time.monotonic(),
            attributes=dict(attributes or {}),
        )
        self._spans.append(span)
        return span

    def end_span(self, span: SpanEvent, **extra_attrs: Any) -> None:
        """Finalise *span* and emit it as a structured log event."""
        span.end_time = time.monotonic()
        span.attributes.update(extra_attrs)
        logger.info(
            "span_closed",
            **span.to_dict(),
            session_id=self._session_id,
        )

    # ── LLM call recording (the main wiring target) ────────────────────────

    def record_llm_call(
        self,
        model: str,
        phase: str,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int = 0,
        latency_ms: float = 0.0,
        hypothesis_id: str = "",
        status: str = "success",
    ) -> None:
        """Record a single LLM call across all subsystems.

        This is the callback target wired into :class:`AnthropicProvider`.
        It fans out to:
        - :class:`CostTracker` — dollar-cost accounting
        - :class:`PrometheusMetrics` — counters / histograms
        - :class:`AuditTrail` — optional, if hypothesis_id is provided
        """
        # 1. Cost tracker
        entry = self._cost_tracker.record(
            phase=phase,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read_tokens,
            latency_ms=latency_ms,
            hypothesis_id=hypothesis_id,
        )

        # 2. Prometheus metrics
        if self._metrics is not None:
            try:
                self._metrics.record_llm_call(
                    model=model,
                    phase=phase,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cache_read_tokens=cache_read_tokens,
                    cost_usd=entry.cost_usd,
                    latency_seconds=latency_ms / 1000.0,
                    status=status,
                )
            except Exception:
                logger.exception("metrics_record_llm_call_failed")

        # 3. Audit trail — only for decisions tied to a hypothesis
        if self._audit_trail is not None and hypothesis_id:
            try:
                self._audit_trail.record(
                    event="llm_call",
                    phase=phase,
                    hypothesis_id=hypothesis_id,
                    actor=model,
                    decision=status,
                    metadata={
                        "input_tokens": input_tokens,
                        "output_tokens": output_tokens,
                        "cost_usd": entry.cost_usd,
                        "latency_ms": latency_ms,
                    },
                )
            except Exception:
                logger.exception("audit_trail_record_failed")

    # ── Phase tracking ─────────────────────────────────────────────────────

    def set_phase(self, phase: str) -> None:
        """Set the current pipeline phase for context on subsequent events."""
        self._phase = phase

    # ── Finding / tool / coverage delegates ────────────────────────────────

    def record_finding(self, severity: str, cwe: str = "") -> None:
        """Record a confirmed vulnerability finding."""
        if self._metrics is not None:
            try:
                self._metrics.record_finding(severity=severity, cwe=cwe)
            except Exception:
                logger.exception("metrics_record_finding_failed")

    def record_tool_call(
        self, tool_name: str, success: bool, latency_seconds: float
    ) -> None:
        """Record a non-LLM tool invocation (CPG query, file read, …)."""
        if self._metrics is not None:
            try:
                self._metrics.record_tool_call(
                    tool_name=tool_name,
                    success=success,
                    latency_seconds=latency_seconds,
                )
            except Exception:
                logger.exception("metrics_record_tool_call_failed")

    def set_coverage(
        self, session_id: str, endpoint: float, risk_weighted: float
    ) -> None:
        """Update the Prometheus coverage gauge."""
        if self._metrics is not None:
            try:
                self._metrics.set_coverage(
                    session_id=session_id,
                    endpoint=endpoint,
                    risk_weighted=risk_weighted,
                )
            except Exception:
                logger.exception("metrics_set_coverage_failed")

    # ── Queries ────────────────────────────────────────────────────────────

    @property
    def cost_tracker(self) -> CostTracker:
        """The underlying :class:`CostTracker` (for summaries / budget checks)."""
        return self._cost_tracker

    @property
    def spans(self) -> list[SpanEvent]:
        """All spans recorded so far."""
        return list(self._spans)

    def flush(self) -> None:
        """Emit any pending spans and clear the trace context."""
        self._current_trace_id = None
        self._spans.clear()
