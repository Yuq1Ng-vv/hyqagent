"""observability/metrics.py — Prometheus metrics implementing the MetricsCollector protocol.

All 6 metrics from DESIGN-IMPLEMENTATION.md §7.3:
- ``hyqagent_llm_calls_total`` (Counter, by model/phase/status)
- ``hyqagent_llm_cost_usd_total`` (Counter)
- ``hyqagent_llm_latency_seconds`` (Histogram)
- ``hyqagent_findings_total`` (Counter, by severity/cwe)
- ``hyqagent_endpoint_coverage_ratio`` (Gauge)
- ``hyqagent_budget_spent_usd`` (Gauge)
"""

from __future__ import annotations

from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest


class PrometheusMetrics:
    """Prometheus metrics registry for HyqAgent audits.

    Implements the :class:`~hyqagent.core.protocols.MetricsCollector` protocol
    so it can be injected anywhere that protocol is expected.

    Parameters
    ----------
    registry:
        An optional :class:`CollectorRegistry`.  When omitted the default
        global registry is used.  Pass a fresh ``CollectorRegistry()`` in
        tests to avoid ``DuplicateTimeseries`` errors.

    """

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self._registry = registry or CollectorRegistry(auto_describe=True)

        # ── LLM counters ──────────────────────────────────────────────────
        self._llm_calls = Counter(
            "hyqagent_llm_calls_total",
            "Total number of LLM API calls",
            labelnames=["model", "phase", "status"],
            registry=self._registry,
        )
        self._llm_cost = Counter(
            "hyqagent_llm_cost_usd_total",
            "Total LLM cost in USD",
            labelnames=["model"],
            registry=self._registry,
        )
        self._llm_latency = Histogram(
            "hyqagent_llm_latency_seconds",
            "LLM call latency in seconds",
            labelnames=["model", "phase"],
            buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0),
            registry=self._registry,
        )

        # ── Finding counters ──────────────────────────────────────────────
        self._findings = Counter(
            "hyqagent_findings_total",
            "Total vulnerability findings",
            labelnames=["severity", "cwe"],
            registry=self._registry,
        )

        # ── Coverage gauge ────────────────────────────────────────────────
        self._coverage = Gauge(
            "hyqagent_endpoint_coverage_ratio",
            "Ratio of endpoints with source→sink coverage",
            registry=self._registry,
        )

        # ── Budget gauge ──────────────────────────────────────────────────
        self._budget = Gauge(
            "hyqagent_budget_spent_usd",
            "Total LLM budget spent in USD",
            registry=self._registry,
        )

    # ── MetricsCollector protocol ──────────────────────────────────────────

    def record_llm_call(
        self,
        model: str,
        phase: str,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int,
        cost_usd: float,
        latency_seconds: float,
        status: str = "success",
    ) -> None:
        """Record a single LLM API call across counters and histogram."""
        self._llm_calls.labels(model=model, phase=phase, status=status).inc()
        self._llm_cost.labels(model=model).inc(cost_usd)
        self._llm_latency.labels(model=model, phase=phase).observe(latency_seconds)

    def record_finding(self, severity: str, cwe: str = "") -> None:
        """Record a confirmed vulnerability finding."""
        self._findings.labels(severity=severity, cwe=cwe).inc()

    def record_tool_call(
        self, tool_name: str, success: bool, latency_seconds: float
    ) -> None:
        """Record a non-LLM tool invocation.

        Note: currently no dedicated tool-call counter exists in the
        Prometheus registry (the DESIGN spec reserves this for future use).
        We record it as an LLM call with phase=tool_name for now.
        """
        status = "success" if success else "failure"
        self._llm_calls.labels(
            model="tool", phase=tool_name, status=status
        ).inc()
        self._llm_latency.labels(model="tool", phase=tool_name).observe(
            latency_seconds
        )

    def set_coverage(
        self, session_id: str, endpoint: float, risk_weighted: float
    ) -> None:
        """Update the endpoint coverage gauge."""
        self._coverage.set(endpoint)

    def set_budget_spent(self, amount_usd: float) -> None:
        """Update the budget-spent gauge (call periodically)."""
        self._budget.set(amount_usd)

    # ── Export ─────────────────────────────────────────────────────────────

    def get_metrics_text(self) -> str:
        """Return Prometheus text format for scraping."""
        return generate_latest(self._registry).decode("utf-8")

    # ── Introspection ──────────────────────────────────────────────────────

    @property
    def llm_calls_total(self) -> dict[str, float]:
        """Snapshot of ``hyqagent_llm_calls_total`` by (model, phase, status)."""
        result: dict[str, float] = {}
        metrics_list = list(self._llm_calls.collect())
        if metrics_list:
            for sample in metrics_list[0].samples:
                result[sample.name] = sample.value
        return result

    def _snapshot_counter(self, counter: Any, label: str) -> dict[str, float]:
        """Return {label_value: total} for a labelled Counter."""
        collected: dict[str, float] = {}
        for metric in counter.collect():
            for sample in metric.samples:
                if sample.name.endswith("_total"):
                    collected[str(sample.labels.get(label, ""))] = sample.value
        return collected
