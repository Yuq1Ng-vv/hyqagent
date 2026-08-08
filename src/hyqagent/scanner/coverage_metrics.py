"""scanner/coverage_metrics.py — Blind-spot manifest and coverage summary.

Wraps :class:`CoverageTracker` (cpg/coverage.py) with scan-mode-aware
convenience methods.  This is the scanner-level entry point; all heavy
lifting is done by the CPG layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from hyqagent.cpg.types import BlindSpot, CoverageReport

if TYPE_CHECKING:
    from hyqagent.cpg.coverage import CoverageTracker


@dataclass
class CoverageSummary:
    """Human-readable scan coverage summary (for report inclusion)."""

    endpoint_coverage_pct: float = 0.0
    sink_coverage_pct: float = 0.0
    total_findings: int = 0
    confirmed_taint_count: int = 0
    sanitized_taint_count: int = 0
    conditional_sanitized_count: int = 0
    heuristic_sink_count: int = 0
    exposed_no_source_count: int = 0
    missing_auth_count: int = 0
    config_issue_count: int = 0
    secret_count: int = 0
    dangerous_call_count: int = 0
    blind_spot_count: int = 0
    blind_spots: list[BlindSpot] = field(default_factory=list)


class CoverageMetrics:
    """Aggregate scanner findings into a structured coverage summary.

    Usage::

        metrics = CoverageMetrics(coverage_tracker)
        metrics.record_annotated_paths(annotated_paths)
        metrics.record_findings(findings)
        summary = metrics.summarize()
    """

    def __init__(self, tracker: CoverageTracker) -> None:
        self._tracker = tracker
        self._counts: dict[str, int] = {}
        self._blind_spots: list[BlindSpot] = []

    def record_annotated_paths(self, annotated: list) -> None:
        """Count annotated paths by label."""
        for ap in annotated:
            label = getattr(ap, "label", None)
            if label is None:
                continue
            key = str(label.value) if hasattr(label, "value") else str(label)
            self._counts[key] = self._counts.get(key, 0) + 1

    def record_findings(self, findings: list) -> None:
        """Count findings by category."""
        self._counts["total_findings"] = len(findings)

    def record_blind_spots(self, spots: list[BlindSpot]) -> None:
        """Register blind spots from external sources."""
        self._blind_spots.extend(spots)

    def summarize(self) -> CoverageSummary:
        """Merge CPG coverage report + finding counts into a single summary."""
        report = self._tracker.compute_coverage()

        summary = CoverageSummary(
            endpoint_coverage_pct=round(report.endpoint_coverage_ratio * 100, 1),
            sink_coverage_pct=round(report.sink_coverage_ratio * 100, 1),
            total_findings=self._counts.get("total_findings", 0),
            confirmed_taint_count=self._counts.get("confirmed_taint", 0),
            sanitized_taint_count=self._counts.get("sanitized_taint", 0),
            conditional_sanitized_count=self._counts.get("conditional_sanitized", 0),
            heuristic_sink_count=self._counts.get("heuristic_sink", 0),
            exposed_no_source_count=self._counts.get("exposed_no_source", 0),
            missing_auth_count=self._counts.get("missing_auth", 0),
            config_issue_count=self._counts.get("config_issue", 0),
            secret_count=self._counts.get("secret", 0),
            dangerous_call_count=self._counts.get("dangerous_call", 0),
            blind_spot_count=len(report.blind_spots) + len(self._blind_spots),
            blind_spots=list(report.blind_spots) + self._blind_spots,
        )
        return summary
