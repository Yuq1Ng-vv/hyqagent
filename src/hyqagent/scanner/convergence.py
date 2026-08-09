"""scanner/convergence.py — Multi-metric convergence detection for long-running audits.

Implements the five convergence criteria from LONG-RUNNING-AGENT-ARCHITECTURE.md §7:

======== ============================== ========================
Metric   Meaning                         Threshold
======== ============================== ========================
VDR      Vulnerability Discovery Rate    0 new HIGH+ over W=3 rounds
EC       Endpoint Coverage               ≥ 95%
RWC      Risk-Weighted Coverage          ≥ 98%
VCC      Vulnerability Class Coverage    ≥ 90%
C_hat    Chao2 estimator (undiscovered)   ≥ 0.85 completeness
======== ============================== ========================

All five criteria must pass for the audit to be considered converged.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── Thresholds ───────────────────────────────────────────────────────────────


@dataclass
class ConvergenceThresholds:
    """Configurable thresholds for each convergence metric."""

    vdr_window: int = 3  # consecutive rounds with zero new HIGH+
    vdr_max_new: int = 0  # max new HIGH+ findings to count as "zero"
    ec_min: float = 0.95  # minimum endpoint coverage ratio
    rwc_min: float = 0.98  # minimum risk-weighted coverage ratio
    vcc_min: float = 0.90  # minimum vuln-class coverage ratio
    c_hat_min: float = 0.85  # minimum Chao2 completeness estimate
    max_rounds: int = 5  # hard cap — escalate to human if not converged


# ── Snapshots ────────────────────────────────────────────────────────────────


@dataclass
class ConvergenceSnapshot:
    """One round's worth of convergence data.

    Captured at the end of each hypothesis-generation + validation cycle.
    """

    round: int
    new_high_findings: int = 0  # HIGH+ findings NEW this round (not seen before)
    endpoints_analyzed: int = 0
    total_endpoints: int = 0
    risk_score_analyzed: float = 0.0
    risk_score_total: float = 0.0
    cwe_classes_covered: set[str] = field(default_factory=set)
    total_cwe_classes: set[str] = field(default_factory=set)
    perspective_a_findings: set[str] = field(default_factory=set)  # hypothesis IDs from lens A
    perspective_b_findings: set[str] = field(default_factory=set)  # hypothesis IDs from lens B
    metadata: dict[str, object] = field(default_factory=dict)


# ── Report ───────────────────────────────────────────────────────────────────


@dataclass
class MetricResult:
    """Single-metric convergence check."""

    name: str  # "VDR" | "EC" | "RWC" | "VCC" | "C_hat"
    current: float
    threshold: float
    passed: bool
    detail: str = ""


@dataclass
class ConvergenceReport:
    """Aggregated convergence verdict after a round."""

    round: int
    converged: bool
    metrics: list[MetricResult] = field(default_factory=list)
    recommendation: str = ""  # "continue" | "converged" | "escalate_to_human"
    escalate_reason: str = ""

    @property
    def passed_count(self) -> int:
        """Number of metrics that passed their thresholds."""
        return sum(1 for m in self.metrics if m.passed)

    @property
    def total_count(self) -> int:
        """Total number of metrics evaluated."""
        return len(self.metrics)

    @property
    def summary(self) -> str:
        """One-line summary for logging / progress display."""
        parts = [f"{m.name}={m.current:.2f}({'✓' if m.passed else '✗'})" for m in self.metrics]
        return f"Round {self.round}: " + ", ".join(parts)


# ── Monitor ──────────────────────────────────────────────────────────────────


class ConvergenceMonitor:
    """Accumulates per-round snapshots and judges convergence.

    Usage::

        monitor = ConvergenceMonitor()
        for round_num in range(1, 6):
            # ... run hypothesis generation + validation ...
            snapshot = ConvergenceSnapshot(
                round=round_num,
                new_high_findings=len(new_confirmed_high),
                endpoints_analyzed=analyzed,
                total_endpoints=total,
                risk_score_analyzed=risk_analyzed,
                risk_score_total=risk_total,
                cwe_classes_covered=covered,
                total_cwe_classes=all_classes,
            )
            report = monitor.update(snapshot)
            if report.converged:
                break
    """

    MAX_ROUNDS = 5

    def __init__(self, thresholds: ConvergenceThresholds | None = None) -> None:
        self._thresholds = thresholds or ConvergenceThresholds()
        self._snapshots: list[ConvergenceSnapshot] = []

    # ── Public API ──────────────────────────────────────────────────────

    def update(self, snapshot: ConvergenceSnapshot) -> ConvergenceReport:
        """Record a round and return the current convergence verdict."""
        self._snapshots.append(snapshot)
        return self._evaluate()

    def is_converged(self) -> bool:
        """Quick check: has the most recent report declared convergence?"""
        if not self._snapshots:
            return False
        return self._evaluate().converged

    @property
    def round_count(self) -> int:
        """Number of rounds recorded so far."""
        return len(self._snapshots)

    @property
    def latest_snapshot(self) -> ConvergenceSnapshot | None:
        """Most recent snapshot, or None if no rounds recorded."""
        return self._snapshots[-1] if self._snapshots else None

    @property
    def history(self) -> list[ConvergenceSnapshot]:
        """Copy of all recorded snapshots."""
        return list(self._snapshots)

    def reset(self) -> None:
        """Clear all history (for testing)."""
        self._snapshots.clear()

    # ── Metric evaluations ──────────────────────────────────────────────

    def _evaluate(self) -> ConvergenceReport:
        t = self._thresholds
        latest = self._snapshots[-1]
        round_num = latest.round

        metrics: list[MetricResult] = []

        # ── VDR: rolling window ────────────────────────────────────
        vdr = self._check_vdr(t.vdr_window, t.vdr_max_new)
        metrics.append(vdr)

        # ── EC: endpoint coverage ──────────────────────────────────
        ec = self._check_ec(latest, t.ec_min)
        metrics.append(ec)

        # ── RWC: risk-weighted coverage ────────────────────────────
        rwc = self._check_rwc(latest, t.rwc_min)
        metrics.append(rwc)

        # ── VCC: vuln-class coverage ───────────────────────────────
        vcc = self._check_vcc(latest, t.vcc_min)
        metrics.append(vcc)

        # ── C_hat: Chao2 completeness ──────────────────────────────
        chat = self._check_c_hat(latest, t.c_hat_min)
        metrics.append(chat)

        all_pass = all(m.passed for m in metrics)

        # ── Recommendation ─────────────────────────────────────────
        if all_pass:
            recommendation = "converged"
            escalate_reason = ""
        elif round_num >= self._thresholds.max_rounds:
            recommendation = "escalate_to_human"
            failed = [m.name for m in metrics if not m.passed]
            escalate_reason = (
                f"Not converged after {self._thresholds.max_rounds} rounds. "
                f"Failed metrics: {', '.join(failed)}. "
                "The codebase may contain complex vulnerability patterns "
                "requiring manual review."
            )
        else:
            recommendation = "continue"
            escalate_reason = ""

        return ConvergenceReport(
            round=round_num,
            converged=all_pass,
            metrics=metrics,
            recommendation=recommendation,
            escalate_reason=escalate_reason,
        )

    def _check_vdr(self, window: int, max_new: int) -> MetricResult:
        """VDR: no more than *max_new* new HIGH+ findings in the last *window* rounds."""
        recent = self._snapshots[-window:]
        total_new = sum(s.new_high_findings for s in recent)
        passed = total_new <= max_new and len(recent) >= window
        return MetricResult(
            name="VDR",
            current=float(total_new),
            threshold=float(max_new),
            passed=passed,
            detail=(
                f"New HIGH+ findings in last {len(recent)} rounds: {total_new} "
                f"(need ≤{max_new} over ≥{window} rounds)"
            ),
        )

    def _check_ec(self, snapshot: ConvergenceSnapshot, threshold: float) -> MetricResult:
        """EC: endpoint coverage ratio."""
        if snapshot.total_endpoints == 0:
            # No endpoints discovered → trivially "covered" (nothing to miss)
            return MetricResult(
                name="EC",
                current=1.0,
                threshold=threshold,
                passed=True,
                detail="No endpoints discovered — nothing to cover.",
            )
        ratio = snapshot.endpoints_analyzed / snapshot.total_endpoints
        return MetricResult(
            name="EC",
            current=ratio,
            threshold=threshold,
            passed=ratio >= threshold,
            detail=(
                f"{snapshot.endpoints_analyzed}/{snapshot.total_endpoints} "
                f"endpoints analyzed ({ratio:.1%})"
            ),
        )

    def _check_rwc(self, snapshot: ConvergenceSnapshot, threshold: float) -> MetricResult:
        """RWC: risk-weighted coverage ratio."""
        if snapshot.risk_score_total == 0.0:
            return MetricResult(
                name="RWC",
                current=1.0,
                threshold=threshold,
                passed=True,
                detail="No risk scores available — trivially covered.",
            )
        ratio = snapshot.risk_score_analyzed / snapshot.risk_score_total
        return MetricResult(
            name="RWC",
            current=ratio,
            threshold=threshold,
            passed=ratio >= threshold,
            detail=(
                f"Risk score {snapshot.risk_score_analyzed:.0f}/"
                f"{snapshot.risk_score_total:.0f} analyzed ({ratio:.1%})"
            ),
        )

    def _check_vcc(self, snapshot: ConvergenceSnapshot, threshold: float) -> MetricResult:
        """VCC: vulnerability class coverage ratio."""
        total = snapshot.total_cwe_classes
        covered = snapshot.cwe_classes_covered
        if not total:
            return MetricResult(
                name="VCC",
                current=1.0,
                threshold=threshold,
                passed=True,
                detail="No target CWE classes defined — trivially covered.",
            )
        ratio = len(covered) / len(total)
        return MetricResult(
            name="VCC",
            current=ratio,
            threshold=threshold,
            passed=ratio >= threshold,
            detail=(
                f"{len(covered)}/{len(total)} CWE classes covered "
                f"({ratio:.1%}), missing: {sorted(total - covered)[:5]}"
            ),
        )

    def _check_c_hat(self, snapshot: ConvergenceSnapshot, threshold: float) -> MetricResult:
        """C_hat: Chao2 estimator of completeness via two-perspective overlap.

        Uses the Chao2 incidence-based estimator (simplified):
            C_hat = 1 - (f1² / (2 * f2))

        where:
          f1 = findings seen by exactly ONE perspective
          f2 = findings seen by BOTH perspectives

        If f2 == 0, the estimator cannot be computed (C_hat → 0).
        If f1 == 0, all findings were seen by both → C_hat = 1.0.
        """
        a = snapshot.perspective_a_findings
        b = snapshot.perspective_b_findings

        if not a and not b:
            # No findings from either perspective — nothing to estimate
            return MetricResult(
                name="C_hat",
                current=1.0,
                threshold=threshold,
                passed=True,
                detail="No findings from either perspective — nothing to estimate.",
            )

        both = a & b
        only_one = (a | b) - both
        f1 = len(only_one)
        f2 = len(both)

        if f2 == 0:
            # No overlap at all → very incomplete
            c_hat = 0.0
        elif f1 == 0:
            # All findings seen by both → complete
            c_hat = 1.0
        else:
            # Chao2 formula
            raw = 1.0 - (f1 * f1) / (2.0 * f2)
            c_hat = max(0.0, min(1.0, raw))

        passed = c_hat >= threshold
        return MetricResult(
            name="C_hat",
            current=c_hat,
            threshold=threshold,
            passed=passed,
            detail=(
                f"f1={f1} (single-perspective), f2={f2} (both), "
                f"Chao2 completeness estimate = {c_hat:.2f}"
            ),
        )
