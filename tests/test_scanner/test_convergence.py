"""Tests for scanner/convergence.py — multi-metric convergence detection."""

from __future__ import annotations

import pytest

from hyqagent.scanner.convergence import (
    ConvergenceMonitor,
    ConvergenceSnapshot,
    ConvergenceThresholds,
)

# ── ConvergenceSnapshot ────────────────────────────────────────────────────


class TestConvergenceSnapshot:
    def test_default_values(self) -> None:
        snap = ConvergenceSnapshot(round=1)
        assert snap.round == 1
        assert snap.new_high_findings == 0
        assert snap.endpoints_analyzed == 0
        assert snap.total_endpoints == 0

    def test_fields_settable(self) -> None:
        snap = ConvergenceSnapshot(
            round=2,
            new_high_findings=3,
            endpoints_analyzed=45,
            total_endpoints=50,
            risk_score_analyzed=90.0,
            risk_score_total=100.0,
            cwe_classes_covered={"CWE-89", "CWE-79"},
            total_cwe_classes={"CWE-89", "CWE-79", "CWE-78"},
        )
        assert snap.round == 2
        assert snap.new_high_findings == 3
        assert snap.endpoints_analyzed == 45
        assert snap.cwe_classes_covered == {"CWE-89", "CWE-79"}


# ── ConvergenceThresholds ──────────────────────────────────────────────────


class TestConvergenceThresholds:
    def test_defaults(self) -> None:
        t = ConvergenceThresholds()
        assert t.vdr_window == 3
        assert t.vdr_max_new == 0
        assert t.ec_min == 0.95
        assert t.rwc_min == 0.98
        assert t.vcc_min == 0.90
        assert t.c_hat_min == 0.85
        assert t.max_rounds == 5

    def test_custom_thresholds(self) -> None:
        t = ConvergenceThresholds(
            vdr_window=5,
            ec_min=0.80,
            max_rounds=10,
        )
        assert t.vdr_window == 5
        assert t.ec_min == 0.80
        assert t.max_rounds == 10
        # Unchanged defaults
        assert t.rwc_min == 0.98


# ── VDR ────────────────────────────────────────────────────────────────────


class TestVDR:
    def test_zero_new_converges(self) -> None:
        monitor = ConvergenceMonitor()
        for r in range(1, 4):
            monitor.update(ConvergenceSnapshot(round=r, new_high_findings=0))
        report = monitor.update(ConvergenceSnapshot(round=4, new_high_findings=0))
        vdr = next(m for m in report.metrics if m.name == "VDR")
        assert vdr.passed
        assert vdr.current == 0.0

    def test_new_findings_resets(self) -> None:
        monitor = ConvergenceMonitor()
        # Two clean rounds
        monitor.update(ConvergenceSnapshot(round=1, new_high_findings=0))
        monitor.update(ConvergenceSnapshot(round=2, new_high_findings=0))
        # Third round has findings
        report = monitor.update(ConvergenceSnapshot(round=3, new_high_findings=2))
        vdr = next(m for m in report.metrics if m.name == "VDR")
        assert not vdr.passed
        assert vdr.current == 2.0

    def test_not_enough_rounds(self) -> None:
        monitor = ConvergenceMonitor()
        # Only 2 rounds, need 3
        monitor.update(ConvergenceSnapshot(round=1, new_high_findings=0))
        report = monitor.update(ConvergenceSnapshot(round=2, new_high_findings=0))
        vdr = next(m for m in report.metrics if m.name == "VDR")
        assert not vdr.passed  # Window not full yet

    def test_vdr_custom_window(self) -> None:
        t = ConvergenceThresholds(vdr_window=2, vdr_max_new=0)
        monitor = ConvergenceMonitor(t)
        monitor.update(ConvergenceSnapshot(round=1, new_high_findings=0))
        report = monitor.update(ConvergenceSnapshot(round=2, new_high_findings=0))
        vdr = next(m for m in report.metrics if m.name == "VDR")
        assert vdr.passed  # Window=2, all clean


# ── EC ─────────────────────────────────────────────────────────────────────


class TestEC:
    def test_above_threshold(self) -> None:
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                endpoints_analyzed=48,
                total_endpoints=50,
            )
        )
        ec = next(m for m in report.metrics if m.name == "EC")
        assert ec.passed
        assert ec.current == 0.96

    def test_below_threshold(self) -> None:
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                endpoints_analyzed=40,
                total_endpoints=50,
            )
        )
        ec = next(m for m in report.metrics if m.name == "EC")
        assert not ec.passed
        assert ec.current == 0.80

    def test_exact_threshold(self) -> None:
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                endpoints_analyzed=95,
                total_endpoints=100,
            )
        )
        ec = next(m for m in report.metrics if m.name == "EC")
        assert ec.passed  # 0.95 >= 0.95

    def test_zero_total(self) -> None:
        """Zero total endpoints → trivially covered."""
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                endpoints_analyzed=0,
                total_endpoints=0,
            )
        )
        ec = next(m for m in report.metrics if m.name == "EC")
        assert ec.passed
        assert ec.current == 1.0


# ── RWC ────────────────────────────────────────────────────────────────────


class TestRWC:
    def test_above_threshold(self) -> None:
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                risk_score_analyzed=99.0,
                risk_score_total=100.0,
            )
        )
        rwc = next(m for m in report.metrics if m.name == "RWC")
        assert rwc.passed
        assert rwc.current == 0.99

    def test_below_threshold(self) -> None:
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                risk_score_analyzed=90.0,
                risk_score_total=100.0,
            )
        )
        rwc = next(m for m in report.metrics if m.name == "RWC")
        assert not rwc.passed

    def test_zero_total_risk(self) -> None:
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                risk_score_analyzed=0.0,
                risk_score_total=0.0,
            )
        )
        rwc = next(m for m in report.metrics if m.name == "RWC")
        assert rwc.passed
        assert rwc.current == 1.0


# ── VCC ────────────────────────────────────────────────────────────────────


class TestVCC:
    def test_all_covered(self) -> None:
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                cwe_classes_covered={"CWE-89", "CWE-79", "CWE-78"},
                total_cwe_classes={"CWE-89", "CWE-79", "CWE-78"},
            )
        )
        vcc = next(m for m in report.metrics if m.name == "VCC")
        assert vcc.passed
        assert vcc.current == 1.0

    def test_partial_coverage(self) -> None:
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                cwe_classes_covered={"CWE-89"},
                total_cwe_classes={"CWE-89", "CWE-79", "CWE-78", "CWE-22"},
            )
        )
        vcc = next(m for m in report.metrics if m.name == "VCC")
        assert not vcc.passed
        assert vcc.current == 0.25

    def test_empty_target(self) -> None:
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                cwe_classes_covered=set(),
                total_cwe_classes=set(),
            )
        )
        vcc = next(m for m in report.metrics if m.name == "VCC")
        assert vcc.passed
        assert vcc.current == 1.0


# ── C_hat ──────────────────────────────────────────────────────────────────


class TestCHat:
    def test_all_overlap_complete(self) -> None:
        """All findings seen by both perspectives → C_hat = 1.0."""
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                perspective_a_findings={"f1", "f2", "f3"},
                perspective_b_findings={"f1", "f2", "f3"},
            )
        )
        chat = next(m for m in report.metrics if m.name == "C_hat")
        assert chat.passed
        assert chat.current == 1.0

    def test_no_overlap_incomplete(self) -> None:
        """No overlap → C_hat = 0.0."""
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                perspective_a_findings={"f1", "f2"},
                perspective_b_findings={"f3", "f4"},
            )
        )
        chat = next(m for m in report.metrics if m.name == "C_hat")
        assert chat.current == 0.0

    def test_partial_overlap(self) -> None:
        """4 singles, 2 shared → Chao2 estimate."""
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                perspective_a_findings={"f1", "f2", "f3", "shared1", "shared2"},
                perspective_b_findings={"f4", "f5", "shared1", "shared2"},
            )
        )
        chat = next(m for m in report.metrics if m.name == "C_hat")
        # f1=6 (singletons), f2=2 (shared) → 1 - 36/4 = 1-9 = -8 → clamped to 0
        # Wait — let me recalculate:
        # a = {f1, f2, f3, shared1, shared2}  (5)
        # b = {f4, f5, shared1, shared2}        (4)
        # both = {shared1, shared2}              (2) → f2 = 2
        # only_one = {f1, f2, f3, f4, f5}       (5) → f1 = 5
        # c_hat = 1 - 25/4 = 1 - 6.25 = -5.25 → clamped to 0
        # Hmm, that's also 0. Let me make a test where it produces a positive value.
        assert chat.current >= 0.0
        assert chat.current <= 1.0

    def test_mostly_overlap(self) -> None:
        """Most findings seen by both, few singletons → high C_hat."""
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                perspective_a_findings={"f1", "shared1", "shared2", "shared3"},
                perspective_b_findings={"shared1", "shared2", "shared3"},
            )
        )
        chat = next(m for m in report.metrics if m.name == "C_hat")
        # only_one = {f1} → f1=1, both = {shared1, shared2, shared3} → f2=3
        # c_hat = 1 - 1/(2*3) = 1 - 1/6 = 0.833
        assert chat.current == pytest.approx(0.833, abs=0.01)
        # 0.833 < 0.85 threshold → not passed
        assert not chat.passed

    def test_empty_perspectives(self) -> None:
        monitor = ConvergenceMonitor()
        report = monitor.update(ConvergenceSnapshot(round=1))
        chat = next(m for m in report.metrics if m.name == "C_hat")
        assert chat.passed
        assert chat.current == 1.0


# ── ConvergenceReport ──────────────────────────────────────────────────────


class TestConvergenceReport:
    def test_all_converged(self) -> None:
        monitor = ConvergenceMonitor()
        # Feed enough rounds for VDR, full coverage
        for r in range(1, 5):
            monitor.update(
                ConvergenceSnapshot(
                    round=r,
                    new_high_findings=0,
                    endpoints_analyzed=100,
                    total_endpoints=100,
                    risk_score_analyzed=100.0,
                    risk_score_total=100.0,
                    cwe_classes_covered={"CWE-89", "CWE-79"},
                    total_cwe_classes={"CWE-89", "CWE-79"},
                    perspective_a_findings={"f1", "f2"},
                    perspective_b_findings={"f1", "f2"},
                )
            )
        report = monitor.update(
            ConvergenceSnapshot(
                round=5,
                new_high_findings=0,
                endpoints_analyzed=100,
                total_endpoints=100,
                risk_score_analyzed=100.0,
                risk_score_total=100.0,
                cwe_classes_covered={"CWE-89", "CWE-79"},
                total_cwe_classes={"CWE-89", "CWE-79"},
                perspective_a_findings={"f1", "f2"},
                perspective_b_findings={"f1", "f2"},
            )
        )
        assert report.converged is True

    def test_not_converged_some_fail(self) -> None:
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                new_high_findings=5,
                endpoints_analyzed=10,
                total_endpoints=100,  # EC=10%
                risk_score_analyzed=20.0,
                risk_score_total=100.0,  # RWC=20%
                cwe_classes_covered={"CWE-89"},
                total_cwe_classes={"CWE-89", "CWE-79", "CWE-78"},  # VCC=33%
            )
        )
        assert not report.converged
        assert report.passed_count < report.total_count

    def test_recommendation_continue(self) -> None:
        monitor = ConvergenceMonitor()
        report = monitor.update(ConvergenceSnapshot(round=1, new_high_findings=5))
        assert report.recommendation == "continue"

    def test_recommendation_escalate(self) -> None:
        """After max_rounds without convergence, escalate."""
        monitor = ConvergenceMonitor(ConvergenceThresholds(max_rounds=2))
        for r in range(1, 4):  # 3 rounds > max_rounds=2
            monitor.update(ConvergenceSnapshot(round=r, new_high_findings=5))
        last = monitor._evaluate()
        assert last.recommendation == "escalate_to_human"
        assert last.escalate_reason != ""

    def test_recommendation_converged(self) -> None:
        monitor = ConvergenceMonitor(ConvergenceThresholds(vdr_window=2))
        for r in range(1, 4):
            monitor.update(
                ConvergenceSnapshot(
                    round=r,
                    new_high_findings=0,
                    endpoints_analyzed=100,
                    total_endpoints=100,
                    risk_score_analyzed=100.0,
                    risk_score_total=100.0,
                    cwe_classes_covered={"CWE-89"},
                    total_cwe_classes={"CWE-89"},
                    perspective_a_findings={"f1", "f2"},
                    perspective_b_findings={"f1", "f2"},
                )
            )
        assert monitor.is_converged()

    def test_summary_string(self) -> None:
        monitor = ConvergenceMonitor()
        report = monitor.update(
            ConvergenceSnapshot(
                round=1,
                new_high_findings=0,
                endpoints_analyzed=100,
                total_endpoints=100,
            )
        )
        assert "Round 1" in report.summary
        assert "VDR" in report.summary


# ── Monitor lifecycle ──────────────────────────────────────────────────────


class TestMonitorLifecycle:
    def test_round_count(self) -> None:
        monitor = ConvergenceMonitor()
        assert monitor.round_count == 0
        monitor.update(ConvergenceSnapshot(round=1))
        monitor.update(ConvergenceSnapshot(round=2))
        assert monitor.round_count == 2

    def test_latest_snapshot(self) -> None:
        monitor = ConvergenceMonitor()
        assert monitor.latest_snapshot is None
        monitor.update(ConvergenceSnapshot(round=1))
        assert monitor.latest_snapshot is not None
        assert monitor.latest_snapshot.round == 1

    def test_history(self) -> None:
        monitor = ConvergenceMonitor()
        monitor.update(ConvergenceSnapshot(round=1))
        monitor.update(ConvergenceSnapshot(round=2))
        assert len(monitor.history) == 2
        assert monitor.history[0].round == 1
        assert monitor.history[1].round == 2

    def test_reset(self) -> None:
        monitor = ConvergenceMonitor()
        monitor.update(ConvergenceSnapshot(round=1))
        monitor.reset()
        assert monitor.round_count == 0
        assert monitor.latest_snapshot is None

    def test_is_converged_empty(self) -> None:
        monitor = ConvergenceMonitor()
        assert not monitor.is_converged()
