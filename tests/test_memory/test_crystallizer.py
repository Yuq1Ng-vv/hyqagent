"""Tests for memory/crystallizer.py — Context crystallization."""

from __future__ import annotations

from hyqagent.memory.context import ContextManager, TurnRecord, ZoneBudget
from hyqagent.memory.crystallizer import (
    ContextCrystallizer,
    CrystalSummary,
    should_crystallize_on_phase_change,
)


class TestCrystalSummary:
    def test_empty_summary(self) -> None:
        s = CrystalSummary(phase="test")
        text = s.to_long_term_text()
        assert "test" in text
        assert "0 个" in text  # 0 files

    def test_with_findings(self) -> None:
        s = CrystalSummary(
            phase="hypothesis_gen",
            files_analyzed=["a.py", "b.py"],
            key_findings=[
                {"id": "hyp_001", "type": "sqli", "verdict": "confirmed", "confidence": 0.95},
            ],
            decisions_made=["Skipped utils.py: no user input"],
            open_questions=["Custom ORM wrapper status unknown"],
        )
        text = s.to_long_term_text()
        assert "hypothesis_gen" in text
        assert "a.py" in text
        assert "hyp_001" in text
        assert "confirmed" in text
        assert "Skipped utils.py" in text
        assert "ORM" in text

    def test_compression_ratio_calculation(self) -> None:
        s = CrystalSummary(
            phase="test",
            turns_compressed=100,
            tokens_before=10_000,
        )
        text = s.to_long_term_text()
        s.tokens_after = max(1, len(text) // 4)
        s.compression_ratio = s.tokens_before / s.tokens_after if s.tokens_after > 0 else 0
        assert s.compression_ratio > 1  # should compress


class TestContextCrystallizer:
    def test_default_init(self) -> None:
        c = ContextCrystallizer()
        assert not c.should_crystallize(ContextManager())

    def test_turn_threshold_trigger(self) -> None:
        c = ContextCrystallizer(turn_threshold=1)
        ctx = ContextManager()
        ctx.add_to_working(TurnRecord(role="user", content="test"))
        c._turns_since_last = 1  # simulate threshold reached
        assert c.should_crystallize(ctx)

    def test_budget_threshold_trigger(self) -> None:
        c = ContextCrystallizer(budget_threshold=0.1)  # trigger at 10%
        ctx = ContextManager(budget=ZoneBudget(working=100))
        ctx.add_to_working(TurnRecord(role="user", content="x" * 80))  # ~20 tokens = 20%
        assert c.should_crystallize(ctx)

    def test_crystallize_extracts_findings(self) -> None:
        c = ContextCrystallizer()
        turns = [
            TurnRecord(
                role="assistant",
                content="Found hyp_abc123: SQL injection in login.py. "
                "verdict: confirmed, confidence: 0.92",
            ),
            TurnRecord(
                role="assistant",
                content="Found hyp_def456: XSS in search.py. verdict: rejected, conf: 0.15",
            ),
        ]
        summary = c.crystallize(
            turns,
            phase="hypothesis_gen",
            files_analyzed=["login.py", "search.py"],
            decisions=["Skipped utils.py"],
            open_questions=["Check ORM safety"],
        )
        assert summary.phase == "hypothesis_gen"
        assert len(summary.key_findings) >= 1
        assert "login.py" in summary.files_analyzed
        assert "Skipped utils.py" in summary.decisions_made
        assert "Check ORM safety" in summary.open_questions
        assert summary.turns_compressed == 2
        assert summary.compression_ratio > 0

    def test_crystallize_resets_counter(self) -> None:
        c = ContextCrystallizer(turn_threshold=5)
        c._turns_since_last = 10
        c.crystallize(
            [TurnRecord(role="user", content="test")],
            phase="test",
        )
        assert c._turns_since_last == 0
        assert c._crystallization_count == 1

    def test_extract_findings_chinese_patterns(self) -> None:
        """Test that Chinese verdict patterns are detected."""
        c = ContextCrystallizer()
        turns = [
            TurnRecord(
                role="assistant",
                content="假设 hyp_xyz: SQL注入漏洞 判定：confirmed 置信度：0.88",
            ),
        ]
        summary = c.crystallize(turns, phase="validation")
        findings = summary.key_findings
        assert len(findings) >= 1
        f = findings[0]
        assert f["id"] == "hyp_xyz"
        assert f["verdict"] == "confirmed"
        assert f["confidence"] > 0

    def test_extract_findings_dedup(self) -> None:
        c = ContextCrystallizer()
        turns = [
            TurnRecord(role="assistant", content="hyp_a: sqli confirmed"),
            TurnRecord(role="assistant", content="hyp_a: same finding again"),
        ]
        summary = c.crystallize(turns, phase="test")
        # Should deduplicate by ID
        ids = [f["id"] for f in summary.key_findings]
        assert len(ids) == len(set(ids))


class TestPhaseChangeTrigger:
    def test_forward_phase_triggers(self) -> None:
        assert should_crystallize_on_phase_change("phase2_scan", "understanding")

    def test_same_phase_no_trigger(self) -> None:
        assert not should_crystallize_on_phase_change("understanding", "understanding")

    def test_backward_phase_no_trigger(self) -> None:
        assert not should_crystallize_on_phase_change("validation", "phase2_scan")

    def test_unknown_phase_no_trigger(self) -> None:
        assert not should_crystallize_on_phase_change("unknown_phase", "report")

    def test_phase_to_report_triggers(self) -> None:
        assert should_crystallize_on_phase_change("completeness_review", "report")
