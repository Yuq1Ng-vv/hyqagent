"""Tests for observability/cost_tracker.py — LLM cost tracking and budget enforcement."""

from __future__ import annotations

import pytest

from hyqagent.observability.cost_tracker import (
    PRICING,
    CostEntry,
    CostSummary,
    CostTracker,
)


class TestPricingTable:
    def test_deepseek_pricing(self) -> None:
        assert "deepseek-v4-flash" in PRICING
        p = PRICING["deepseek-v4-flash"]
        assert p["input"] < p["output"]
        assert p["input"] < 0.01

    def test_claude_sonnet_pricing(self) -> None:
        assert "claude-sonnet-5" in PRICING
        p = PRICING["claude-sonnet-5"]
        assert p["output"] > p["input"]

    def test_claude_opus_pricing(self) -> None:
        assert "claude-opus-5" in PRICING
        p = PRICING["claude-opus-5"]
        # Opus should be more expensive than Sonnet
        assert p["input"] > PRICING["claude-sonnet-5"]["input"]

    def test_default_fallback(self) -> None:
        assert "default" in PRICING


class TestCostEntry:
    def test_defaults(self) -> None:
        entry = CostEntry(phase="test", model="test-model", input_tokens=100, output_tokens=50)
        assert entry.cost_usd == 0.0
        assert entry.cache_read_tokens == 0
        assert entry.latency_ms == 0.0
        assert entry.hypothesis_id == ""


class TestCostTracker:
    @pytest.fixture
    def tracker(self) -> CostTracker:
        return CostTracker(max_budget=5.0)

    def test_initial_cost_zero(self, tracker: CostTracker) -> None:
        assert tracker.total_cost() == 0.0
        assert tracker.remaining_budget() == 5.0
        assert not tracker.is_budget_exceeded()

    def test_record_single_call(self, tracker: CostTracker) -> None:
        entry = tracker.record(
            phase="hypothesis_gen",
            model="deepseek-v4-flash",
            input_tokens=1000,
            output_tokens=200,
        )
        assert entry.input_tokens == 1000
        assert entry.output_tokens == 200
        assert entry.cost_usd > 0
        assert len(tracker.entries) == 1

    def test_record_multiple_calls(self, tracker: CostTracker) -> None:
        tracker.record("phase_a", "deepseek-v4-flash", input_tokens=1000, output_tokens=200)
        tracker.record("phase_b", "claude-sonnet-5", input_tokens=500, output_tokens=100)
        assert len(tracker.entries) == 2
        assert tracker.total_cost() > 0

    def test_deepseek_cheaper_than_claude(self, tracker: CostTracker) -> None:
        """DeepSeek should be ~50x cheaper per token than Claude Opus."""
        ds = tracker.record(
            "test", "deepseek-v4-flash",
            input_tokens=10000, output_tokens=1000,
        )
        opus = tracker.record(
            "test", "claude-opus-5",
            input_tokens=10000, output_tokens=1000,
        )
        assert ds.cost_usd < opus.cost_usd
        # Opus should be at least 10x more expensive
        assert opus.cost_usd > ds.cost_usd * 10

    def test_budget_not_exceeded_initially(self, tracker: CostTracker) -> None:
        tracker.record("test", "deepseek-v4-flash", input_tokens=1000, output_tokens=100)
        assert not tracker.is_budget_exceeded()

    def test_budget_exceeded(self, tracker: CostTracker) -> None:
        # Force budget exhaustion
        tracker._max_budget = 0.0001
        tracker.record("test", "claude-opus-5", input_tokens=500000, output_tokens=100000)
        assert tracker.is_budget_exceeded()

    def test_remaining_budget_floor_zero(self, tracker: CostTracker) -> None:
        tracker._max_budget = 0.01
        tracker.record("test", "claude-opus-5", input_tokens=100000, output_tokens=50000)
        assert tracker.remaining_budget() == 0.0

    def test_cost_by_phase(self, tracker: CostTracker) -> None:
        tracker.record("discovery", "deepseek-v4-flash", input_tokens=1000, output_tokens=200)
        tracker.record("verification", "claude-sonnet-5", input_tokens=500, output_tokens=100)
        tracker.record("discovery", "deepseek-v4-flash", input_tokens=800, output_tokens=150)

        by_phase = tracker.cost_by_phase()
        assert "discovery" in by_phase
        assert "verification" in by_phase
        assert by_phase["discovery"] > 0
        assert by_phase["verification"] > 0

    def test_cost_by_model(self, tracker: CostTracker) -> None:
        tracker.record("a", "deepseek-v4-flash", input_tokens=1000, output_tokens=200)
        tracker.record("b", "claude-sonnet-5", input_tokens=500, output_tokens=100)

        by_model = tracker.cost_by_model()
        assert "deepseek-v4-flash" in by_model
        assert "claude-sonnet-5" in by_model

    def test_summary(self, tracker: CostTracker) -> None:
        tracker.record("a", "deepseek-v4-flash", input_tokens=1000, output_tokens=200)
        tracker.record("b", "deepseek-v4-flash", input_tokens=500, output_tokens=100)

        summary = tracker.summary()
        assert isinstance(summary, CostSummary)
        assert summary.total_calls == 2
        assert summary.total_input_tokens == 1500
        assert summary.total_output_tokens == 300
        assert summary.total_cost > 0

    def test_entries_are_copies(self, tracker: CostTracker) -> None:
        tracker.record("a", "model", input_tokens=100, output_tokens=50)
        entries = tracker.entries
        assert len(entries) == 1
        # Should be a copy, not the original list
        entries.pop()
        assert len(tracker.entries) == 1

    def test_cache_read_tokens_reduce_cost(self, tracker: CostTracker) -> None:
        """Cache reads should be cheaper than fresh reads."""
        no_cache = tracker.record(
            "a", "deepseek-v4-flash", input_tokens=1000, output_tokens=100,
        )
        # Same tokens but with cache reads
        tracker2 = CostTracker()
        with_cache = tracker2.record("a", "deepseek-v4-flash",
                                     input_tokens=1000, output_tokens=100,
                                     cache_read_tokens=500)
        # Cache reads should reduce the cost
        assert with_cache.cost_usd < no_cache.cost_usd

    def test_hypothesis_id_tracking(self, tracker: CostTracker) -> None:
        entry = tracker.record("hypothesis_gen", "model",
                               input_tokens=100, output_tokens=50,
                               hypothesis_id="hyp-abc123")
        assert entry.hypothesis_id == "hyp-abc123"

    def test_latency_tracking(self, tracker: CostTracker) -> None:
        entry = tracker.record("test", "model", input_tokens=100, output_tokens=50,
                               latency_ms=250.5)
        assert entry.latency_ms == 250.5
