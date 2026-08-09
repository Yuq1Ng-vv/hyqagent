"""Tests for memory/context.py — Three-zone context model."""

from __future__ import annotations

from hyqagent.memory.context import ContextManager, TurnRecord, ZoneBudget


class TestZoneBudget:
    def test_defaults(self) -> None:
        b = ZoneBudget()
        assert b.fixed == 5_000
        assert b.long_term == 30_000
        assert b.working == 60_000
        assert b.total_limit == 200_000

    def test_total_used(self) -> None:
        b = ZoneBudget(fixed=1000, long_term=2000, working=3000)
        assert b.total_used == 6000

    def test_custom(self) -> None:
        b = ZoneBudget(fixed=100, long_term=200, working=300, total_limit=1000)
        assert b.fixed == 100
        assert b.total_limit == 1000


class TestTurnRecord:
    def test_basic(self) -> None:
        turn = TurnRecord(role="user", content="Find SQL injection")
        assert turn.role == "user"
        assert turn.content == "Find SQL injection"

    def test_estimate_tokens(self) -> None:
        turn = TurnRecord(role="user", content="a" * 100)
        assert turn.estimate_tokens() == 25  # 100 / 4

    def test_estimate_tokens_short_content(self) -> None:
        turn = TurnRecord(role="user", content="hi")
        assert turn.estimate_tokens() == 1  # minimum 1

    def test_default_metadata(self) -> None:
        turn = TurnRecord(role="assistant", content="ok")
        assert turn.metadata == {}

    def test_timestamp_auto_set(self) -> None:
        turn = TurnRecord(role="user", content="test")
        assert turn.timestamp > 0


class TestContextManager:
    def test_default_init(self) -> None:
        ctx = ContextManager()
        assert ctx.turn_count == 0
        assert ctx.crystallization_count == 0
        tokens = ctx.estimate_tokens()
        assert tokens["total"] == 0

    def test_set_fixed(self) -> None:
        ctx = ContextManager()
        ctx.set_fixed("System prompt", rules="No XSS", metadata="Test project")
        tokens = ctx.estimate_tokens()
        assert tokens["fixed"] > 0

    def test_update_long_term(self) -> None:
        ctx = ContextManager()
        ctx.update_long_term("Phase 1: 10 files analyzed")
        assert ctx.estimate_tokens()["long_term"] > 0

    def test_long_term_accumulates(self) -> None:
        ctx = ContextManager()
        ctx.update_long_term("First summary")
        ctx.update_long_term("Second summary")
        lt = ctx._long_term
        assert "Second summary" in lt
        assert "First summary" in lt  # old content preserved

    def test_add_to_working(self) -> None:
        ctx = ContextManager()
        ctx.add_to_working(TurnRecord(role="user", content="Find vulns"))
        assert ctx.turn_count == 1
        assert ctx.estimate_tokens()["working"] > 0

    def test_working_sliding_window_eviction(self) -> None:
        ctx = ContextManager(budget=ZoneBudget(working=50))  # tiny budget
        for i in range(10):
            ctx.add_to_working(
                TurnRecord(
                    role="user",
                    content=f"Turn {i} with enough content to fill budget " + "x" * 30,
                )
            )
        # Should have evicted some turns
        assert ctx.turn_count == 10
        assert len(ctx._working) < 10

    def test_needs_crystallization_budget_trigger(self) -> None:
        ctx = ContextManager(budget=ZoneBudget(working=50))
        ctx.add_to_working(TurnRecord(role="user", content="x" * 200))  # ~50 tokens
        # Working memory at ~50 tokens, 80% of 50 → triggers
        assert ctx.needs_crystallization(turn_threshold=999)

    def test_needs_crystallization_turn_count_trigger(self) -> None:
        ctx = ContextManager()
        for i in range(10):
            ctx.add_to_working(TurnRecord(role="user", content="short"))
        # turn_count >= 50 with threshold=10
        assert ctx.needs_crystallization(turn_threshold=10)

    def test_needs_crystallization_false_when_under_both(self) -> None:
        ctx = ContextManager(budget=ZoneBudget(working=60000))
        ctx.add_to_working(TurnRecord(role="user", content="short"))
        assert not ctx.needs_crystallization(turn_threshold=999)

    def test_build_messages_empty(self) -> None:
        ctx = ContextManager()
        msgs = ctx.build_messages()
        assert msgs == []

    def test_build_messages_with_fixed_and_long_term(self) -> None:
        ctx = ContextManager()
        ctx.set_fixed("System", rules="Rules")
        ctx.update_long_term("Long-term summary")
        msgs = ctx.build_messages(include_cache_control=False)
        assert len(msgs) == 2  # fixed + long_term (no working memory)

    def test_build_messages_includes_working(self) -> None:
        ctx = ContextManager()
        ctx.add_to_working(TurnRecord(role="user", content="Find vulns"))
        msgs = ctx.build_messages()
        assert len(msgs) == 1  # one working turn, no fixed/lt
        assert msgs[0]["role"] == "user"

    def test_build_messages_cache_control(self) -> None:
        ctx = ContextManager()
        ctx.set_fixed("System prompt")
        ctx.update_long_term("Long-term")
        msgs = ctx.build_messages(include_cache_control=True)
        assert len(msgs) == 2
        # First message should have cache_control
        content0 = msgs[0]["content"]
        assert isinstance(content0, list)
        has_cache = any(isinstance(b, dict) and "cache_control" in b for b in content0)
        assert has_cache

    def test_build_simple_messages(self) -> None:
        ctx = ContextManager()
        ctx.set_fixed("System prompt", rules="Rule 1")
        ctx.update_long_term("Long-term context")
        msgs = ctx.build_simple_messages("Find XSS", system="You are an auditor")
        assert len(msgs) == 2  # system + user
        assert msgs[0]["role"] == "system"
        assert "System prompt" in msgs[0]["content"]
        assert "Long-term context" in msgs[0]["content"]
        assert "Find XSS" in msgs[1]["content"]

    def test_build_simple_messages_no_fixed(self) -> None:
        ctx = ContextManager()
        msgs = ctx.build_simple_messages("Hello", system="")
        assert len(msgs) == 1  # just user, no system
        assert msgs[0]["role"] == "user"

    def test_recent_turns(self) -> None:
        ctx = ContextManager()
        for i in range(5):
            ctx.add_to_working(TurnRecord(role="user", content=f"Turn {i}"))
        recent = ctx.recent_turns(3)
        assert len(recent) == 3
        assert recent[-1].content == "Turn 4"

    def test_recent_turns_all(self) -> None:
        ctx = ContextManager()
        for i in range(3):
            ctx.add_to_working(TurnRecord(role="user", content=f"Turn {i}"))
        assert len(ctx.recent_turns()) == 3

    def test_snapshot(self) -> None:
        ctx = ContextManager()
        ctx.set_fixed("System", rules="Rules")
        ctx.update_long_term("Phase 1 done")
        ctx.add_to_working(TurnRecord(role="user", content="Find vuln"))
        snap = ctx.snapshot()
        assert "long_term" in snap
        assert "turn_count" in snap
        assert "token_estimate" in snap

    def test_restore(self) -> None:
        ctx = ContextManager()
        ctx.update_long_term("Original")
        ctx.restore({"long_term": "Restored", "turn_count": 42, "crystallization_count": 3})
        assert ctx._long_term == "Restored"
        assert ctx.turn_count == 42
        assert ctx.crystallization_count == 3
