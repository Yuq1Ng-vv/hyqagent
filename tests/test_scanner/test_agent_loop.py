"""Tests for scanner/agent_loop.py — AgentLoop and AgentLoopConfig."""

from __future__ import annotations

from hyqagent.scanner.agent_loop import AgentLoopConfig, AgentLoopResult

# ── AgentLoopConfig tests ──────────────────────────────────────────────────


class TestAgentLoopConfig:
    """Unit tests for AgentLoopConfig dataclass."""

    def test_defaults(self) -> None:
        """Verify sensible defaults."""
        cfg = AgentLoopConfig()
        assert cfg.max_turns == 10
        assert cfg.tool_result_max_chars == 8_000
        assert cfg.max_temperature == 0.3

    def test_custom_values(self) -> None:
        """All fields are overridable."""
        cfg = AgentLoopConfig(
            max_turns=5,
            tool_result_max_chars=2_000,
            max_temperature=0.7,
        )
        assert cfg.max_turns == 5
        assert cfg.tool_result_max_chars == 2_000
        assert cfg.max_temperature == 0.7


# ── AgentLoopResult tests ──────────────────────────────────────────────────


class TestAgentLoopResult:
    """Unit tests for AgentLoopResult dataclass."""

    def test_construction(self) -> None:
        """Basic construction with required fields."""
        r = AgentLoopResult(
            output={"verdict": "confirmed"},
            turns=3,
            tool_calls=[
                {"turn": 1, "tool": "grep_code", "input": {}, "success": True, "chars": 42},
                {"turn": 2, "tool": "read_file", "input": {}, "success": True, "chars": 200},
            ],
            total_tool_chars=242,
        )
        assert r.output == {"verdict": "confirmed"}
        assert r.turns == 3
        assert len(r.tool_calls) == 2
        assert r.total_tool_chars == 242
        assert not r.truncated  # default

    def test_truncated_flag(self) -> None:
        """Truncated flag is stored correctly."""
        r = AgentLoopResult(
            output={},
            turns=10,
            tool_calls=[],
            total_tool_chars=12_000,
            truncated=True,
        )
        assert r.truncated


# ── AgentLoop._truncate_tool_results tests ─────────────────────────────────


class TestTruncateToolResults:
    """Tests for AgentLoop._truncate_tool_results static method."""

    def test_no_truncation_when_few_results(self) -> None:
        """Messages with ≤3 tool-result pairs are unchanged."""
        from hyqagent.scanner.agent_loop import AgentLoop

        messages = [
            {"role": "system", "content": "You are a security auditor."},
            {"role": "user", "content": "Find bugs."},
            {
                "role": "user",
                "content": [{"type": "tool_result", "content": "result 1"}],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "content": "result 2"}],
            },
        ]
        result = AgentLoop._truncate_tool_results(messages)
        assert result is messages  # same list reference
        assert result[2]["content"][0]["content"] == "result 1"

    def test_truncates_old_results(self) -> None:
        """Oldest tool results beyond last 3 are truncated."""
        from hyqagent.scanner.agent_loop import AgentLoop

        messages = [
            {"role": "user", "content": "hi"},
            {
                "role": "user",
                "content": [{"type": "tool_result", "content": "old 1"}],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "content": "old 2"}],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "content": "old 3"}],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "content": "keep 1"}],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "content": "keep 2"}],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "content": "keep 3"}],
            },
        ]
        result = AgentLoop._truncate_tool_results(messages)
        # 6 tool-result pairs (indices 1-6), keep last 3 → truncate first 3
        assert "[content truncated" in result[1]["content"][0]["content"]
        assert "[content truncated" in result[2]["content"][0]["content"]
        assert "[content truncated" in result[3]["content"][0]["content"]
        assert result[4]["content"][0]["content"] == "keep 1"
        assert result[5]["content"][0]["content"] == "keep 2"
        assert result[6]["content"][0]["content"] == "keep 3"

    def test_mixed_content_types_ignored(self) -> None:
        """Non-tool_result user messages are ignored."""
        from hyqagent.scanner.agent_loop import AgentLoop

        messages = [
            {"role": "user", "content": "text message"},
            {
                "role": "user",
                "content": [{"type": "text", "content": "not a tool result"}],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "content": "only one"}],
            },
        ]
        result = AgentLoop._truncate_tool_results(messages)
        # Only one tool_result → ≤3 → no truncation
        assert result[2]["content"][0]["content"] == "only one"
