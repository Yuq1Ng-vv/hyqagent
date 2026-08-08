"""Tests for scanner/nudge.py — Nudge loop and quality checks.

Tests are independent of real LLM calls; they verify:
- NudgeConfig defaults and limits
- Continue-intent pattern matching
- Stop-hook logic (empty, low confidence, missing verdict)
- NudgeLoop result structure and termination reasons
- NudgeLoop integration with a fake provider (no real API calls)
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from hyqagent.scanner.nudge import (
    NudgeConfig,
    NudgeLoop,
    NudgeType,
    _detect_continue_intent,
    _last_text_from_messages,
    stop_on_empty,
    stop_on_low_confidence,
    stop_on_missing_verdict,
)

# ── NudgeConfig ────────────────────────────────────────────────────────────────


class TestNudgeConfig:
    def test_defaults_are_reasonable(self) -> None:
        c = NudgeConfig()
        assert c.max_turns == 5
        assert c.terminal_nudge_limit == 2
        assert c.continue_nudge_limit == 2
        assert c.quality_nudge_limit == 2
        assert c.enable_continue_intent_detection is True

    def test_custom_limits(self) -> None:
        c = NudgeConfig(max_turns=3, terminal_nudge_limit=1)
        assert c.max_turns == 3
        assert c.terminal_nudge_limit == 1

    def test_disable_continue_intent(self) -> None:
        c = NudgeConfig(enable_continue_intent_detection=False)
        assert c.enable_continue_intent_detection is False


# ── Continue-intent detection ──────────────────────────────────────────────────


class TestContinueIntentDetection:
    @pytest.mark.parametrize(
        "text",
        [
            "Let me continue reviewing the authentication module.",
            "I'll check the next endpoint now.",
            "Continuing with the analysis of the database layer.",
            "Next, I will examine the file upload handler.",
            "Moving on to the admin controller.",
            "I need to check the CSRF tokens in the forms.",
            "Let me further read the middleware chain.",
        ],
    )
    def test_english_continue_intent(self, text: str) -> None:
        assert _detect_continue_intent(text), f"Should detect: {text!r}"

    @pytest.mark.parametrize(
        "text",
        [
            "继续审查下一个模块。",
            "接下来检查用户认证部分。",
            "还需要分析数据验证逻辑。",
            "让我继续深入查看文件上传流程。",
            "接下来需要确认权限校验是否正确。",
        ],
    )
    def test_chinese_continue_intent(self, text: str) -> None:
        assert _detect_continue_intent(text), f"Should detect: {text!r}"

    @pytest.mark.parametrize(
        "text",
        [
            "No vulnerabilities found in this code.",
            "The analysis is complete. All endpoints are secure.",
            "I have finished the audit.",
            "Here is my final report.",
            "This function properly sanitizes all inputs.",
        ],
    )
    def test_non_continue_text(self, text: str) -> None:
        assert not _detect_continue_intent(text), f"Should NOT detect: {text!r}"

    def test_empty_text(self) -> None:
        assert not _detect_continue_intent("")
        assert not _detect_continue_intent("   ")


# ── Message text extraction ────────────────────────────────────────────────────


class TestLastTextFromMessages:
    def test_string_content(self) -> None:
        msgs = [
            {"role": "user", "content": "Analyze this code."},
            {"role": "assistant", "content": "I found an XSS vulnerability."},
        ]
        assert _last_text_from_messages(msgs) == "I found an XSS vulnerability."

    def test_block_content(self) -> None:
        msgs = [
            {"role": "assistant", "content": [
                {"type": "text", "text": "First paragraph."},
                {"type": "text", "text": "Second paragraph."},
            ]},
        ]
        result = _last_text_from_messages(msgs)
        assert "First paragraph." in result
        assert "Second paragraph." in result

    def test_no_assistant_message(self) -> None:
        msgs = [{"role": "user", "content": "Hello"}]
        assert _last_text_from_messages(msgs) == ""

    def test_last_assistant_only(self) -> None:
        msgs = [
            {"role": "assistant", "content": "First response."},
            {"role": "user", "content": "Continue."},
            {"role": "assistant", "content": "Second response."},
        ]
        assert _last_text_from_messages(msgs) == "Second response."


# ── Stop hooks ─────────────────────────────────────────────────────────────────


class TestStopOnEmpty:
    def test_blocks_empty_list(self) -> None:
        hook = stop_on_empty("hypotheses")
        reason = hook({"hypotheses": []})
        assert reason is not None
        assert "empty" in reason

    def test_allows_nonempty_list(self) -> None:
        hook = stop_on_empty("hypotheses")
        reason = hook({"hypotheses": [{"vuln_type": "xss"}]})
        assert reason is None

    def test_allows_missing_key(self) -> None:
        hook = stop_on_empty("hypotheses")
        reason = hook({})
        assert reason is None

    def test_custom_key(self) -> None:
        hook = stop_on_empty("findings")
        reason = hook({"findings": []})
        assert reason is not None
        assert "findings" in reason


class TestStopOnLowConfidence:
    def test_blocks_when_all_below_threshold(self) -> None:
        hook = stop_on_low_confidence(0.3)
        reason = hook({
            "hypotheses": [
                {"confidence": 0.1},
                {"confidence": 0.2},
            ]
        })
        assert reason is not None
        assert "confidence < 30%" in reason

    def test_allows_when_any_above_threshold(self) -> None:
        hook = stop_on_low_confidence(0.3)
        reason = hook({
            "hypotheses": [
                {"confidence": 0.1},
                {"confidence": 0.5},
            ]
        })
        assert reason is None

    def test_ignores_empty_list(self) -> None:
        hook = stop_on_low_confidence(0.3)
        reason = hook({"hypotheses": []})
        assert reason is None  # handled by stop_on_empty


class TestStopOnMissingVerdict:
    def test_blocks_inconclusive_without_reasoning(self) -> None:
        reason = stop_on_missing_verdict({"verdict": "inconclusive"})
        assert reason is not None
        assert "inconclusive" in reason

    def test_allows_inconclusive_with_reasoning(self) -> None:
        reason = stop_on_missing_verdict({
            "verdict": "inconclusive",
            "q1_reachability": "Source can reach sink.",
            "q5_judgment": "Needs more investigation.",
        })
        assert reason is None

    def test_allows_confirmed(self) -> None:
        reason = stop_on_missing_verdict({
            "verdict": "confirmed",
            "confidence": 0.9,
        })
        assert reason is None

    def test_allows_rejected(self) -> None:
        reason = stop_on_missing_verdict({"verdict": "rejected"})
        assert reason is None


# ── NudgeLoop with fake provider ───────────────────────────────────────────────


def _fake_provider_returning(result: dict) -> AsyncMock:
    """Build an AsyncMock that returns *result* from generate_structured."""
    mock = AsyncMock()
    mock.generate_structured = AsyncMock(return_value=result)
    return mock


class TestNudgeLoopWithFakeProvider:
    @pytest.mark.asyncio
    async def test_immediate_success(self) -> None:
        """When provider returns valid data on first try, loop exits immediately."""
        loop = NudgeLoop(NudgeConfig(max_turns=3))
        provider = _fake_provider_returning({"hypotheses": [{"vuln_type": "xss"}]})

        result = await loop.run(
            provider=provider,
            model="test-model",
            messages=[{"role": "user", "content": "Test"}],
            output_schema={"name": "test", "input_schema": {"type": "object"}},
        )

        assert result.success is True
        assert result.turns == 1
        assert result.termination_reason == "completed"
        assert len(result.nudges) == 0
        assert result.data == {"hypotheses": [{"vuln_type": "xss"}]}

    @pytest.mark.asyncio
    async def test_terminal_nudge_then_success(self) -> None:
        """Empty result → TERMINAL nudge → model calls tool → success."""
        loop = NudgeLoop(NudgeConfig(max_turns=5, terminal_nudge_limit=2))
        provider = _fake_provider_returning({})  # first call: empty
        # Second call: success
        provider.generate_structured.side_effect = [
            {},  # turn 1: text-only, triggers TERMINAL nudge
            {"hypotheses": [{"vuln_type": "sqli"}]},  # turn 2: success
        ]

        result = await loop.run(
            provider=provider,
            model="test-model",
            messages=[{"role": "user", "content": "Test"}],
            output_schema={"name": "test", "input_schema": {"type": "object"}},
        )

        assert result.success is True
        assert result.turns == 2
        assert len(result.nudges) == 1
        assert result.nudges[0]["type"] == NudgeType.TERMINAL.value

    @pytest.mark.asyncio
    async def test_terminal_limit_exceeded(self) -> None:
        """When terminal nudge limit is exceeded, loop terminates with failure."""
        loop = NudgeLoop(NudgeConfig(max_turns=5, terminal_nudge_limit=2))
        provider = _fake_provider_returning({})  # always empty

        result = await loop.run(
            provider=provider,
            model="test-model",
            messages=[{"role": "user", "content": "Test"}],
            output_schema={"name": "test", "input_schema": {"type": "object"}},
        )

        assert result.success is False
        assert result.termination_reason == "terminal_limit"

    @pytest.mark.asyncio
    async def test_quality_nudge_then_success(self) -> None:
        """Empty hypotheses blocked → QUALITY nudge → model fixes → success."""
        loop = NudgeLoop(NudgeConfig(max_turns=5, quality_nudge_limit=2))
        provider = _fake_provider_returning({})
        provider.generate_structured.side_effect = [
            {"hypotheses": []},  # turn 1: empty, triggers QUALITY nudge
            {"hypotheses": [{"vuln_type": "idor", "confidence": 0.8}]},  # turn 2: ok
        ]

        result = await loop.run(
            provider=provider,
            model="test-model",
            messages=[{"role": "user", "content": "Test"}],
            output_schema={"name": "test", "input_schema": {"type": "object"}},
            stop_hooks=[stop_on_empty("hypotheses")],
        )

        assert result.success is True
        assert result.turns == 2
        assert len(result.nudges) == 1
        assert result.nudges[0]["type"] == NudgeType.QUALITY.value

    @pytest.mark.asyncio
    async def test_quality_limit_exceeded_accepts_anyway(self) -> None:
        """When quality limit is hit, loop accepts the result anyway."""
        loop = NudgeLoop(NudgeConfig(max_turns=5, quality_nudge_limit=2))
        provider = _fake_provider_returning({})
        provider.generate_structured.side_effect = [
            {"hypotheses": []},  # turn 1
            {"hypotheses": []},  # turn 2
            {"hypotheses": []},  # turn 3: limit hit → accepted
        ]

        result = await loop.run(
            provider=provider,
            model="test-model",
            messages=[{"role": "user", "content": "Test"}],
            output_schema={"name": "test", "input_schema": {"type": "object"}},
            stop_hooks=[stop_on_empty("hypotheses")],
        )

        # After quality limit, it accepts the last result and reports success
        assert result.turns >= 3

    @pytest.mark.asyncio
    async def test_max_turns_exceeded(self) -> None:
        """When max_turns is hit, loop terminates."""
        loop = NudgeLoop(NudgeConfig(max_turns=2, terminal_nudge_limit=5))
        provider = _fake_provider_returning({})

        result = await loop.run(
            provider=provider,
            model="test-model",
            messages=[{"role": "user", "content": "Test"}],
            output_schema={"name": "test", "input_schema": {"type": "object"}},
        )

        assert result.success is False
        assert result.termination_reason == "max_turns"

    @pytest.mark.asyncio
    async def test_model_error_is_caught(self) -> None:
        """When provider raises, loop returns model_error."""
        loop = NudgeLoop()
        provider = _fake_provider_returning({})
        provider.generate_structured.side_effect = RuntimeError("API down")

        result = await loop.run(
            provider=provider,
            model="test-model",
            messages=[{"role": "user", "content": "Test"}],
            output_schema={"name": "test", "input_schema": {"type": "object"}},
        )

        assert result.success is False
        assert result.termination_reason == "model_error"
        assert result.turns == 1

    @pytest.mark.asyncio
    async def test_nudge_records_are_complete(self) -> None:
        """Each nudge record has all required fields."""
        loop = NudgeLoop(NudgeConfig(max_turns=5))
        provider = _fake_provider_returning({})
        provider.generate_structured.side_effect = [
            {},
            {"hypotheses": [{"vuln_type": "xss", "confidence": 0.8}]},
        ]

        result = await loop.run(
            provider=provider,
            model="test-model",
            messages=[{"role": "user", "content": "Test"}],
            output_schema={"name": "test", "input_schema": {"type": "object"}},
        )

        for nudge in result.nudges:
            assert "turn" in nudge
            assert "type" in nudge
            assert "message" in nudge
            assert nudge["type"] in (
                NudgeType.TERMINAL.value,
                NudgeType.CONTINUE.value,
                NudgeType.QUALITY.value,
            )

    @pytest.mark.asyncio
    async def test_multiple_stop_hooks_all_run(self) -> None:
        """All registered stop hooks are checked."""
        loop = NudgeLoop(NudgeConfig(max_turns=3, quality_nudge_limit=1))

        # A result that passes empty check but fails low-confidence check
        provider = _fake_provider_returning({})
        provider.generate_structured.side_effect = [
            {
                "hypotheses": [
                    {"vuln_type": "xss", "confidence": 0.1},
                ]
            },
            {
                "hypotheses": [
                    {"vuln_type": "xss", "confidence": 0.8},
                ]
            },
        ]

        result = await loop.run(
            provider=provider,
            model="test-model",
            messages=[{"role": "user", "content": "Test"}],
            output_schema={"name": "test", "input_schema": {"type": "object"}},
            stop_hooks=[stop_on_empty("hypotheses"), stop_on_low_confidence(0.3)],
        )

        assert result.success is True
        # First call blocked by low-confidence hook → QUALITY nudge
        assert len(result.nudges) == 1
        assert result.nudges[0]["type"] == NudgeType.QUALITY.value


# ── NudgeType enum ─────────────────────────────────────────────────────────────


class TestNudgeType:
    def test_values(self) -> None:
        assert NudgeType.TERMINAL.value == "terminal_action"
        assert NudgeType.CONTINUE.value == "continue_intent"
        assert NudgeType.QUALITY.value == "quality_block"
