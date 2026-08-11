"""scanner/nudge.py — Multi-turn LLM nudges to prevent premature termination.

Inspired by AutoCVE's Nudge system (AGPL v3, https://github.com/larlarua/AutoCVE).
See docs/AUTOCVE-RESEARCH.md for the full attribution and comparison.

The core insight from AutoCVE is that LLMs in security-audit loops exhibit
predictable failure modes:

1. **Terminal-action omission** — the model writes a natural-language summary
   ("analysis complete, no vulnerabilities found") but never calls the
   structured-output tool, so no machine-usable result is produced.
2. **Continue-intent without action** — the model says "I'll continue reviewing
   the authentication module next" but produces no tool calls.  The next turn
   is silent.
3. **Low-quality finalisation** — the model calls the termination tool but
   with empty payloads, extremely low confidence, or missing required fields.

Each failure mode is addressed by a *nudge*: a synthetic user message injected
back into the conversation that corrects the behaviour without restarting the
whole turn.

HyqAgent adapts three of AutoCVE's seven nudge types and adds one of its own
(``QUALITY``, a stop-hook for structured-output payload validation):

============ ===================================================== ========
Nudge        Trigger                                                Limit
============ ===================================================== ========
TERMINAL     Model returned text-only response when a structured-   2
             output tool call was required.
CONTINUE     Model expressed intent to keep working but produced    2
             no tool calls (detected via regex patterns).
QUALITY      Stop-hook blocked: result is empty, confidence too     2
             low, or required fields are missing.
============ ===================================================== ========

Usage::

    from hyqagent.scanner.nudge import NudgeLoop, NudgeConfig, stop_on_empty

    loop = NudgeLoop(NudgeConfig(max_turns=5))
    result = await loop.run(
        provider=provider,
        model="claude-sonnet-5",
        messages=[{"role": "user", "content": "Analyse this code..."}],
        output_schema=HYPOTHESIS_SCHEMA,
        system="You are a security auditor.",
        stop_hooks=[stop_on_empty("hypotheses")],
    )
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol

import structlog

if TYPE_CHECKING:
    from hyqagent.core.protocols import LlmProvider

logger = structlog.get_logger(__name__)


# ── Nudge type ─────────────────────────────────────────────────────────────────


class NudgeType(Enum):
    """Classification of a nudge event.

    Adapted from AutoCVE's taxonomy (ARCHITECTURE_DESIGN_EN.md §8).
    We implement the three types most relevant to HyqAgent's single-Agent,
    structured-output pipeline.
    """

    TERMINAL = "terminal_action"
    """Model produced text without calling the required structured-output tool."""

    CONTINUE = "continue_intent"
    """Model signalled intent to continue but produced no tool calls."""

    QUALITY = "quality_block"
    """A stop-hook rejected the output — e.g. empty result or low confidence."""


# ── Configuration ──────────────────────────────────────────────────────────────


@dataclass
class NudgeConfig:
    """Tunable limits for the nudge loop.

    Attributes:
        max_turns: Hard ceiling on total LLM calls per invocation.
        terminal_nudge_limit: Max TERMINAL nudges before giving up.
        continue_nudge_limit: Max CONTINUE nudges before giving up.
        quality_nudge_limit: Max QUALITY nudges before giving up.
        enable_continue_intent_detection: When ``False``, skip the regex-based
            continue-intent check entirely.

    """

    max_turns: int = 5
    terminal_nudge_limit: int = 2
    continue_nudge_limit: int = 2
    quality_nudge_limit: int = 2
    enable_continue_intent_detection: bool = True


# ── Stop hook protocol ─────────────────────────────────────────────────────────


class StopHook(Protocol):
    """Inspect a structured result and decide whether the loop may terminate.

    Return ``None`` to allow termination, or a string (the blocking reason)
    to inject a QUALITY nudge and try again.
    """

    def __call__(self, result: dict[str, Any]) -> str | None:
        """Evaluate *result* and optionally block termination."""
        ...


# ── Built-in stop hooks ────────────────────────────────────────────────────────


def stop_on_empty(key: str = "hypotheses") -> StopHook:
    """Build a stop hook that blocks when *key* is an empty list.

    Example::

        hook = stop_on_empty("hypotheses")
        # Blocks: {"hypotheses": []}
        # Allows: {"hypotheses": [{"vuln_type": "xss", ...}]}
    """

    def _hook(result: dict[str, Any]) -> str | None:
        value = result.get(key)
        if isinstance(value, list) and len(value) == 0:
            return (
                f"You returned an empty `{key}` list. Before finalising, "
                f"verify: did you examine ALL the code in the provided "
                f"slice? If you genuinely found no vulnerabilities, "
                f"explain why each potential sink is safe."
            )
        return None

    return _hook


def stop_on_low_confidence(threshold: float = 0.3) -> StopHook:
    """Build a stop hook that blocks when ALL items have confidence < *threshold*."""

    def _hook(result: dict[str, Any]) -> str | None:
        items = result.get("hypotheses", [])
        if not isinstance(items, list) or len(items) == 0:
            return None  # handled by stop_on_empty

        confidences = [float(item.get("confidence", 0)) for item in items if isinstance(item, dict)]
        if confidences and all(c < threshold for c in confidences):
            return (
                f"All {len(confidences)} findings have confidence < "
                f"{threshold:.0%}. Re-examine the code and provide more "
                f"specific evidence, or reduce the number of low-quality "
                f"findings."
            )
        return None

    return _hook


def stop_on_missing_verdict(result: dict[str, Any]) -> str | None:
    """Stop hook for validator: blocks on 'inconclusive' without detailed reasoning."""
    verdict = result.get("verdict", "")
    if verdict == "inconclusive":
        has_reasoning = any(
            result.get(q)
            for q in [
                "q1_reachability",
                "q2_bypass",
                "q3_sanitizer",
                "q4_framework",
                "q5_judgment",
            ]
        )
        if not has_reasoning:
            return (
                "Your verdict is 'inconclusive' but you provided no detailed "
                "reasoning. Please answer each of the 5 validation questions "
                "with specific code references."
            )
    return None


# ── Continue-intent patterns ───────────────────────────────────────────────────
#
# Adapted from AutoCVE's _CONTINUE_INTENT_PATTERNS (query_loop.py).
# These regexes detect when a model has signalled it wants to keep working
# but failed to produce an actual tool call — a common LLM failure mode
# where the model narrates its plan without executing it.

_CONTINUE_INTENT_PATTERNS: list[re.Pattern[str]] = [
    # English patterns
    re.compile(
        r"let\s+me\s+(continue|check|examine|review|"
        r"analyse|analyze|look|inspect|investigate|dig)",
        re.IGNORECASE,
    ),
    re.compile(
        r"i\s*(?:'ll|\s+will)\s+(continue|check|examine|"
        r"review|analyse|analyze|look|read|investigate)",
        re.IGNORECASE,
    ),
    re.compile(r"continuing\s+(with|to|the)", re.IGNORECASE),
    re.compile(
        r"next\s*,?\s*i\s*(?:'ll|will)\s+"
        r"(check|examine|review|read|look)",
        re.IGNORECASE,
    ),
    re.compile(r"(?:moving|proceeding)\s+on\s+to", re.IGNORECASE),
    re.compile(
        r"i\s+(?:still\s+)?need\s+to\s+"
        r"(check|examine|review|read|verify|confirm|look)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:let|allow)\s+me\s+(?:further\s+)?"
        r"(?:check|examine|review|read)",
        re.IGNORECASE,
    ),
    # Chinese patterns
    re.compile(r"继续(?:审查|分析|检查|查看|审计|追踪)"),
    re.compile(r"接下来(?:我|需要|检查|分析|查看)"),
    re.compile(r"还需要(?:检查|分析|查看|确认|验证)"),
    re.compile(r"让我(?:继续|进一步|深入)"),
]


def _detect_continue_intent(text: str) -> bool:
    """Return ``True`` if *text* signals the model intends to continue."""
    return any(p.search(text) for p in _CONTINUE_INTENT_PATTERNS)


# ── Nudge messages ─────────────────────────────────────────────────────────────

_TERMINAL_NUDGE = (
    "You responded with text but did NOT call the required tool. "
    "This is not completion — you MUST use the provided tool to "
    "produce structured output before the task is finished. "
    "Call the tool now."
)

_CONTINUE_NUDGE = (
    "You indicated you would continue the analysis, but you did not "
    "call any tools. If you need more information, use the available "
    "tools (Read, Grep, etc.) to gather it. Otherwise, finalise your "
    "findings using the structured-output tool. Do not just describe "
    "what you plan to do — actually do it."
)


def _quality_nudge(reason: str) -> str:
    """Format a quality-block nudge with the stop-hook's specific reason."""
    return (
        f"Your output was rejected by the quality gate: {reason}\n\n"
        "Please address this issue and re-submit your findings using "
        "the structured-output tool."
    )


# ── Result ─────────────────────────────────────────────────────────────────────


@dataclass
class NudgeResult:
    """Outcome of a :meth:`NudgeLoop.run` invocation.

    Attributes:
        data: The final structured output dict (empty dict on failure).
        turns: Total LLM calls made.
        nudges: Sequence of nudge records for observability.
        success: ``True`` iff the loop terminated with a valid tool call.
        termination_reason: One of ``completed``, ``max_turns``,
            ``terminal_limit``, ``continue_limit``, ``quality_limit``,
            ``model_error``.

    """

    data: dict[str, Any]
    turns: int
    nudges: list[dict[str, Any]] = field(default_factory=list)
    success: bool = False
    termination_reason: str = "completed"


# ── NudgeLoop ──────────────────────────────────────────────────────────────────


class NudgeLoop:
    """Multi-turn LLM wrapper that prevents premature termination.

    Wraps :meth:`LlmProvider.generate_structured` in a loop that:

    1. Calls the model.
    2. Checks whether a structured tool call was actually produced
       (``TERMINAL`` nudge if not).
    3. Optionally checks the response text for continue-intent language
       (``CONTINUE`` nudge if detected alongside missing tool calls).
    4. Runs registered stop-hooks on the structured result
       (``QUALITY`` nudge if any hook blocks).
    5. Repeats until a terminal condition is met or a hard limit is hit.

    Each nudge is recorded in the result for observability / cost tracking.
    """

    def __init__(self, config: NudgeConfig | None = None) -> None:
        self._config = config or NudgeConfig()

    # ── Public API ──────────────────────────────────────────────────────

    async def run(
        self,
        provider: LlmProvider,
        model: str,
        messages: list[dict[str, Any]],
        output_schema: dict[str, Any],
        system: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.1,
        stop_hooks: list[StopHook] | None = None,
    ) -> NudgeResult:
        """Execute the nudge-protected LLM call.

        Parameters
        ----------
        provider:
            The Anthropic-compatible provider to use.
        model:
            Model id to pass through.
        messages:
            Conversation messages so far (will be mutated!).
        output_schema:
            The structured-output tool schema.
        system:
            System prompt.
        max_tokens:
            Per-call token cap.
        temperature:
            Sampling temperature.
        stop_hooks:
            Optional list of quality-check callbacks.

        Returns
        -------
        NudgeResult
            with the final data and diagnostic info.

        """
        config = self._config
        nudges: list[dict[str, Any]] = []
        working_messages = list(messages)  # defensive copy

        # State counters (mirrors AutoCVE's per-nudge-type counters)
        terminal_count = 0
        continue_count = 0
        quality_count = 0

        for turn in range(1, config.max_turns + 1):
            logger.debug(
                "nudge_loop_turn",
                turn=turn,
                terminal_count=terminal_count,
                continue_count=continue_count,
                quality_count=quality_count,
            )

            # ── Call the model ───────────────────────────────────────────
            try:
                result = await provider.generate_structured(
                    messages=working_messages,
                    model=model,
                    output_schema=output_schema,
                    system=system,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
            except Exception:
                logger.exception("nudge_loop_model_error", turn=turn)
                return NudgeResult(
                    data={},
                    turns=turn,
                    nudges=nudges,
                    success=False,
                    termination_reason="model_error",
                )

            # ── Detect text-only response ─────────────────────────────────
            # generate_structured returns {} when no tool_use block is found
            # (see LlmProvider.generate_structured fallback).
            if result == {} or not result:
                # Try to extract text from the last assistant response
                # to check for continue-intent language.
                text_response = _last_text_from_messages(working_messages)

                if config.enable_continue_intent_detection and _detect_continue_intent(
                    text_response
                ):
                    if continue_count < config.continue_nudge_limit:
                        continue_count += 1
                        _record_nudge(nudges, turn, NudgeType.CONTINUE, _CONTINUE_NUDGE)
                        working_messages.append({"role": "user", "content": _CONTINUE_NUDGE})
                        continue
                    else:
                        # CONTINUE limit hit
                        return NudgeResult(
                            data={},
                            turns=turn,
                            nudges=nudges,
                            success=False,
                            termination_reason="continue_limit",
                        )

                # TERMINAL nudge
                if terminal_count < config.terminal_nudge_limit:
                    terminal_count += 1
                    _record_nudge(nudges, turn, NudgeType.TERMINAL, _TERMINAL_NUDGE)
                    working_messages.append({"role": "user", "content": _TERMINAL_NUDGE})
                    continue
                else:
                    # TERMINAL limit hit
                    return NudgeResult(
                        data={},
                        turns=turn,
                        nudges=nudges,
                        success=False,
                        termination_reason="terminal_limit",
                    )

            # ── Stop-hook checks ─────────────────────────────────────────
            blocked = False
            for hook in stop_hooks or []:
                blocking_reason = hook(result)
                if blocking_reason is not None:
                    blocked = True
                    if quality_count < config.quality_nudge_limit:
                        quality_count += 1
                        msg = _quality_nudge(blocking_reason)
                        _record_nudge(nudges, turn, NudgeType.QUALITY, msg)
                        working_messages.append({"role": "user", "content": msg})
                    else:
                        # QUALITY limit hit — accept the result anyway
                        logger.warning(
                            "nudge_loop_quality_limit_hit",
                            turn=turn,
                            blocking_reason=blocking_reason,
                        )
                    break  # one hook blocks → skip remaining hooks, retry

            if not blocked:
                # All checks passed
                logger.info(
                    "nudge_loop_completed",
                    turns=turn,
                    nudge_count=len(nudges),
                )
                return NudgeResult(
                    data=result,
                    turns=turn,
                    nudges=nudges,
                    success=True,
                    termination_reason="completed",
                )

        # Max turns reached
        logger.warning("nudge_loop_max_turns", turns=config.max_turns)
        return NudgeResult(
            data=result if "result" in dir() else {},
            turns=config.max_turns,
            nudges=nudges,
            success=False,
            termination_reason="max_turns",
        )


# ── Helpers ────────────────────────────────────────────────────────────────────


def _last_text_from_messages(messages: list[dict[str, Any]]) -> str:
    """Extract the text content from the last assistant message."""
    for m in reversed(messages):
        if m.get("role") == "assistant":
            content = m.get("content", "")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                parts = []
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
                return "\n".join(parts)
    return ""


def _record_nudge(
    nudges: list[dict[str, Any]],
    turn: int,
    nudge_type: NudgeType,
    message: str,
) -> None:
    """Append a nudge record for observability."""
    nudges.append(
        {
            "turn": turn,
            "type": nudge_type.value,
            "message": message[:200],  # truncated for logging compactness
        }
    )
