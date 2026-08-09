"""scanner/agent_loop.py — ReAct-style multi-turn LLM loop with tool access.

Encapsulates the observe→reason→act cycle where the LLM can:
1. Call read-only audit tools (read_file, grep_code, etc.) to explore code
2. Receive tool results in subsequent turns
3. Eventually call the structured-output tool to report findings

Inspired by AutoCVE's QueryLoop pattern but simplified for HyqAgent's
single-Agent architecture.  Integrates with the existing Nudge system
for premature-termination detection and quality enforcement.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from hyqagent.scanner.nudge import (
    _CONTINUE_NUDGE,
    _TERMINAL_NUDGE,
    _detect_continue_intent,
)

logger = logging.getLogger(__name__)

# ── Data model ───────────────────────────────────────────────────────────────


@dataclass
class AgentLoopResult:
    """Structured return from :meth:`AgentLoop.run`."""

    output: dict[str, Any]  # Parsed structured output (tool_use input)
    turns: int  # Number of turns taken
    tool_calls: list[dict[str, Any]]  # Audit trail of tool calls
    total_tool_chars: int  # Cumulative chars of tool results
    truncated: bool = False  # True if old results were truncated for budget


@dataclass
class AgentLoopConfig:
    """Tunable parameters for :class:`AgentLoop`."""

    max_turns: int = 10
    tool_result_max_chars: int = 8_000
    max_temperature: float = 0.3


# ── AgentLoop ────────────────────────────────────────────────────────────────


class AgentLoop:
    """Multi-turn LLM loop with tool-based code exploration.

    Usage::

        loop = AgentLoop(provider, tool_registry, config)
        result = await loop.run(
            messages=[{"role": "user", "content": prompt}],
            output_schema=SCHEMA,
            system=SYSTEM_PROMPT,
            model="claude-sonnet-5",
        )
        if result:
            hypotheses = result.output  # parsed structured JSON
    """

    def __init__(
        self,
        provider: Any,  # LlmProvider protocol — duck-typed
        tool_registry: Any,  # ToolRegistry — duck-typed
        config: AgentLoopConfig | None = None,
    ) -> None:
        self._provider = provider
        self._tool_registry = tool_registry
        self._cfg = config or AgentLoopConfig()

    # ── Public API ───────────────────────────────────────────────────────

    async def run(
        self,
        messages: list[dict[str, Any]],
        output_schema: dict[str, Any],
        system: str,
        model: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> AgentLoopResult | None:
        """Run the ReAct loop and return structured output, or ``None``.

        Returns ``None`` when the loop exhausts ``max_turns`` without the
        model ever calling the output tool.
        """
        output_tool_name = output_schema.get("name", "output")
        audit_tool_defs = self._tool_registry.to_anthropic_tools()

        tool_calls: list[dict[str, Any]] = []
        total_tool_chars = 0
        truncated = False

        for turn in range(1, self._cfg.max_turns + 1):
            logger.debug(
                "agent_loop_turn",
                turn=turn,
                max_turns=self._cfg.max_turns,
                msg_count=len(messages),
            )

            # ── Call LLM ────────────────────────────────────────────
            try:
                response = await self._provider.generate_with_tools(
                    messages=messages,
                    model=model,
                    output_schema=output_schema,
                    audit_tools=audit_tool_defs,
                    system=system,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
            except Exception:
                logger.exception("agent_loop_provider_error", turn=turn)
                return None

            content = response.get("content", [])
            if not content:
                logger.warning("agent_loop_empty_response", turn=turn)
                return None

            # ── Inspect blocks ───────────────────────────────────────
            tool_use_block: dict[str, Any] | None = None
            text_blocks: list[str] = []

            for block in content:
                btype = block.get("type", "")
                if btype == "tool_use":
                    tool_use_block = block
                    break  # handle one tool_use per turn for simplicity
                elif btype == "text":
                    text_blocks.append(block.get("text", ""))

            # ── Case 1: Model called a tool ──────────────────────────
            if tool_use_block is not None:
                tool_name = tool_use_block.get("name", "")
                tool_input = tool_use_block.get("input", {})
                tool_use_id = tool_use_block.get("id", f"toolu_{turn}")

                logger.info(
                    "agent_loop_tool_call",
                    turn=turn,
                    tool=tool_name,
                )

                if tool_name == output_tool_name:
                    # ── Output tool → done ──────────────────────────
                    return AgentLoopResult(
                        output=tool_input,
                        turns=turn,
                        tool_calls=tool_calls,
                        total_tool_chars=total_tool_chars,
                        truncated=truncated,
                    )

                # ── Audit tool → execute and feed back ───────────────
                result = await self._tool_registry.execute(tool_name, **tool_input)
                result_msg = self._tool_registry.to_tool_result_message(tool_use_id, result)

                # Track budget
                result_chars = len(result_msg.get("content", ""))
                total_tool_chars += result_chars

                # Truncate old tool results if over budget
                if total_tool_chars > self._cfg.tool_result_max_chars:
                    messages = self._truncate_tool_results(messages)
                    truncated = True

                # Build the assistant + user turn
                assistant_block = {
                    "type": "tool_use",
                    "id": tool_use_id,
                    "name": tool_name,
                    "input": tool_input,
                }

                messages.append({"role": "assistant", "content": [assistant_block]})
                messages.append({"role": "user", "content": [result_msg]})

                tool_calls.append(
                    {
                        "turn": turn,
                        "tool": tool_name,
                        "input": tool_input,
                        "success": result.success,
                        "chars": result_chars,
                    }
                )
                continue

            # ── Case 2: Text-only response ───────────────────────────
            combined_text = " ".join(text_blocks)

            if _detect_continue_intent(combined_text) and turn < self._cfg.max_turns:
                # Model wants to continue but didn't use tools → nudge
                logger.info("agent_loop_continue_nudge", turn=turn)
                messages.append({"role": "assistant", "content": combined_text[:500]})
                messages.append({"role": "user", "content": _CONTINUE_NUDGE})
                continue

            # Terminal: text-only but no continue intent → final nudge
            logger.info("agent_loop_terminal_nudge", turn=turn)
            messages.append({"role": "assistant", "content": combined_text[:500]})
            messages.append({"role": "user", "content": _TERMINAL_NUDGE})
            # One more chance — if LLM still doesn't produce output tool
            # on the next turn, the loop will detect it and return None.

        # ── Exhausted turns ───────────────────────────────────────────
        logger.warning("agent_loop_max_turns_exceeded", max_turns=self._cfg.max_turns)
        return None

    # ── Internal helpers ──────────────────────────────────────────────────

    @staticmethod
    def _truncate_tool_results(
        messages: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Truncate the oldest tool-result content to stay within budget.

        Keeps the system prompt and first user message intact.
        Only shortens ``tool_result`` blocks older than the most recent
        ``max_keep`` turns.
        """
        max_keep = 3  # Keep the 3 most recent tool-result pairs
        tool_result_indices = [
            i
            for i, m in enumerate(messages)
            if m.get("role") == "user"
            and isinstance(m.get("content"), list)
            and any(b.get("type") == "tool_result" for b in m["content"])
        ]

        if len(tool_result_indices) <= max_keep:
            return messages

        for idx in tool_result_indices[:-max_keep]:
            content = messages[idx].get("content", [])
            for block in content:
                if block.get("type") == "tool_result":
                    block["content"] = "[content truncated for context budget]"

        return messages
