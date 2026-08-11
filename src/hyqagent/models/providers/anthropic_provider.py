"""models/providers/anthropic_provider.py — Anthropic SDK wrapper implementing LlmProvider.

Works with:
- Claude (Anthropic native) — ``base_url=None``
- DeepSeek (Anthropic-compatible endpoint) — ``base_url="https://api.deepseek.com/anthropic"``
- Any other Anthropic Messages API-compatible service.

Key features:
- ``generate()`` — raw Messages API call with tenacity retry + circuit breaker
- ``generate_structured()`` — tool_use-based structured JSON output
- ``generate_with_tools()`` — ReAct-style multi-tool generation (agent loop)
- ``count_tokens()`` — token counting with fallback estimation
"""

from __future__ import annotations

import contextlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

import structlog
from anthropic import Anthropic, APIStatusError, RateLimitError
from circuitbreaker import CircuitBreaker
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from hyqagent.core.protocols import LlmProvider

logger = structlog.get_logger(__name__)


# ── Config dataclass ────────────────────────────────────────────────────────


@dataclass
class ProviderConfig:
    """Configuration for a single Anthropic-compatible provider.

    For Claude::

        ProviderConfig(api_key="sk-ant-...", base_url=None)

    For DeepSeek (Anthropic-compatible endpoint)::

        ProviderConfig(
            api_key="sk-...",
            base_url="https://api.deepseek.com/anthropic",
            disable_thinking=True,   # DeepSeek defaults to thinking mode
            force_auto_tool_choice=True,  # DeepSeek needs auto tool_choice
        )
    """

    api_key: str
    base_url: str | None = None

    # ── Quirk flags — for providers that deviate from Anthropic behaviour ──
    disable_thinking: bool = field(
        default=False,
        metadata={
            "help": (
                'Set thinking={"type":"disabled"} on every request. '
                "Needed for DeepSeek which defaults to thinking mode that "
                "wraps output in thinking blocks, burying tool_use payloads."
            )
        },
    )
    force_auto_tool_choice: bool = field(
        default=False,
        metadata={
            "help": (
                'Use tool_choice={"type":"auto"} instead of forcing a '
                "specific tool.  DeepSeek and some compatible endpoints don't "
                'support {"type":"tool","name":"..."}.'
            )
        },
    )


# ── Circuit breaker ─────────────────────────────────────────────────────────

_breaker = CircuitBreaker(
    failure_threshold=5,
    recovery_timeout=60,
    name="llm_provider",
)


# ── AnthropicProvider ───────────────────────────────────────────────────────


class AnthropicProvider(LlmProvider):
    """Anthropic-compatible LLM provider with retry and circuit-breaking.

    Usage::

        config = ProviderConfig(api_key="sk-...", base_url=None)
        provider = AnthropicProvider(config)
        resp = await provider.generate(
            [{"role":"user","content":"Hello"}],
            model="claude-sonnet-5",
        )
    """

    def __init__(
        self,
        config: ProviderConfig,
        max_retries: int = 3,
        timeout_seconds: int = 120,
        on_call_complete: Any = None,
    ) -> None:
        self._config = config
        self._max_retries = max_retries
        self._timeout = timeout_seconds
        self._client = Anthropic(
            api_key=config.api_key,
            base_url=config.base_url,
            max_retries=0,  # we handle retries ourselves via tenacity
            timeout=timeout_seconds,
        )
        self._call_history: list[dict[str, Any]] = []
        self._on_call_complete = on_call_complete

    # ── Public API ──────────────────────────────────────────────────────

    async def generate(
        self,
        messages: list[dict[str, Any]],
        *,
        model: str,
        system: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.0,
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Call the Messages API with retry on transient failures.

        Returns a dict with keys: ``content`` (list of content blocks),
        ``model``, ``usage`` (input/output tokens), ``stop_reason``.
        """
        # Apply quirk flags as default kwargs (caller can override)
        merged_kwargs: dict[str, Any] = dict(kwargs)
        if self._config.disable_thinking:
            merged_kwargs.setdefault("thinking", {"type": "disabled"})

        call_start = time.monotonic()
        result = await self._call_with_retry(
            messages=messages,
            model=model,
            system=system,
            max_tokens=max_tokens,
            temperature=temperature,
            tools=tools,
            **merged_kwargs,
        )
        elapsed_ms = (time.monotonic() - call_start) * 1000

        usage = result.get("usage", {})
        self._call_history.append(
            {
                "model": model,
                "input_tokens": usage.get("input_tokens", 0),
                "output_tokens": usage.get("output_tokens", 0),
                "cache_read_tokens": usage.get("cache_read_input_tokens", 0),
                "latency_ms": elapsed_ms,
            }
        )

        logger.info(
            "llm_call_completed",
            model=model,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            latency_ms=round(elapsed_ms, 1),
        )

        # ── Observability callback (CostTracker / Prometheus / AuditTrail) ──
        if self._on_call_complete is not None:
            try:
                self._on_call_complete(
                    model=model,
                    phase=getattr(self, "_current_phase", "unknown"),
                    input_tokens=usage.get("input_tokens", 0),
                    output_tokens=usage.get("output_tokens", 0),
                    cache_read_tokens=usage.get("cache_read_input_tokens", 0),
                    latency_ms=elapsed_ms,
                )
            except Exception:
                logger.exception("on_call_complete_callback_failed")

        return result

    async def generate_structured(
        self,
        messages: list[dict[str, Any]],
        output_schema: dict[str, Any],
        *,
        model: str,
        system: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate structured JSON output via tool_use.

        Defines a single tool with *output_schema* as its ``input_schema``
        and forces the model to call it via ``tool_choice``.

        Returns the parsed JSON dict (the tool_use input).
        """
        tool_name = output_schema.get("name", "output")
        tools = [
            {
                "name": tool_name,
                "description": output_schema.get("description", "Structured output"),
                "input_schema": output_schema.get("input_schema", output_schema),
            }
        ]

        tool_choice: dict[str, Any]
        if self._config.force_auto_tool_choice:
            tool_choice = {"type": "auto"}
        else:
            tool_choice = {"type": "tool", "name": tool_name}

        response = await self.generate(
            messages=messages,
            model=model,
            system=(
                system
                + "\n\nYou MUST call the `"
                + tool_name
                + "` tool to produce structured output. Do not respond with text only."
            ),
            max_tokens=max_tokens,
            temperature=temperature,
            tools=tools,
            tool_choice=tool_choice,
            **kwargs,
        )

        # Extract tool_use block (skip thinking / redacted_thinking blocks).
        content = response.get("content", [])
        for block in content:
            if block.get("type") == "tool_use":
                return block.get("input", {})  # type: ignore[no-any-return]

        # Fallback: parse text blocks as JSON.
        for block in content:
            if block.get("type") == "text":
                text = block.get("text", "")
                try:
                    return json.loads(text)  # type: ignore[no-any-return]
                except (json.JSONDecodeError, TypeError):
                    continue

        logger.warning(
            "structured_output_fallback",
            model=model,
            content_types=[b.get("type") for b in content],
        )
        return {}

    async def generate_with_tools(
        self,
        messages: list[dict[str, Any]],
        model: str,
        output_schema: dict[str, Any],
        audit_tools: list[dict[str, Any]],
        *,
        system: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate a response that may include intermediate tool calls.

        Unlike :meth:`generate_structured`, this does NOT force the output
        tool.  The model is free to call audit tools, the output tool, or
        both, in any order.  The caller is responsible for inspecting
        ``content`` and deciding whether to continue the loop.

        Args:
            messages: Conversation history (may include prior tool results).
            model: Model ID to use.
            output_schema: Schema for the final structured-output tool.
            audit_tools: Additional tools the model may use to explore code.
            system: System prompt.
            max_tokens: Max tokens for this turn.
            temperature: Sampling temperature.
            **kwargs: Forwarded to :meth:`generate` unchanged.

        Returns:
            A dict with ``content`` (list of block dicts), ``model``,
            and ``usage`` — the raw :meth:`generate` result.
        """
        output_tool_name = output_schema.get("name", "output")
        output_tool = {
            "name": output_tool_name,
            "description": output_schema.get("description", "Structured output"),
            "input_schema": output_schema.get("input_schema", output_schema),
        }

        # Combine: audit tools first so the model explores before reporting
        tools = [*list(audit_tools), output_tool]

        system_prompt = system
        if system_prompt:
            system_prompt += "\n\n"
        system_prompt += (
            "You have access to code-exploration tools. Use them to gather "
            "information before making your final assessment. When you are "
            "ready to report your findings, call the `" + output_tool_name + "` tool."
        )

        return await self.generate(
            messages=messages,
            model=model,
            system=system_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            tools=tools,
            tool_choice={"type": "auto"},
            **kwargs,
        )

    def count_tokens(
        self,
        messages: list[dict[str, Any]],
        model: str,
        *,
        system: str = "",
        tools: list[dict[str, Any]] | None = None,
    ) -> int:
        """Estimate token count for *messages*.

        Uses Anthropic's ``count_tokens`` endpoint when available.
        Falls back to character-based estimation (~4 chars/token).
        """
        try:
            params: dict[str, Any] = {
                "model": model,
                "messages": messages,
            }
            if system:
                params["system"] = system
            if tools:
                params["tools"] = tools
            result = self._client.messages.count_tokens(**params)
            return result.input_tokens  # type: ignore[no-any-return]
        except Exception:
            # Fallback: rough character-based estimate
            total = sum(len(str(m.get("content", ""))) for m in messages)
            if system:
                total += len(system)
            return max(1, total // 4)

    @property
    def call_history(self) -> list[dict[str, Any]]:
        """Return a copy of the call history for cost tracking."""
        return list(self._call_history)

    # ── Internal ────────────────────────────────────────────────────────

    @_breaker
    async def _call_with_retry(
        self,
        messages: list[dict[str, Any]],
        model: str,
        system: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.0,
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Single API call with tenacity retry wrapper."""

        @retry(
            retry=retry_if_exception_type((RateLimitError, ConnectionError, TimeoutError))
            | retry_if_exception_type(APIStatusError),
            stop=stop_after_attempt(self._max_retries),
            wait=wait_exponential_jitter(initial=1, max=30),
            reraise=True,
        )
        async def _call() -> dict[str, Any]:
            import asyncio

            response = await asyncio.to_thread(
                self._client.messages.create,
                model=model,
                max_tokens=max_tokens,
                system=system,
                messages=messages,
                temperature=temperature,
                tools=tools or [],
                **kwargs,
            )
            return {
                "content": [
                    {
                        "type": (b.type if hasattr(b, "type") else "text"),
                        "text": b.text if hasattr(b, "text") else "",
                        "input": b.input if hasattr(b, "input") else {},
                        "name": b.name if hasattr(b, "name") else "",
                    }
                    for b in response.content
                ],
                "model": response.model,
                "usage": {
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens,
                    "cache_read_input_tokens": getattr(
                        response.usage, "cache_read_input_tokens", 0
                    ),
                }
                if response.usage
                else {},
                "stop_reason": response.stop_reason,
            }

        return await _call()
