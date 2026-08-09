"""models/providers/anthropic_provider.py — Anthropic SDK wrapper for Phase 3 LLM.

Implements the :class:`LlmProvider` protocol from :mod:`hyqagent.core.protocols`.
Works with both Anthropic (Claude) and DeepSeek (Anthropic-format API) by
accepting a configurable ``base_url``.

Key features:
- ``generate()`` — raw Messages API call with tenacity retry + circuit breaker
- ``generate_structured()`` — tool_use-based structured JSON output
- ``count_tokens()`` — token counting with fallback estimation
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
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

logger = structlog.get_logger(__name__)


# ── Config dataclass ────────────────────────────────────────────────────────


@dataclass
class ProviderConfig:
    """Configuration for a single Anthropic-compatible provider.

    For Claude::

        ProviderConfig(api_key="sk-ant-...", base_url=None)

    For DeepSeek::

        ProviderConfig(
            api_key="sk-...",
            base_url="https://api.deepseek.com/anthropic",
        )
    """

    api_key: str
    base_url: str | None = None


# ── Circuit breaker ─────────────────────────────────────────────────────────

_breaker = CircuitBreaker(
    failure_threshold=5,
    recovery_timeout=60,
    name="llm_provider",
)


# ── AnthropicProvider ───────────────────────────────────────────────────────


class AnthropicProvider:
    """Anthropic-compatible LLM provider with retry and circuit-breaking.

    Usage::

        config = ProviderConfig(api_key="sk-...", base_url=None)
        provider = AnthropicProvider(config)
        resp = await provider.generate([{"role":"user","content":"Hello"}],
                                        model="claude-sonnet-5")
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
        call_start = time.monotonic()
        result = await self._call_with_retry(
            messages=messages,
            model=model,
            system=system,
            max_tokens=max_tokens,
            temperature=temperature,
            tools=tools,
            **kwargs,
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
                    input_tokens=usage.get("input_tokens", 0),
                    output_tokens=usage.get("output_tokens", 0),
                    cache_read_tokens=usage.get("cache_read_input_tokens", 0),
                    latency_ms=elapsed_ms,
                )
            except Exception:
                pass  # Never let metrics break the audit

        return result

    async def generate_structured(
        self,
        messages: list[dict[str, Any]],
        model: str,
        output_schema: dict[str, Any],
        system: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate structured JSON output via Anthropic tool_use.

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

        # Detect DeepSeek endpoint: requiring workarounds for tool_choice and
        # thinking mode (DeepSeek 默认开启思考模式, which wraps output in
        # `thinking` blocks that bury the tool_use payload).
        _is_deepseek = self._config.base_url and "deepseek" in self._config.base_url

        # DeepSeek: disable thinking so tool_use comes back cleanly.
        _extra_kwargs: dict[str, Any] = dict(kwargs)
        if _is_deepseek:
            _extra_kwargs.setdefault("thinking", {"type": "disabled"})

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
            tool_choice=(
                {"type": "auto"} if _is_deepseek else {"type": "tool", "name": tool_name}
            ),
            **_extra_kwargs,
        )

        # Extract tool_use block (skip thinking / redacted_thinking blocks
        # that DeepSeek may emit even with thinking disabled).
        content = response.get("content", [])
        for block in content:
            if block.get("type") == "tool_use":
                return block.get("input", {})  # type: ignore[no-any-return]

        # Fallback: parse text blocks as JSON (skip non-structured blocks).
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

    def count_tokens(
        self,
        messages: list[dict[str, Any]],
        model: str,
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
