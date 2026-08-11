"""models/providers/openai_provider.py — OpenAI SDK wrapper implementing LlmProvider.

Works with:
- OpenAI (GPT-4o, GPT-4, etc.) — ``base_url=None``
- Any OpenAI-compatible API (DeepSeek, Kimi, Qwen, one-api gateways, etc.)
  — ``base_url="https://api.deepseek.com/v1"``

Converts OpenAI response format → canonical internal format expected by all
scanner modules (same format AnthropicProvider produces).

Key features:
- ``generate()`` — Chat Completions API call with tenacity retry + circuit breaker
- ``generate_structured()`` — function-calling-based structured JSON output
- ``generate_with_tools()`` — ReAct-style multi-tool generation (agent loop)
- ``count_tokens()`` — tiktoken-based counting with fallback estimation
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import structlog
from circuitbreaker import CircuitBreaker
from openai import AsyncOpenAI, RateLimitError
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
    """Configuration for a single OpenAI-compatible provider.

    For OpenAI::

        ProviderConfig(api_key="sk-...", base_url=None)

    For DeepSeek (OpenAI-compatible endpoint)::

        ProviderConfig(
            api_key="sk-...",
            base_url="https://api.deepseek.com/v1",
        )

    For any OpenAI-compatible gateway (one-api, LiteLLM, etc.)::

        ProviderConfig(
            api_key="sk-...",
            base_url="https://your-gateway.example.com/v1",
        )
    """

    api_key: str
    base_url: str | None = None


# ── Circuit breaker ─────────────────────────────────────────────────────────

_breaker = CircuitBreaker(
    failure_threshold=5,
    recovery_timeout=60,
    name="llm_openai_provider",
)


# ── Helpers ─────────────────────────────────────────────────────────────────


def _normalize_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize tool definitions to OpenAI function-calling format.

    Accepts both Anthropic-native (``name/description/input_schema``) and
    OpenAI-native (``type/function``) formats and always returns the
    OpenAI format.
    """
    normalized: list[dict[str, Any]] = []
    for t in tools:
        # Already OpenAI format?
        if t.get("type") == "function" and "function" in t:
            normalized.append(t)
            continue

        # Anthropic format → convert
        name = t.get("name", "unknown_tool")
        description = t.get("description", "")
        params = t.get("input_schema", t.get("parameters", {"type": "object"}))

        normalized.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": params,
                },
            }
        )
    return normalized


def _convert_response(resp: Any) -> dict[str, Any]:
    """Convert OpenAI ChatCompletion → canonical internal format.

    Canonical format (same as AnthropicProvider)::

        {
            "content": [
                {"type": "text", "text": "...", "input": {}, "name": ""},
                {"type": "tool_use", "text": "", "input": {...}, "name": "..."},
            ],
            "model": "gpt-4o",
            "usage": {"input_tokens": N, "output_tokens": N, "cache_read_input_tokens": 0},
            "stop_reason": "stop",
        }
    """
    choice = resp.choices[0]
    message = choice.message
    content_blocks: list[dict[str, Any]] = []

    # Text content
    if message.content:
        content_blocks.append(
            {
                "type": "text",
                "text": (
                message.content
                if isinstance(message.content, str)
                else str(message.content)
            ),
                "input": {},
                "name": "",
            }
        )

    # Tool calls → tool_use blocks
    if message.tool_calls:
        for tc in message.tool_calls:
            try:
                parsed_input = json.loads(tc.function.arguments)
            except (json.JSONDecodeError, TypeError):
                parsed_input = {"_raw": tc.function.arguments}

            content_blocks.append(
                {
                    "type": "tool_use",
                    "text": "",
                    "input": parsed_input,
                    "name": tc.function.name,
                }
            )

    # Usage normalization
    usage = resp.usage
    input_tokens = usage.prompt_tokens if usage else 0
    output_tokens = usage.completion_tokens if usage else 0

    # OpenAI doesn't have prompt caching, but include the field for compatibility
    cache_read = getattr(usage, "prompt_tokens_details", None)
    cache_read_tokens = (
        cache_read.cached_tokens
        if (cache_read and hasattr(cache_read, "cached_tokens"))
        else 0
    )

    finish_reason = choice.finish_reason or "stop"

    return {
        "content": content_blocks,
        "model": resp.model,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_input_tokens": cache_read_tokens,
        },
        "stop_reason": finish_reason,
    }


# ── OpenAIProvider ──────────────────────────────────────────────────────────


class OpenAIProvider(LlmProvider):
    """OpenAI-compatible LLM provider with retry and circuit-breaking.

    Usage::

        config = ProviderConfig(api_key="sk-...", base_url=None)
        provider = OpenAIProvider(config)
        resp = await provider.generate(
            [{"role":"user","content":"Hello"}],
            model="gpt-4o",
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
        self._client = AsyncOpenAI(
            api_key=config.api_key,
            base_url=config.base_url,
            max_retries=0,  # we handle retries ourselves via tenacity
            timeout=timeout_seconds,
        )
        self._call_history: list[dict[str, Any]] = []
        self._on_call_complete = on_call_complete

    # ── Public API (LlmProvider impl) ───────────────────────────────────

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
        """Call Chat Completions API with retry on transient failures.

        Returns the canonical internal format (same as AnthropicProvider).
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
            provider="openai",
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            latency_ms=round(elapsed_ms, 1),
        )

        # ── Observability callback ──
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
        """Generate structured JSON output via OpenAI function-calling.

        Defines a single tool from *output_schema* and forces the model
        to call it via ``tool_choice="required"`` with the specific function.
        """
        tool_name = output_schema.get("name", "output")
        tool_desc = output_schema.get("description", "Structured output")
        params = output_schema.get("input_schema", output_schema)

        tools = [
            {
                "type": "function",
                "function": {
                    "name": tool_name,
                    "description": tool_desc,
                    "parameters": params,
                },
            }
        ]

        response = await self.generate(
            messages=messages,
            model=model,
            system=(
                system
                + "\n\nYou MUST call the `"
                + tool_name
                + "` function to produce structured output. Do not respond with text only."
            ),
            max_tokens=max_tokens,
            temperature=temperature,
            tools=tools,
            tool_choice={
                "type": "function",
                "function": {"name": tool_name},
            },
            **kwargs,
        )

        # Extract tool_use blocks (already normalized to tool_use format).
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
            provider="openai",
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
        """ReAct-style generation with audit tools.

        The model is free to call audit tools, the output tool, or both
        in any order.  The caller is responsible for inspecting the
        ``content`` blocks and continuing the loop.
        """
        output_tool_name = output_schema.get("name", "output")
        output_tool = {
            "type": "function",
            "function": {
                "name": output_tool_name,
                "description": output_schema.get("description", "Structured output"),
                "parameters": output_schema.get("input_schema", output_schema),
            },
        }

        # Audit tools first → model explores before reporting
        tools = [*list(audit_tools), output_tool]

        system_prompt = system
        if system_prompt:
            system_prompt += "\n\n"
        system_prompt += (
            "You have access to code-exploration tools. Use them to gather "
            "information before making your final assessment. When you are "
            "ready to report your findings, call the `" + output_tool_name + "` function."
        )

        return await self.generate(
            messages=messages,
            model=model,
            system=system_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            tools=tools,
            tool_choice="auto",
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
        """Estimate token count using tiktoken, falling back to char/4 heuristic."""
        try:
            import tiktoken  # type: ignore[import-not-found]

            enc = tiktoken.encoding_for_model(model)
        except (ImportError, KeyError):
            # Fallback: rough character-based estimate
            total = sum(len(str(m.get("content", ""))) for m in messages)
            if system:
                total += len(system)
            return max(1, total // 4)

        total = 0
        for m in messages:
            content = m.get("content", "")
            if isinstance(content, str):
                total += len(enc.encode(content))
            elif isinstance(content, list):
                # Multi-part content
                for part in content:
                    if isinstance(part, dict) and "text" in part:
                        total += len(enc.encode(part["text"]))
        if system:
            total += len(enc.encode(system))
        return max(1, total)

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
        """Single Chat Completions call with tenacity retry."""

        @retry(
            retry=retry_if_exception_type(
                (RateLimitError, ConnectionError, TimeoutError)
            ),
            stop=stop_after_attempt(self._max_retries),
            wait=wait_exponential_jitter(initial=1, max=30),
            reraise=True,
        )
        async def _call() -> dict[str, Any]:
            # Build OpenAI-format messages
            api_messages: list[dict[str, Any]] = []
            if system:
                api_messages.append({"role": "system", "content": system})
            api_messages.extend(messages)

            # Normalize tool definitions
            normalized_tools = _normalize_tools(tools) if tools else None

            # Handle tool_choice: OpenAI uses different format
            tool_choice_kw = kwargs.pop("tool_choice", None)
            openai_tool_choice: Any = "auto"
            if tool_choice_kw is not None:
                if isinstance(tool_choice_kw, dict):
                    tc_type = tool_choice_kw.get("type", "auto")
                    if tc_type == "tool":
                        openai_tool_choice = {
                            "type": "function",
                            "function": {"name": tool_choice_kw.get("name", "")},
                        }
                    elif tc_type == "function":
                        openai_tool_choice = tool_choice_kw
                    else:
                        openai_tool_choice = tc_type  # "auto", "none", "required"
                else:
                    openai_tool_choice = tool_choice_kw  # "auto", "none", "required"

            # thinking mode — OpenAI doesn't support it, silently drop
            kwargs.pop("thinking", None)

            response = await self._client.chat.completions.create(
                model=model,
                messages=api_messages,  # type: ignore[arg-type]  # generic dict → OpenAI TypedDict
                max_tokens=max_tokens,
                temperature=temperature,
                tools=normalized_tools,  # type: ignore[arg-type]  # generic dict → OpenAI TypedDict
                tool_choice=openai_tool_choice,
                **kwargs,
            )

            return _convert_response(response)

        return await _call()
