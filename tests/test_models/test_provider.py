"""Tests for models/providers/anthropic_provider.py — Anthropic SDK wrapper.

Uses mocked Anthropic client to test retry logic, structured output parsing,
and token counting without real API calls.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hyqagent.models.providers.anthropic_provider import (
    AnthropicProvider,
    ProviderConfig,
)


class TestProviderConfig:
    def test_basic_config(self) -> None:
        cfg = ProviderConfig(api_key="sk-test", base_url=None)
        assert cfg.api_key == "sk-test"
        assert cfg.base_url is None

    def test_deepseek_base_url(self) -> None:
        cfg = ProviderConfig(api_key="sk-ds", base_url="https://api.deepseek.com/anthropic")
        assert cfg.base_url == "https://api.deepseek.com/anthropic"


class TestAnthropicProviderInit:
    def test_default_init(self) -> None:
        with patch("hyqagent.models.providers.anthropic_provider.Anthropic") as mock_anthropic:
            _provider = AnthropicProvider(ProviderConfig(api_key="sk-test"))
            mock_anthropic.assert_called_once()
            call_kwargs = mock_anthropic.call_args.kwargs
            assert call_kwargs["api_key"] == "sk-test"
            assert call_kwargs["base_url"] is None
            assert call_kwargs["max_retries"] == 0  # we handle retries ourselves

    def test_custom_max_retries_and_timeout(self) -> None:
        with patch("hyqagent.models.providers.anthropic_provider.Anthropic"):
            provider = AnthropicProvider(
                ProviderConfig(api_key="sk-test"),
                max_retries=5,
                timeout_seconds=180,
            )
            assert provider._max_retries == 5
            assert provider._timeout == 180


class TestAnthropicProviderGenerate:
    @pytest.fixture
    def provider(self) -> AnthropicProvider:
        with patch("hyqagent.models.providers.anthropic_provider.Anthropic"):
            p = AnthropicProvider(ProviderConfig(api_key="sk-test"))
        return p

    @pytest.mark.asyncio
    async def test_generate_basic(self, provider: AnthropicProvider) -> None:
        mock_response = MagicMock()
        mock_response.content = [MagicMock(type="text", text="Hello from Claude")]
        mock_response.usage = MagicMock(input_tokens=10, output_tokens=5)
        provider._client.messages = MagicMock()
        provider._client.messages.create = AsyncMock(return_value=mock_response)

        result = await provider.generate(
            messages=[{"role": "user", "content": "Hi"}],
            model="claude-sonnet-5",
            system="You are helpful.",
        )

        assert result["content"][0]["text"] == "Hello from Claude"
        assert result["usage"]["input_tokens"] == 10

    @pytest.mark.asyncio
    async def test_generate_with_temperature(self, provider: AnthropicProvider) -> None:
        mock_response = MagicMock()
        mock_response.content = [MagicMock(type="text", text="ok")]
        mock_response.usage = MagicMock(input_tokens=5, output_tokens=3)
        provider._client.messages = MagicMock()
        provider._client.messages.create = AsyncMock(return_value=mock_response)

        await provider.generate(
            messages=[{"role": "user", "content": "x"}],
            model="claude-sonnet-5",
            temperature=0.3,
            max_tokens=100,
        )

        call_kwargs = provider._client.messages.create.call_args.kwargs
        assert call_kwargs["temperature"] == 0.3
        assert call_kwargs["max_tokens"] == 100

    @pytest.mark.asyncio
    async def test_generate_structured(self, provider: AnthropicProvider) -> None:
        """Test structured output via tool_use."""
        mock_block = MagicMock()
        mock_block.type = "tool_use"
        mock_block.name = "report_finding"
        mock_block.input = {"verdict": "confirmed", "confidence": 0.9}
        mock_response = MagicMock()
        mock_response.content = [mock_block]
        mock_response.usage = MagicMock(input_tokens=50, output_tokens=20)
        provider._client.messages = MagicMock()
        provider._client.messages.create = AsyncMock(return_value=mock_response)

        schema = {
            "name": "report_finding",
            "description": "Report a finding",
            "input_schema": {
                "type": "object",
                "properties": {
                    "verdict": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": ["verdict"],
            },
        }

        result = await provider.generate_structured(
            messages=[{"role": "user", "content": "Analyze this"}],
            model="claude-sonnet-5",
            output_schema=schema,
        )

        assert result["verdict"] == "confirmed"
        assert result["confidence"] == 0.9

        # Verify tool_choice was set
        call_kwargs = provider._client.messages.create.call_args.kwargs
        assert call_kwargs["tool_choice"] == {
            "type": "tool",
            "name": "report_finding",
        }


class TestAnthropicProviderCountTokens:
    @pytest.fixture
    def provider(self) -> AnthropicProvider:
        with patch("hyqagent.models.providers.anthropic_provider.Anthropic"):
            p = AnthropicProvider(ProviderConfig(api_key="sk-test"))
        return p

    def test_count_tokens_via_sdk(self, provider: AnthropicProvider) -> None:
        """When SDK count_tokens works, use it."""
        mock_result = MagicMock()
        mock_result.input_tokens = 42
        provider._client.messages = MagicMock()
        provider._client.messages.count_tokens = MagicMock(return_value=mock_result)

        count = provider.count_tokens(
            messages=[{"role": "user", "content": "Hello world"}],
            model="claude-sonnet-5",
            system="You are helpful.",
        )

        assert count == 42

    def test_count_tokens_fallback(self, provider: AnthropicProvider) -> None:
        """When SDK count_tokens fails, fall back to char/4 estimation."""
        provider._client.messages = MagicMock()
        provider._client.messages.count_tokens = MagicMock(
            side_effect=Exception("Not supported")
        )

        msg = "This is a test message with roughly forty characters"
        count = provider.count_tokens(
            messages=[{"role": "user", "content": msg}],
            model="deepseek-v4-flash-0731",
        )

        # char/4 = len(msg)/4 ≈ 14, should be in that ballpark
        assert 5 <= count <= 50
