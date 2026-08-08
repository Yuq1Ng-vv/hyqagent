"""Tests for core/protocols.py — ToolResult, protocol interfaces, and type contracts.

These tests verify the foundational data structures that all modules depend on.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import pytest

from hyqagent.core.protocols import ToolResult


# ── ToolResult ───────────────────────────────────────────────────────────────


class TestToolResult:
    """ToolResult is the universal return type for all tool executions."""

    def test_ok_creates_success_result(self):
        result = ToolResult.ok("search_code", {"matches": [1, 2, 3]})
        assert result.success is True
        assert result.tool_name == "search_code"
        assert result.result == {"matches": [1, 2, 3]}
        assert result.error is None
        assert isinstance(result.metadata, dict)

    def test_ok_default_metadata(self):
        result = ToolResult.ok("test", None)
        assert result.metadata == {}

    def test_ok_with_metadata(self):
        result = ToolResult.ok("test", "value", duration_ms=42)
        assert result.metadata["duration_ms"] == 42

    def test_fail_creates_error_result(self):
        result = ToolResult.fail("read_file", "File not found")
        assert result.success is False
        assert result.tool_name == "read_file"
        assert result.error == "File not found"
        assert result.result is None

    def test_fail_with_metadata(self):
        """fail() doesn't accept metadata — verify error_code default."""
        result = ToolResult.fail("parse", "Syntax error", error_code="PARSE_ERROR")
        assert result.success is False
        assert result.error_code == "PARSE_ERROR"

    def test_fail_error_required(self):
        """error should be a non-empty string for fail results."""
        result = ToolResult.fail("x", "something went wrong")
        assert result.error
        assert isinstance(result.error, str)

    def test_ok_error_is_none(self):
        result = ToolResult.ok("x", {})
        assert result.error is None

    def test_fail_result_is_none(self):
        result = ToolResult.fail("x", "error")
        assert result.result is None

    def test_can_create_directly(self):
        """ToolResult can also be constructed directly (not via factory)."""
        r = ToolResult(
            success=True,
            tool_name="my_tool",
            result={"data": 1},
        )
        assert r.success is True
        assert r.tool_name == "my_tool"

    def test_repr_ok(self):
        r = ToolResult.ok("find", "result")
        s = repr(r)
        assert "ToolResult" in s
        assert "success=True" in s
        assert "find" in s

    def test_repr_fail(self):
        r = ToolResult.fail("find", "bad input")
        s = repr(r)
        assert "ToolResult" in s
        assert "success=False" in s

    def test_equality(self):
        r1 = ToolResult.ok("t", 1)
        r2 = ToolResult.ok("t", 1)
        r3 = ToolResult.fail("t", "err")
        assert r1 == r2
        assert r1 != r3

    def test_various_result_types(self):
        """result can be str, int, list, dict, None."""
        assert ToolResult.ok("a", "string").result == "string"
        assert ToolResult.ok("b", 42).result == 42
        assert ToolResult.ok("c", [1, 2]).result == [1, 2]
        assert ToolResult.ok("d", {"k": "v"}).result == {"k": "v"}
        assert ToolResult.ok("e", None).result is None

    def test_metadata_persistence(self):
        r = ToolResult.ok("t", "val", key="value")
        assert r.metadata["key"] == "value"
        r.metadata["new_key"] = 123
        assert r.metadata["new_key"] == 123


# ── Protocol conformance ─────────────────────────────────────────────────────


class TestProtocolConformance:
    """Verify that concrete classes satisfy their protocol contracts."""

    def test_tool_result_matches_annotation(self):
        """ToolResult fields match the expected types."""
        r = ToolResult.ok("n", 1)
        assert isinstance(r.success, bool)
        assert isinstance(r.tool_name, str)
        # result can be Any
        # error can be str | None
        assert isinstance(r.metadata, dict)

    def test_tool_result_factory_pattern(self):
        """Both ok() and fail() are class methods returning ToolResult."""
        assert isinstance(ToolResult.ok("x", None), ToolResult)
        assert isinstance(ToolResult.fail("x", "err"), ToolResult)


# ── Edge cases ───────────────────────────────────────────────────────────────


class TestToolResultEdgeCases:
    """Corner cases for ToolResult."""

    def test_empty_tool_name(self):
        r = ToolResult.ok("", None)
        assert r.tool_name == ""
        assert r.success is True

    def test_special_chars_in_tool_name(self):
        r = ToolResult.ok("my-tool.v2/search", None)
        assert "my-tool" in r.tool_name

    def test_unicode_in_result(self):
        r = ToolResult.ok("t", "こんにちは")
        assert r.result == "こんにちは"

    def test_unicode_in_error(self):
        r = ToolResult.fail("t", "エラーが発生しました")
        assert "エラー" in r.error

    def test_large_result(self):
        big = "x" * 10000
        r = ToolResult.ok("t", big)
        assert len(r.result) == 10000

    def test_nested_metadata(self):
        r = ToolResult.ok("t", None, nested={"deep": True})
        assert r.metadata["nested"]["deep"] is True
