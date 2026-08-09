"""Tests for scanner/tools/ — ToolRegistry + tool formatting."""

from __future__ import annotations

from hyqagent.core.protocols import ToolResult
from hyqagent.scanner.tools.tool_registry import ToolRegistry

# ── Fake tool for testing ─────────────────────────────────────────────────


class _FakeEchoTool:
    """Minimal BaseTool duck-type for registry tests."""

    @property
    def name(self) -> str:
        return "echo"

    @property
    def description(self) -> str:
        return "Echo back the input."

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        }

    async def execute(self, **kwargs):
        text = kwargs.get("text", "")
        return ToolResult.ok("echo", text, echoed=text)

    def to_openai_tool(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters,
        }


class _FakeFailingTool:
    """Tool whose execute() always raises."""

    @property
    def name(self) -> str:
        return "failer"

    @property
    def description(self) -> str:
        return "Always fails."

    @property
    def parameters(self) -> dict:
        return {"type": "object", "properties": {}}

    async def execute(self, **kwargs):
        raise RuntimeError("boom")

    def to_openai_tool(self) -> dict:
        return {"name": self.name, "description": self.description, "input_schema": self.parameters}


# ── ToolRegistry tests ────────────────────────────────────────────────────


class TestToolRegistry:
    """Unit tests for ToolRegistry."""

    def test_register_and_get(self) -> None:
        """Register a tool and retrieve it by name."""
        reg = ToolRegistry()
        echo = _FakeEchoTool()
        reg.register(echo)
        assert reg.get("echo") is echo
        assert reg.get("nonexistent") is None

    def test_register_overwrites(self) -> None:
        """Registering a tool with the same name overwrites the previous."""
        reg = ToolRegistry()
        reg.register(_FakeEchoTool())
        reg.register(_FakeFailingTool())  # different class, same name "echo"? No—different names
        # Actually test real overwrite
        reg2 = ToolRegistry()
        echo1 = _FakeEchoTool()
        echo2 = _FakeEchoTool()
        reg2.register(echo1)
        reg2.register(echo2)
        assert reg2.get("echo") is echo2

    def test_tool_names_sorted(self) -> None:
        """tool_names returns sorted list."""
        reg = ToolRegistry()
        reg.register(_FakeEchoTool())
        reg.register(_FakeFailingTool())
        assert reg.tool_names == ["echo", "failer"]

    def test_to_anthropic_tools_format(self) -> None:
        """to_anthropic_tools returns list of dicts with name/description/input_schema."""
        reg = ToolRegistry()
        reg.register(_FakeEchoTool())
        tools = reg.to_anthropic_tools()
        assert isinstance(tools, list)
        assert len(tools) == 1
        assert tools[0]["name"] == "echo"
        assert tools[0]["description"] == "Echo back the input."
        assert "input_schema" in tools[0]

    async def test_execute_success(self) -> None:
        """Dispatch to the correct tool and return ToolResult."""
        reg = ToolRegistry()
        reg.register(_FakeEchoTool())
        result = await reg.execute("echo", text="hello")
        assert result.success
        assert result.result == "hello"
        assert result.tool_name == "echo"

    async def test_execute_unknown_tool(self) -> None:
        """Return fail for unknown tool name."""
        reg = ToolRegistry()
        result = await reg.execute("ghost")
        assert not result.success
        assert result.error_code == "UNKNOWN_TOOL"

    async def test_execute_tool_raises(self) -> None:
        """Catch tool exceptions and return fail."""
        reg = ToolRegistry()
        reg.register(_FakeFailingTool())
        result = await reg.execute("failer")
        assert not result.success
        assert result.error_code == "TOOL_EXEC_ERROR"

    def test_to_tool_result_message_success(self) -> None:
        """Format a successful ToolResult as a tool_result block."""
        result = ToolResult.ok("read_file", "line1\nline2", lines=2)
        msg = ToolRegistry.to_tool_result_message("toolu_001", result)
        assert msg["type"] == "tool_result"
        assert msg["tool_use_id"] == "toolu_001"
        assert "line1" in msg["content"]
        assert "lines: 2" in msg["content"]

    def test_to_tool_result_message_failure(self) -> None:
        """Format a failed ToolResult with error info."""
        result = ToolResult.fail("read_file", "File not found", error_code="FILE_NOT_FOUND")
        msg = ToolRegistry.to_tool_result_message("toolu_002", result)
        assert msg["type"] == "tool_result"
        assert "Error: File not found" in msg["content"]
        assert "FILE_NOT_FOUND" in msg["content"]

    def test_to_tool_result_message_empty_result(self) -> None:
        """Handle None result in success case."""
        result = ToolResult.ok("list_functions", None)
        msg = ToolRegistry.to_tool_result_message("toolu_003", result)
        assert "(empty)" in msg["content"]
