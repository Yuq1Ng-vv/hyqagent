"""ToolRegistry — register, list, dispatch, and format tool results.

Holds a dict of :class:`BaseTool` instances keyed by name.  Provides
convenience methods to emit Anthropic-format tool definitions and to
convert tool-execution results into ``tool_result`` content blocks.
"""

from __future__ import annotations

from typing import Any

from hyqagent.core.protocols import BaseTool, ToolResult


class ToolRegistry:
    """A named collection of :class:`BaseTool` instances.

    Usage::

        reg = ToolRegistry()
        reg.register(ReadFileTool(retriever))
        reg.register(GrepCodeTool(retriever))

        # Get Anthropic-format tool definitions
        tool_defs = reg.to_anthropic_tools()

        # Execute a tool by name
        result = await reg.execute("read_file", file_path="app.py")
    """

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    # ── Registration ─────────────────────────────────────────────────────

    def register(self, tool: BaseTool) -> None:
        """Add a tool instance.  Overwrites any tool with the same name."""
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseTool | None:
        """Look up a tool by name, or ``None``."""
        return self._tools.get(name)

    @property
    def tool_names(self) -> list[str]:
        """Sorted list of registered tool names."""
        return sorted(self._tools.keys())

    # ── Anthropic / OpenAI format ────────────────────────────────────────

    def to_anthropic_tools(self) -> list[dict[str, Any]]:
        """Return Anthropic-format tool definitions for all registered tools."""
        return [t.to_openai_tool() for t in self._tools.values()]

    # ── Execution ────────────────────────────────────────────────────────

    async def execute(self, name: str, **kwargs: Any) -> ToolResult[Any]:
        """Execute a tool by name, forwarding all keyword arguments.

        Returns:
            ``ToolResult.ok(...)`` on success,
            ``ToolResult.fail(...)`` if the tool is not registered or raises.

        """
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult.fail(
                name,
                f"Unknown tool: {name}. Available: {', '.join(self.tool_names)}",
                error_code="UNKNOWN_TOOL",
            )
        try:
            return await tool.execute(**kwargs)
        except Exception as exc:
            return ToolResult.fail(name, str(exc), error_code="TOOL_EXEC_ERROR")

    # ── Content-block formatting ─────────────────────────────────────────

    @staticmethod
    def to_tool_result_message(
        tool_use_id: str,
        result: ToolResult[Any],
    ) -> dict[str, Any]:
        """Convert a :class:`ToolResult` into an Anthropic ``tool_result`` block.

        The caller provides the ``tool_use_id`` from the LLM's request.
        """
        if result.success:
            content_str = str(result.result) if result.result is not None else "(empty)"
        else:
            content_str = f"Error: {result.error or 'unknown'}"
            if result.error_code:
                content_str += f" [code: {result.error_code}]"

        # Attach metadata as a human-readable footer
        if result.metadata:
            meta_lines = "\n".join(f"  {k}: {v}" for k, v in sorted(result.metadata.items()))
            content_str += f"\n\n--- metadata ---\n{meta_lines}"

        return {
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": content_str,
        }
