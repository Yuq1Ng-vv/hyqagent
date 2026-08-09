"""GetRelatedTool — find callers, callees, and same-file neighbours.

Backed by :class:`CodeRetriever.find_related`.
Capped at 30 related chunks.
"""

from __future__ import annotations

from typing import Any

from hyqagent.core.protocols import BaseTool, ToolResult
from hyqagent.memory.retriever import CodeChunk, CodeRetriever

_MAX_RELATED = 30


class GetRelatedTool(BaseTool):
    """Find functions related to a target—same file, callers, callees.

    Returns a list of functions in the same file, ordered by proximity
    (closest line numbers first).  Use this to understand what code
    surrounds or interacts with a target function.
    """

    def __init__(self, retriever: CodeRetriever) -> None:
        self._retriever = retriever

    # ── BaseTool interface ───────────────────────────────────────────────

    @property
    def name(self) -> str:
        """Return the tool name."""
        return "get_related"

    @property
    def description(self) -> str:
        """Return the tool description."""
        return (
            "Find functions related to a target function in the same file. "
            "Returns nearby functions (callers, callees, imports in the same "
            "file). Use this to understand the context around a function "
            "you've already identified as relevant."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        """Return the JSON Schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the source file.",
                },
                "function_name": {
                    "type": "string",
                    "description": "Name of the function to find related code for.",
                },
            },
            "required": ["file_path", "function_name"],
        }

    async def execute(self, **kwargs: Any) -> ToolResult[list[dict[str, Any]]]:
        """Execute the get_related tool."""
        file_path = str(kwargs.get("file_path", ""))
        func_name = str(kwargs.get("function_name", ""))

        if not file_path or not func_name:
            return ToolResult.fail(
                self.name,
                "Missing required parameters: file_path and function_name",
            )

        # Build a synthetic chunk to query with
        synthetic = CodeChunk(
            file_path=file_path,
            function_name=func_name,
            start_line=0,
            end_line=0,
            code="",
            language="",
        )
        related = self._retriever.find_related(synthetic)

        if not related:
            return ToolResult.ok(
                self.name,
                [],
                file_path=file_path,
                function_name=func_name,
                count=0,
            )

        # Cap
        total = len(related)
        related = related[:_MAX_RELATED]

        results: list[dict[str, Any]] = []
        for c in related:
            sig = c.code.split("\n")[0].strip()[:120] if c.code else ""
            results.append(
                {
                    "name": c.function_name or "<module>",
                    "start_line": c.start_line,
                    "end_line": c.end_line,
                    "signature": sig,
                }
            )

        return ToolResult.ok(
            self.name,
            results,
            file_path=file_path,
            function_name=func_name,
            count=total,
            shown=len(results),
        )
