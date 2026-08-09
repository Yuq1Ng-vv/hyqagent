"""ListFunctionsTool — enumerate all functions in a file.

Backed by :class:`CodeRetriever.get_chunks_for_file`.
Capped at 100 functions.
"""

from __future__ import annotations

from typing import Any

from hyqagent.core.protocols import BaseTool, ToolResult
from hyqagent.memory.retriever import CodeRetriever

_MAX_FUNCS = 100


class ListFunctionsTool(BaseTool):
    """List all functions defined in a given source file.

    Returns function names, line ranges, and (if available) parameter lists.
    Use this as a first step when exploring an unfamiliar file.
    """

    def __init__(self, retriever: CodeRetriever) -> None:
        self._retriever = retriever

    # ── BaseTool interface ───────────────────────────────────────────────

    @property
    def name(self) -> str:
        """Return the tool name."""
        return "list_functions"

    @property
    def description(self) -> str:
        """Return the tool description."""
        return (
            "List all functions and methods defined in a source file. "
            "Returns name, start line, end line, and the function signature "
            "(first line of code). Use this to survey a file before reading "
            "specific functions."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        """Return the JSON Schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the source file to list functions from.",
                },
            },
            "required": ["file_path"],
        }

    async def execute(self, **kwargs: Any) -> ToolResult[list[dict[str, Any]]]:
        """Execute the list_functions tool."""
        file_path = str(kwargs.get("file_path", ""))

        if not file_path:
            return ToolResult.fail(self.name, "Missing required parameter: file_path")

        chunks = self._retriever.get_chunks_for_file(file_path)
        if not chunks:
            return ToolResult.fail(
                self.name,
                f"No functions found in: {file_path}",
                error_code="FILE_NOT_INDEXED",
            )

        # Cap
        total = len(chunks)
        chunks = chunks[:_MAX_FUNCS]

        results: list[dict[str, Any]] = []
        for c in chunks:
            sig_line = c.code.split("\n")[0].strip()[:120] if c.code else ""
            results.append(
                {
                    "name": c.function_name or "<module>",
                    "start_line": c.start_line,
                    "end_line": c.end_line,
                    "signature": sig_line,
                    "language": c.language,
                }
            )

        return ToolResult.ok(
            self.name,
            results,
            file_path=file_path,
            total_functions=total,
            shown=len(results),
        )
