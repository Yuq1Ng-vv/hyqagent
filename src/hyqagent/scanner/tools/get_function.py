"""GetFunctionTool — fetch the full source of a function by name.

Backed by :class:`CodeRetriever.search_structural` (AST-based).
Capped at 200 lines / 6 000 characters.
"""

from __future__ import annotations

from typing import Any

from hyqagent.core.protocols import BaseTool, ToolResult
from hyqagent.memory.retriever import CodeRetriever

_MAX_LINES = 200
_MAX_CHARS = 6_000


class GetFunctionTool(BaseTool):
    """Retrieve the full source code of a function by name.

    Searches across all indexed files.  Optionally narrow to a single file
    with ``file_path``.
    """

    def __init__(self, retriever: CodeRetriever) -> None:
        self._retriever = retriever

    # ── BaseTool interface ───────────────────────────────────────────────

    @property
    def name(self) -> str:
        """Return the tool name."""
        return "get_function"

    @property
    def description(self) -> str:
        """Return the tool description."""
        return (
            "Retrieve the complete source code of a named function or method. "
            "Returns the full function body. Use this after finding a "
            "suspicious function via grep_code or list_functions."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        """Return the JSON Schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "Name of the function or method to retrieve.",
                },
                "file_path": {
                    "type": "string",
                    "description": "Optional: limit search to this file path.",
                },
            },
            "required": ["function_name"],
        }

    async def execute(self, **kwargs: Any) -> ToolResult[dict[str, Any]]:
        """Execute the get_function tool."""
        func_name = str(kwargs.get("function_name", ""))
        file_path = kwargs.get("file_path")

        if not func_name:
            return ToolResult.fail(self.name, "Missing required parameter: function_name")

        hits = self._retriever.search_structural("function_definition", name=func_name)
        if not hits:
            return ToolResult.fail(
                self.name,
                f"Function not found: {func_name}",
                error_code="FUNC_NOT_FOUND",
            )

        # Prefer exact name match
        exact = [h for h in hits if h.chunk.function_name == func_name]
        best = exact[0] if exact else hits[0]

        # Filter by file_path if provided
        if file_path:
            fp = str(file_path)
            hits_in_file = [h for h in hits if h.chunk.file_path == fp]
            if hits_in_file:
                best = hits_in_file[0]

        code = best.chunk.code
        lines = code.split("\n")

        # Cap
        if len(lines) > _MAX_LINES:
            lines = lines[:_MAX_LINES]
            lines.append(f"  # ... [truncated: function exceeds {_MAX_LINES} lines]")

        truncated = "\n".join(lines)
        if len(truncated) > _MAX_CHARS:
            suffix = f"\n  # ... [truncated: {len(code) - _MAX_CHARS} more chars]"
            truncated = truncated[:_MAX_CHARS] + suffix

        result: dict[str, Any] = {
            "name": best.chunk.function_name,
            "file": best.chunk.file_path,
            "start_line": best.chunk.start_line,
            "end_line": best.chunk.end_line,
            "language": best.chunk.language,
            "code": truncated,
        }
        return ToolResult.ok(self.name, result)
