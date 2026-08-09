"""GrepCodeTool — regex search over indexed source files.

Backed by :class:`CodeRetriever.search_exact`.
Results are capped at 20 hits / 4 000 characters.
"""

from __future__ import annotations

from typing import Any

from hyqagent.core.protocols import BaseTool, ToolResult
from hyqagent.memory.retriever import CodeRetriever

_MAX_HITS = 20
_MAX_CHARS = 4_000


class GrepCodeTool(BaseTool):
    """Search source code with a regex pattern.

    Searches across all indexed files.  Optionally narrow to a single file
    by passing ``file_path``.
    """

    def __init__(self, retriever: CodeRetriever) -> None:
        self._retriever = retriever

    # ── BaseTool interface ───────────────────────────────────────────────

    @property
    def name(self) -> str:
        """Return the tool name."""
        return "grep_code"

    @property
    def description(self) -> str:
        """Return the tool description."""
        return (
            "Search source code with a regular expression pattern. "
            "Returns matching lines with file paths, line numbers, and "
            "surrounding context. Use this to find function calls, "
            "variable assignments, imports, or any text pattern in the code."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        """Return the JSON Schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regular expression pattern to search for.",
                },
                "file_path": {
                    "type": "string",
                    "description": "Optional: limit search to this file path.",
                },
            },
            "required": ["pattern"],
        }

    async def execute(self, **kwargs: Any) -> ToolResult[list[dict[str, Any]]]:
        """Execute the grep_code tool."""
        pattern = str(kwargs.get("pattern", ""))
        file_path = kwargs.get("file_path")

        if not pattern:
            return ToolResult.fail(self.name, "Missing required parameter: pattern")

        try:
            hits = self._retriever.search_exact(pattern)
        except Exception as exc:
            return ToolResult.fail(self.name, f"Search failed: {exc}", error_code="SEARCH_ERROR")

        # Filter by file_path if provided
        if file_path:
            fp = str(file_path)
            hits = [h for h in hits if h.chunk.file_path == fp]

        # Cap
        total = len(hits)
        hits = hits[:_MAX_HITS]

        results: list[dict[str, Any]] = []
        for h in hits:
            results.append(
                {
                    "file": h.chunk.file_path,
                    "function": h.chunk.function_name or "<module>",
                    "start_line": h.chunk.start_line,
                    "end_line": h.chunk.end_line,
                    "code": h.chunk.code[:_MAX_CHARS],
                    "score": round(h.score, 3),
                    "match_type": h.match_type,
                }
            )

        # Truncate aggregated result if too large
        summary = f"Found {total} hits (showing top {len(results)})"
        return ToolResult.ok(
            self.name,
            results,
            summary=summary,
            total_hits=total,
            shown=len(results),
        )
