"""ReadFileTool — read a source file (optionally a line range).

Backed by :class:`CodeRetriever` file-content cache.
Results are capped at 200 lines / 8 000 characters to prevent context blowup.
"""

from __future__ import annotations

from typing import Any

from hyqagent.core.protocols import BaseTool, ToolResult
from hyqagent.memory.retriever import CodeRetriever

_MAX_LINES = 200
_MAX_CHARS = 8_000


class ReadFileTool(BaseTool):
    """Read all or part of a source file.

    Returns the file content with line numbers.
    Use ``start_line`` / ``end_line`` to narrow to a specific region.
    """

    def __init__(self, retriever: CodeRetriever) -> None:
        self._retriever = retriever

    # ── BaseTool interface ───────────────────────────────────────────────

    @property
    def name(self) -> str:
        """Return the tool name."""
        return "read_file"

    @property
    def description(self) -> str:
        """Return the tool description."""
        return (
            "Read the contents of a source file. "
            "Optionally specify `start_line` and `end_line` to read a "
            "subset of lines. Returns the file content with line numbers."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        """Return the JSON Schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the source file to read.",
                },
                "start_line": {
                    "type": "integer",
                    "description": "Optional first line to read (1-indexed, inclusive).",
                },
                "end_line": {
                    "type": "integer",
                    "description": "Optional last line to read (1-indexed, inclusive).",
                },
            },
            "required": ["file_path"],
        }

    async def execute(self, **kwargs: Any) -> ToolResult[str]:
        """Execute the read_file tool."""
        file_path = str(kwargs.get("file_path", ""))
        start_line = kwargs.get("start_line")
        end_line = kwargs.get("end_line")

        if not file_path:
            return ToolResult.fail(self.name, "Missing required parameter: file_path")

        # Try the retriever's file-content cache first
        content = self._retriever._file_contents.get(file_path)
        if content is None:
            return ToolResult.fail(
                self.name,
                f"File not found in index: {file_path}",
                error_code="FILE_NOT_FOUND",
            )

        lines = content.split("\n")

        # Apply line-range slicing
        start_idx = max(0, (start_line - 1) if start_line is not None else 0)
        end_idx = min(len(lines), end_line if end_line is not None else len(lines))
        sliced = lines[start_idx:end_idx]

        # Cap
        if len(sliced) > _MAX_LINES:
            sliced = sliced[:_MAX_LINES]
            sliced.append(f"  ... [truncated: {len(lines) - _MAX_LINES} more lines]")

        numbered = "\n".join(f"{i + start_idx + 1:4d} │ {ln}" for i, ln in enumerate(sliced))
        result = numbered

        if len(result) > _MAX_CHARS:
            suffix = f"\n  ... [truncated: {len(numbered) - _MAX_CHARS} more chars]"
            result = result[:_MAX_CHARS] + suffix

        return ToolResult.ok(
            self.name,
            result,
            file_path=file_path,
            total_lines=len(lines),
            shown_lines=len(sliced),
        )
