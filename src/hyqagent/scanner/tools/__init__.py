"""scanner/tools — Read-only code exploration tools for LLM agent use.

Each tool wraps a :class:`CodeRetriever` method and implements the
:class:`BaseTool` protocol from :mod:`hyqagent.core.protocols`.

All tools are read-only, stateless, and safe for parallel execution.
Results are capped to prevent context blowup.
"""

from __future__ import annotations

from hyqagent.scanner.tools.get_function import GetFunctionTool
from hyqagent.scanner.tools.get_related import GetRelatedTool
from hyqagent.scanner.tools.grep_code import GrepCodeTool
from hyqagent.scanner.tools.list_functions import ListFunctionsTool
from hyqagent.scanner.tools.read_file import ReadFileTool
from hyqagent.scanner.tools.tool_registry import ToolRegistry

__all__ = [
    "GetFunctionTool",
    "GetRelatedTool",
    "GrepCodeTool",
    "ListFunctionsTool",
    "ReadFileTool",
    "ToolRegistry",
    "create_default_tools",
]


def create_default_tools() -> list:
    """Produce the default set of code-exploration tools.

    Callers should instantiate tools with a :class:`CodeRetriever` that
    has already had :meth:`~CodeRetriever.build_index` called.
    """
    return [
        ReadFileTool,
        GrepCodeTool,
        GetFunctionTool,
        ListFunctionsTool,
        GetRelatedTool,
    ]
