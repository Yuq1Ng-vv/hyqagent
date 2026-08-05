"""cpg/frameworks/base.py — Framework extractor abstract base and shared types.

Each supported web framework implements :class:`BaseFrameworkExtractor`.
Adding a new framework means creating one file in this package — zero changes
to the CPG graph builder or query layer.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node

    from hyqagent.cpg.parser import Parser


# ─── Shared data types ───────────────────────────────────────────────────────


@dataclass
class RouteParam:
    """A single parameter extracted from an HTTP endpoint definition.

    Attributes:
        name: Parameter name.
        source: Where the parameter comes from —
                ``"path"``, ``"query"``, ``"body"``, ``"header"``, ``"cookie"``, ``"form"``.
        type_hint: Type annotation if present (``"int"``, ``"str"``, …).
        required: Whether the parameter is mandatory.

    """

    name: str
    source: str = "query"
    type_hint: str = ""
    required: bool = True


@dataclass
class HttpEndpoint:
    """A single HTTP endpoint discovered in source code.

    Attributes:
        route: URL pattern (``"/users/<id>"``, ``"/users/:id"``, …).
        methods: HTTP methods (``["GET", "POST"]``).
        handler_func: Name of the function / method that handles requests.
        file_path: Absolute path to the source file.
        line: 1-indexed line number of the route definition.
        params: List of extracted parameters.
        auth_required: ``True`` if authentication decorators / middleware present.
        auth_decorators: List of authentication markers found.
        framework: Label — ``"flask"``, ``"django"``, ``"fastapi"``,
                   ``"express"``, or ``"spring"``.
        source_lines: Source-code lines within the handler that look like
                      user-input entry points (e.g. ``request.args.get``).

    """

    route: str
    methods: list[str] = field(default_factory=list)
    handler_func: str = ""
    file_path: str = ""
    line: int = 0
    params: list[RouteParam] = field(default_factory=list)
    auth_required: bool = False
    auth_decorators: list[str] = field(default_factory=list)
    framework: str = ""
    source_lines: list[str] = field(default_factory=list)


# ─── Abstract base ───────────────────────────────────────────────────────────


class BaseFrameworkExtractor(ABC):
    """Abstract interface for framework-specific route extraction.

    Each concrete extractor parses one web framework's routing syntax
    using tree-sitter AST queries and returns a list of
    :class:`HttpEndpoint` objects.  All extractors are pure-deterministic
    (no LLM calls).
    """

    def __init__(self, parser: Parser) -> None:
        self._parser = parser

    @property
    @abstractmethod
    def framework_name(self) -> str:
        """Unique framework identifier (``"flask"``, ``"express"``, …)."""
        ...

    @abstractmethod
    def detect(self, file_path: str | Path) -> bool:
        """Quick check: does *file_path* use this framework.

        Implementations should do a fast tree-sitter scan for a tell-tale
        import or decorator pattern — no full route extraction.
        """
        ...

    @abstractmethod
    def extract_routes(self, file_path: str | Path) -> list[HttpEndpoint]:
        """Parse *file_path* and return every HTTP endpoint found."""
        ...

    # ── Shared helpers for subclasses ────────────────────────────────────

    @staticmethod
    def _source(node: Node) -> str:
        """Decode *node* text safely."""
        return node.text.decode("utf-8") if node.text else ""

    @staticmethod
    def _line(node: Node) -> int:
        """1-indexed line number of *node*."""
        return node.start_point[0] + 1

    @staticmethod
    def _walk_subtree(root: Node):
        """Yield every node in *root*'s subtree (pre-order)."""
        stack = [root]
        while stack:
            node = stack.pop()
            yield node
            # Push children in reverse so first child is yielded first
            for child in reversed(node.children):
                stack.append(child)

    @staticmethod
    def _find_decorator_names(func_node: Node) -> list[str]:
        """Return decorator name strings for a Python function node.

        Handles both ``decorated_definition`` wrappers and bare functions.
        """
        decorators: list[str] = []
        target = func_node
        if func_node.type == "decorated_definition":
            target = func_node
        for child in target.children:
            if child.type == "decorator":
                text = child.text.decode("utf-8") if child.text else ""
                decorators.append(text.strip())
        return decorators
