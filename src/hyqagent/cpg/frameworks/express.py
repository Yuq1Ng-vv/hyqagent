"""cpg/frameworks/express.py — Express.js route extractor.

Detects ``app.get`` / ``app.post`` / ``router.delete`` style method calls
and extracts route patterns, middleware chains, and handler functions.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from hyqagent.cpg.frameworks.base import BaseFrameworkExtractor, HttpEndpoint, RouteParam
from hyqagent.cpg.traversal import Traverser

if TYPE_CHECKING:
    from tree_sitter import Node

    from hyqagent.cpg.parser import Parser

_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "all", "use"}

_EXPRESS_SOURCE_PATTERNS = [
    "req.query", "req.body", "req.params", "req.cookies",
    "req.headers", "req.files", "req.ip", "req.hostname",
    "request.query", "request.body", "request.params",
]

_EXPRESS_AUTH_PATTERNS = [
    "authenticate", "authorize", "auth", "passport",
    "requireAuth", "isAuthenticated", "hasRole", "guard",
]


class ExpressExtractor(BaseFrameworkExtractor):
    """Extract HTTP routes from Express.js applications."""

    def __init__(self, parser: Parser) -> None:
        super().__init__(parser)

    @property
    def framework_name(self) -> str:  # noqa: D102
        return "express"

    def detect(self, file_path: str | Path) -> bool:  # noqa: D102
        path = str(Path(file_path).resolve())
        try:
            tree = self._parser.parse_file(path)
        except Exception:
            return False
        source = self._source(tree.root_node)
        has_require = "require('express')" in source or 'require("express")' in source
        _route_pats = ("app.get(", "app.post(", "app.put(", "app.delete(", "router.get(")
        has_route_call = any(pat in source for pat in _route_pats)
        return has_require and has_route_call

    def extract_routes(self, file_path: str | Path) -> list[HttpEndpoint]:  # noqa: D102
        path = str(Path(file_path).resolve())
        tree = self._parser.parse_file(path)
        endpoints: list[HttpEndpoint] = []

        for node in Traverser(tree).traverse():
            if node.type != "call_expression":
                continue

            func = node.child_by_field_name("function")
            if func is None or func.type != "member_expression":
                continue

            # Check if method name is an HTTP verb
            prop = func.child_by_field_name("property")
            if prop is None:
                continue
            method_name = self._source(prop)
            if method_name not in _HTTP_METHODS:
                continue

            # Extract route string (first string argument)
            args = node.child_by_field_name("arguments")
            if args is None:
                continue

            route_pattern = "/"
            middleware: list[str] = []
            handler_name = "anonymous"

            arg_children = list(args.named_children)
            for i, arg in enumerate(arg_children):
                if arg.type == "string" and i == 0:
                    route_pattern = self._source(arg).strip("\"'`")
                elif arg.type in ("identifier", "member_expression"):
                    if i == len(arg_children) - 1:
                        handler_name = self._source(arg)
                    else:
                        mw_name = self._source(arg)
                        middleware.append(mw_name)

            # Check for auth middleware
            auth_decorators = [
                m for m in middleware
                if any(p in m.lower() for p in _EXPRESS_AUTH_PATTERNS)
            ]

            params = self._extract_path_params(route_pattern)

            endpoints.append(
                HttpEndpoint(
                    route=route_pattern,
                    methods=[method_name.upper()],
                    handler_func=handler_name,
                    file_path=path,
                    line=self._line(node),
                    params=params,
                    auth_required=len(auth_decorators) > 0,
                    auth_decorators=auth_decorators,
                    framework="express",
                    source_lines=self._find_source_lines(args),
                )
            )

        return endpoints

    def _find_source_lines(self, args_node: Node) -> list[str]:
        """Look for req.query/body/params patterns in handler arguments."""
        lines: list[str] = []
        for child in args_node.named_children:
            text = self._source(child)
            for pat in _EXPRESS_SOURCE_PATTERNS:
                if pat in text:
                    lines.append(text[:120])
                    break
        return lines

    @staticmethod
    def _extract_path_params(route: str) -> list[RouteParam]:
        import re
        params: list[RouteParam] = []
        for match in re.finditer(r":(\w+)", route):
            params.append(RouteParam(name=match.group(1), source="path"))
        return params
