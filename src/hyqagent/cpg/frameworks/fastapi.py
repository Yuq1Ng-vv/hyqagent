"""cpg/frameworks/fastapi.py — FastAPI route extractor.

Detects ``@app.get`` / ``@app.post`` / … decorators and analyses function
signature type-hints to identify path / query / body / header parameters.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from hyqagent.cpg.frameworks.base import BaseFrameworkExtractor, HttpEndpoint, RouteParam
from hyqagent.cpg.traversal import Traverser

if TYPE_CHECKING:
    from tree_sitter import Node

    from hyqagent.cpg.parser import Parser

# FastAPI HTTP-method decorator names
_FASTAPI_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "trace"}

# FastAPI parameter type patterns (appear in default values of function params)
_PARAM_SOURCE_MAP = {
    "Query": "query",
    "Body": "body",
    "Path": "path",
    "Header": "header",
    "Cookie": "cookie",
    "Form": "form",
    "File": "body",
}


class FastAPIExtractor(BaseFrameworkExtractor):
    """Extract HTTP routes from FastAPI applications."""

    def __init__(self, parser: Parser) -> None:
        super().__init__(parser)

    @property
    def framework_name(self) -> str:  # noqa: D102
        return "fastapi"

    def detect(self, file_path: str | Path) -> bool:  # noqa: D102
        path = str(Path(file_path).resolve())
        try:
            tree = self._parser.parse_file(path)
        except (FileNotFoundError, ValueError, OSError):
            return False
        source = self._source(tree.root_node)
        return "fastapi" in source.lower() and "from fastapi" in source

    def extract_routes(self, file_path: str | Path) -> list[HttpEndpoint]:  # noqa: D102
        path = str(Path(file_path).resolve())
        tree = self._parser.parse_file(path)
        language = self._parser.get_language(tree)
        provider = self._parser.get_provider(language)
        endpoints: list[HttpEndpoint] = []

        for node in Traverser(tree).traverse():
            if node.type != "decorated_definition":
                continue

            func_node = self._find_function_child(node)
            if func_node is None:
                continue

            func_name = provider.extract_function_name(func_node) or "unknown"

            # Check decorators for HTTP-method names
            method, route_pattern = self._extract_method_route(node)
            if method is None:
                continue

            # Auth decorators
            auth_decorators = self._find_auth_decorators(node)
            auth_required = len(auth_decorators) > 0

            # Parameters from function signature type hints
            params = self._extract_params(func_node, provider)
            # Add path params from route pattern
            for pp in self._extract_path_params(route_pattern):
                if not any(p.name == pp.name for p in params):
                    params.append(pp)

            endpoints.append(
                HttpEndpoint(
                    route=route_pattern,
                    methods=[method.upper()],
                    handler_func=func_name,
                    file_path=path,
                    line=self._line(node),
                    params=params,
                    auth_required=auth_required,
                    auth_decorators=auth_decorators,
                    framework="fastapi",
                    source_lines=self._find_source_lines(func_node),
                )
            )

        return endpoints

    # ── Internal ────────────────────────────────────────────────────────

    @staticmethod
    def _find_function_child(node: Node) -> Node | None:
        for child in node.children:
            if child.type == "function_definition":
                return child
            if child.type == "decorated_definition":
                return FastAPIExtractor._find_function_child(child)
        return None

    def _extract_method_route(self, node: Node) -> tuple[str | None, str]:
        """Return (HTTP_method, route_pattern) from decorators."""
        for child in node.children:
            if child.type != "decorator":
                continue
            # decorator → call → attribute (app.get) + string arg
            for sub in child.children:
                if sub.type != "call":
                    continue
                func = sub.child_by_field_name("function")
                if func is None or func.type != "attribute":
                    continue
                # Last named child of attribute is the method name
                named = [c for c in func.children if c.is_named]
                if not named:
                    continue
                method_name = self._source(named[-1])
                if method_name not in _FASTAPI_METHODS:
                    continue

                # Extract route string from arguments
                route = "/"
                args = sub.child_by_field_name("arguments")
                if args is not None:
                    for ac in args.children:
                        if ac.type == "string":
                            route = self._source(ac).strip("\"'")
                            break
                return method_name, route
        return None, "/"

    def _extract_params(self, func_node: Node, provider) -> list[RouteParam]:
        """Extract FastAPI-style parameters from function signature."""
        params: list[RouteParam] = []
        params_node = func_node.child_by_field_name("parameters")
        if params_node is None:
            return params

        provider.extract_parameters(func_node)  # verify available

        for child in params_node.children:
            if child.type in (
                    "identifier", "typed_parameter",
                    "typed_default_parameter", "default_parameter",
                ):
                name = ""
                source = "query"  # default FastAPI source
                type_hint = ""
                required = True

                # Extract name
                for sub in child.children:
                    if sub.type == "identifier" and sub.is_named:
                        name = self._source(sub)
                        break

                if not name or name == "self":
                    continue

                # Check for FastAPI type annotations in default value
                default_text = self._source(child)
                for fastapi_type, src in _PARAM_SOURCE_MAP.items():
                    if fastapi_type + "(" in default_text:
                        source = src
                        break

                # Check if parameter has a default value (not required)
                if "=" in default_text:
                    required = False

                # Extract type hint
                type_node = child.child_by_field_name("type")
                if type_node is not None:
                    type_hint = self._source(type_node)

                params.append(RouteParam(
                    name=name, source=source, type_hint=type_hint, required=required,
                ))

        return params

    def _find_auth_decorators(self, node: Node) -> list[str]:
        found: list[str] = []
        auth_names = {
            "login_required", "jwt_required", "requires", "has_permission",
            "Depends", "Security",
        }
        for child in node.children:
            if child.type == "decorator":
                text = self._source(child).strip()
                for name in auth_names:
                    if name in text:
                        found.append(text)
                        break
        return found

    def _find_source_lines(self, func_node: Node) -> list[str]:
        lines: list[str] = []
        body = func_node.child_by_field_name("body")
        if body is None:
            return lines
        for line_text in self._source(body).split("\n"):
            stripped = line_text.strip()
            if any(p in stripped for p in ["request.", "Depends(", "Header(", "Cookie("]):
                lines.append(stripped[:120])
        return lines

    @staticmethod
    def _extract_path_params(route: str) -> list[RouteParam]:
        import re
        params: list[RouteParam] = []
        for match in re.finditer(r"\{(\w+)\}", route):
            params.append(RouteParam(name=match.group(1), source="path"))
        return params
