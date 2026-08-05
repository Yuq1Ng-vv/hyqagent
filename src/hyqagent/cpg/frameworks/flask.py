"""cpg/frameworks/flask.py — Flask route extractor.

Detects ``@app.route`` / ``@blueprint.route`` decorators and extracts
HTTP methods, route patterns, auth decorators, and taint-source lines.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from hyqagent.cpg.frameworks.base import BaseFrameworkExtractor, HttpEndpoint, RouteParam
from hyqagent.cpg.traversal import Traverser

if TYPE_CHECKING:
    from tree_sitter import Node

    from hyqagent.cpg.parser import Parser

# Patterns that indicate an auth decorator on a Flask handler
_FLASK_AUTH_DECORATORS = {
    "login_required",
    "jwt_required",
    "fresh_login_required",
    "admin_required",
    "permission_required",
    "roles_required",
    "has_role",
    "require_auth",
    "authenticated",
}

# Patterns that indicate a taint source in the handler body
_TAINT_SOURCE_PATTERNS = [
    "request.args",
    "request.form",
    "request.json",
    "request.data",
    "request.values",
    "request.cookies",
    "request.headers",
    "request.files",
    "request.get_json(",
]


class FlaskExtractor(BaseFrameworkExtractor):
    """Extract HTTP routes from Flask applications."""

    def __init__(self, parser: Parser) -> None:
        super().__init__(parser)

    @property
    def framework_name(self) -> str:  # noqa: D102
        return "flask"

    def detect(self, file_path: str | Path) -> bool:
        """Detect Flask via ``Flask(__name__)`` or ``@app.route`` patterns."""
        path = str(Path(file_path).resolve())
        try:
            tree = self._parser.parse_file(path)
        except (FileNotFoundError, ValueError, OSError):
            return False
        source = self._source(tree.root_node)
        # Must have both a Flask import AND actual Flask usage
        has_flask_import = "from flask" in source or "import flask" in source
        has_flask_app = "Flask(__name__)" in source
        has_route = ".route(" in source
        return has_flask_import and (has_flask_app or has_route)

    def extract_routes(self, file_path: str | Path) -> list[HttpEndpoint]:  # noqa: D102
        path = str(Path(file_path).resolve())
        tree = self._parser.parse_file(path)
        language = self._parser.get_language(tree)
        provider = self._parser.get_provider(language)
        endpoints: list[HttpEndpoint] = []

        for node in Traverser(tree).traverse():
            # Flask routes are decorated_definition with function_definition inside
            if node.type != "decorated_definition":
                continue

            func_node = self._find_function_child(node)
            if func_node is None:
                continue

            func_name = provider.extract_function_name(func_node) or "unknown"

            # Check decorators for @app.route / @bp.route
            route_info = self._extract_route_info(node)
            if route_info is None:
                continue

            route_pattern, methods = route_info

            # Auth decorators
            auth_decorators = self._find_auth_decorators(node)
            auth_required = len(auth_decorators) > 0

            # Taint sources in handler body
            source_lines = self._find_source_lines(func_node)

            endpoints.append(
                HttpEndpoint(
                    route=route_pattern,
                    methods=methods,
                    handler_func=func_name,
                    file_path=path,
                    line=self._line(node),
                    params=self._extract_path_params(route_pattern),
                    auth_required=auth_required,
                    auth_decorators=auth_decorators,
                    framework="flask",
                    source_lines=source_lines,
                )
            )

        return endpoints

    # ── Internal helpers ────────────────────────────────────────────────

    @staticmethod
    def _find_function_child(node: Node) -> Node | None:
        for child in node.children:
            if child.type == "function_definition":
                return child
            # Decorated definition wrapping another decorated definition
            if child.type == "decorated_definition":
                return FlaskExtractor._find_function_child(child)
        return None

    def _extract_route_info(self, node: Node) -> tuple[str, list[str]] | None:
        """Extract (route_pattern, methods) from decorator nodes."""
        for child in node.children:
            if child.type == "decorator":
                result = self._parse_route_decorator(child)
                if result:
                    return result
        return None

    def _parse_route_decorator(self, deco_node: Node) -> tuple[str, list[str]] | None:
        """Parse a single decorator looking for ``@xxx.route(...)``."""
        # decorator → call → attribute (xxx.route) + argument_list
        for child in deco_node.children:
            if child.type == "call":
                return self._parse_route_call(child)
        return None

    def _parse_route_call(self, call_node: Node) -> tuple[str, list[str]] | None:
        """Check if a call node is a ``.route(...)`` invocation."""
        func = call_node.child_by_field_name("function")
        if func is None or func.type != "attribute":
            return None

        # Check the attribute is named 'route'
        named = [c for c in func.children if c.is_named]
        if not named or self._source(named[-1]) != "route":
            return None

        # Extract the route string (first argument)
        route_pattern = "/"
        methods: list[str] = ["GET"]

        args = call_node.child_by_field_name("arguments")
        if args is not None:
            named_args = [c for c in args.children if c.is_named]
            for i, child in enumerate(named_args):
                if child.type == "string" and i == 0:
                    route_pattern = self._source(child).strip("\"'")
                elif child.type == "keyword_argument":
                    kw_name = child.child_by_field_name("name")
                    if kw_name and self._source(kw_name) == "methods":
                        kw_val = child.child_by_field_name("value")
                        if kw_val:
                            methods = self._parse_methods_list(kw_val) or methods

        return route_pattern, methods

    def _parse_methods_list(self, node: Node) -> list[str] | None:
        """Parse ``["GET", "POST"]`` list literal."""
        if node.type == "list":
            methods: list[str] = []
            for child in node.children:
                if child.type == "string":
                    m = self._source(child).strip("\"'").upper()
                    if m:
                        methods.append(m)
            return methods if methods else None
        return None

    def _find_auth_decorators(self, node: Node) -> list[str]:
        """Collect auth-related decorator names."""
        found: list[str] = []
        for child in node.children:
            if child.type == "decorator":
                text = self._source(child).strip()
                # Extract the decorator name (after @, before any args)
                name = text.lstrip("@").split("(")[0].split(".")[-1]
                if name in _FLASK_AUTH_DECORATORS:
                    found.append(text)
        return found

    def _find_source_lines(self, func_node: Node) -> list[str]:
        """Scan function body for lines containing taint-source patterns."""
        lines: list[str] = []
        body = func_node.child_by_field_name("body")
        if body is None:
            return lines
        body_text = self._source(body)
        for line_text in body_text.split("\n"):
            stripped = line_text.strip()
            for pat in _TAINT_SOURCE_PATTERNS:
                if pat in stripped:
                    lines.append(stripped[:120])
                    break
        return lines

    @staticmethod
    def _extract_path_params(route: str) -> list[RouteParam]:
        """Extract ``<param>`` placeholders from a Flask route pattern."""
        params: list[RouteParam] = []
        import re
        for match in re.finditer(r"<(?:[^:>]+:)?([^>]+)>", route):
            params.append(RouteParam(name=match.group(1), source="path"))
        return params
