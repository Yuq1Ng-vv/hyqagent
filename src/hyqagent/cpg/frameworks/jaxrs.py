"""cpg/frameworks/jaxrs.py — JAX-RS / Jakarta REST route extractor.

Detects ``@Path``, ``@GET``, ``@POST``, ``@PUT``, ``@DELETE``, ``@PATCH``,
``@HEAD``, ``@OPTIONS`` annotations on Java methods and extracts route
patterns, HTTP methods, parameters (``@PathParam``, ``@QueryParam``,
``@FormParam``, ``@HeaderParam``, ``@CookieParam``, ``@MatrixParam``,
``@BeanParam``), and security annotations.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from hyqagent.cpg.frameworks.base import BaseFrameworkExtractor, HttpEndpoint, RouteParam
from hyqagent.cpg.traversal import Traverser

if TYPE_CHECKING:
    from tree_sitter import Node

    from hyqagent.cpg.parser import Parser

# Map JAX-RS annotation to HTTP method
_JAXRS_METHOD_ANNOTATIONS = {
    "GET": "GET",
    "POST": "POST",
    "PUT": "PUT",
    "DELETE": "DELETE",
    "PATCH": "PATCH",
    "HEAD": "HEAD",
    "OPTIONS": "OPTIONS",
}

_JAXRS_PARAM_ANNOTATIONS = {
    "PathParam": "path",
    "QueryParam": "query",
    "FormParam": "form",
    "HeaderParam": "header",
    "CookieParam": "cookie",
    "MatrixParam": "query",
    "BeanParam": "body",
}

_JAXRS_SECURITY_ANNOTATIONS = {
    "RolesAllowed",
    "PermitAll",
    "DenyAll",
    "ServletSecurity",
}


def _merge_routes(prefix: str, route: str) -> str:
    """Merge a class-level @Path prefix with a method-level @Path.

    >>> _merge_routes("/api", "/users")
    "/api/users"
    >>> _merge_routes("/api/", "users")
    "/api/users"
    """
    prefix = prefix.rstrip("/")
    if not prefix:
        return route if route.startswith("/") else "/" + route
    if not route.startswith("/"):
        route = "/" + route
    return prefix + route


class JaxRsExtractor(BaseFrameworkExtractor):
    """Extract HTTP routes from JAX-RS / Jakarta REST applications."""

    def __init__(self, parser: Parser) -> None:
        super().__init__(parser)

    @property
    def framework_name(self) -> str:  # noqa: D102
        return "jaxrs"

    def detect(self, file_path: str | Path) -> bool:  # noqa: D102
        path = str(Path(file_path).resolve())
        try:
            tree = self._parser.parse_file(path)
        except (FileNotFoundError, ValueError, OSError):
            return False
        source = self._source(tree.root_node)
        has_import = (
            "javax.ws.rs" in source
            or "jakarta.ws.rs" in source
        )
        has_path_annotation = "@Path" in source
        return has_import and has_path_annotation

    def extract_routes(self, file_path: str | Path) -> list[HttpEndpoint]:  # noqa: D102
        path = str(Path(file_path).resolve())
        tree = self._parser.parse_file(path)
        language = self._parser.get_language(tree)
        provider = self._parser.get_provider(language)
        endpoints: list[HttpEndpoint] = []

        for node in Traverser(tree).traverse():
            if node.type != "method_declaration":
                continue

            method_name = provider.extract_function_name(node)
            if method_name is None:
                continue

            # Check for JAX-RS HTTP method annotations
            http_methods = self._find_http_method_annotations(node)
            if not http_methods:
                continue

            # Find method-level @Path
            route = self._find_route_path(node) or "/"

            # Merge class-level @Path prefix
            class_prefix = self._find_class_path_prefix(node)
            if class_prefix:
                route = _merge_routes(class_prefix, route)

            # Parameters
            params = self._extract_method_params(node, provider)

            # Security annotations
            security = self._find_security_annotations(node)

            # Taint sources in method body
            source_lines = self._find_source_lines(node)

            for http_method in http_methods:
                endpoints.append(
                    HttpEndpoint(
                        route=route,
                        methods=[http_method],
                        handler_func=method_name,
                        file_path=path,
                        line=self._line(node),
                        params=params,
                        auth_required=len(security) > 0,
                        auth_decorators=security,
                        framework="jaxrs",
                        source_lines=source_lines,
                    )
                )

        return endpoints

    # ── Annotation parsing ──────────────────────────────────────────────

    def _find_http_method_annotations(self, method_node: Node) -> list[str]:
        """Return HTTP methods from JAX-RS method annotations (e.g. ``@GET``)."""
        methods: list[str] = []
        for child in method_node.children:
            if child.type != "modifiers":
                continue
            modifiers_text = self._source(child)
            for ann_name, http_method in _JAXRS_METHOD_ANNOTATIONS.items():
                if ann_name in modifiers_text:
                    # Verify it's a standalone annotation, not part of another name
                    for sub in self._walk_subtree(child):
                        if sub.type in ("marker_annotation", "annotation"):
                            ann_text = self._source(sub)
                            if ann_text.lstrip("@").startswith(ann_name):
                                if ann_name not in methods:
                                    methods.append(http_method)
                                break
        return methods

    def _find_route_path(self, method_node: Node) -> str | None:
        """Extract the method-level ``@Path("/route")`` value."""
        for child in method_node.children:
            if child.type != "modifiers":
                continue
            modifiers_text = self._source(child)
            if "@Path" not in modifiers_text:
                continue
            for sub in self._walk_subtree(child):
                if sub.type == "annotation":
                    ann_text = self._source(sub)
                    if ann_text.lstrip("@").startswith("Path"):
                        path_val = self._extract_annotation_value(sub)
                        if path_val is not None:
                            return path_val
        return None

    def _find_class_path_prefix(self, method_node: Node) -> str:
        """Return the class-level ``@Path`` value, or ``""``.

        Also checks for ``@ApplicationPath`` on enclosing class.
        """
        for ancestor in Traverser.get_ancestors(method_node):
            if ancestor.type == "class_declaration":
                for child in ancestor.children:
                    if child.type == "modifiers":
                        modifiers_text = self._source(child)
                        if "@Path" in modifiers_text:
                            for sub in self._walk_subtree(child):
                                if sub.type == "annotation":
                                    ann_text = self._source(sub)
                                    if ann_text.lstrip("@").startswith("Path"):
                                        prefix = self._extract_annotation_value(sub)
                                        if prefix and prefix != "/":
                                            return prefix
                                        return ""
                break
        return ""

    def _extract_annotation_value(self, ann_node: Node) -> str | None:
        """Extract the string argument from an annotation like ``@Path("/users")``."""
        for child in self._walk_subtree(ann_node):
            if child.type in ("string_literal", "string"):
                return self._source(child).strip("\"'")
            # Annotation with explicit value= key
            if child.type == "element_value_pair":
                name = child.child_by_field_name("name")
                if name and self._source(name) == "value":
                    val = child.child_by_field_name("value")
                    if (
                        val is not None
                        and hasattr(val, "type")
                        and val.type in ("string_literal", "string")
                    ):
                        return self._source(val).strip("\"'")
        return None

    def _find_security_annotations(self, method_node: Node) -> list[str]:
        """Find JAX-RS / Java EE security annotations."""
        found: list[str] = []
        for child in method_node.children:
            if child.type == "modifiers":
                text = self._source(child)
                for ann_name in _JAXRS_SECURITY_ANNOTATIONS:
                    if ann_name in text:
                        found.append("@" + ann_name)
        return found

    # ── Parameter extraction ────────────────────────────────────────────

    def _extract_method_params(
        self, method_node: Node, provider: object
    ) -> list[RouteParam]:
        """Extract parameters with JAX-RS annotations."""
        params: list[RouteParam] = []
        params_node = method_node.child_by_field_name("parameters")
        if params_node is None:
            return params

        for child in params_node.children:
            if child.type != "formal_parameter":
                continue

            name_node = child.child_by_field_name("name")
            if name_node is None:
                continue
            name = self._source(name_node)
            source = "query"  # default
            type_hint = ""
            has_bean_param = False

            # Check annotations on this parameter
            for modifier in child.children:
                if modifier.type == "modifiers":
                    mod_text = self._source(modifier)
                    for ann_name, param_source in _JAXRS_PARAM_ANNOTATIONS.items():
                        if ann_name in mod_text:
                            source = param_source
                            if ann_name == "BeanParam":
                                has_bean_param = True
                            break

            # Type hint
            type_node = child.child_by_field_name("type")
            if type_node is not None:
                type_hint = self._source(type_node)

            if not has_bean_param:
                params.append(
                    RouteParam(
                        name=name,
                        source=source,
                        type_hint=type_hint,
                        required=source in ("path", "body"),
                    )
                )

        return params

    def _find_source_lines(self, method_node: Node) -> list[str]:
        """Find taint-source patterns in method body."""
        lines: list[str] = []
        body = method_node.child_by_field_name("body")
        if body is None:
            return lines
        source_text = self._source(body)
        for line_text in source_text.split("\n"):
            stripped = line_text.strip()
            if any(
                p in stripped
                for p in [
                    "getParameter(",
                    "getHeader(",
                    "getCookies(",
                    "getQueryString(",
                    "getRequestURI(",
                    "getInputStream(",
                    "getReader(",
                ]
            ):
                lines.append(stripped[:120])
        return lines
