"""cpg/frameworks/spring.py — Spring Boot route extractor.

Detects ``@GetMapping`` / ``@PostMapping`` / ``@RequestMapping`` annotations
on Java methods and extracts route patterns, HTTP methods, parameters
(``@PathVariable``, ``@RequestParam``, ``@RequestBody``, ``@RequestHeader``),
and security annotations.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from hyqagent.cpg.frameworks.base import BaseFrameworkExtractor, HttpEndpoint, RouteParam
from hyqagent.cpg.traversal import Traverser

if TYPE_CHECKING:
    from tree_sitter import Node

    from hyqagent.cpg.parser import Parser

# Map Spring annotation to HTTP method
_SPRING_METHOD_ANNOTATIONS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
    "RequestMapping": "GET",  # default, may be overridden by method= attribute
}

_SPRING_SECURITY_ANNOTATIONS = {
    "PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed",
    "PreFilter", "PostFilter", "Authenticated",
}


class SpringExtractor(BaseFrameworkExtractor):
    """Extract HTTP routes from Spring Boot / Spring MVC applications."""

    def __init__(self, parser: Parser) -> None:
        super().__init__(parser)

    @property
    def framework_name(self) -> str:  # noqa: D102
        return "spring"

    def detect(self, file_path: str | Path) -> bool:  # noqa: D102
        path = str(Path(file_path).resolve())
        try:
            tree = self._parser.parse_file(path)
        except Exception:
            return False
        source = self._source(tree.root_node)
        return any(ann in source for ann in _SPRING_METHOD_ANNOTATIONS) and (
            "org.springframework" in source or "org.springdoc" in source
        )

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

            # Check for Spring mapping annotations
            route_annotation = self._find_route_annotation(node)
            if route_annotation is None:
                continue

            http_method, route_pattern = route_annotation

            # Parameters
            params = self._extract_method_params(node, provider)

            # Auth annotations
            security = self._find_security_annotations(node)

            # Taint sources in method body
            source_lines = self._find_source_lines(node)

            endpoints.append(
                HttpEndpoint(
                    route=route_pattern,
                    methods=[http_method],
                    handler_func=method_name,
                    file_path=path,
                    line=self._line(node),
                    params=params,
                    auth_required=len(security) > 0,
                    auth_decorators=security,
                    framework="spring",
                    source_lines=source_lines,
                )
            )

        return endpoints

    # ── Annotation parsing ──────────────────────────────────────────────

    def _find_route_annotation(self, method_node: Node) -> tuple[str, str] | None:
        """Find the first Spring mapping annotation, return (HTTP_method, route)."""
        for child in method_node.children:
            if child.type != "modifiers":
                continue
            modifiers_text = self._source(child)

            for ann_name, http_method in _SPRING_METHOD_ANNOTATIONS.items():
                if ann_name not in modifiers_text:
                    continue

                # Extract route string from annotation value
                route = "/"
                for sub in self._walk_subtree(child):
                    if sub.type == "annotation":
                        ann_text = self._source(sub)
                        if ann_name in ann_text:
                            route = self._extract_annotation_value(sub) or route
                            break

                return http_method, route

        return None

    def _extract_annotation_value(self, ann_node: Node) -> str | None:
        """Extract the string argument from an annotation like @GetMapping("/path")."""
        for child in self._walk_subtree(ann_node):
            if child.type == "string_literal" or child.type == "string":
                return self._source(child).strip("\"'")
            # Annotation with explicit value= key
            if child.type == "element_value_pair":
                name = child.child_by_field_name("name")
                if name and self._source(name) == "value":
                    val = child.child_by_field_name("value")
                    if val and hasattr(val, 'type') and val.type in ("string_literal", "string"):
                        return self._source(val).strip("\"'")
        return None

    def _find_security_annotations(self, method_node: Node) -> list[str]:
        """Find Spring Security annotations."""
        found: list[str] = []
        for child in method_node.children:
            if child.type == "modifiers":
                text = self._source(child)
                for ann_name in _SPRING_SECURITY_ANNOTATIONS:
                    if ann_name in text:
                        found.append("@" + ann_name)
        return found

    # ── Parameter extraction ────────────────────────────────────────────

    def _extract_method_params(self, method_node: Node, provider) -> list[RouteParam]:
        """Extract parameters with Spring annotations."""
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
            required = True

            # Check annotations on this parameter
            for modifier in child.children:
                if modifier.type == "modifiers":
                    mod_text = self._source(modifier)
                    if "@PathVariable" in mod_text:
                        source = "path"
                    elif "@RequestBody" in mod_text:
                        source = "body"
                    elif "@RequestHeader" in mod_text:
                        source = "header"
                    elif "@CookieValue" in mod_text:
                        source = "cookie"
                    elif "@RequestParam" in mod_text:
                        source = "query"
                        # Check required= attribute
                        if "required = false" in mod_text.lower():
                            required = False

            # Type hint
            type_node = child.child_by_field_name("type")
            if type_node is not None:
                type_hint = self._source(type_node)

            params.append(RouteParam(
                name=name, source=source, type_hint=type_hint, required=required,
            ))

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
            if any(p in stripped for p in [
                "getParameter(", "getHeader(", "getCookies(",
                "getInputStream(", "getReader(",
            ]):
                lines.append(stripped[:120])
        return lines
