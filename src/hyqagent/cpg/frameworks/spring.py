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

    from hyqagent.cpg.languages.base import LanguageProvider
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


def _merge_routes(prefix: str, route: str) -> str:
    """Merge a class-level prefix with a method-level route (BUG 11).

    >>> _merge_routes("/api", "/users")
    "/api/users"
    >>> _merge_routes("/api/", "/users")
    "/api/users"
    """
    prefix = prefix.rstrip("/")
    if not prefix:
        return route
    if not route.startswith("/"):
        route = "/" + route
    return prefix + route


_SPRING_SECURITY_ANNOTATIONS = {
    "PreAuthorize",
    "PostAuthorize",
    "Secured",
    "RolesAllowed",
    "PreFilter",
    "PostFilter",
    "Authenticated",
}

# Class-level controller annotations — methods inside non-controller classes
# that happen to have a mapping annotation (e.g. @Scheduled inside @Service)
# should not be treated as HTTP endpoints.
_SPRING_CONTROLLER_ANNOTATIONS = {
    "RestController",
    "Controller",
    "RequestMapping",
}

# Spring Cloud / micro-service annotations.
_SPRING_CLOUD_FEIGN = "FeignClient"

# Spring Boot Actuator endpoint annotations.
_SPRING_ACTUATOR_ENDPOINT_ANNOTATIONS = {
    "Endpoint",
    "WebEndpoint",
    "RestControllerEndpoint",
    "ControllerEndpoint",
}

_SPRING_ACTUATOR_OPERATION_ANNOTATIONS = {
    "ReadOperation",
    "WriteOperation",
    "DeleteOperation",
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
        except (FileNotFoundError, ValueError, OSError):
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

            # ── Actuator endpoints ───────────────────────────────────────
            actuator = self._find_actuator_endpoint(node)
            if actuator is not None:
                endpoint_id, operation = actuator
                endpoints.append(
                    HttpEndpoint(
                        route=f"/actuator/{endpoint_id}",
                        methods=[operation] if operation else ["GET"],
                        handler_func=method_name,
                        file_path=path,
                        line=self._line(node),
                        params=[],
                        auth_required=False,
                        auth_decorators=[],
                        framework="spring-actuator",
                        source_lines=[],
                    )
                )
                continue

            # ── FeignClient methods ──────────────────────────────────────
            feign_info = self._find_feign_client(node)
            if feign_info is not None:
                _feign_name, feign_url = feign_info
                route_annotation = self._find_route_annotation(node)
                if route_annotation is not None:
                    http_method, route_pattern = route_annotation
                    if feign_url:
                        route_pattern = _merge_routes(feign_url, route_pattern)
                    endpoints.append(
                        HttpEndpoint(
                            route=route_pattern,
                            methods=[http_method],
                            handler_func=method_name,
                            file_path=path,
                            line=self._line(node),
                            params=self._extract_method_params(node, provider),
                            auth_required=False,
                            auth_decorators=[],
                            framework="spring-cloud",
                            source_lines=[],
                        )
                    )
                continue

            # ── Standard controller endpoints ────────────────────────────
            # Skip methods whose enclosing class is not a controller
            if not self._is_controller_class(node):
                continue

            # Check for Spring mapping annotations
            route_annotation = self._find_route_annotation(node)
            if route_annotation is None:
                continue

            http_method, route_pattern = route_annotation

            # BUG 11: Merge class-level @RequestMapping prefix
            class_prefix = self._find_class_route_prefix(node)
            if class_prefix:
                route_pattern = _merge_routes(class_prefix, route_pattern)

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
        """Find the first Spring mapping annotation, return (HTTP_method, route).

        For ``@RequestMapping``, also checks the ``method=`` attribute
        (e.g. ``method=RequestMethod.POST``) to determine the actual HTTP
        method instead of always defaulting to GET (BUG 10).
        """
        for child in method_node.children:
            if child.type != "modifiers":
                continue
            modifiers_text = self._source(child)

            for ann_name, http_method in _SPRING_METHOD_ANNOTATIONS.items():
                if ann_name not in modifiers_text:
                    continue

                # Extract route string from annotation value
                route = "/"
                method_override: str | None = None
                for sub in self._walk_subtree(child):
                    if sub.type == "annotation":
                        ann_text = self._source(sub)
                        if ann_name in ann_text:
                            route = self._extract_annotation_value(sub) or route
                            # BUG 10: @RequestMapping can specify method= attribute
                            if ann_name == "RequestMapping":
                                method_override = self._extract_method_attribute(sub)
                            break

                if ann_name == "RequestMapping" and method_override:
                    return method_override, route
                return http_method, route

        return None

    @staticmethod
    def _extract_method_attribute(ann_node: Node) -> str | None:
        """Extract ``method=RequestMethod.X`` from a ``@RequestMapping`` annotation (BUG 10)."""
        for child in ann_node.children:
            if child.type == "element_value_pair":
                name_node = child.child_by_field_name("name")
                if name_node and name_node.text and name_node.text.decode() == "method":
                    val_node = child.child_by_field_name("value")
                    if val_node is not None and hasattr(val_node, "text") and val_node.text:
                        val_text = val_node.text.decode()
                        if "RequestMethod." in val_text:
                            return val_text.split("RequestMethod.")[-1].strip()
        return None

    def _find_class_route_prefix(self, method_node: Node) -> str:
        """Return the class-level ``@RequestMapping`` route prefix, or ``""`` (BUG 11).

        Walks ancestors to the enclosing ``class_declaration``, then checks
        its modifiers for ``@RequestMapping``.  The prefix is prepended to
        each method-level route, e.g. ``"/api" + "/users"`` → ``"/api/users"``.
        """
        for ancestor in Traverser.get_ancestors(method_node):
            if ancestor.type == "class_declaration":
                for child in ancestor.children:
                    if child.type == "modifiers":
                        modifiers_text = self._source(child)
                        if "@RequestMapping" in modifiers_text:
                            for sub in self._walk_subtree(child):
                                if sub.type == "annotation":
                                    ann_text = self._source(sub)
                                    if "RequestMapping" in ann_text:
                                        prefix = self._extract_annotation_value(sub)
                                        if prefix and prefix != "/":
                                            return prefix
                                        return ""
                break  # Only check the first enclosing class
        return ""

    def _is_controller_class(self, method_node: Node) -> bool:
        """Return ``True`` if the enclosing class is a Spring controller.

        Checks for ``@RestController``, ``@Controller``, or ``@RequestMapping``
        on the enclosing class.  Methods inside non-controller classes
        (e.g. ``@Service``, ``@Component``) that happen to carry a mapping
        annotation are skipped to reduce false positives.
        """
        for ancestor in Traverser.get_ancestors(method_node):
            if ancestor.type == "class_declaration":
                for child in ancestor.children:
                    if child.type == "modifiers":
                        modifiers_text = self._source(child)
                        for ann_name in _SPRING_CONTROLLER_ANNOTATIONS:
                            if ann_name in modifiers_text:
                                return True
                return False  # Class has no controller annotation
        return True  # No enclosing class → treat as controller (e.g. Kotlin top-level)

    def _find_feign_client(self, method_node: Node) -> tuple[str, str] | None:
        """Return ``(name, url)`` if enclosing interface has ``@FeignClient``, else ``None``.

        FeignClient methods define remote HTTP endpoints for declarative
        service-to-service calls.  The ``url`` can be a hard-coded string
        or a placeholder (``"${service.url}"``).
        """
        for ancestor in Traverser.get_ancestors(method_node):
            if ancestor.type in ("class_declaration", "interface_declaration"):
                for child in ancestor.children:
                    if child.type == "modifiers":
                        modifiers_text = self._source(child)
                        if _SPRING_CLOUD_FEIGN in modifiers_text:
                            feign_name = ""
                            feign_url = ""
                            for sub in self._walk_subtree(child):
                                if sub.type == "annotation":
                                    ann_text = self._source(sub)
                                    if _SPRING_CLOUD_FEIGN in ann_text:
                                        feign_name = self._extract_element_value(sub, "name") or ""
                                        feign_url = self._extract_element_value(sub, "url") or ""
                                        break
                            return (feign_name, feign_url)
                break
        return None

    def _find_actuator_endpoint(self, method_node: Node) -> tuple[str, str] | None:
        """Return ``(endpoint_id, operation)`` for Actuator endpoints, or ``None``.

        Spring Boot Actuator ``@Endpoint`` / ``@WebEndpoint`` classes expose
        management endpoints at ``/actuator/{id}``.  Method-level
        ``@ReadOperation`` → GET, ``@WriteOperation`` → POST,
        ``@DeleteOperation`` → DELETE.
        """
        for ancestor in Traverser.get_ancestors(method_node):
            if ancestor.type == "class_declaration":
                # Check for Actuator endpoint class annotations
                endpoint_id: str | None = None
                for child in ancestor.children:
                    if child.type == "modifiers":
                        modifiers_text = self._source(child)
                        is_actuator = any(
                            ann in modifiers_text for ann in _SPRING_ACTUATOR_ENDPOINT_ANNOTATIONS
                        )
                        if is_actuator:
                            # Extract endpoint id
                            for sub in self._walk_subtree(child):
                                if sub.type == "annotation":
                                    ann_text = self._source(sub)
                                    if any(
                                        ann in ann_text
                                        for ann in _SPRING_ACTUATOR_ENDPOINT_ANNOTATIONS
                                    ):
                                        eid = self._extract_element_value(sub, "id")
                                        if eid:
                                            endpoint_id = eid
                                            break

                if endpoint_id is None:
                    break

                # Check method for operation annotations
                for child in method_node.children:
                    if child.type == "modifiers":
                        mod_text = self._source(child)
                        if "ReadOperation" in mod_text:
                            return (endpoint_id, "GET")
                        if "WriteOperation" in mod_text:
                            return (endpoint_id, "POST")
                        if "DeleteOperation" in mod_text:
                            return (endpoint_id, "DELETE")
                # Default: method in an @Endpoint class → GET
                return (endpoint_id, "GET")

        return None

    @staticmethod
    def _extract_element_value(ann_node: Node, key: str) -> str | None:
        """Extract a named element-value pair from an annotation node.

        For ``@FeignClient(name="svc", url="http://...")``, calling
        ``_extract_element_value(node, "url")`` returns ``"http://..."``.
        """
        for child in SpringExtractor._walk_subtree(ann_node):
            if child.type == "element_value_pair":
                # The key is the first named child (identifier), not a
                # named field — tree-sitter Java doesn't use field names
                # for element_value_pair keys.
                named_children = [c for c in child.children if c.is_named]
                if named_children and SpringExtractor._source(named_children[0]) == key:
                    val = child.child_by_field_name("value")
                    if (
                        val is not None
                        and hasattr(val, "type")
                        and val.type in ("string_literal", "string")
                    ):
                        return SpringExtractor._source(val).strip("\"'")
                    # Array initializer: url = {"http://..."}
                    if val and val.type == "array_initializer":
                        for item in val.named_children:
                            if item.type in ("string_literal", "string"):
                                return SpringExtractor._source(item).strip("\"'")
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
                    if (
                        val is not None
                        and hasattr(val, "type")
                        and val.type in ("string_literal", "string")
                    ):
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

    def _extract_method_params(
        self, method_node: Node, provider: LanguageProvider
    ) -> list[RouteParam]:
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

            params.append(
                RouteParam(
                    name=name,
                    source=source,
                    type_hint=type_hint,
                    required=required,
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
                    "getInputStream(",
                    "getReader(",
                ]
            ):
                lines.append(stripped[:120])
        return lines
