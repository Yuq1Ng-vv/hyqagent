"""cpg/frameworks/django.py — Django URL-config + view extractor.

Parses ``urls.py`` for ``path()`` / ``re_path()`` route definitions and
maps them to view functions in ``views.py``.  Cross-file resolution is
performed via import analysis using the shared parser.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from hyqagent.cpg.frameworks.base import BaseFrameworkExtractor, HttpEndpoint, RouteParam
from hyqagent.cpg.traversal import Traverser

if TYPE_CHECKING:
    from tree_sitter import Node

    from hyqagent.cpg.parser import Parser

_DJANGO_SOURCE_PATTERNS = [
    "request.POST",
    "request.GET",
    "request.body",
    "request.data",
    "request.META",
    "request.COOKIES",
    "request.FILES",
    "request.headers",
    "request.build_absolute_uri",
]

_DJANGO_AUTH_DECORATORS = {
    "login_required",
    "permission_required",
    "user_passes_test",
    "staff_member_required",
    "superuser_required",
}


class DjangoExtractor(BaseFrameworkExtractor):
    """Extract HTTP routes from Django applications.

    Works in two phases:
    1. Parse ``*urls*.py`` files for ``path()`` / ``re_path()`` calls.
    2. Locate view functions and scan for taint sources.
    """

    def __init__(self, parser: Parser) -> None:
        super().__init__(parser)
        self._url_configs: dict[str, list[dict]] = {}  # file → [{route, view, name}]

    @property
    def framework_name(self) -> str:  # noqa: D102
        return "django"

    def detect(self, file_path: str | Path) -> bool:  # noqa: D102
        path = str(Path(file_path).resolve())
        try:
            tree = self._parser.parse_file(path)
        except (FileNotFoundError, ValueError, OSError):
            return False
        source = self._source(tree.root_node)
        return "django" in source.lower() and ("from django" in source or "import django" in source)

    def extract_routes(self, file_path: str | Path) -> list[HttpEndpoint]:  # noqa: D102
        path = str(Path(file_path).resolve())
        tree = self._parser.parse_file(path)
        language = self._parser.get_language(tree)
        provider = self._parser.get_provider(language)
        endpoints: list[HttpEndpoint] = []

        # Lazily scan for URL configs on first call
        if not self._url_configs:
            self._scan_url_dir(str(Path(path).parent))

        # Detect URL config files
        if self._is_url_config(path):
            url_entries = self._parse_url_config(tree)
            self._url_configs[path] = url_entries

        # Detect view files and match against URL config
        funcs = self._parser.extract_functions(tree, language)
        for fn in funcs:
            # Check if this function appears in any URL config
            route_info = self._find_route_for_view(fn.name)
            if route_info:
                # Find auth decorators by locating the function node
                auth_decorators: list[str] = []
                for node in Traverser(tree).traverse():
                    if node.type == "decorated_definition":
                        for child in node.children:
                            if child.type == "function_definition":
                                extracted = provider.extract_function_name(child)
                                if extracted == fn.name:
                                    auth_decorators = self._find_auth_decorators(node)
                                    break

                # Taint sources from function body
                source_lines = self._find_source_lines(tree, fn)

                params = DjangoExtractor._extract_path_params(route_info["route"])
                endpoints.append(
                    HttpEndpoint(
                        route=route_info["route"],
                        methods=route_info.get("methods", ["GET"]),
                        handler_func=fn.name,
                        file_path=path,
                        line=fn.start_line,
                        params=params,
                        auth_required=len(auth_decorators) > 0,
                        auth_decorators=auth_decorators,
                        framework="django",
                        source_lines=source_lines,
                    )
                )

        return endpoints

    # ── URL config parsing ──────────────────────────────────────────────

    @staticmethod
    def _is_url_config(file_path: str) -> bool:
        return "urls" in Path(file_path).stem

    def _parse_url_config(self, tree) -> list[dict]:
        """Extract route entries from urlpatterns in a urls.py file.

        BUG 12: The regex now handles ``re_path`` patterns that may
        contain embedded quotes (e.g. ``re_path(r"^api/v1/'special'/$")``).
        It uses a backreference ``(?P<quote>[\"'])…(?P=quote)`` to match
        balanced quotes so an inner single-quote doesn't prematurely
        terminate a double-quoted string.
        """
        entries: list[dict] = []
        source = self._source(tree.root_node)
        import re

        # BUG 12: Match with balanced-quote backreference
        for match in re.finditer(
            r"(?:path|re_path)\s*\(\s*(?:r)?(?P<quote>[\"'])(.+?)(?P=quote)\s*,\s*(\w+(?:\.\w+)*)",
            source,
        ):
            route = match.group(2)
            view = match.group(3)
            entries.append({"route": route, "view": view})
        return entries

    def _scan_url_dir(self, dir_path: str) -> None:
        """Scan directory for ``*urls*.py`` files and pre-parse URL configs."""
        root = Path(dir_path)
        for entry in sorted(root.rglob("*urls*.py")):
            if entry.is_file():
                try:
                    t = self._parser.parse_file(str(entry))
                    self._url_configs[str(entry)] = self._parse_url_config(t)
                except Exception:
                    pass

    def _find_route_for_view(self, func_name: str) -> dict | None:
        for _file_path, entries in self._url_configs.items():
            for entry in entries:
                view = entry["view"]
                # Match "views.func_name" or bare "func_name"
                if view == func_name or view.endswith("." + func_name):
                    return entry
        return None

    # ── View analysis ───────────────────────────────────────────────────

    def _find_source_lines(self, tree, fn) -> list[str]:
        """Scan the target function body for Django-specific taint sources."""
        lines: list[str] = []
        provider = self._parser.get_provider(self._parser.get_language(tree))
        for node in Traverser(tree).traverse():
            if node.type in ("function_definition", "decorated_definition"):
                name = provider.extract_function_name(
                    node
                    if node.type == "function_definition"
                    else next((c for c in node.children if c.type == "function_definition"), node)
                )
                if name != fn.name:
                    continue
                text = self._source(node)
                for pat in _DJANGO_SOURCE_PATTERNS:
                    if pat in text:
                        for line_text in text.split("\n"):
                            if pat in line_text:
                                lines.append(line_text.strip()[:120])
        return lines

    def _find_auth_decorators(self, node: Node) -> list[str]:
        found: list[str] = []
        for child in node.children:
            if child.type == "decorator":
                text = self._source(child).strip().lstrip("@").split("(")[0].split(".")[-1]
                if text in _DJANGO_AUTH_DECORATORS:
                    found.append(self._source(child).strip())
        return found

    @staticmethod
    def _extract_path_params(route: str) -> list[RouteParam]:
        import re

        params: list[RouteParam] = []
        for match in re.finditer(r"<(?:int|str|slug|uuid|path):(\w+)>", route):
            params.append(RouteParam(name=match.group(1), source="path"))
        return params
