"""cpg/parser.py — Multi-language tree-sitter parser wrapper.

Parses Python, JavaScript, and Java source files.  All language-specific
logic lives in :mod:`hyqagent.cpg.languages` — adding a new language
requires zero changes to this file.

See DESIGN-IMPLEMENTATION.md Section 2.1 for the full interface specification.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from tree_sitter import Node, Query, QueryCursor, Tree
from tree_sitter import Parser as TSParser

from hyqagent.cpg.languages import (
    detect_by_extension,
    get_all_names,
    get_provider,
)
from hyqagent.cpg.languages.base import LanguageProvider
from hyqagent.cpg.types import ClassNode, FunctionNode, ImportNode

# Re-export for backward compatibility (other modules import from parser)
__all__ = [
    "ClassNode",
    "FunctionNode",
    "ImportNode",
    "Parser",
]


class Parser:
    """Multi-language tree-sitter parser.

    Supports all languages registered in :mod:`hyqagent.cpg.languages`.
    Auto-detects language from file extension on ``parse_file``; requires
    explicit language on ``parse_code``.

    Usage::

        parser = Parser()
        tree = parser.parse_file("app.py")
        funcs = parser.extract_functions(tree)
        classes = parser.extract_classes(tree)
        imports = parser.extract_imports(tree)

        # Access the language provider:
        prov = parser.get_provider(tree)
        print(prov.name)  # "python"
    """

    # Language names we support (populated dynamically from registry)
    SUPPORTED_LANGUAGES: ClassVar[tuple[str, ...]]

    def __init__(self, languages: list[str] | None = None) -> None:
        """Initialise parsers for the given (or all registered) languages.

        Args:
            languages: Subset of registered language names.
                       Defaults to all registered languages.

        """
        lang_names = languages or get_all_names()
        self._parsers: dict[str, TSParser] = {}
        self._languages: dict[int, str] = {}
        self._query_cache: dict[tuple[str, str], Query] = {}

        self._providers: dict[str, LanguageProvider] = {}
        for name in lang_names:
            prov = get_provider(name)
            if __debug__:
                issues = prov._validate()  # noqa: SLF001
                if issues:
                    import warnings

                    warnings.warn(
                        f"LanguageProvider {name!r} has contract issues: {issues}"
                    )
            self._providers[name] = prov
            self._parsers[name] = prov.build_ts_parser()

        # Detect cache leak: _languages dict grows unboundedly
        # with parsed trees. Warn if it exceeds a reasonable threshold.
        self._max_lang_entries = 10_000

    @classmethod
    def __init_subclass__(cls, **kwargs: object) -> None:
        """Dynamically compute SUPPORTED_LANGUAGES from the registry."""
        super().__init_subclass__(**kwargs)
        if "SUPPORTED_LANGUAGES" not in cls.__dict__:
            cls.SUPPORTED_LANGUAGES = tuple(get_all_names())

    # ── Public API ───────────────────────────────────────────────────────

    def parse_file(self, file_path: str | Path) -> Tree:
        """Parse a source file, auto-detecting the language from extension.

        Raises:
            FileNotFoundError: If *file_path* does not exist.
            ValueError: If the language cannot be detected from the extension.

        """
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        language = self._detect_language(path)
        try:
            code = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            code = path.read_text(encoding="latin-1")
        return self._parse(code, language, str(path))

    def parse_code(self, code: str, language: str) -> Tree:
        """Parse source code given as a string.

        Args:
            code: Source code text.
            language: One of the registered language names.

        Raises:
            ValueError: If *language* is unsupported or not initialised.

        """
        return self._parse(code, language, "<string>")

    def get_language(self, tree: Tree) -> str:
        """Return the language name associated with *tree*.

        This is the public replacement for the former ``_get_language``.
        """
        lang = self._languages.get(id(tree))
        if lang is None:
            raise ValueError(
                "Cannot determine language for this tree. "
                "Pass language= explicitly or use parse_file/parse_code first."
            )
        return lang

    def get_provider(self, language: str) -> LanguageProvider:
        """Return the :class:`LanguageProvider` for *language* (e.g. ``"python"``).

        Raises:
            ValueError: If *language* is not initialised in this Parser instance.
        """
        if language not in self._providers:
            raise ValueError(
                f"Unsupported language: {language!r}. "
                f"Initialised: {sorted(self._providers)}"
            )
        return self._providers[language]

    @property
    def providers(self) -> dict[str, LanguageProvider]:
        """Read-only view of the active language providers."""
        return dict(self._providers)

    # ── Extractors ───────────────────────────────────────────────────────

    def extract_functions(self, tree: Tree, language: str | None = None) -> list[FunctionNode]:
        """Extract all function / method definitions from *tree*."""
        lang = language or self.get_language(tree)
        prov = self._providers[lang]
        query = self._compile_query(lang, prov.function_query)
        cursor = QueryCursor(query)
        seen: set[tuple[str, int]] = set()
        funcs: list[FunctionNode] = []

        for _pattern_idx, captures in cursor.matches(tree.root_node):
            if "function" not in captures:
                continue
            func_name_nodes = captures.get("func.name", [])
            func_param_nodes = captures.get("func.params", [])
            for node in captures["function"]:
                func = prov.build_function_node(
                    node,
                    tree,
                    name_nodes=func_name_nodes,
                    param_nodes=func_param_nodes,
                )
                if func is None:
                    continue
                key = (func.name, func.start_line)
                if key not in seen:
                    seen.add(key)
                    funcs.append(func)

        return funcs

    def extract_classes(self, tree: Tree, language: str | None = None) -> list[ClassNode]:
        """Extract all class definitions from *tree*."""
        lang = language or self.get_language(tree)
        prov = self._providers[lang]
        query = self._compile_query(lang, prov.class_query)
        cursor = QueryCursor(query)
        classes: list[ClassNode] = []

        for _pattern_idx, captures in cursor.matches(tree.root_node):
            if "class" in captures:
                for node in captures["class"]:
                    cls = prov.build_class_node(node, tree)
                    if cls is not None:
                        classes.append(cls)

        return classes

    def extract_imports(self, tree: Tree, language: str | None = None) -> list[ImportNode]:
        """Extract all import statements from *tree*."""
        lang = language or self.get_language(tree)
        prov = self._providers[lang]
        query = self._compile_query(lang, prov.import_query)
        cursor = QueryCursor(query)
        imports: list[ImportNode] = []

        for _pattern_idx, captures in cursor.matches(tree.root_node):
            if "import" in captures:
                for node in captures["import"]:
                    imp = prov.build_import_node(node, tree)
                    if imp is not None:
                        imports.append(imp)

        return imports

    # ── Internal helpers ─────────────────────────────────────────────────

    def _parse(self, code: str, language: str, label: str) -> Tree:
        """Encode source, parse into a Tree, and store the language mapping."""
        if language not in self._parsers:
            raise ValueError(
                f"Parser for {language!r} not initialised. Available: {list(self._parsers)}"
            )
        tree = self._parsers[language].parse(code.encode("utf-8"))
        n_entries = len(self._languages)
        if n_entries >= self._max_lang_entries:
            import warnings

            warnings.warn(
                f"Parser._languages has {n_entries} entries — possible cache leak. "
                f"Reuse Parser instances across many parses.",
                ResourceWarning,
                stacklevel=2,
            )
        self._languages[id(tree)] = language
        return tree

    @staticmethod
    def _detect_language(path: Path) -> str:
        """Detect language from file extension using provider extensions."""
        name = detect_by_extension(str(path))
        if name is not None:
            return name
        raise ValueError(
            f"Cannot detect language for {path.name!r}. Use parse_code() with an explicit language."
        )

    # ── Legacy alias (for tests that accessed _get_language directly) ───

    _get_language = get_language

    def _compile_query(self, language: str, query_str: str) -> Query:
        """Compile a tree-sitter Query (cached because creation is expensive)."""
        cache_key = (language, query_str)
        cached = self._query_cache.get(cache_key)
        if cached is not None:
            return cached
        ts_lang = self._providers[language].build_ts_language()
        query = Query(ts_lang, query_str)
        self._query_cache[cache_key] = query
        return query

    # ── Generic node helpers (language-agnostic) ─────────────────────────

    @staticmethod
    def _node_text(node: Node, tree: Tree) -> str:
        """Safely decode a node's text from the source tree."""
        return node.text.decode("utf-8") if node.text else ""

    @staticmethod
    def _start_line(node: Node) -> int:
        """1-indexed start line."""
        return node.start_point[0] + 1

    @staticmethod
    def _end_line(node: Node) -> int:
        """1-indexed end line."""
        return node.end_point[0] + 1


# ─── Set SUPPORTED_LANGUAGES at class creation time ──────────────────────
Parser.SUPPORTED_LANGUAGES = tuple(get_all_names())
