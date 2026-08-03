"""cpg/parser.py — Multi-language tree-sitter parser wrapper.

Supports Python, JavaScript, and Java source files.
Provides parse_file/parse_code and extraction of functions, classes, and imports.

See DESIGN-IMPLEMENTATION.md Section 2.1 for the full interface specification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

import tree_sitter_java as tsjava
import tree_sitter_javascript as tsjs
import tree_sitter_python as tspy
from tree_sitter import Language, Node, Query, QueryCursor, Tree
from tree_sitter import Parser as TSParser

# ─── Data types ───────────────────────────────────────────────────────────


@dataclass
class FunctionNode:
    """Represents a function or method definition."""

    name: str
    start_line: int
    end_line: int
    source: str
    params: list[str] = field(default_factory=list)
    is_method: bool = False
    class_name: str | None = None
    decorators: list[str] = field(default_factory=list)
    return_type: str | None = None
    docstring: str | None = None


@dataclass
class ClassNode:
    """Represents a class definition."""

    name: str
    start_line: int
    end_line: int
    source: str
    methods: list[FunctionNode] = field(default_factory=list)
    base_classes: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    docstring: str | None = None


@dataclass
class ImportNode:
    """Represents an import statement."""

    module: str
    names: list[str] = field(default_factory=list)
    start_line: int = 0
    is_relative: bool = False
    alias: str | None = None
    source: str = ""


# ─── Constant: file extension → language mapping ──────────────────────────

_EXTENSION_MAP: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".java": "java",
}


# ─── tree-sitter queries per language ──────────────────────────────────────

_FUNCTION_QUERIES: dict[str, str] = {
    "python": """
        (function_definition
          name: (identifier) @func.name
          parameters: (parameters) @func.params
        ) @function
        (decorated_definition
          (function_definition
            name: (identifier) @func.name
            parameters: (parameters) @func.params
          ) @function
        )
    """,
    "javascript": """
        (function_declaration
          name: (identifier) @func.name
          parameters: (formal_parameters) @func.params
        ) @function
        (method_definition
          name: (property_identifier) @func.name
          parameters: (formal_parameters) @func.params
        ) @function
        (lexical_declaration
          (variable_declarator
            name: (identifier) @func.name
            value: (arrow_function
              parameters: (formal_parameters) @func.params) @function
          )
        )
        (variable_declaration
          (variable_declarator
            name: (identifier) @func.name
            value: (arrow_function
              parameters: (formal_parameters) @func.params) @function
          )
        )
    """,
    "java": """
        (method_declaration
          name: (identifier) @func.name
          parameters: (formal_parameters) @func.params
        ) @function
        (constructor_declaration
          name: (identifier) @func.name
          parameters: (formal_parameters) @func.params
        ) @function
    """,
}

_CLASS_QUERIES: dict[str, str] = {
    "python": """
        (class_definition
          name: (identifier) @class.name
        ) @class
        (decorated_definition
          (class_definition
            name: (identifier) @class.name
          ) @class
        )
    """,
    "javascript": """
        (class_declaration
          name: (identifier) @class.name
        ) @class
    """,
    "java": """
        (class_declaration
          name: (identifier) @class.name
        ) @class
    """,
}

_IMPORT_QUERIES: dict[str, str] = {
    "python": """
        (import_statement) @import
        (import_from_statement) @import
    """,
    "javascript": """
        (import_statement) @import
    """,
    "java": """
        (import_declaration) @import
    """,
}


class Parser:
    """Multi-language tree-sitter parser.

    Supports Python, JavaScript, and Java. Auto-detects language from
    file extension on ``parse_file``; requires explicit language on
    ``parse_code``.

    Usage::

        parser = Parser()
        tree = parser.parse_file("app.py")
        funcs = parser.extract_functions(tree)
        classes = parser.extract_classes(tree)
        imports = parser.extract_imports(tree)
    """

    # Language names we support
    SUPPORTED_LANGUAGES: ClassVar[tuple[str, ...]] = ("python", "javascript", "java")

    def __init__(self, languages: list[str] | None = None) -> None:
        """Initialise parsers for the given (or all supported) languages.

        Args:
            languages: Subset of ``["python", "javascript", "java"]``.
                       Defaults to all three.

        """
        lang_names = languages or list(self.SUPPORTED_LANGUAGES)
        self._parsers: dict[str, TSParser] = {}
        self._languages: dict[int, str] = {}  # id(tree) → language
        self._query_cache: dict[tuple[str, str], Query] = {}

        for name in lang_names:
            if name not in self.SUPPORTED_LANGUAGES:
                raise ValueError(
                    f"Unsupported language: {name!r}. Supported: {self.SUPPORTED_LANGUAGES}"
                )
            self._parsers[name] = self._build_parser(name)

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
        return self._parse(path.read_text(encoding="utf-8"), language, str(path))

    def parse_code(self, code: str, language: str) -> Tree:
        """Parse source code given as a string.

        Args:
            code: Source code text.
            language: One of ``"python"``, ``"javascript"``, ``"java"``.

        Raises:
            ValueError: If *language* is unsupported or not in the initialised set.

        """
        return self._parse(code, language, "<string>")

    # ── Extractors ───────────────────────────────────────────────────────

    def extract_functions(self, tree: Tree, language: str | None = None) -> list[FunctionNode]:
        """Extract all top-level functions and methods from *tree*.

        Uses the cached language if *language* is not provided.
        """
        lang = language or self._get_language(tree)
        query_str = _FUNCTION_QUERIES[lang]
        query = self._compile_query(lang, query_str)
        cursor = QueryCursor(query)
        seen: set[tuple[str, int]] = set()
        funcs: list[FunctionNode] = []

        for _pattern_idx, captures in cursor.matches(tree.root_node):
            if "function" in captures:
                func_name_nodes = captures.get("func.name", [])
                func_param_nodes = captures.get("func.params", [])
                for node in captures["function"]:
                    func = self._build_function_node(
                        lang,
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
        """Extract all top-level classes from *tree*."""
        lang = language or self._get_language(tree)
        query_str = _CLASS_QUERIES[lang]
        query = self._compile_query(lang, query_str)
        cursor = QueryCursor(query)
        classes: list[ClassNode] = []

        for _pattern_idx, captures in cursor.matches(tree.root_node):
            if "class" in captures:
                for node in captures["class"]:
                    cls = self._build_class_node(lang, node, tree)
                    if cls is not None:
                        classes.append(cls)

        return classes

    def extract_imports(self, tree: Tree, language: str | None = None) -> list[ImportNode]:
        """Extract all import statements from *tree*."""
        lang = language or self._get_language(tree)
        query_str = _IMPORT_QUERIES[lang]
        query = self._compile_query(lang, query_str)
        cursor = QueryCursor(query)
        imports: list[ImportNode] = []

        for _pattern_idx, captures in cursor.matches(tree.root_node):
            if "import" in captures:
                for node in captures["import"]:
                    imp = self._build_import_node(lang, node, tree)
                    if imp is not None:
                        imports.append(imp)

        return imports

    # ── Internal helpers ─────────────────────────────────────────────────

    @staticmethod
    def _build_parser(language: str) -> TSParser:
        """Construct a tree-sitter Parser for a single language."""
        lang_modules = {"python": tspy, "javascript": tsjs, "java": tsjava}
        ts_lang = Language(lang_modules[language].language())
        parser = TSParser(ts_lang)
        return parser

    def _parse(self, code: str, language: str, label: str) -> Tree:
        """Encode source, parse into a Tree, and store the language mapping."""
        if language not in self._parsers:
            raise ValueError(
                f"Parser for {language!r} not initialised. Available: {list(self._parsers)}"
            )
        tree = self._parsers[language].parse(code.encode("utf-8"))
        self._languages[id(tree)] = language
        return tree

    def _get_language(self, tree: Tree) -> str:
        """Retrieve the language a *tree* was parsed with."""
        lang = self._languages.get(id(tree))
        if lang is None:
            raise ValueError(
                "Cannot determine language for this tree. "
                "Pass language= explicitly or use parse_file/parse_code first."
            )
        return lang

    @staticmethod
    def _detect_language(path: Path) -> str:
        suffix = path.suffix
        if suffix in _EXTENSION_MAP:
            return _EXTENSION_MAP[suffix]
        # Try double extension (.test.js → .js)
        if path.suffixes and len(path.suffixes) >= 2:
            two_part = "".join(path.suffixes[-2:])
            if two_part in _EXTENSION_MAP:
                return _EXTENSION_MAP[two_part]
        raise ValueError(
            f"Cannot detect language for {path.name!r} (suffix={suffix!r}). "
            "Use parse_code() with an explicit language."
        )

    def _compile_query(self, language: str, query_str: str) -> Query:
        """Compile a tree-sitter Query (cached because Query creation is expensive)."""
        cache_key = (language, query_str)
        cached = self._query_cache.get(cache_key)
        if cached is not None:
            return cached
        lang_modules = {"python": tspy, "javascript": tsjs, "java": tsjava}
        ts_lang = Language(lang_modules[language].language())
        query = Query(ts_lang, query_str)
        self._query_cache[cache_key] = query
        return query

    # ── Node builders ────────────────────────────────────────────────────

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

    # ── Function extraction ──────────────────────────────────────────────

    def _build_function_node(
        self,
        lang: str,
        node: Node,
        tree: Tree,
        name_nodes: list[Node] | None = None,
        param_nodes: list[Node] | None = None,
    ) -> FunctionNode | None:
        """Build a FunctionNode from a captured function node.

        *name_nodes* and *param_nodes* are the separately-captured name and
        parameter nodes from the query (needed when the function node itself
        doesn't carry a ``name`` field, e.g. arrow functions in JS).
        """
        # 1. Determine function name
        name_node = node.child_by_field_name("name")
        if name_node is None and name_nodes:
            name_node = name_nodes[0]
        if name_node is None:
            for child in node.children:
                if child.type in ("identifier", "property_identifier"):
                    name_node = child
                    break
        if name_node is None:
            return None

        name = self._node_text(name_node, tree)

        # 2. Extract parameters
        params = self._extract_params(lang, node, param_nodes)

        # 3. Extract decorators — check both the node itself and its parent
        decorators = self._extract_decorators(lang, node)
        parent = node.parent
        if parent is not None and parent.type == "decorated_definition":
            decorators = self._extract_decorators(lang, parent)

        source = self._node_text(node, tree)

        func = FunctionNode(
            name=name,
            start_line=self._start_line(node),
            end_line=self._end_line(node),
            source=source,
            params=params,
            decorators=decorators,
        )

        # 4. Check if it's a method (parent is class body)
        if parent is not None and parent.type in ("block", "class_body"):
            grandparent = parent.parent
            if grandparent is not None and grandparent.type in (
                "class_definition",
                "class_declaration",
            ):
                func.is_method = True
                cls_name_node = grandparent.child_by_field_name("name")
                if cls_name_node is not None:
                    func.class_name = self._node_text(cls_name_node, tree)

        return func

    @staticmethod
    def _extract_params(
        lang: str, node: Node, captured_param_nodes: list[Node] | None = None
    ) -> list[str]:
        """Extract parameter names from a function node."""
        params_node = node.child_by_field_name("parameters")
        if params_node is None and captured_param_nodes:
            params_node = captured_param_nodes[0]
        if params_node is None:
            return []

        params: list[str] = []
        for child in params_node.children:
            if child.type in ("identifier",):
                text = child.text.decode("utf-8") if child.text else ""
                if text not in ("self",):  # skip Python self
                    params.append(text)
            elif child.type in (
                "typed_parameter",
                "typed_default_parameter",
                "formal_parameter",
                "required_parameter",
                "optional_parameter",
                "rest_parameter",
            ):
                for sub in child.children:
                    if sub.type == "identifier":
                        text = sub.text.decode("utf-8") if sub.text else ""
                        if text not in ("self",):
                            params.append(text)
                        break
        return params

    @staticmethod
    def _extract_decorators(lang: str, node: Node) -> list[str]:
        """Extract decorator names from a function/class node."""
        decorators: list[str] = []
        for child in node.children:
            if child.type == "decorator":
                decorators.append(child.text.decode("utf-8") if child.text else "")
        return decorators

    # ── Class extraction ─────────────────────────────────────────────────

    def _build_class_node(self, lang: str, node: Node, tree: Tree) -> ClassNode | None:
        """Build a ClassNode from a captured class node."""
        name_node = node.child_by_field_name("name")
        if name_node is None:
            for child in node.children:
                if child.type == "identifier":
                    name_node = child
                    break
        if name_node is None:
            return None

        name = self._node_text(name_node, tree)
        source = self._node_text(node, tree)
        bases = self._extract_base_classes(lang, node, tree)
        decorators = self._extract_decorators(lang, node)

        return ClassNode(
            name=name,
            start_line=self._start_line(node),
            end_line=self._end_line(node),
            source=source,
            base_classes=bases,
            decorators=decorators,
        )

    @staticmethod
    def _extract_base_classes(lang: str, node: Node, tree: Tree) -> list[str]:
        """Extract base class names from a class definition."""
        bases: list[str] = []
        if lang == "python":
            # class Foo(Base1, Base2):
            for child in node.children:
                if child.type == "argument_list":
                    for sub in child.children:
                        if sub.type == "identifier" or sub.type == "attribute":
                            bases.append(sub.text.decode("utf-8") if sub.text else "")
        elif lang == "javascript":
            # class Foo extends Base / class Foo extends React.Component
            for child in node.children:
                if child.type == "class_heritage":
                    for sub in child.children:
                        # Simple extends: extends_clause doesn't exist; the
                        # identifier is directly inside class_heritage.
                        if sub.type in ("identifier", "member_expression", "call_expression"):
                            bases.append(sub.text.decode("utf-8") if sub.text else "")
        elif lang == "java":
            # class Foo extends Base implements IFace
            for child in node.children:
                if child.type == "superclass":
                    for sub in child.children:
                        if sub.type in ("identifier", "type_identifier", "scoped_identifier"):
                            bases.append(sub.text.decode("utf-8") if sub.text else "")
                if child.type == "super_interfaces":
                    for sub in child.children:
                        if sub.type == "type_list":
                            for t in sub.children:
                                if t.type in ("type_identifier", "scoped_identifier"):
                                    bases.append(t.text.decode("utf-8") if t.text else "")
        return bases

    # ── Import extraction ────────────────────────────────────────────────

    def _build_import_node(self, lang: str, node: Node, tree: Tree) -> ImportNode | None:
        """Build an ImportNode from a captured import node."""
        if lang == "python":
            return self._build_python_import(node, tree)
        elif lang == "javascript":
            return self._build_javascript_import(node, tree)
        elif lang == "java":
            return self._build_java_import(node, tree)
        return None

    @staticmethod
    def _build_python_import(node: Node, tree: Tree) -> ImportNode:
        """Extract Python import statement details."""
        source = node.text.decode("utf-8") if node.text else ""
        module = ""
        names: list[str] = []
        is_relative = False
        alias: str | None = None

        if node.type == "import_statement":
            # "import X" or "import X as Y" or "import X, Y"
            for child in node.children:
                if child.type == "dotted_name":
                    name = child.text.decode("utf-8") if child.text else ""
                    if not module:
                        module = name
                    names.append(name)
                elif child.type == "aliased_import":
                    # "X as Y"
                    for sub in child.children:
                        if sub.type == "dotted_name":
                            name = sub.text.decode("utf-8") if sub.text else ""
                            if not module:
                                module = name
                            names.append(name)
                        elif sub.type == "identifier":
                            # This is the alias part (after 'as')
                            pass

        elif node.type == "import_from_statement":
            # "from <module> import <names>"
            names = []
            was_import_kw = False
            for child in node.children:
                if child.type == "dotted_name" and not was_import_kw:
                    module = child.text.decode("utf-8") if child.text else ""
                elif child.type == "relative_import":
                    is_relative = True
                    module = child.text.decode("utf-8") if child.text else ""
                elif child.type == "import":
                    was_import_kw = True
                elif child.type == "dotted_name" and was_import_kw:
                    names.append(child.text.decode("utf-8") if child.text else "")
                elif child.type == "aliased_import":
                    # "Y as Z"
                    for sub in child.children:
                        if sub.type == "dotted_name":
                            names.append(sub.text.decode("utf-8") if sub.text else "")
                elif child.type == "wildcard_import":
                    names.append("*")

        return ImportNode(
            module=module,
            names=names,
            start_line=Parser._start_line(node),
            is_relative=is_relative,
            alias=alias,
            source=source,
        )

    @staticmethod
    def _build_javascript_import(node: Node, tree: Tree) -> ImportNode:
        """Extract JavaScript import statement details."""
        source = node.text.decode("utf-8") if node.text else ""
        module = ""
        names: list[str] = []

        for child in node.children:
            if child.type == "string":
                # The module path: './foo', 'react', etc.
                # Strip quotes
                raw = child.text.decode("utf-8") if child.text else ""
                module = raw.strip("\"'")
            elif child.type == "import_clause":
                for sub in child.children:
                    if sub.type == "identifier":
                        names.append(sub.text.decode("utf-8") if sub.text else "")
                    elif sub.type == "named_imports":
                        for spec in sub.children:
                            if spec.type == "import_specifier":
                                for s in spec.children:
                                    if s.type == "identifier":
                                        names.append(s.text.decode("utf-8") if s.text else "")
                    elif sub.type == "namespace_import":
                        for s in sub.children:
                            if s.type == "identifier":
                                names.append(f"* as {s.text.decode('utf-8') if s.text else ''}")

        return ImportNode(
            module=module,
            names=names,
            start_line=Parser._start_line(node),
            is_relative=module.startswith(".") if module else False,
            source=source,
        )

    @staticmethod
    def _build_java_import(node: Node, tree: Tree) -> ImportNode:
        """Extract Java import declaration details."""
        source = node.text.decode("utf-8") if node.text else ""
        module = ""

        # Java import: "import java.util.List;"
        for child in node.children:
            if child.type == "scoped_identifier" or child.type == "identifier":
                module = child.text.decode("utf-8") if child.text else ""

        return ImportNode(
            module=module,
            names=[module.split(".")[-1]] if module else [],
            start_line=Parser._start_line(node),
            source=source,
        )
