"""cpg/callgraph.py — Single-file call graph builder.

Builds caller→callee relationships within a single source file using
language-specific providers.  All language knowledge lives in
:mod:`hyqagent.cpg.languages` — adding a new language requires zero
changes to this file.

See DESIGN-IMPLEMENTATION.md Section 2.2 for the interface specification.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from tree_sitter import Node, Tree

from hyqagent.cpg.languages.base import LanguageProvider
from hyqagent.cpg.parser import Parser
from hyqagent.cpg.traversal import Traverser

# ─── Data types ───────────────────────────────────────────────────────────


@dataclass
class CallEdge:
    """A single call edge: one function calls another (or an external).

    Attributes:
        caller: Name of the calling function.
        callee: Bare name of the called function (e.g. ``"execute"`` from
                ``self.db.execute(sql)``).
        call_line: 1-indexed line number of the call site.
        full_expression: Full text of the call expression
                         (e.g. ``"self.db.execute(sql)"``).
        is_resolved: True if *callee* matches a function defined in the same file.
        is_method_call: True if the call uses an object prefix
                        (``obj.method()``).
        file_path: Source file where the call occurs.

    """

    caller: str
    callee: str
    call_line: int
    full_expression: str
    is_resolved: bool = False
    is_method_call: bool = False
    file_path: str = ""


@dataclass
class UnresolvedCall:
    """A call whose target could not be matched to a local function definition.

    These are candidates for cross-file resolution in :class:`CallGraphBuilder`.
    """

    callee: str
    full_expression: str
    call_line: int
    caller: str
    is_method_call: bool
    file_path: str


# ─── Core class ────────────────────────────────────────────────────────────


class SingleFileCallGraph:
    """Build a call graph for a single source file.

    Identifies function definitions and call expressions within one file,
    then resolves calls to local definitions by name.  Calls that cannot be
    resolved locally are available via :attr:`unresolved` for later
    cross-file resolution.

    Usage::

        parser = Parser()
        cg = SingleFileCallGraph(parser)
        cg.build_from_file("app.py")

        for edge in cg.edges:
            print(f"{edge.caller} -> {edge.callee}  (resolved={edge.is_resolved})")
    """

    def __init__(self, parser: Parser) -> None:
        self._parser = parser
        self._edges: list[CallEdge] = []
        self._function_names: set[str] = set()
        self._qualified_function_names: set[str] = set()  # BUG 9: ClassName.methodName

    # ── Public properties ──────────────────────────────────────────────

    @property
    def edges(self) -> list[CallEdge]:
        """All call edges discovered in the file (read-only copy)."""
        return list(self._edges)

    @property
    def resolved_edges(self) -> list[CallEdge]:
        """Edges whose callee matches a function defined in the same file."""
        return [e for e in self._edges if e.is_resolved]

    @property
    def unresolved(self) -> list[UnresolvedCall]:
        """Calls that could not be resolved to a local function."""
        return [
            UnresolvedCall(
                callee=e.callee,
                full_expression=e.full_expression,
                call_line=e.call_line,
                caller=e.caller,
                is_method_call=e.is_method_call,
                file_path=e.file_path,
            )
            for e in self._edges
            if not e.is_resolved
        ]

    @property
    def function_names(self) -> set[str]:
        """Names of all functions / methods defined in this file."""
        return set(self._function_names)

    @property
    def qualified_function_names(self) -> set[str]:
        """Qualified names (e.g. ``ClassName.methodName``) for Java methods (BUG 9)."""
        return set(self._qualified_function_names)

    # ── Build methods ──────────────────────────────────────────────────

    def build_from_file(self, file_path: str | Path) -> None:
        """Build the call graph for *file_path*.

        Raises:
            FileNotFoundError: If *file_path* does not exist.
            ValueError: If the language cannot be detected.

        """
        path = Path(file_path).resolve()
        tree = self._parser.parse_file(str(path))
        language = self._parser.get_language(tree)
        self._build(tree, language, str(path))

    def build_from_tree(
        self,
        tree: Tree,
        language: str,
        file_path: str = "<string>",
    ) -> None:
        """Build the call graph from an already-parsed tree.

        Args:
            tree: A tree-sitter ``Tree``.
            language: One of the registered language names.
            file_path: Label used in edge metadata.

        """
        self._build(tree, language, file_path)

    # ── Query methods ──────────────────────────────────────────────────

    def get_callees(self, func_name: str) -> list[CallEdge]:
        """Return all edges where *func_name* is the caller."""
        return [e for e in self._edges if e.caller == func_name]

    def get_callers(self, func_name: str) -> list[CallEdge]:
        """Return all *resolved* edges where *func_name* is the callee."""
        return [e for e in self._edges if e.callee == func_name and e.is_resolved]

    def has_edge(self, caller: str, callee: str) -> bool:
        """Return True if there is a resolved edge *caller* → *callee*."""
        return any(e.caller == caller and e.callee == callee and e.is_resolved for e in self._edges)

    # ── Internal build pipeline ────────────────────────────────────────

    def _build(self, tree: Tree, language: str, file_path: str) -> None:
        """Reset state and populate the graph from *tree*."""
        self._edges.clear()
        self._function_names.clear()

        provider = self._parser.get_provider(language)
        traverser = Traverser(tree)
        func_def_types = provider.func_def_types
        call_type = provider.call_node_type

        # Phase 1 — collect all function definition names
        # BUG 9: Also generate qualified names (ClassName.methodName)
        # for Java methods to avoid collisions from overloaded methods.
        for func_node in traverser.traverse(func_def_types):
            name = provider.extract_function_name(func_node)
            if name:
                self._function_names.add(name)
                qualified = self._make_qualified_name(func_node, name, language)
                if qualified and qualified != name:
                    self._qualified_function_names.add(qualified)

        # Phase 2 — walk every call node and attribute to enclosing function
        for call_node in traverser.traverse({call_type}):
            callee_info = provider.extract_callee_info(call_node)
            if callee_info is None:
                continue

            bare_name, full_expr, is_method = callee_info

            caller = self._find_enclosing_func(call_node, provider)
            if caller is None:
                continue

            call_line = call_node.start_point[0] + 1
            # BUG 9: Resolve callee using qualified names for method calls
            resolved_callee = bare_name
            is_resolved = bare_name in self._function_names
            if not is_resolved and is_method and self._qualified_function_names:
                suffix = f".{bare_name}"
                for qn in self._qualified_function_names:
                    if qn.endswith(suffix):
                        is_resolved = True
                        resolved_callee = qn
                        break

            edge = CallEdge(
                caller=caller,
                callee=resolved_callee,
                call_line=call_line,
                full_expression=full_expr,
                is_resolved=is_resolved,
                is_method_call=is_method,
                file_path=file_path,
            )
            self._edges.append(edge)

    # ── Enclosing function detection ───────────────────────────────────

    @staticmethod
    def _find_enclosing_func(node: Node, provider: LanguageProvider) -> str | None:
        """Walk ancestors to find the nearest named function definition."""
        func_types = provider.func_def_types
        for ancestor in Traverser.get_ancestors(node):
            if ancestor.type in func_types:
                return provider.extract_function_name(ancestor)
        return None

    @staticmethod
    def _make_qualified_name(func_node: Node, base_name: str, language: str) -> str | None:
        """Generate ``ClassName.methodName`` for Java methods (BUG 9).

        Returns *base_name* unchanged for non-Java languages or top-level
        functions without an enclosing class.
        """
        if language != "java":
            return base_name
        parent = func_node.parent
        if parent is not None and parent.type == "class_body":
            grandparent = parent.parent
            if grandparent is not None and grandparent.type == "class_declaration":
                cls_name_node = grandparent.child_by_field_name("name")
                if cls_name_node is not None and cls_name_node.text:
                    cls_name = cls_name_node.text.decode("utf-8")
                    return f"{cls_name}.{base_name}"
        return base_name

    # ── Dunder helpers ─────────────────────────────────────────────────

    def __repr__(self) -> str:
        """Return a compact representation with function / edge / resolved counts."""
        return (
            f"SingleFileCallGraph(functions={len(self._function_names)}, "
            f"edges={len(self._edges)}, "
            f"resolved={sum(1 for e in self._edges if e.is_resolved)})"
        )

    def __len__(self) -> int:
        """Return the total number of call edges."""
        return len(self._edges)

    def __iter__(self) -> Iterator[CallEdge]:
        """Iterate over all call edges."""
        return iter(self._edges)
