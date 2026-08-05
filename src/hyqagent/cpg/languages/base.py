"""cpg/languages/base.py — Abstract base class for language-specific providers.

Each supported programming language implements :class:`LanguageProvider`.
Adding a new language (e.g., Go) means creating one new file in this
package — no changes to ``parser.py`` or ``callgraph.py`` are needed.

See the plan at ``.claude/plans/linear-gliding-stroustrup.md`` for the
full architecture rationale.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from tree_sitter import Language
from tree_sitter import Parser as TSParser

from hyqagent.cpg.types import ClassNode, FunctionNode, ImportNode

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


class LanguageProvider(ABC):
    """Abstract interface for language-specific AST analysis.

    Each concrete adapter provides:

    * Metadata (name, file extensions)
    * tree-sitter grammar module (lazy-loaded)
    * Query strings for function / class / import extraction
    * Node-to-dataclass builders (functions, classes, imports)
    * Call-graph helpers (call node type, callee extraction)

    To add a new language:

    1. Create ``cpg/languages/golang.py`` implementing this class.
    2. Register it in ``cpg/languages/__init__.py``.
    3. Done — ``parser.py`` and ``callgraph.py`` need no changes.
    """

    # ── Metadata ──────────────────────────────────────────────────────

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique language identifier, e.g. ``"python"``."""
        ...

    @property
    @abstractmethod
    def extensions(self) -> list[str]:
        """File extensions for this language, e.g. ``[".py", ".pyi"]``."""
        ...

    # ── tree-sitter grammar (lazy-loaded) ─────────────────────────────

    @property
    @abstractmethod
    def _ts_module(self) -> Any:
        """Return the tree-sitter grammar module (lazily imported).

        Concrete adapters should use ``functools.cached_property`` so the
        heavy ``import`` only happens when this language is actually used.
        """
        ...

    # ── Query strings ─────────────────────────────────────────────────

    @property
    @abstractmethod
    def function_query(self) -> str:
        """Tree-sitter query for function / method definitions."""
        ...

    @property
    @abstractmethod
    def class_query(self) -> str:
        """Tree-sitter query for class definitions."""
        ...

    @property
    @abstractmethod
    def import_query(self) -> str:
        """Tree-sitter query for import statements."""
        ...

    # ── Node builders (parser.py delegates to these) ───────────────────

    @abstractmethod
    def extract_function_name(self, node: Node) -> str | None:
        """Extract the function / method name from a definition node.

        For languages with decorators (Python), this must unwrap
        ``decorated_definition`` wrappers.
        """
        ...

    @abstractmethod
    def extract_parameters(
        self, node: Node, captured_params: list[Node] | None = None
    ) -> list[str]:
        """Extract parameter names from a function definition node."""
        ...

    @abstractmethod
    def extract_decorators(self, node: Node) -> list[str]:
        """Extract decorator / annotation names from a definition node."""
        ...

    @abstractmethod
    def extract_base_classes(self, node: Node, tree: Tree) -> list[str]:
        """Extract base class / superclass names from a class definition."""
        ...

    @abstractmethod
    def build_import_node(self, node: Node, tree: Tree) -> ImportNode | None:
        """Build an :class:`ImportNode` from an import statement node."""
        ...

    @abstractmethod
    def build_function_node(
        self,
        node: Node,
        tree: Tree,
        name_nodes: list[Node] | None = None,
        param_nodes: list[Node] | None = None,
    ) -> FunctionNode | None:
        """Build a :class:`FunctionNode` from a function definition node.

        Responsible for detecting whether the function is a method
        (i.e. enclosed in a class body).
        """
        ...

    @abstractmethod
    def build_class_node(self, node: Node, tree: Tree) -> ClassNode | None:
        """Build a :class:`ClassNode` from a class definition node."""
        ...

    # ── Call-graph helpers (callgraph.py delegates to these) ────────────

    @property
    @abstractmethod
    def call_node_type(self) -> str:
        """Tree-sitter node type for a function call, e.g. ``"call"``."""
        ...

    @property
    @abstractmethod
    def func_def_types(self) -> set[str]:
        """Set of tree-sitter node types that represent function definitions."""
        ...

    @abstractmethod
    def extract_callee_info(self, node: Node) -> tuple[str, str, bool] | None:
        """Extract ``(bare_name, full_expression, is_method_call)`` from a call node.

        *bare_name* is the last component (``"query"`` from
        ``self.db.query()``).  *full_expression* is the text of the
        function-expression child.  *is_method_call* is ``True`` when the
        call has an explicit object prefix.

        Returns ``None`` if the callee cannot be determined.
        """
        ...

    # ── Contract validation (debug-only) ────────────────────────────────

    def _validate(self) -> list[str]:
        """Return list of contract violations (empty = valid).

        Called in ``if __debug__:`` blocks during :class:`Parser`
        initialisation to catch misconfigured adapters early.
        """
        issues: list[str] = []
        if not self.name or not isinstance(self.name, str):
            issues.append(f"{type(self).__name__}.name must be a non-empty str")
        if not isinstance(self.extensions, list) or not self.extensions:
            issues.append(f"{type(self).__name__}.extensions must be a non-empty list")
        if not isinstance(self.function_query, str):
            issues.append(f"{type(self).__name__}.function_query must be a str")
        if not isinstance(self.func_def_types, set) or not self.func_def_types:
            issues.append(f"{type(self).__name__}.func_def_types must be a non-empty set")
        return issues

    # ── Convenience: tree-sitter Language / Parser construction ─────────

    def build_ts_language(self) -> Language:
        """Build a tree-sitter :class:`~tree_sitter.Language` for this language."""
        return Language(self._ts_module.language())

    def build_ts_parser(self) -> TSParser:
        """Build a tree-sitter :class:`~tree_sitter.Parser` for this language."""
        return TSParser(self.build_ts_language())
