"""cpg/traversal.py — AST traversal utilities using tree-sitter TreeCursor.

Provides DFS traversal with node-type filtering, subtree walking, and
navigation helpers (parent, ancestors, children). Language-agnostic —
works with any tree-sitter parse tree.

See DESIGN-IMPLEMENTATION.md Section 2.1 for context.
"""

from __future__ import annotations

from collections.abc import Iterator
from enum import Enum

from tree_sitter import Node, Tree, TreeCursor


class Order(Enum):
    """Traversal order."""

    PRE = "pre"
    POST = "post"


class Traverser:
    """Generic AST traverser using tree-sitter's TreeCursor.

    Language-agnostic — works with parse trees from any language.

    Usage::

        from hyqagent.cpg.parser import Parser
        from hyqagent.cpg.traversal import Traverser

        parser = Parser()
        tree = parser.parse_file("app.py")
        t = Traverser(tree)

        # Iterate function definitions only
        for node in t.traverse({"function_definition"}):
            print(node.type, node.start_point)

        # Find the first class
        cls = t.find_first("class_definition")

        # Get the enclosing function of a return statement
        ret = t.find_first("return_statement")
        func = t.ancestor_of_type(ret, "function_definition")
    """

    __slots__ = ("_tree",)

    def __init__(self, tree: Tree) -> None:
        self._tree = tree

    # ── Core traversal ──────────────────────────────────────────────────

    def traverse(
        self,
        node_types: set[str] | None = None,
        order: Order = Order.PRE,
        named_only: bool = False,
        root: Node | None = None,
    ) -> Iterator[Node]:
        """Iterate over nodes in DFS order, optionally filtered by type.

        Args:
            node_types: If set, only yield nodes whose ``.type`` is in this set.
            order: ``Order.PRE`` yields parent before children;
                   ``Order.POST`` yields children before parent.
            named_only: If True, skip anonymous nodes (punctuation,
                        keywords, etc.).  Anonymous nodes are CST
                        tokens like ``(``, ``:``, ``def``.
            root: If given, traverse only the subtree rooted at this
                  node.  Defaults to the tree's root node.

        Yields:
            tree-sitter ``Node`` objects in DFS order.

        """
        start = root or self._tree.root_node
        if order is Order.PRE:
            yield from self._walk_pre(start, node_types, named_only)
        else:
            yield from self._walk_post(start, node_types, named_only)

    # ── Search ──────────────────────────────────────────────────────────

    def find_first(
        self,
        node_type: str,
        named_only: bool = False,
        root: Node | None = None,
    ) -> Node | None:
        """Return the first node whose ``.type`` is *node_type*, or None.

        This is equivalent to ``next(traverse({node_type}), None)`` but
        implemented with early termination for efficiency.
        """
        for node in self.traverse({node_type}, named_only=named_only, root=root):
            return node
        return None

    def find_all(
        self,
        node_type: str,
        named_only: bool = False,
        root: Node | None = None,
    ) -> list[Node]:
        """Return all nodes whose ``.type`` is *node_type*."""
        return list(self.traverse({node_type}, named_only=named_only, root=root))

    # ── Navigation ──────────────────────────────────────────────────────

    @staticmethod
    def get_children(node: Node, named_only: bool = True) -> list[Node]:
        """Return the direct children of *node*.

        Args:
            node: The parent node.
            named_only: If True (default), return named children only
                        (excludes CST tokens like punctuation).

        """
        return list(node.named_children if named_only else node.children)

    @staticmethod
    def get_parent(node: Node) -> Node | None:
        """Return the parent of *node*, or None if *node* is the root."""
        return node.parent

    @staticmethod
    def get_ancestors(node: Node) -> Iterator[Node]:
        """Iterate over ancestors from immediate parent up to the root."""
        current = node.parent
        while current is not None:
            yield current
            current = current.parent

    @classmethod
    def ancestor_of_type(cls, node: Node, node_type: str) -> Node | None:
        """Return the nearest ancestor whose ``.type`` is *node_type*.

        Returns None if no such ancestor exists. This is the typical
        pattern for answering "what function/class contains this node?".
        """
        for ancestor in cls.get_ancestors(node):
            if ancestor.type == node_type:
                return ancestor
        return None

    # ── Utility ─────────────────────────────────────────────────────────

    @staticmethod
    def node_type_path(node: Node) -> str:
        """Return a dotted path of node types from the root to *node*.

        Example::

            >>> t.node_type_path(return_node)
            'module.function_definition.block.return_statement'
        """
        parts: list[str] = []
        current: Node | None = node
        while current is not None:
            parts.append(current.type)
            current = current.parent
        parts.reverse()
        return ".".join(parts)

    def count(
        self,
        node_type: str | None = None,
        named_only: bool = False,
        root: Node | None = None,
    ) -> int:
        """Return the total number of nodes, optionally filtered by type.

        Args:
            node_type: If given, count only nodes of this type.
            named_only: If True, skip anonymous nodes.
            root: If given, count only within this subtree.

        """
        types: set[str] | None = {node_type} if node_type else None
        return sum(1 for _ in self.traverse(types, named_only=named_only, root=root))

    # ── Properties ──────────────────────────────────────────────────────

    @property
    def root(self) -> Node:
        """The root node of the tree."""
        return self._tree.root_node

    # ── Internal: pre-order DFS (cursor-based) ──────────────────────────

    @staticmethod
    def _walk_pre(
        start: Node,
        node_types: set[str] | None,
        named_only: bool,
    ) -> Iterator[Node]:
        """Pre-order DFS using a TreeCursor — efficient and stack-safe."""
        cursor: TreeCursor = start.walk()
        reached_end = False

        while not reached_end:
            node = cursor.node
            if node is None:  # pragma: no cover — cursor always has a node
                raise RuntimeError("TreeCursor returned None node")
            if Traverser._accept(node, node_types, named_only):
                yield node

            if cursor.goto_first_child():
                continue
            if cursor.goto_next_sibling():
                continue

            # Backtrack to find the next unvisited sibling
            while True:
                if not cursor.goto_parent():
                    reached_end = True
                    break
                if cursor.goto_next_sibling():
                    break

    # ── Internal: post-order DFS (iterative stack, avoids recursion) ────

    @staticmethod
    def _walk_post(
        start: Node,
        node_types: set[str] | None,
        named_only: bool,
    ) -> Iterator[Node]:
        """Post-order DFS using an explicit stack.

        Each stack entry is ``(node, children_processed)``.  When
        *children_processed* is False we push the node back with
        True and push its children; when True we yield the node.
        """
        stack: list[tuple[Node, bool]] = [(start, False)]

        while stack:
            node, processed = stack.pop()
            if processed:
                if Traverser._accept(node, node_types, named_only):
                    yield node
            else:
                stack.append((node, True))
                # Push children in reverse so they're processed
                # left-to-right (first child yielded first).
                for child in reversed(node.children):
                    stack.append((child, False))

    # ── Internal helpers ────────────────────────────────────────────────

    @staticmethod
    def _accept(node: Node, node_types: set[str] | None, named_only: bool) -> bool:
        """Return True if *node* passes the filter criteria."""
        return (not named_only or node.is_named) and (node_types is None or node.type in node_types)
