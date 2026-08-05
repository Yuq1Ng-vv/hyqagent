"""cpg/languages/java.java — Java language adapter.

Implements :class:`LanguageProvider` for Java source code using the
tree-sitter-java grammar.
"""

from __future__ import annotations

from functools import cached_property
from typing import Any

from tree_sitter import Node

from hyqagent.cpg.languages.base import LanguageProvider
from hyqagent.cpg.types import ClassNode, FunctionNode, ImportNode

if __debug__:
    from tree_sitter import Tree


class JavaAdapter(LanguageProvider):
    """Language adapter for Java."""

    # ── Metadata ──────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "java"

    @property
    def extensions(self) -> list[str]:
        return [".java"]

    # ── Grammar (lazy) ────────────────────────────────────────────────

    @cached_property
    def _ts_module(self) -> Any:
        import tree_sitter_java as tsjava

        return tsjava

    # ── Queries ───────────────────────────────────────────────────────

    @property
    def function_query(self) -> str:
        return """
            (method_declaration
              name: (identifier) @func.name
              parameters: (formal_parameters) @func.params
            ) @function
            (constructor_declaration
              name: (identifier) @func.name
              parameters: (formal_parameters) @func.params
            ) @function
        """

    @property
    def class_query(self) -> str:
        return """
            (class_declaration
              name: (identifier) @class.name
            ) @class
        """

    @property
    def import_query(self) -> str:
        return """
            (import_declaration) @import
        """

    # ── Function name extraction ──────────────────────────────────────

    def extract_function_name(self, node: Node) -> str | None:
        name_node = node.child_by_field_name("name")
        if name_node is not None and name_node.text:
            return name_node.text.decode("utf-8")

        for child in node.children:
            if child.type == "identifier":
                return child.text.decode("utf-8") if child.text else None

        return None

    # ── Parameter extraction ──────────────────────────────────────────

    def extract_parameters(
        self, node: Node, captured_params: list[Node] | None = None
    ) -> list[str]:
        params_node = node.child_by_field_name("parameters")
        if params_node is None and captured_params:
            params_node = captured_params[0]
        if params_node is None:
            return []

        params: list[str] = []
        for child in params_node.children:
            if child.type in ("formal_parameter", "spread_parameter"):
                for sub in child.children:
                    if sub.type == "identifier":
                        params.append(sub.text.decode("utf-8") if sub.text else "")
                        break
        return params

    # ── Decorator extraction ──────────────────────────────────────────

    def extract_decorators(self, node: Node) -> list[str]:
        # Java uses annotations (not yet extracted)
        return []

    # ── Base class extraction ─────────────────────────────────────────

    def extract_base_classes(self, node: Node, tree: Tree) -> list[str]:
        bases: list[str] = []
        for child in node.children:
            if child.type == "superclass":
                for sub in child.children:
                    if sub.type in (
                        "identifier",
                        "type_identifier",
                        "scoped_identifier",
                    ):
                        bases.append(sub.text.decode("utf-8") if sub.text else "")
            if child.type == "super_interfaces":
                for sub in child.children:
                    if sub.type == "type_list":
                        for t in sub.children:
                            if t.type in ("type_identifier", "scoped_identifier"):
                                bases.append(t.text.decode("utf-8") if t.text else "")
        return bases

    # ── Import extraction ─────────────────────────────────────────────

    def build_import_node(self, node: Node, tree: Tree) -> ImportNode | None:
        if node.type != "import_declaration":
            return None

        source = node.text.decode("utf-8") if node.text else ""
        module = ""

        for child in node.children:
            if child.type in ("scoped_identifier", "identifier"):
                module = child.text.decode("utf-8") if child.text else ""

        return ImportNode(
            module=module,
            names=[module.split(".")[-1]] if module else [],
            start_line=node.start_point[0] + 1,
            source=source,
        )

    # ── Function node builder ─────────────────────────────────────────

    def build_function_node(
        self,
        node: Node,
        tree: Tree,
        name_nodes: list[Node] | None = None,
        param_nodes: list[Node] | None = None,
    ) -> FunctionNode | None:
        name_node = node.child_by_field_name("name")
        if name_node is None and name_nodes:
            name_node = name_nodes[0]
        if name_node is None:
            for child in node.children:
                if child.type == "identifier":
                    name_node = child
                    break
        if name_node is None:
            return None

        name = name_node.text.decode("utf-8") if name_node.text else ""
        params = self.extract_parameters(node, param_nodes)
        decorators: list[str] = []
        source = node.text.decode("utf-8") if node.text else ""

        func = FunctionNode(
            name=name,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            source=source,
            params=params,
            decorators=decorators,
        )

        parent = node.parent
        if parent is not None and parent.type == "class_body":
            grandparent = parent.parent
            if grandparent is not None and grandparent.type == "class_declaration":
                func.is_method = True
                cls_name_node = grandparent.child_by_field_name("name")
                if cls_name_node is not None:
                    func.class_name = (
                        cls_name_node.text.decode("utf-8") if cls_name_node.text else None
                    )

        return func

    # ── Class node builder ────────────────────────────────────────────

    def build_class_node(self, node: Node, tree: Tree) -> ClassNode | None:
        name_node = node.child_by_field_name("name")
        if name_node is None:
            for child in node.children:
                if child.type == "identifier":
                    name_node = child
                    break
        if name_node is None:
            return None

        name = name_node.text.decode("utf-8") if name_node.text else ""
        source = node.text.decode("utf-8") if node.text else ""
        bases = self.extract_base_classes(node, tree)
        decorators: list[str] = []

        return ClassNode(
            name=name,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            source=source,
            base_classes=bases,
            decorators=decorators,
        )

    # ── Call graph ────────────────────────────────────────────────────

    @property
    def call_node_type(self) -> str:
        return "method_invocation"

    @property
    def func_def_types(self) -> set[str]:
        return {"method_declaration", "constructor_declaration"}

    def extract_callee_info(self, node: Node) -> tuple[str, str, bool] | None:
        name_node = node.child_by_field_name("name")
        if name_node is None or not name_node.text:
            return None

        bare = name_node.text.decode("utf-8")
        full = node.text.decode("utf-8") if node.text else ""
        obj_node = node.child_by_field_name("object")
        return (bare, full, obj_node is not None)
