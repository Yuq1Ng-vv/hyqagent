"""cpg/languages/java.py — Java language adapter.

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
        """Extract Java annotation names from *node*.

        Java annotations live inside the ``modifiers`` node as either
        ``marker_annotation`` (no arguments, e.g. ``@Override``) or
        ``annotation`` (with arguments, e.g. ``@GetMapping("/path")``).
        Returns the full text of each annotation node.
        """
        decorators: list[str] = []
        for child in node.children:
            if child.type == "modifiers":
                for modifier in child.children:
                    if modifier.type in ("marker_annotation", "annotation"):
                        text = modifier.text.decode("utf-8") if modifier.text else ""
                        if text:
                            decorators.append(text)
                break  # Only the first modifiers block
        return decorators

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
        decorators = self.extract_decorators(node)
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
        decorators = self.extract_decorators(node)

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

    # ── Data flow ───────────────────────────────────────────────────────

    @property
    def assignment_types(self) -> set[str]:
        return {
            "assignment_expression",
            "local_variable_declaration",
            "enhanced_for_statement",
        }

    def extract_assignment_target(self, node: Node) -> str | None:
        """Extract variable name from Java assignment / declaration."""
        if node.type == "local_variable_declaration":
            # int x = 1; → declarator → name field
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    if name_node is not None and name_node.type == "identifier":
                        return name_node.text.decode("utf-8") if name_node.text else None
            return None

        if node.type == "enhanced_for_statement":
            # for (String s : list) → find the variable declarator
            for child in node.children:
                if child.type == "identifier" and child.is_named:
                    return child.text.decode("utf-8") if child.text else None
            return None

        # assignment_expression: x = 1;
        left = node.child_by_field_name("left")
        if left is None:
            # Try first named child
            named = [c for c in node.children if c.is_named]
            if named and named[0].type == "identifier":
                return named[0].text.decode("utf-8") if named[0].text else None
            return None
        if left.type == "identifier":
            return left.text.decode("utf-8") if left.text else None
        # Field access / array access: not a simple variable
        return None

    def is_variable_identifier(self, node: Node) -> bool:
        """Check whether an ``identifier`` node is a variable reference."""
        if node.type != "identifier":
            return False
        parent = node.parent
        if parent is None:
            return False

        # Method name in an invocation: foo.bar() → "bar" is method, not variable
        if parent.type == "method_invocation" and parent.child_by_field_name("name") is node:
            return False

        # Field access: obj.field
        if parent.type == "field_access":
            # Last named child is the field name
            named = [c for c in parent.children if c.is_named]
            if named and named[-1] is node:
                return False

        # Method / class declaration name
        return not (
            parent.type
            in (
                "method_declaration",
                "class_declaration",
                "constructor_declaration",
            )
            and parent.child_by_field_name("name") is node
        )

    # ── CFG ────────────────────────────────────────────────────────────

    @property
    def control_flow_node_types(self) -> set[str]:
        return {
            "if_statement",
            "for_statement",
            "enhanced_for_statement",
            "while_statement",
            "switch_expression",
            "try_statement",
            "try_with_resources_statement",
            "return_statement",
            "break_statement",
            "continue_statement",
            "throw_statement",
        }

    @property
    def statement_types(self) -> set[str]:
        return (
            self.control_flow_node_types
            | {
                "expression_statement",
                "local_variable_declaration",
                "assert_statement",
                "synchronized_statement",
                "class_declaration",
                "method_declaration",
                "constructor_declaration",
            }
        )

    def get_branch_targets(
        self, node: Node
    ) -> dict[str, Node | list[Node] | None]:
        ntype = node.type
        result: dict[str, Node | list[Node] | None] = {
            "consequence": None,
            "alternative": None,
            "body": None,
            "handlers": [],
            "finalizer": None,
        }

        if ntype == "if_statement":
            result["consequence"] = node.child_by_field_name("consequence")
            result["alternative"] = node.child_by_field_name("alternative")
        elif ntype == "switch_expression":
            result["body"] = node.child_by_field_name("body")
        elif ntype in ("try_statement", "try_with_resources_statement"):
            result["body"] = node.child_by_field_name("body")
            handlers: list[Node] = []
            for child in node.named_children:
                if child.type == "catch_clause":
                    handlers.append(child)
            result["handlers"] = handlers
            result["finalizer"] = node.child_by_field_name("finalizer")
        elif ntype in ("for_statement", "enhanced_for_statement",
                       "while_statement"):
            result["body"] = node.child_by_field_name("body")
        elif ntype in ("return_statement", "break_statement",
                       "continue_statement", "throw_statement"):
            pass  # Unconditional jumps

        return result
