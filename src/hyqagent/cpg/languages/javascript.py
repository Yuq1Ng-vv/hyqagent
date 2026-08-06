"""cpg/languages/javascript.py — JavaScript language adapter.

Implements :class:`LanguageProvider` for JavaScript / ECMAScript source
code using the tree-sitter-javascript grammar.
"""

from __future__ import annotations

from functools import cached_property
from typing import Any

from tree_sitter import Node

from hyqagent.cpg.languages.base import LanguageProvider
from hyqagent.cpg.types import ClassNode, FunctionNode, ImportNode

if __debug__:
    from tree_sitter import Tree


class JavaScriptAdapter(LanguageProvider):
    """Language adapter for JavaScript / ECMAScript."""

    # ── Metadata ──────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "javascript"

    @property
    def extensions(self) -> list[str]:
        return [".js", ".jsx", ".mjs", ".cjs"]

    # ── Grammar (lazy) ────────────────────────────────────────────────

    @cached_property
    def _ts_module(self) -> Any:
        import tree_sitter_javascript as tsjs

        return tsjs

    # ── Queries ───────────────────────────────────────────────────────

    @property
    def function_query(self) -> str:
        return """
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
            (import_statement) @import
        """

    # ── Function name extraction ──────────────────────────────────────

    def extract_function_name(self, node: Node) -> str | None:
        name_node = node.child_by_field_name("name")
        if name_node is not None and name_node.text:
            return name_node.text.decode("utf-8")

        # Fallback for constructors and arrow functions
        for child in node.children:
            if child.type in ("identifier", "property_identifier"):
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
            if child.type == "identifier":
                params.append(child.text.decode("utf-8") if child.text else "")
            elif child.type in (
                "formal_parameter",
                "required_parameter",
                "optional_parameter",
                "rest_parameter",
            ):
                for sub in child.children:
                    if sub.type == "identifier":
                        params.append(sub.text.decode("utf-8") if sub.text else "")
                    elif sub.type == "object_pattern":
                        for p in sub.children:
                            if p.type == "shorthand_property_identifier_pattern":
                                params.append(p.text.decode("utf-8") if p.text else "")
        return params

    # ── Decorator extraction ──────────────────────────────────────────

    def extract_decorators(self, node: Node) -> list[str]:
        # JavaScript does not have decorators in the standard grammar
        return []

    # ── Base class extraction ─────────────────────────────────────────

    def extract_base_classes(self, node: Node, tree: Tree) -> list[str]:
        bases: list[str] = []
        for child in node.children:
            if child.type == "class_heritage":
                for sub in child.children:
                    if sub.type in (
                        "identifier",
                        "member_expression",
                        "call_expression",
                    ):
                        bases.append(sub.text.decode("utf-8") if sub.text else "")
        return bases

    # ── Import extraction ─────────────────────────────────────────────

    def build_import_node(self, node: Node, tree: Tree) -> ImportNode | None:
        if node.type != "import_statement":
            return None

        source = node.text.decode("utf-8") if node.text else ""
        module = ""
        names: list[str] = []

        for child in node.children:
            if child.type == "string":
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
            start_line=node.start_point[0] + 1,
            is_relative=module.startswith(".") if module else False,
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
                if child.type in ("identifier", "property_identifier"):
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
        return "call_expression"

    @property
    def func_def_types(self) -> set[str]:
        return {
            "function_declaration",
            "method_definition",
            "arrow_function",
        }

    def extract_callee_info(self, node: Node) -> tuple[str, str, bool] | None:
        func_expr = node.child_by_field_name("function")
        if func_expr is None:
            return None

        full = func_expr.text.decode("utf-8") if func_expr.text else ""

        if func_expr.type == "identifier":
            return (full, full, False)

        if func_expr.type == "member_expression":
            prop = func_expr.child_by_field_name("property")
            if prop is not None and prop.text:
                bare = prop.text.decode("utf-8")
                return (bare, full, True)
            # Fallback: last named child
            named = [c for c in func_expr.children if c.is_named]
            if named:
                last = named[-1]
                bare = last.text.decode("utf-8") if last.text else ""
                return (bare, full, True)

        return (full, full, False)

    # ── Data flow ───────────────────────────────────────────────────────

    @property
    def assignment_types(self) -> set[str]:
        return {
            "assignment_expression",
            "augmented_assignment_expression",
            "variable_declarator",
        }

    def extract_assignment_target(self, node: Node) -> str | None:
        """Extract variable name from JavaScript assignment."""
        if node.type == "variable_declarator":
            # let x = 1 → name field is the identifier
            name_node = node.child_by_field_name("name")
            if name_node is not None and name_node.type == "identifier":
                return name_node.text.decode("utf-8") if name_node.text else None
            # Destructuring: not a simple variable
            return None

        # assignment_expression / augmented_assignment_expression
        left = node.child_by_field_name("left")
        if left is None:
            return None
        if left.type == "identifier":
            return left.text.decode("utf-8") if left.text else None
        # Member expression / destructuring: not a simple variable
        return None

    def is_variable_identifier(self, node: Node) -> bool:
        """Check whether an ``identifier`` node is a variable reference."""
        if node.type != "identifier":
            return False
        parent = node.parent
        if parent is None:
            return False

        # Function name in a call: foo(x) → "foo" is not a variable
        if parent.type == "call_expression" and parent.child_by_field_name("function") is node:
            return False

        # Property name in member expression: obj.prop → "prop" is not a variable
        if parent.type == "member_expression" and parent.child_by_field_name("property") is node:
            return False

        # Function / class definition name
        return not (
            parent.type
            in (
                "function_declaration",
                "class_declaration",
                "method_definition",
            )
            and parent.child_by_field_name("name") is node
        )
