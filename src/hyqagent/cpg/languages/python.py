"""cpg/languages/python.py — Python language adapter.

Implements :class:`LanguageProvider` for Python 3.x source code using the
tree-sitter-python grammar.
"""

from __future__ import annotations

from functools import cached_property
from typing import Any

from tree_sitter import Node

from hyqagent.cpg.languages.base import LanguageProvider
from hyqagent.cpg.types import ClassNode, FunctionNode, ImportNode

if __debug__:
    from tree_sitter import Tree


class PythonAdapter(LanguageProvider):
    """Language adapter for Python."""

    # ── Metadata ──────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "python"

    @property
    def extensions(self) -> list[str]:
        return [".py", ".pyi"]

    # ── Grammar (lazy) ────────────────────────────────────────────────

    @cached_property
    def _ts_module(self) -> Any:
        import tree_sitter_python as tspy

        return tspy

    # ── Queries ───────────────────────────────────────────────────────

    @property
    def function_query(self) -> str:
        return """
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
        """

    @property
    def class_query(self) -> str:
        return """
            (class_definition
              name: (identifier) @class.name
            ) @class
            (decorated_definition
              (class_definition
                name: (identifier) @class.name
              ) @class
            )
        """

    @property
    def import_query(self) -> str:
        return """
            (import_statement) @import
            (import_from_statement) @import
        """

    # ── Function name extraction ──────────────────────────────────────

    def extract_function_name(self, node: Node) -> str | None:
        """Unwrap ``decorated_definition``, then find the name identifier."""
        target = node

        if target.type == "decorated_definition":
            for child in target.named_children:
                if child.type == "function_definition":
                    target = child
                    break
            else:
                return None

        name_node = target.child_by_field_name("name")
        if name_node is not None and name_node.text:
            return name_node.text.decode("utf-8")

        for child in target.children:
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
            if child.type == "identifier":
                text = child.text.decode("utf-8") if child.text else ""
                if text != "self":
                    params.append(text)
            elif child.type in (
                "typed_parameter",
                "typed_default_parameter",
                "default_parameter",
            ):
                # First named child is typically the identifier
                for sub in child.children:
                    if sub.type == "identifier" and sub.is_named:
                        text = sub.text.decode("utf-8") if sub.text else ""
                        if text != "self":
                            params.append(text)
                        break
                else:
                    # Some typed parameters have the identifier as the last named child
                    named = [c for c in child.children if c.is_named]
                    if named:
                        text = named[-1].text.decode("utf-8") if named[-1].text else ""
                        if text != "self":
                            params.append(text)
            elif child.type in ("list_splat_pattern", "dict_splat_pattern"):
                for sub in child.children:
                    if sub.type == "identifier":
                        params.append(sub.text.decode("utf-8") if sub.text else "")

        return params

    # ── Decorator extraction ──────────────────────────────────────────

    def extract_decorators(self, node: Node) -> list[str]:
        decorators: list[str] = []
        for child in node.children:
            if child.type == "decorator":
                decorators.append(child.text.decode("utf-8") if child.text else "")
        return decorators

    # ── Base class extraction ─────────────────────────────────────────

    def extract_base_classes(self, node: Node, tree: Tree) -> list[str]:
        bases: list[str] = []
        for child in node.children:
            if child.type == "argument_list":
                for sub in child.children:
                    if sub.type in ("identifier", "attribute"):
                        bases.append(sub.text.decode("utf-8") if sub.text else "")
        return bases

    # ── Import extraction ─────────────────────────────────────────────

    def build_import_node(self, node: Node, tree: Tree) -> ImportNode | None:
        if node.type not in ("import_statement", "import_from_statement"):
            return None

        if node.type == "import_statement":
            return self._build_simple_import(node)
        return self._build_from_import(node)

    @staticmethod
    def _build_simple_import(node: Node) -> ImportNode:
        source = node.text.decode("utf-8") if node.text else ""
        module = ""
        names: list[str] = []

        for child in node.children:
            if child.type == "dotted_name":
                name = child.text.decode("utf-8") if child.text else ""
                if not module:
                    module = name
                names.append(name)
            elif child.type == "aliased_import":
                for sub in child.children:
                    if sub.type == "dotted_name":
                        name = sub.text.decode("utf-8") if sub.text else ""
                        if not module:
                            module = name
                        names.append(name)

        return ImportNode(
            module=module,
            names=names,
            start_line=node.start_point[0] + 1,
            source=source,
        )

    @staticmethod
    def _build_from_import(node: Node) -> ImportNode:
        source = node.text.decode("utf-8") if node.text else ""
        module = ""
        names: list[str] = []
        is_relative = False
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
                for sub in child.children:
                    if sub.type == "dotted_name":
                        names.append(sub.text.decode("utf-8") if sub.text else "")
            elif child.type == "wildcard_import":
                names.append("*")

        return ImportNode(
            module=module,
            names=names,
            start_line=node.start_point[0] + 1,
            is_relative=is_relative,
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

        # Decorators: check both the node itself and its parent
        decorators = self.extract_decorators(node)
        parent = node.parent
        if parent is not None and parent.type == "decorated_definition":
            decorators = self.extract_decorators(parent)

        source = node.text.decode("utf-8") if node.text else ""

        func = FunctionNode(
            name=name,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            source=source,
            params=params,
            decorators=decorators,
        )

        # Detect method: parent is block inside a class body
        if parent is not None and parent.type == "block":
            grandparent = parent.parent
            if grandparent is not None and grandparent.type in (
                "class_definition",
                "class_declaration",
            ):
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
    def call_node_type(self) -> set[str]:
        return {"call"}

    @property
    def func_def_types(self) -> set[str]:
        return {"function_definition", "decorated_definition"}

    def extract_callee_info(self, node: Node) -> tuple[str, str, bool] | None:
        func_expr = node.child_by_field_name("function")
        if func_expr is None:
            return None

        full = func_expr.text.decode("utf-8") if func_expr.text else ""

        if func_expr.type == "identifier":
            return (full, full, False)

        if func_expr.type == "attribute":
            named = [c for c in func_expr.children if c.is_named]
            if named:
                last = named[-1]
                bare = last.text.decode("utf-8") if last.text else ""
                return (bare, full, True)

        # Catch-all for nested calls like ``foo()()``
        return (full, full, False)

    # ── Data flow ───────────────────────────────────────────────────────

    @property
    def assignment_types(self) -> set[str]:
        return {"assignment", "augmented_assignment", "named_expression"}

    def extract_assignment_target(self, node: Node) -> str | None:
        """Extract variable name from Python assignment LHS.

        Handles ``x = ...``, ``x += ...``, ``x := ...``, and simple
        single-target patterns.  Returns ``None`` for multi-target
        assignments (``a, b = ...``) and complex targets.
        """
        if node.type == "named_expression":
            # walrus: name := value → find the identifier on the left
            for child in node.children:
                if child.type == "identifier" and child.is_named:
                    return child.text.decode("utf-8") if child.text else None
            return None

        # assignment / augmented_assignment: left child is the target
        left = node.child_by_field_name("left")
        if left is None:
            # Try first named child
            named = [c for c in node.children if c.is_named]
            if named:
                left = named[0]

        if left is None:
            return None

        if left.type == "identifier":
            return left.text.decode("utf-8") if left.text else None

        # Multi-target / tuple-unpacking: too complex for single name
        if left.type in ("pattern_list", "tuple_pattern"):
            return None

        # Subscript / attribute: e.g. obj.attr = ... → not a simple variable
        if left.type in ("attribute", "subscript"):
            return None

        return None

    def is_variable_identifier(self, node: Node) -> bool:
        """Check whether an ``identifier`` node is a variable reference.

        Returns ``False`` for:
        * Function names in call expressions (the ``print`` in ``print(x)``)
        * Attribute names (the ``attr`` in ``obj.attr``)
        * Definition names (function / class names)
        """
        if node.type != "identifier":
            return False
        parent = node.parent
        if parent is None:
            return False

        # Function name in a call: print(x) → "print" is not a variable
        if parent.type == "call" and parent.child_by_field_name("function") is node:
            return False

        # Attribute name: obj.attr → "attr" is not a variable reference
        if parent.type == "attribute":
            # The last named child of an attribute is the attribute name
            named = [c for c in parent.children if c.is_named]
            if named and named[-1] is node:
                return False

        # Function / class definition name
        return not (
            parent.type
            in (
                "function_definition",
                "class_definition",
                "decorated_definition",
            )
            and parent.child_by_field_name("name") is node
        )

    # ── CFG ────────────────────────────────────────────────────────────

    @property
    def control_flow_node_types(self) -> set[str]:
        return {
            "if_statement",
            "for_statement",
            "while_statement",
            "try_statement",
            "return_statement",
            "break_statement",
            "continue_statement",
            "raise_statement",
        }

    @property
    def statement_types(self) -> set[str]:
        return self.control_flow_node_types | {
            "expression_statement",
            "assert_statement",
            "pass_statement",
            "import_statement",
            "import_from_statement",
            "function_definition",
            "class_definition",
            "decorated_definition",
        }

    def get_branch_targets(self, node: Node) -> dict[str, Node | list[Node] | None]:
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
        elif ntype in ("for_statement", "while_statement"):
            result["body"] = node.child_by_field_name("body")
            result["alternative"] = node.child_by_field_name("alternative")  # else clause
        elif ntype == "try_statement":
            result["body"] = node.child_by_field_name("body")
            # Collect except_clause children as handlers
            handlers: list[Node] = []
            for child in node.named_children:
                if child.type in ("except_clause", "except_group_clause"):
                    handlers.append(child)
            result["handlers"] = handlers
            result["finalizer"] = node.child_by_field_name("finalizer")
        elif ntype in (
            "return_statement",
            "break_statement",
            "continue_statement",
            "raise_statement",
        ):
            pass  # Unconditional jumps — no branch targets

        return result
