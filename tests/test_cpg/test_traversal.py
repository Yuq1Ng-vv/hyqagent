"""tests/test_cpg/test_traversal.py — Tests for cpg/traversal.py.

Covers DFS pre/post-order, node-type filtering, named-only filtering,
subtree walk, find/search, navigation (children/parent/ancestors),
and utility methods across Python, JavaScript, and Java.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tree_sitter import Node, Tree

from hyqagent.cpg.parser import Parser
from hyqagent.cpg.traversal import Order, Traverser

FIXTURES = Path(__file__).parent / "fixtures"


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


@pytest.fixture(scope="module")
def py_tree(parser: Parser) -> Tree:
    return parser.parse_file(FIXTURES / "sample.py")


@pytest.fixture(scope="module")
def py_traverser(py_tree: Tree) -> Traverser:
    return Traverser(py_tree)


@pytest.fixture(scope="module")
def js_tree(parser: Parser) -> Tree:
    return parser.parse_file(FIXTURES / "sample.js")


@pytest.fixture(scope="module")
def js_traverser(js_tree: Tree) -> Traverser:
    return Traverser(js_tree)


@pytest.fixture(scope="module")
def java_tree(parser: Parser) -> Tree:
    return parser.parse_file(FIXTURES / "sample.java")


@pytest.fixture(scope="module")
def java_traverser(java_tree: Tree) -> Traverser:
    return Traverser(java_tree)


# ── Construction ────────────────────────────────────────────────────────────


class TestConstruction:
    def test_creates_with_tree(self, py_tree: Tree) -> None:
        t = Traverser(py_tree)
        assert t.root is not None
        assert t.root.type == "module"

    def test_root_property(self, py_traverser: Traverser) -> None:
        assert py_traverser.root.type == "module"


# ── traverse — pre-order (default) ──────────────────────────────────────────


class TestTraversePreOrder:
    def test_yields_root_first(self, py_traverser: Traverser) -> None:
        nodes = list(py_traverser.traverse())
        assert len(nodes) > 0
        assert nodes[0].type == "module"

    def test_children_before_siblings(self, py_traverser: Traverser) -> None:
        """In pre-order, after a node, its first child should appear before its sibling."""
        nodes = list(py_traverser.traverse())
        # Find the first import_statement and verify its children appear next
        import_idx = next(i for i, n in enumerate(nodes) if n.type == "import_statement")
        # import_statement's first child should be next or very close
        import_node = nodes[import_idx]
        first_child = import_node.named_children[0] if import_node.named_children else None
        if first_child is not None:
            # The first child should appear soon after (within the import's subtree)
            found_child = False
            for offset in range(1, min(20, len(nodes) - import_idx)):
                if nodes[import_idx + offset].id == first_child.id:
                    found_child = True
                    break
            assert found_child, "First child of import_statement not found nearby in pre-order"

    def test_visits_all_nodes(self, py_traverser: Traverser) -> None:
        nodes = list(py_traverser.traverse())
        # sample.py has dozens of nodes
        assert len(nodes) > 30

    def test_js_traversal(self, js_traverser: Traverser) -> None:
        nodes = list(js_traverser.traverse())
        assert len(nodes) > 0
        assert nodes[0].type == "program"
        # Should find function_declaration and class_declaration
        types = {n.type for n in nodes}
        assert "function_declaration" in types
        assert "class_declaration" in types

    def test_java_traversal(self, java_traverser: Traverser) -> None:
        nodes = list(java_traverser.traverse())
        assert len(nodes) > 0
        assert nodes[0].type == "program"
        types = {n.type for n in nodes}
        assert "method_declaration" in types
        assert "class_declaration" in types


# ── traverse — node type filtering ─────────────────────────────────────────


class TestTraverseTypeFilter:
    def test_single_type_python(self, py_traverser: Traverser) -> None:
        nodes = list(py_traverser.traverse({"function_definition"}))
        # sample.py has: login, __init__, get_user, list_users, delete_all
        assert len(nodes) == 5
        for n in nodes:
            assert n.type == "function_definition"

    def test_multiple_types(self, py_traverser: Traverser) -> None:
        nodes = list(
            py_traverser.traverse({"function_definition", "class_definition"})
        )
        types = {n.type for n in nodes}
        assert types <= {"function_definition", "class_definition"}
        # 5 functions + 2 classes = 7 in sample.py
        assert len(nodes) == 7

    def test_empty_set_yields_nothing(self, py_traverser: Traverser) -> None:
        nodes = list(py_traverser.traverse(set()))
        assert nodes == []

    def test_js_type_filter(self, js_traverser: Traverser) -> None:
        nodes = list(js_traverser.traverse({"function_declaration"}))
        assert len(nodes) >= 2  # getUser, createUser
        for n in nodes:
            assert n.type == "function_declaration"

    def test_java_type_filter(self, java_traverser: Traverser) -> None:
        nodes = list(java_traverser.traverse({"method_declaration"}))
        # getUser, listUsers, validate
        assert len(nodes) >= 3
        for n in nodes:
            assert n.type == "method_declaration"


# ── traverse — named_only ───────────────────────────────────────────────────


class TestTraverseNamedOnly:
    def test_named_only_fewer_nodes(self, py_traverser: Traverser) -> None:
        all_nodes = list(py_traverser.traverse())
        named_nodes = list(py_traverser.traverse(named_only=True))
        # named_only should yield strictly fewer nodes
        assert len(named_nodes) < len(all_nodes)
        # But still plenty
        assert len(named_nodes) > 10

    def test_named_only_all_are_named(self, py_traverser: Traverser) -> None:
        named_nodes = list(py_traverser.traverse(named_only=True))
        for n in named_nodes:
            assert n.is_named, f"Node type={n.type!r} should be named"

    def test_named_only_with_type_filter(self, py_traverser: Traverser) -> None:
        # function_definition is always a named node
        nodes = list(
            py_traverser.traverse({"function_definition"}, named_only=True)
        )
        assert len(nodes) == 5
        for n in nodes:
            assert n.type == "function_definition"
            assert n.is_named


# ── traverse — post-order ───────────────────────────────────────────────────


class TestTraversePostOrder:
    def test_parent_after_children(self, py_traverser: Traverser) -> None:
        """In post-order, every parent node appears after all its children."""
        nodes = list(py_traverser.traverse(order=Order.POST))
        position: dict[int, int] = {n.id: i for i, n in enumerate(nodes)}
        for node in nodes:
            for child in node.named_children:
                if child.id in position:
                    assert (
                        position[child.id] < position[node.id]
                    ), (
                        f"In post-order, child {child.type!r} should appear "
                        f"before parent {node.type!r}"
                    )

    def test_root_is_last(self, py_traverser: Traverser) -> None:
        nodes = list(py_traverser.traverse(order=Order.POST))
        assert nodes[-1].type == "module"

    def test_different_from_pre_order(self, py_traverser: Traverser) -> None:
        pre = [n.id for n in py_traverser.traverse(order=Order.PRE)]
        post = [n.id for n in py_traverser.traverse(order=Order.POST)]
        # They should have the same nodes but in different order
        assert set(pre) == set(post)
        assert pre != post

    def test_post_order_with_type_filter(self, py_traverser: Traverser) -> None:
        nodes = list(
            py_traverser.traverse({"return_statement"}, order=Order.POST)
        )
        for n in nodes:
            assert n.type == "return_statement"


# ── traverse — subtree ──────────────────────────────────────────────────────


class TestTraverseSubtree:
    def test_subtree_from_function(self, py_traverser: Traverser) -> None:
        func = py_traverser.find_first("function_definition")
        assert func is not None
        subtree_nodes = list(py_traverser.traverse(root=func))
        # All nodes should be descendants of func
        for n in subtree_nodes:
            assert n.id == func.id or _is_descendant(n, func)
        assert len(subtree_nodes) > 0

    def test_subtree_starts_at_root(self, py_traverser: Traverser) -> None:
        """Subtree from a leaf node should just yield that node."""
        # Find a leaf node: the 'pass' keyword inside delete_all
        pass_node = py_traverser.find_first("pass")
        if pass_node is None:
            # Try an identifier instead
            pass_node = py_traverser.find_first("identifier")
        assert pass_node is not None
        sub = list(py_traverser.traverse(root=pass_node))
        assert len(sub) >= 1
        assert sub[0].id == pass_node.id

    def test_subtree_filtered(self, py_traverser: Traverser) -> None:
        func = py_traverser.find_first("function_definition")
        assert func is not None
        ids = list(py_traverser.traverse({"identifier"}, root=func))
        for n in ids:
            assert n.type == "identifier"


# ── find_first / find_all ───────────────────────────────────────────────────


class TestFindFirst:
    def test_finds_function(self, py_traverser: Traverser) -> None:
        node = py_traverser.find_first("function_definition")
        assert node is not None
        assert node.type == "function_definition"

    def test_returns_none_for_absent(self, py_traverser: Traverser) -> None:
        node = py_traverser.find_first("nonexistent_type_xyz")
        assert node is None

    def test_find_in_subtree(self, py_traverser: Traverser) -> None:
        func = py_traverser.find_first("function_definition")
        assert func is not None
        ret = py_traverser.find_first("return_statement", root=func)
        assert ret is not None
        assert ret.type == "return_statement"
        assert _is_descendant(ret, func)

    def test_js_find(self, js_traverser: Traverser) -> None:
        cls = js_traverser.find_first("class_declaration")
        assert cls is not None
        assert cls.type == "class_declaration"

    def test_java_find(self, java_traverser: Traverser) -> None:
        method = java_traverser.find_first("method_declaration")
        assert method is not None
        assert method.type == "method_declaration"


class TestFindAll:
    def test_all_identifiers(self, py_traverser: Traverser) -> None:
        ids = py_traverser.find_all("identifier")
        assert len(ids) > 5
        for n in ids:
            assert n.type == "identifier"

    def test_empty_for_absent(self, py_traverser: Traverser) -> None:
        assert py_traverser.find_all("nonexistent_type_xyz") == []

    def test_match_with_traverse(self, py_traverser: Traverser) -> None:
        """find_all should equal traverse with the same filter."""
        found = py_traverser.find_all("string")
        via_traverse = list(py_traverser.traverse({"string"}))
        assert len(found) == len(via_traverse)
        assert [n.id for n in found] == [n.id for n in via_traverse]


# ── get_children ────────────────────────────────────────────────────────────


class TestGetChildren:
    def test_named_children_of_function(self, py_traverser: Traverser) -> None:
        func = py_traverser.find_first("function_definition")
        assert func is not None
        children = Traverser.get_children(func)
        assert len(children) > 0
        # Should include the 'def' keyword node, identifier, parameters, body
        child_types = {c.type for c in children}
        assert "identifier" in child_types
        assert "parameters" in child_types

    def test_all_children_includes_anonymous(self, py_traverser: Traverser) -> None:
        func = py_traverser.find_first("function_definition")
        assert func is not None
        named = Traverser.get_children(func, named_only=True)
        all_children = Traverser.get_children(func, named_only=False)
        # There should be more children when including anonymous
        assert len(all_children) >= len(named)

    def test_no_children_of_leaf(self, py_traverser: Traverser) -> None:
        """A 'pass' keyword node has no named children (true leaf)."""
        pass_nodes = py_traverser.find_all("pass")
        if pass_nodes:
            assert Traverser.get_children(pass_nodes[0]) == []


# ── get_parent / get_ancestors ──────────────────────────────────────────────


class TestGetParent:
    def test_parent_of_child(self, py_traverser: Traverser) -> None:
        func = py_traverser.find_first("function_definition")
        assert func is not None
        ident = py_traverser.find_first("identifier", root=func)
        if ident is not None:
            parent = Traverser.get_parent(ident)
            assert parent is not None

    def test_root_has_no_parent(self, py_traverser: Traverser) -> None:
        assert Traverser.get_parent(py_traverser.root) is None


class TestGetAncestors:
    def test_ancestors_chain(self, py_traverser: Traverser) -> None:
        """Ancestors of a return_statement should include block and function_definition."""
        ret = py_traverser.find_first("return_statement")
        assert ret is not None
        ancestors = list(Traverser.get_ancestors(ret))
        ancestor_types = {a.type for a in ancestors}
        assert len(ancestors) > 0
        # return_statement is inside a block, which is inside function_definition
        assert "block" in ancestor_types
        assert "function_definition" in ancestor_types

    def test_root_has_no_ancestors(self, py_traverser: Traverser) -> None:
        assert list(Traverser.get_ancestors(py_traverser.root)) == []


# ── ancestor_of_type ────────────────────────────────────────────────────────


class TestAncestorOfType:
    def test_find_enclosing_function(self, py_traverser: Traverser) -> None:
        ret = py_traverser.find_first("return_statement")
        assert ret is not None
        func = Traverser.ancestor_of_type(ret, "function_definition")
        assert func is not None
        assert func.type == "function_definition"

    def test_find_enclosing_class(self, py_traverser: Traverser) -> None:
        # The __init__ method is inside UserService class
        funcs = py_traverser.find_all("function_definition")
        init_func = None
        for f in funcs:
            ident = py_traverser.find_first("identifier", root=f)
            if ident is not None and ident.text and ident.text.decode("utf-8") == "__init__":
                init_func = f
                break
        if init_func is not None:
            cls = Traverser.ancestor_of_type(init_func, "class_definition")
            assert cls is not None
            assert cls.type == "class_definition"

    def test_returns_none_when_no_match(self, py_traverser: Traverser) -> None:
        ident = py_traverser.find_first("identifier")
        assert ident is not None
        result = Traverser.ancestor_of_type(ident, "nonexistent_xyz")
        assert result is None

    def test_js_enclosing_class(self, js_traverser: Traverser) -> None:
        # Find a method inside class and verify ancestor is class_declaration
        methods = js_traverser.find_all("method_definition")
        method_in_class = None
        for m in methods:
            cls = Traverser.ancestor_of_type(m, "class_declaration")
            if cls is not None:
                method_in_class = m
                break
        if method_in_class is not None:
            cls = Traverser.ancestor_of_type(method_in_class, "class_declaration")
            assert cls is not None
            assert cls.type == "class_declaration"


# ── node_type_path ──────────────────────────────────────────────────────────


class TestNodeTypePath:
    def test_format_is_dotted(self, py_traverser: Traverser) -> None:
        path = Traverser.node_type_path(py_traverser.root)
        assert path == "module"

    def test_path_ends_with_own_type(self, py_traverser: Traverser) -> None:
        func = py_traverser.find_first("function_definition")
        assert func is not None
        path = Traverser.node_type_path(func)
        assert path.endswith(".function_definition")

    def test_path_starts_with_module(self, py_traverser: Traverser) -> None:
        ident = py_traverser.find_first("identifier")
        assert ident is not None
        path = Traverser.node_type_path(ident)
        assert path.startswith("module")


# ── count ───────────────────────────────────────────────────────────────────


class TestCount:
    def test_total_count_positive(self, py_traverser: Traverser) -> None:
        assert py_traverser.count() > 0

    def test_filtered_count(self, py_traverser: Traverser) -> None:
        n = py_traverser.count("function_definition")
        assert n == 5

    def test_named_count(self, py_traverser: Traverser) -> None:
        total = py_traverser.count()
        named = py_traverser.count(named_only=True)
        assert named < total
        assert named > 0

    def test_count_subtree(self, py_traverser: Traverser) -> None:
        func = py_traverser.find_first("function_definition")
        assert func is not None
        subtree_count = py_traverser.count(root=func)
        total_count = py_traverser.count()
        assert subtree_count < total_count
        assert subtree_count > 0

    def test_js_count(self, js_traverser: Traverser) -> None:
        assert js_traverser.count() > 0
        assert js_traverser.count("function_declaration") >= 2

    def test_java_count(self, java_traverser: Traverser) -> None:
        assert java_traverser.count() > 0
        assert java_traverser.count("method_declaration") >= 3


# ── Edge cases ──────────────────────────────────────────────────────────────


class TestEdgeCases:
    @classmethod
    @pytest.fixture(scope="class")
    def empty_parser(cls) -> Parser:
        return Parser()

    def test_empty_file(self, empty_parser: Parser) -> None:
        tree = empty_parser.parse_code("", "python")
        t = Traverser(tree)
        nodes = list(t.traverse())
        # Even an empty file has a module node
        assert len(nodes) == 1
        assert nodes[0].type == "module"

    def test_simple_code(self, empty_parser: Parser) -> None:
        tree = empty_parser.parse_code("x = 1", "python")
        t = Traverser(tree)
        nodes = list(t.traverse())
        assert len(nodes) > 1
        assert nodes[0].type == "module"

    def test_syntax_error_code(self, empty_parser: Parser) -> None:
        """tree-sitter is error-tolerant — traversal should not crash."""
        tree = empty_parser.parse_code("def foo(:", "python")
        t = Traverser(tree)
        nodes = list(t.traverse())
        assert len(nodes) > 0  # At minimum the module node

    def test_deeply_nested_code(self, empty_parser: Parser) -> None:
        """Verify no stack overflow on deeply nested structures."""
        # Generate deeply nested if-statements
        code = "x = 0\n"
        for _i in range(200):
            code = f"if True:\n    {code.replace(chr(10), chr(10) + '    ')}"
        tree = empty_parser.parse_code(code, "python")
        t = Traverser(tree)
        nodes = list(t.traverse())
        assert len(nodes) > 200  # Each 'if' + body = many nodes

    def test_nonexistent_type_find_first(self, py_traverser: Traverser) -> None:
        assert py_traverser.find_first("does_not_exist_xyz") is None

    def test_nonexistent_type_find_all(self, py_traverser: Traverser) -> None:
        assert py_traverser.find_all("does_not_exist_xyz") == []


# ── Consistency checks ──────────────────────────────────────────────────────


class TestConsistency:
    def test_pre_post_same_node_set(self, py_traverser: Traverser) -> None:
        pre_ids = {n.id for n in py_traverser.traverse(order=Order.PRE)}
        post_ids = {n.id for n in py_traverser.traverse(order=Order.POST)}
        assert pre_ids == post_ids

    def test_subtree_nodes_are_subset(self, py_traverser: Traverser) -> None:
        func = py_traverser.find_first("function_definition")
        assert func is not None
        all_ids = {n.id for n in py_traverser.traverse()}
        sub_ids = {n.id for n in py_traverser.traverse(root=func)}
        assert sub_ids <= all_ids

    def test_find_all_equals_filtered_traverse(self, py_traverser: Traverser) -> None:
        for node_type in ("function_definition", "class_definition", "string"):
            via_find = [n.id for n in py_traverser.find_all(node_type)]
            via_traverse = [
                n.id for n in py_traverser.traverse({node_type})
            ]
            assert via_find == via_traverse


# ── Helpers ─────────────────────────────────────────────────────────────────


def _is_descendant(node: Node, ancestor: Node) -> bool:
    """Return True if *node* is a descendant of *ancestor*."""
    current = node.parent
    while current is not None:
        if current.id == ancestor.id:
            return True
        current = current.parent
    return False
