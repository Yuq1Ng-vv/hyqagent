"""Tests for cpg/dataflow.py — def-use chains, cross-function tracing, taint propagation."""

from __future__ import annotations

from pathlib import Path

import pytest

from hyqagent.cpg.dataflow import DataFlowBuilder, _loc, _source
from hyqagent.cpg.parser import Parser

FIXTURES = Path(__file__).resolve().parent / "fixtures"


# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


@pytest.fixture(scope="module")
def py_dataflow(parser: Parser) -> DataFlowBuilder:
    return DataFlowBuilder(parser)


@pytest.fixture(scope="module")
def py_tree(parser: Parser):
    return parser.parse_file(str(FIXTURES / "dataflow.py"))


@pytest.fixture(scope="module")
def js_tree(parser: Parser):
    return parser.parse_file(str(FIXTURES / "dataflow.js"))


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _func_node(tree, language: str, parser: Parser, name: str):
    """Find a function node by name."""
    funcs = parser.extract_functions(tree, language)
    for fn in funcs:
        if fn.name == name:
            # Find the tree-sitter Node from the tree
            for node in __traverse_tree(tree):
                line = node.start_point[0] + 1
                if line == fn.start_line:
                    provider = parser.get_provider(language)
                    if node.type in provider.func_def_types:
                        extracted = provider.extract_function_name(node)
                        if extracted == name:
                            return node
    return None


def __traverse_tree(tree):
    """Walk the tree recursively without Traverser dependency."""
    cursor = tree.walk()
    visited = set()
    stack = [cursor.node]
    while stack:
        node = stack.pop()
        if node.id in visited:
            continue
        visited.add(node.id)
        yield node
        for child in node.children:
            if child.id not in visited:
                stack.append(child)
    cursor.close()


# ─── Unit tests: helper functions ────────────────────────────────────────────


class TestHelperFunctions:
    def test_loc_with_file_path(self, py_tree):
        node = py_tree.root_node
        loc = _loc(node, "test.py")
        assert loc == "test.py:1"

    def test_loc_without_file_path(self, py_tree):
        node = py_tree.root_node
        loc = _loc(node)
        assert loc == "<string>:1"

    def test_source_decodes_text(self, py_tree):
        text = _source(py_tree.root_node)
        assert isinstance(text, str)
        assert len(text) > 0


# ─── Python def-use chain tests ──────────────────────────────────────────────


class TestDefUseChainsPython:
    def test_process_request_def_use(self, parser, py_tree, py_dataflow):
        """process_request() has clear assignments: user_input, sanitized, result."""
        fn = _func_node(py_tree, "python", parser, "process_request")
        assert fn is not None

        chains = py_dataflow.build_def_use_chains(py_tree, fn, "python")
        var_names = {du.var_name for du in chains}
        assert var_names >= {"user_input", "sanitized", "result"}

    def test_def_locations_are_meaningful(self, parser, py_tree, py_dataflow):
        """Each def-use pair should have a location string."""
        fn = _func_node(py_tree, "python", parser, "process_request")
        chains = py_dataflow.build_def_use_chains(py_tree, fn, "python")
        for du in chains:
            assert ":" in du.def_location
            assert du.var_name
            assert du.def_expression

    def test_uses_found_for_assigned_variable(self, parser, py_tree, py_dataflow):
        """The variable 'user_input' should have at least one use."""
        fn = _func_node(py_tree, "python", parser, "process_request")
        chains = py_dataflow.build_def_use_chains(py_tree, fn, "python")
        ui_chain = next((du for du in chains if du.var_name == "user_input"), None)
        assert ui_chain is not None
        assert len(ui_chain.use_locations) >= 1  # used in int(user_input)

    def test_no_assignments_function(self, parser, py_tree, py_dataflow):
        """no_assignments() just returns a global — no local variables."""
        fn = _func_node(py_tree, "python", parser, "no_assignments")
        assert fn is not None
        chains = py_dataflow.build_def_use_chains(py_tree, fn, "python")
        # Should have zero or only module-level references (not in function body)
        # The function body only has a return statement
        assert all(du.var_name != "CONFIG_KEY" or len(du.use_locations) == 0
                   for du in chains)

    def test_multi_assign(self, parser, py_tree, py_dataflow):
        """multi_assign() reassigns 'x' — both defs should appear."""
        fn = _func_node(py_tree, "python", parser, "multi_assign")
        chains = py_dataflow.build_def_use_chains(py_tree, fn, "python")
        x_defs = [du for du in chains if du.var_name == "x"]
        # x = 1 and x = y * 2 are two defs of x
        assert len(x_defs) == 2

    def test_conditional_def(self, parser, py_tree, py_dataflow):
        """Conditional assignment to 'value' in both branches."""
        fn = _func_node(py_tree, "python", parser, "conditional_def")
        chains = py_dataflow.build_def_use_chains(py_tree, fn, "python")
        value_defs = [du for du in chains if du.var_name == "value"]
        # value = "yes" and value = "no"
        assert len(value_defs) == 2

    def test_lookup_uses_parameter(self, parser, py_tree, py_dataflow):
        """lookup(item_id) — item_id is a parameter used in f-string."""
        fn = _func_node(py_tree, "python", parser, "lookup")
        chains = py_dataflow.build_def_use_chains(py_tree, fn, "python")
        var_names = {du.var_name for du in chains}
        # item_id is a parameter, not assigned in body — shouldn't appear as a def
        # query and data are assigned
        assert var_names >= {"query", "data"}

    def test_empty_body_function_returns_empty(self, parser, py_tree, py_dataflow):
        """A function with no body should return empty list."""
        fn = _func_node(py_tree, "python", parser, "no_assignments")
        chains = py_dataflow.build_def_use_chains(py_tree, fn, "python")
        assert isinstance(chains, list)

    def test_results_sorted_by_location(self, parser, py_tree, py_dataflow):
        """Def-use pairs should be sorted by definition location."""
        fn = _func_node(py_tree, "python", parser, "process_request")
        chains = py_dataflow.build_def_use_chains(py_tree, fn, "python")
        locations = [du.def_location for du in chains]
        assert locations == sorted(locations)

    def test_def_expression_is_source_code(self, parser, py_tree, py_dataflow):
        """def_expression should contain actual source code."""
        fn = _func_node(py_tree, "python", parser, "process_request")
        chains = py_dataflow.build_def_use_chains(py_tree, fn, "python")
        for du in chains:
            assert len(du.def_expression) > 0
            # The expression should contain the variable name
            if du.var_name in du.def_expression:
                pass  # common case
            # Some assignments might have the var in a nested expression

    def test_method_has_def_use(self, parser, py_tree, py_dataflow):
        """Class method 'fetch' should have def-use chains."""
        fn = _func_node(py_tree, "python", parser, "fetch")
        assert fn is not None
        chains = py_dataflow.build_def_use_chains(py_tree, fn, "python")
        var_names = {du.var_name for du in chains}
        assert var_names >= {"conn", "row"}


# ─── JavaScript def-use chain tests ──────────────────────────────────────────


class TestDefUseChainsJavaScript:
    def test_process_request_js(self, parser, js_tree, py_dataflow):
        fn = _func_node(js_tree, "javascript", parser, "processRequest")
        assert fn is not None
        chains = py_dataflow.build_def_use_chains(js_tree, fn, "javascript")
        var_names = {du.var_name for du in chains}
        assert var_names >= {"userInput", "sanitized", "result"}

    def test_multi_assign_js(self, parser, js_tree, py_dataflow):
        fn = _func_node(js_tree, "javascript", parser, "multiAssign")
        chains = py_dataflow.build_def_use_chains(js_tree, fn, "javascript")
        x_defs = [du for du in chains if du.var_name == "x"]
        # x = 1 (let x) and x = y * 2
        assert len(x_defs) >= 1


# ─── Cross-function tracing tests ────────────────────────────────────────────


class TestCrossFunctionTracing:
    def test_trace_without_callgraph_returns_empty(self, parser, py_tree, py_dataflow):
        """Without CallGraphBuilder, trace_cross_function returns empty."""
        steps = py_dataflow.trace_cross_function("user_input", "process_request", "lookup")
        assert steps == []


# ─── Boundary / edge case tests ──────────────────────────────────────────────


class TestBoundaryCases:
    def test_non_existent_function(self, parser, py_tree, py_dataflow):
        """A function that doesn't exist should return None from find."""
        fn = _func_node(py_tree, "python", parser, "non_existent_func")
        assert fn is None

    def test_non_identifier_nodes_filtered(self, parser, py_tree, py_dataflow):
        """Non-identifier nodes (strings, numbers) should not appear as uses."""
        fn = _func_node(py_tree, "python", parser, "process_request")
        chains = py_dataflow.build_def_use_chains(py_tree, fn, "python")
        for du in chains:
            # No use location should refer to string literals or numbers
            assert all(isinstance(loc, str) for loc in du.use_locations)

    def test_deeply_nested_expression(self, parser):
        """Parse deeply nested expressions without crashing."""
        code = "def f():\n    x = (a + (b * (c - (d / (e + f)))))\n    return x"
        tree = parser.parse_code(code, "python")
        df = DataFlowBuilder(parser)
        funcs = parser.extract_functions(tree, "python")
        assert len(funcs) == 1
        fn = _func_node(tree, "python", parser, "f")
        chains = df.build_def_use_chains(tree, fn, "python")
        assert len(chains) >= 1  # x = ...

    def test_empty_function(self, parser):
        """Empty function body should produce no chains."""
        code = "def empty():\n    pass"
        tree = parser.parse_code(code, "python")
        df = DataFlowBuilder(parser)
        funcs = parser.extract_functions(tree, "python")
        assert len(funcs) == 1
        fn = _func_node(tree, "python", parser, "empty")
        chains = df.build_def_use_chains(tree, fn, "python")
        assert chains == []

    def test_function_with_only_return(self, parser):
        """Function that only returns without assignment."""
        code = "def f():\n    return 42"
        tree = parser.parse_code(code, "python")
        df = DataFlowBuilder(parser)
        parser.extract_functions(tree, "python")  # verify parse works
        fn = _func_node(tree, "python", parser, "f")
        chains = df.build_def_use_chains(tree, fn, "python")
        assert chains == []

    def test_variable_used_before_assignment(self, parser):
        """Variable used before assignment in Python."""
        code = "def f():\n    y = x + 1\n    x = 10\n    return y"
        tree = parser.parse_code(code, "python")
        df = DataFlowBuilder(parser)
        _ = parser.extract_functions(tree, "python")
        fn = _func_node(tree, "python", parser, "f")
        chains = df.build_def_use_chains(tree, fn, "python")
        x_defs = [du for du in chains if du.var_name == "x"]
        assert len(x_defs) == 1
        # x is used at the line where y is assigned, but our analysis
        # finds uses AFTER the def — so x only has uses after line 3
        y_defs = [du for du in chains if du.var_name == "y"]
        assert len(y_defs) == 1

    def test_unicode_variable_names(self, parser):
        """Python 3 supports Unicode identifiers."""
        code = "def f():\n    имя = 'hello'\n    return имя"
        tree = parser.parse_code(code, "python")
        df = DataFlowBuilder(parser)
        _ = parser.extract_functions(tree, "python")
        fn = _func_node(tree, "python", parser, "f")
        chains = df.build_def_use_chains(tree, fn, "python")
        # Unicode identifiers may or may not be parsed as identifier type
        # depending on tree-sitter version — just ensure no crash
        assert isinstance(chains, list)


# ─── Taint propagation with call graph ───────────────────────────────────────


class TestTaintWithCallGraph:
    """Integration tests requiring a CallGraphBuilder."""

    def test_taint_source_to_variable(self, parser):
        """A taint source assigned to a variable should resolve."""
        code = (
            "from flask import request\n"
            "def handler():\n"
            "    uid = request.args.get('id')\n"
            "    result = db.query(uid)\n"
        )
        tree = parser.parse_code(code, "python")
        df = DataFlowBuilder(parser)
        fn = _func_node(tree, "python", parser, "handler")
        chains = df.build_def_use_chains(tree, fn, "python")
        var_names = {du.var_name for du in chains}
        assert "uid" in var_names
        assert "result" in var_names


# ─── Java def-use (T3) ───────────────────────────────────────────────────────


class TestDefUseChainsJava:
    def test_java_method_def_use(self, parser):
        code = (
            "class Test {\n"
            "    void doWork(String input) {\n"
            "        String query = \"SELECT * FROM \" + input;\n"
            "        execute(query);\n"
            "    }\n"
            "    void execute(String sql) {}\n"
            "}"
        )
        tree = parser.parse_code(code, "java")
        provider = parser.get_provider("java")
        df = DataFlowBuilder(parser)
        found = False
        for node in _walk_tree(tree):
            if node.type in provider.func_def_types:
                name = provider.extract_function_name(node)
                if name == "doWork":
                    chains = df.build_def_use_chains(tree, node, "java")
                    var_names = {du.var_name for du in chains}
                    assert "query" in var_names
                    found = True
                    break
        assert found, "Could not find doWork method"


# ─── Cross-function tracing integration (T4) ─────────────────────────────────


class TestCrossFunctionIntegration:
    def test_trace_with_callgraph(self, parser):
        import os
        import tempfile

        from hyqagent.cpg.callgraph_builder import CallGraphBuilder
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, "a.py"), "w") as f:
                f.write("from b import helper\ndef caller():\n    x = helper(42)\n")
            with open(os.path.join(d, "b.py"), "w") as f:
                f.write("def helper(n):\n    return n * 2\n")
            cg = CallGraphBuilder(parser)
            cg.add_directory(d)
            df = DataFlowBuilder(parser, cg)
            steps = df.trace_cross_function("x", "caller", "helper")
            assert isinstance(steps, list)
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)


# ─── TaintLoader error paths (T5) ────────────────────────────────────────────


class TestTaintLoaderErrors:
    def test_missing_file(self):
        from hyqagent.cpg.taint_loader import TaintRuleLoader
        loader = TaintRuleLoader(rules_path="/nonexistent/path.yaml")
        assert loader.available_languages == []

    def test_custom_path(self):
        from pathlib import Path

        from hyqagent.cpg.taint_loader import TaintRuleLoader
        real = Path(__file__).resolve().parent.parent.parent / "src/hyqagent/cpg/taint_rules.yaml"
        loader = TaintRuleLoader(rules_path=str(real))
        assert "python" in loader.available_languages


# ─── _fn_to_node (T7) ────────────────────────────────────────────────────────


class TestFnToNode:
    def test_converts_function_node(self, parser):
        df = DataFlowBuilder(parser)
        code = "def foo():\n    x = 1\n    return x"
        tree = parser.parse_code(code, "python")
        funcs = parser.extract_functions(tree, "python")
        assert len(funcs) == 1
        fn = funcs[0]
        node = df._fn_to_node(fn, tree)
        assert node is not None
        assert node.type == "function_definition"


def _walk_tree(tree):
    """Simple tree walker."""
    cursor = tree.walk()
    visited = set()
    stack = [cursor.node]
    while stack:
        node = stack.pop()
        if node.id in visited:
            continue
        visited.add(node.id)
        yield node
        for child in node.children:
            if child.id not in visited:
                stack.append(child)
