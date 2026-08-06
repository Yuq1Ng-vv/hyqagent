"""tests/test_cpg/test_callgraph.py — Tests for cpg/callgraph.py.

Covers: construction, function-name collection, call-edge building, edge
resolution, query methods (get_callees/get_callers/has_edge), properties
(edges/resolved_edges/unresolved/function_names), dunder methods, and
edge cases across Python, JavaScript, and Java.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hyqagent.cpg.callgraph import CallEdge, SingleFileCallGraph, UnresolvedCall
from hyqagent.cpg.parser import Parser

FIXTURES = Path(__file__).parent / "fixtures"


# ── Module-level fixtures ────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


@pytest.fixture(scope="module")
def py_cg(parser: Parser) -> SingleFileCallGraph:
    cg = SingleFileCallGraph(parser)
    cg.build_from_file(FIXTURES / "callgraph.py")
    return cg


@pytest.fixture(scope="module")
def js_cg(parser: Parser) -> SingleFileCallGraph:
    cg = SingleFileCallGraph(parser)
    cg.build_from_file(FIXTURES / "callgraph.js")
    return cg


@pytest.fixture(scope="module")
def java_cg(parser: Parser) -> SingleFileCallGraph:
    cg = SingleFileCallGraph(parser)
    cg.build_from_file(FIXTURES / "callgraph.java")
    return cg


# ── Helper ────────────────────────────────────────────────────────────────────


def _names(edges: list[CallEdge]) -> list[str]:
    """Return sorted list of callee names for assertion helpers."""
    return sorted(e.callee for e in edges)


def _unresolved_names(unresolved: list[UnresolvedCall]) -> list[str]:
    return sorted(u.callee for u in unresolved)


# ═════════════════════════════════════════════════════════════════════════════
#  Construction & basic properties
# ═════════════════════════════════════════════════════════════════════════════


class TestConstruction:
    """Tests for __init__ and initial state."""

    def test_initial_state_empty(self, parser: Parser) -> None:
        cg = SingleFileCallGraph(parser)
        assert len(cg.edges) == 0
        assert len(cg.resolved_edges) == 0
        assert len(cg.unresolved) == 0
        assert cg.function_names == set()
        assert len(cg) == 0
        assert list(cg) == []

    def test_build_from_file_returns_none(self, parser: Parser) -> None:
        """build_from_file mutates in place, returns None."""
        cg = SingleFileCallGraph(parser)
        result = cg.build_from_file(FIXTURES / "sample.py")
        assert result is None

    def test_build_from_tree_returns_none(self, parser: Parser) -> None:
        """build_from_tree mutates in place, returns None."""
        cg = SingleFileCallGraph(parser)
        tree = parser.parse_file(FIXTURES / "sample.py")
        language = parser.get_language(tree)
        result = cg.build_from_tree(tree, language)
        assert result is None

    def test_build_from_tree_accepts_explicit_path(self, parser: Parser) -> None:
        cg = SingleFileCallGraph(parser)
        tree = parser.parse_file(FIXTURES / "sample.py")
        language = parser.get_language(tree)
        cg.build_from_tree(tree, language, file_path="/custom/path.py")
        assert all(e.file_path == "/custom/path.py" for e in cg.edges)


# ═════════════════════════════════════════════════════════════════════════════
#  Function name collection
# ═════════════════════════════════════════════════════════════════════════════


class TestFunctionNames:
    """Tests for function_names property across languages."""

    # Python ──────────────────────────────────────────────────────────────

    def test_python_all_functions_found(self, py_cg: SingleFileCallGraph) -> None:
        """All named functions in callgraph.py should be collected."""
        names = py_cg.function_names
        assert "helper" in names
        assert "compute" in names
        assert "recursive_fib" in names
        assert "calls_external" in names
        assert "no_calls" in names
        assert "outer" in names
        assert "inner" in names  # nested function
        assert "uses_lambda" in names
        assert "max_value" in names
        assert "decorated_func" in names  # decorated function

    def test_python_class_methods_found(self, py_cg: SingleFileCallGraph) -> None:
        names = py_cg.function_names
        assert "__init__" in names
        assert "connect" in names
        assert "query" in names
        assert "batch_query" in names
        assert "fallback" in names

    def test_python_decorator_not_treated_as_function(self, py_cg: SingleFileCallGraph) -> None:
        """'with_decorator' IS a function and should be tracked."""
        assert "with_decorator" in py_cg.function_names

    # JavaScript ──────────────────────────────────────────────────────────

    def test_js_functions_found(self, js_cg: SingleFileCallGraph) -> None:
        names = js_cg.function_names
        for expected in [
            "helper",
            "compute",
            "recursiveFib",
            "callsExternal",
            "noCalls",
            "asyncRunner",
            "outer",
            "inner",
        ]:
            assert expected in names

    def test_js_class_methods_found(self, js_cg: SingleFileCallGraph) -> None:
        names = js_cg.function_names
        for expected in ["constructor", "connect", "query", "batchQuery", "fallback"]:
            assert expected in names

    def test_js_arrow_not_in_function_names(self, js_cg: SingleFileCallGraph) -> None:
        """Arrow functions are anonymous — not collected as named functions."""
        assert "arrowHandler" not in js_cg.function_names

    # Java ────────────────────────────────────────────────────────────────

    def test_java_methods_found(self, java_cg: SingleFileCallGraph) -> None:
        names = java_cg.function_names
        for expected in [
            "compute",
            "recursiveFib",
            "noCalls",
            "getUser",
            "listUsers",
            "process",
            "validate",
            "runPipeline",
            "stepOne",
            "stepTwo",
            "helper",
            "log",
            "execute",
            "executeQuery",
            "UserService",
        ]:
            assert expected in names


# ═════════════════════════════════════════════════════════════════════════════
#  Call edges — resolution
# ═════════════════════════════════════════════════════════════════════════════


class TestCallEdgesPython:
    """Resolved and unresolved edges for Python callgraph.py."""

    def test_simple_call_resolved(self, py_cg: SingleFileCallGraph) -> None:
        """Compute → helper should be resolved."""
        assert py_cg.has_edge("compute", "helper")
        edges = [e for e in py_cg.get_callees("compute") if e.callee == "helper"]
        assert len(edges) == 2  # two calls to helper in compute
        assert all(e.is_resolved for e in edges)
        assert not any(e.is_method_call for e in edges)
        assert all(e.file_path.endswith("callgraph.py") for e in edges)

    def test_recursion_self_loop(self, py_cg: SingleFileCallGraph) -> None:
        assert py_cg.has_edge("recursive_fib", "recursive_fib")
        edges = py_cg.get_callees("recursive_fib")
        assert len(edges) == 2  # two recursive calls

    def test_method_call_resolved(self, py_cg: SingleFileCallGraph) -> None:
        """self.connect() inside query() → resolved to 'connect'."""
        assert py_cg.has_edge("query", "connect")
        edges = [e for e in py_cg.get_callees("query") if e.callee == "connect"]
        assert len(edges) == 1
        edge = edges[0]
        assert edge.is_resolved
        assert edge.is_method_call
        assert "self.connect" in edge.full_expression

    def test_chain_batch_query_to_query(self, py_cg: SingleFileCallGraph) -> None:
        """batch_query → query → connect chain."""
        assert py_cg.has_edge("batch_query", "query")
        assert py_cg.has_edge("query", "connect")

    def test_nested_function_inner_calls(self, py_cg: SingleFileCallGraph) -> None:
        """inner() → helper() should be resolved."""
        assert py_cg.has_edge("inner", "helper")
        edges = [e for e in py_cg.get_callees("inner") if e.callee == "helper"]
        assert len(edges) == 1
        assert edges[0].caller == "inner"

    def test_outer_calls_inner_and_helper(self, py_cg: SingleFileCallGraph) -> None:
        assert py_cg.has_edge("outer", "helper")
        assert py_cg.has_edge("outer", "inner")

    def test_decorated_func_calls(self, py_cg: SingleFileCallGraph) -> None:
        """decorated_func → helper resolved."""
        assert py_cg.has_edge("decorated_func", "helper")

    def test_lambda_call_attributed_to_enclosing(self, py_cg: SingleFileCallGraph) -> None:
        """Calls inside lambda attributed to 'uses_lambda'."""
        assert py_cg.has_edge("uses_lambda", "helper")

    # Unresolved ──────────────────────────────────────────────────────

    def test_builtins_unresolved(self, py_cg: SingleFileCallGraph) -> None:
        unresolved_names = {u.callee for u in py_cg.unresolved}
        assert "print" in unresolved_names
        assert "len" in unresolved_names
        assert "str" in unresolved_names

    def test_external_method_unresolved(self, py_cg: SingleFileCallGraph) -> None:
        """self.db.execute() should be unresolved (db is external)."""
        unresolved = {u.callee: u for u in py_cg.unresolved}
        assert "execute" in unresolved
        assert unresolved["execute"].is_method_call
        assert "self.db.execute" in unresolved["execute"].full_expression

    def test_fetch_from_cache_unresolved(self, py_cg: SingleFileCallGraph) -> None:
        unresolved_names = {u.callee for u in py_cg.unresolved}
        assert "fetch_from_cache" in unresolved_names

    def test_no_calls_leaf_function(self, py_cg: SingleFileCallGraph) -> None:
        """no_calls has zero call edges."""
        assert len(py_cg.get_callees("no_calls")) == 0


class TestCallEdgesJavaScript:
    """Resolved / unresolved edges for JavaScript callgraph.js."""

    def test_simple_call_resolved(self, js_cg: SingleFileCallGraph) -> None:
        assert js_cg.has_edge("compute", "helper")

    def test_recursion_self_loop(self, js_cg: SingleFileCallGraph) -> None:
        assert js_cg.has_edge("recursiveFib", "recursiveFib")

    def test_method_call_resolved(self, js_cg: SingleFileCallGraph) -> None:
        """this.connect() inside query() → resolved to 'connect'."""
        assert js_cg.has_edge("query", "connect")

    def test_chain_batch_to_query(self, js_cg: SingleFileCallGraph) -> None:
        assert js_cg.has_edge("batchQuery", "query")

    def test_nested_function(self, js_cg: SingleFileCallGraph) -> None:
        assert js_cg.has_edge("inner", "helper")
        assert js_cg.has_edge("outer", "helper")
        assert js_cg.has_edge("outer", "inner")

    def test_async_function_calls(self, js_cg: SingleFileCallGraph) -> None:
        assert js_cg.has_edge("asyncRunner", "helper")

    def test_arrow_calls_not_attributed(self, js_cg: SingleFileCallGraph) -> None:
        """Module-level arrow function calls should not be attributed."""
        callers = {e.caller for e in js_cg.edges}
        assert "arrowHandler" not in callers

    def test_console_log_unresolved(self, js_cg: SingleFileCallGraph) -> None:
        unresolved = {u.callee for u in js_cg.unresolved}
        assert "log" in unresolved

    def test_read_file_sync_unresolved(self, js_cg: SingleFileCallGraph) -> None:
        unresolved = {u.callee for u in js_cg.unresolved}
        assert "readFileSync" in unresolved

    def test_fetch_from_cache_unresolved(self, js_cg: SingleFileCallGraph) -> None:
        unresolved = {u.callee for u in js_cg.unresolved}
        assert "fetchFromCache" in unresolved


class TestCallEdgesJava:
    """Resolved / unresolved edges for Java callgraph.java."""

    def test_simple_call(self, java_cg: SingleFileCallGraph) -> None:
        """Utils.helper() → bare name 'helper'.

        Not resolved locally because helper is in a different class (Utils).
        """
        edges = [e for e in java_cg.edges if e.callee == "helper"]
        assert len(edges) == 2  # two calls from compute
        # helper IS defined in Utils class, so it should be in function_names
        assert all(e.is_resolved for e in edges)

    def test_recursion_self_loop(self, java_cg: SingleFileCallGraph) -> None:
        assert java_cg.has_edge("recursiveFib", "recursiveFib")

    def test_method_call_resolved(self, java_cg: SingleFileCallGraph) -> None:
        """this.getUser(1) → 'getUser' resolved."""
        assert java_cg.has_edge("process", "getUser")
        assert java_cg.has_edge("process", "validate")

    def test_chain_run_pipeline(self, java_cg: SingleFileCallGraph) -> None:
        """RunPipeline → stepOne → stepTwo → log."""
        assert java_cg.has_edge("runPipeline", "stepOne")
        assert java_cg.has_edge("stepOne", "stepTwo")
        # stepTwo calls Utils.log → 'log', which IS defined locally
        assert java_cg.has_edge("stepTwo", "log")

    def test_external_db_calls(self, java_cg: SingleFileCallGraph) -> None:
        """this.db.execute(query) / this.db.executeQuery(query)."""
        assert java_cg.has_edge("getUser", "execute")
        assert java_cg.has_edge("listUsers", "executeQuery")

    def test_system_out_println_unresolved(self, java_cg: SingleFileCallGraph) -> None:
        unresolved = {u.callee for u in java_cg.unresolved}
        assert "println" in unresolved

    def test_no_calls_leaf(self, java_cg: SingleFileCallGraph) -> None:
        assert len(java_cg.get_callees("noCalls")) == 0


# ═════════════════════════════════════════════════════════════════════════════
#  Query methods
# ═════════════════════════════════════════════════════════════════════════════


class TestQueryMethods:
    """Tests for get_callees, get_callers, has_edge."""

    def test_get_callees_includes_unresolved(self, py_cg: SingleFileCallGraph) -> None:
        edges = py_cg.get_callees("compute")
        callees = _names(edges)
        assert "helper" in callees
        assert "print" in callees  # unresolved but still returned

    def test_get_callers_only_resolved(self, py_cg: SingleFileCallGraph) -> None:
        """get_callers returns only resolved edges."""
        callers = py_cg.get_callers("helper")
        assert all(e.is_resolved for e in callers)
        caller_names = sorted({e.caller for e in callers})
        assert "compute" in caller_names
        assert "outer" in caller_names
        assert "inner" in caller_names

    def test_get_callers_empty_for_undefined(self, py_cg: SingleFileCallGraph) -> None:
        assert len(py_cg.get_callers("nonexistent")) == 0

    def test_get_callees_empty_for_leaf(self, py_cg: SingleFileCallGraph) -> None:
        assert len(py_cg.get_callees("no_calls")) == 0

    def test_get_callees_nonexistent_function(self, py_cg: SingleFileCallGraph) -> None:
        assert len(py_cg.get_callees("nonexistent")) == 0

    def test_has_edge_positive(self, py_cg: SingleFileCallGraph) -> None:
        assert py_cg.has_edge("compute", "helper")

    def test_has_edge_negative_wrong_direction(self, py_cg: SingleFileCallGraph) -> None:
        assert not py_cg.has_edge("helper", "compute")

    def test_has_edge_unresolved_is_false(self, py_cg: SingleFileCallGraph) -> None:
        """has_edge returns False for unresolved calls."""
        assert not py_cg.has_edge("compute", "print")

    def test_has_edge_nonexistent(self, py_cg: SingleFileCallGraph) -> None:
        assert not py_cg.has_edge("foo", "bar")


# ═════════════════════════════════════════════════════════════════════════════
#  Properties: edges, resolved_edges, unresolved
# ═════════════════════════════════════════════════════════════════════════════


class TestProperties:
    """Tests for edges, resolved_edges, unresolved, function_names."""

    def test_edges_is_copy(self, py_cg: SingleFileCallGraph) -> None:
        original = py_cg.edges
        original.append(
            CallEdge(
                caller="test",
                callee="test",
                call_line=1,
                full_expression="test()",
            )
        )
        assert len(py_cg.edges) == len(original) - 1  # not mutated

    def test_resolved_edges_subset(self, py_cg: SingleFileCallGraph) -> None:
        resolved = py_cg.resolved_edges
        assert all(e.is_resolved for e in resolved)
        assert len(resolved) <= len(py_cg.edges)

    def test_unresolved_are_not_resolved(self, py_cg: SingleFileCallGraph) -> None:
        unresolved = py_cg.unresolved
        resolved_names = {e.callee for e in py_cg.resolved_edges}
        for u in unresolved:
            assert u.callee not in resolved_names or any(
                e.callee == u.callee and not e.is_resolved for e in py_cg.edges
            )

    def test_total_partition(self, py_cg: SingleFileCallGraph) -> None:
        assert len(py_cg.resolved_edges) + len(py_cg.unresolved) == len(py_cg.edges)

    def test_function_names_is_copy(self, py_cg: SingleFileCallGraph) -> None:
        names = py_cg.function_names
        names.add("intruder")
        assert "intruder" not in py_cg.function_names


# ═════════════════════════════════════════════════════════════════════════════
#  Dunder methods
# ═════════════════════════════════════════════════════════════════════════════


class TestDunder:
    """Tests for __repr__, __len__, __iter__."""

    def test_repr_includes_counts(self, py_cg: SingleFileCallGraph) -> None:
        rep = repr(py_cg)
        assert "SingleFileCallGraph" in rep
        assert "functions=" in rep
        assert "edges=" in rep
        assert "resolved=" in rep

    def test_len_matches_edges(self, py_cg: SingleFileCallGraph) -> None:
        assert len(py_cg) == len(py_cg.edges)

    def test_iter_yields_all_edges(self, py_cg: SingleFileCallGraph) -> None:
        assert list(py_cg) == py_cg.edges

    def test_repr_empty(self, parser: Parser) -> None:
        cg = SingleFileCallGraph(parser)
        rep = repr(cg)
        assert "functions=0" in rep
        assert "edges=0" in rep
        assert "resolved=0" in rep


# ═════════════════════════════════════════════════════════════════════════════
#  Edge cases
# ═════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    """Various edge-case scenarios."""

    def test_empty_file_no_errors(self, parser: Parser) -> None:
        """Parsing a near-empty file should produce no edges."""
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(
            parser.parse_code("x = 1", "python"),
            "python",
        )
        assert len(cg.edges) == 0
        assert cg.function_names == set()

    def test_code_without_functions(self, parser: Parser) -> None:
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(
            parser.parse_code(
                "import os\nx = os.path.join('a', 'b')\n",
                "python",
            ),
            "python",
        )
        # Module-level call without enclosing function — no edges
        assert len(cg.edges) == 0

    def test_function_without_calls(self, parser: Parser) -> None:
        code = "def foo():\n    pass\n"
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(parser.parse_code(code, "python"), "python")
        assert "foo" in cg.function_names
        assert len(cg.get_callees("foo")) == 0

    def test_matching_by_name_only(self, parser: Parser) -> None:
        """Two classes with same method name — both resolve by name.

        This is a limitation: we can't distinguish ClassA.foo() from
        ClassB.foo() without type information.  That's for Session 1.5+.
        """
        code = """
class A:
    def do_it(self):
        return self.helper()

    def helper(self):
        return 1

class B:
    def do_it(self):
        return self.helper()

    def helper(self):
        return 2
"""
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(parser.parse_code(code, "python"), "python")
        assert cg.has_edge("do_it", "helper")
        # Both 'do_it' and 'helper' appear once (name collision across classes)
        # The call graph matches by name, so both class A and B "do_it" map
        # to the same "do_it" entry.

    def test_build_twice_overwrites(self, parser: Parser) -> None:
        """Second build_from_file overwrites state."""
        cg = SingleFileCallGraph(parser)
        cg.build_from_file(FIXTURES / "callgraph.py")
        first_len = len(cg.edges)
        cg.build_from_file(FIXTURES / "sample.py")
        assert len(cg.edges) != first_len  # overwritten
        # sample.py has get_user, list_users, delete_all, login, __init__
        assert "login" in cg.function_names or "get_user" in cg.function_names

    def test_call_edge_dataclass_fields(self) -> None:
        edge = CallEdge(
            caller="foo",
            callee="bar",
            call_line=10,
            full_expression="bar(x)",
            is_resolved=True,
            is_method_call=False,
            file_path="/test.py",
        )
        assert edge.caller == "foo"
        assert edge.callee == "bar"
        assert edge.call_line == 10
        assert edge.full_expression == "bar(x)"
        assert edge.is_resolved
        assert not edge.is_method_call
        assert edge.file_path == "/test.py"

    def test_unresolved_call_dataclass_fields(self) -> None:
        uc = UnresolvedCall(
            callee="external_func",
            full_expression="external_func()",
            call_line=5,
            caller="main",
            is_method_call=False,
            file_path="/app.py",
        )
        assert uc.callee == "external_func"
        assert uc.caller == "main"
        assert uc.call_line == 5

    def test_python_chain_call_nested(self, parser: Parser) -> None:
        """chain1(chain2(x)) — both should be detected."""
        code = """
def chain1(x):
    return x

def chain2(x):
    return x

def runner():
    return chain1(chain2(42))
"""
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(parser.parse_code(code, "python"), "python")
        assert cg.has_edge("runner", "chain1")
        assert cg.has_edge("runner", "chain2")

    def test_python_attribute_call_full_expression(self, parser: Parser) -> None:
        """Verify full_expression for attribute calls."""
        code = """
class X:
    def method(self):
        return self.helper(1)
    def helper(self, n):
        return n
"""
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(parser.parse_code(code, "python"), "python")
        edges = cg.get_callees("method")
        assert len(edges) == 1
        assert edges[0].full_expression == "self.helper"

    def test_js_member_expression_full_expression(self, parser: Parser) -> None:
        """Verify full_expression captures the member expression."""
        code = """
class Svc {
    query() { return this.db.execute("sql"); }
}
"""
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(parser.parse_code(code, "javascript"), "javascript")
        edges = cg.get_callees("query")
        assert len(edges) == 1
        assert edges[0].callee == "execute"
        assert "this.db.execute" in edges[0].full_expression

    def test_java_bare_call_full_expression(self, parser: Parser) -> None:
        """Java method_invocation full_expression includes arguments."""
        code = """
class Foo {
    void bar() {
        baz(42);
    }
    void baz(int x) {}
}
"""
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(parser.parse_code(code, "java"), "java")
        edges = cg.get_callees("bar")
        assert len(edges) == 1
        assert edges[0].callee == "baz"
        assert "baz(42)" in edges[0].full_expression
