"""Tests for cpg/graph.py — CPG graph builder."""

from __future__ import annotations

from pathlib import Path

import pytest

from hyqagent.cpg.graph import CPGGraphBuilder, NODE_FUNCTION, NODE_CALL_SITE, NODE_ASSIGNMENT
from hyqagent.cpg.parser import Parser

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


@pytest.fixture(scope="module")
def builder(parser: Parser) -> CPGGraphBuilder:
    b = CPGGraphBuilder(parser)
    b.add_file(str(FIXTURES / "dataflow.py"))
    return b


class TestGraphBuilding:
    def test_builder_creates_graph(self, builder):
        assert builder.graph is not None
        assert builder.node_count > 0

    def test_functions_indexed(self, builder):
        funcs = builder.nodes_by_type(NODE_FUNCTION)
        func_names = {
            builder.graph.nodes[n].get("name")
            for n in funcs
        }
        assert "process_request" in func_names
        assert "lookup" in func_names
        assert "db_execute" in func_names

    def test_call_sites_indexed(self, builder):
        call_sites = builder.nodes_by_type(NODE_CALL_SITE)
        assert len(call_sites) > 0
        # Should have calls like lookup(sanitized) and db_execute(query)

    def test_assignments_indexed(self, builder):
        assigns = builder.nodes_by_type(NODE_ASSIGNMENT)
        var_names = {
            builder.graph.nodes[n].get("var_name")
            for n in assigns
        }
        assert "user_input" in var_names
        assert "sanitized" in var_names
        assert "result" in var_names

    def test_calls_edges_exist(self, builder):
        """Call edges connect functions through call-site nodes."""
        call_edges = [
            (u, v, d)
            for u, v, d in builder.graph.edges(data=True)
            if d.get("edge_type") == "CALLS"
        ]
        assert len(call_edges) > 0

    def test_dataflow_edges_exist(self, builder):
        """Data flow edges connect assignments to variable refs."""
        df_edges = [
            (u, v, d)
            for u, v, d in builder.graph.edges(data=True)
            if d.get("edge_type") == "DATA_FLOW"
        ]
        assert len(df_edges) > 0

    def test_graph_repr(self, builder):
        r = repr(builder)
        assert "CPGGraphBuilder" in r
        assert "nodes=" in r
        assert "edges=" in r

    def test_add_file_idempotent(self, parser, builder):
        before = builder.node_count
        builder.add_file(str(FIXTURES / "dataflow.py"))
        assert builder.node_count == before

    def test_add_directory(self, parser):
        b = CPGGraphBuilder(parser)
        b.add_directory(str(FIXTURES))
        assert b.node_count > 0
        # Should have indexed dataflow.py and callgraph fixtures
        funcs = b.nodes_by_type(NODE_FUNCTION)
        func_names = {
            b.graph.nodes[n].get("name") for n in funcs
        }
        # At minimum the dataflow.py functions
        assert "process_request" in func_names

    def test_function_node_attrs(self, builder):
        funcs = builder.nodes_by_type(NODE_FUNCTION)
        for nid in funcs:
            data = builder.graph.nodes[nid]
            assert "name" in data
            assert "file_path" in data
            assert "start_line" in data

    def test_js_file_indexing(self, parser):
        b = CPGGraphBuilder(parser)
        b.add_file(str(FIXTURES / "dataflow.js"))
        funcs = b.nodes_by_type(NODE_FUNCTION)
        func_names = {
            b.graph.nodes[n].get("name") for n in funcs
        }
        assert "processRequest" in func_names


class TestMixedLanguageDirectory:
    def test_mixed_lang_indexing(self, parser):
        import tempfile, os
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, "app.py"), "w") as f:
                f.write("def foo():\n    return bar()\ndef bar():\n    return 1\n")
            with open(os.path.join(d, "util.js"), "w") as f:
                f.write("function foo() { return bar(); }\nfunction bar() { return 1; }\n")
            b = CPGGraphBuilder(parser)
            b.add_directory(d)
            funcs = b.nodes_by_type(NODE_FUNCTION)
            func_names = {b.graph.nodes[n].get("name") for n in funcs}
            assert "foo" in func_names
            assert "bar" in func_names
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)

