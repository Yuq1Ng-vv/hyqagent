"""Tests for cpg/graph.py — CPG graph builder."""

from __future__ import annotations

from pathlib import Path

import pytest

from hyqagent.cpg.graph import (
    NODE_ASSIGNMENT,
    NODE_CALL_SITE,
    NODE_FUNCTION,
    NODE_PARAMETER,
    CPGGraphBuilder,
    _classify_parameter_source,
)
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
        func_names = {builder.graph.nodes[n].get("name") for n in funcs}
        assert "process_request" in func_names
        assert "lookup" in func_names
        assert "db_execute" in func_names

    def test_call_sites_indexed(self, builder):
        call_sites = builder.nodes_by_type(NODE_CALL_SITE)
        assert len(call_sites) > 0
        # Should have calls like lookup(sanitized) and db_execute(query)

    def test_assignments_indexed(self, builder):
        assigns = builder.nodes_by_type(NODE_ASSIGNMENT)
        var_names = {builder.graph.nodes[n].get("var_name") for n in assigns}
        assert "user_input" in var_names
        assert "sanitized" in var_names
        assert "result" in var_names

    def test_calls_edges_exist(self, builder):
        """Call edges connect functions through call-site nodes."""
        call_edges = [
            (u, v, d) for u, v, d in builder.graph.edges(data=True) if d.get("edge_type") == "CALLS"
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
        func_names = {b.graph.nodes[n].get("name") for n in funcs}
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
        func_names = {b.graph.nodes[n].get("name") for n in funcs}
        assert "processRequest" in func_names


class TestMixedLanguageDirectory:
    def test_mixed_lang_indexing(self, parser):
        import os
        import tempfile

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


class TestParameterSourceClassification:
    """NODE_PARAMETER over-labeling fix — one annotation → one category."""

    def test_path_variable_maps_to_path_traversal(self):
        sig = 'public byte[] download(@PathVariable("name") String name, @RequestParam String type)'
        assert _classify_parameter_source(sig, 0) == ["path_traversal"]

    def test_request_param_maps_to_generic_injection(self):
        sig = 'public byte[] download(@PathVariable("name") String name, @RequestParam String type)'
        assert _classify_parameter_source(sig, 1) == ["injection_general"]

    def test_sibling_parameter_does_not_leak_annotation(self):
        # A plain parameter must not inherit its sibling's @PathVariable.
        sig = "public String getUser(@PathVariable int id, String name)"
        assert _classify_parameter_source(sig, 1) == []

    def test_request_body(self):
        sig = "public String createUser(@RequestBody String body)"
        assert _classify_parameter_source(sig, 0) == ["injection_general"]

    def test_request_header(self):
        assert _classify_parameter_source(
            'public String auth(@RequestHeader("Authorization") String token)', 0
        ) == ["header_injection"]

    def test_plain_parameter_is_not_a_source(self):
        assert _classify_parameter_source("public void download(String name)", 0) == []

    def test_http_servlet_request_parameter(self):
        assert _classify_parameter_source("public void handler(HttpServletRequest req)", 0) == [
            "injection_general"
        ]

    def test_fully_qualified_annotation(self):
        sig = 'public Response get(@javax.ws.rs.PathParam("id") long id)'
        assert _classify_parameter_source(sig, 0) == ["path_traversal"]

    def test_generic_return_type_and_throws(self):
        sig = "public ResponseEntity<byte[]> download(@PathVariable String name) throws IOException"
        assert _classify_parameter_source(sig, 0) == ["path_traversal"]

    def test_no_parameters(self):
        assert _classify_parameter_source("public void baz()", 0) == []


class TestParameterNodeLabeling:
    """End-to-end: NODE_PARAMETER nodes get precise (not exploded) labels."""

    @pytest.fixture(scope="module")
    def spring_builder(self, parser):
        from hyqagent.cpg.taint_loader import TaintRuleLoader

        b = CPGGraphBuilder(parser, taint_loader=TaintRuleLoader())
        b.add_file(str(FIXTURES / "spring_sample.java"))
        return b

    def _param_labels(self, builder, func_name, var_name):
        for _nid, data in builder.graph.nodes(data=True):
            if data.get("node_type") != NODE_PARAMETER:
                continue
            if data.get("enclosing_function") == func_name and data.get("var_name") == var_name:
                return data.get("taint_source", "")
        return None

    def test_path_variable_param_is_only_path_traversal(self, spring_builder):
        assert self._param_labels(spring_builder, "getUser", "id") == "path_traversal"

    def test_request_param_param_is_only_generic(self, spring_builder):
        assert self._param_labels(spring_builder, "getUser", "name") == "injection_general"

    def test_request_body_param_is_only_generic(self, spring_builder):
        assert self._param_labels(spring_builder, "createUser", "body") == "injection_general"
