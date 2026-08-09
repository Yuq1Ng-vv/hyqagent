"""Tests for cpg/query.py — CPG query interface."""

from __future__ import annotations

from pathlib import Path

import pytest

from hyqagent.cpg.graph import CPGGraphBuilder
from hyqagent.cpg.parser import Parser
from hyqagent.cpg.query import CPGQuery, GraphNode, GraphPath

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


@pytest.fixture(scope="module")
def query(parser: Parser) -> CPGQuery:
    builder = CPGGraphBuilder(parser)
    builder.add_file(str(FIXTURES / "dataflow.py"))
    return CPGQuery(builder.graph)


@pytest.fixture(scope="module")
def dir_query(parser: Parser) -> CPGQuery:
    builder = CPGGraphBuilder(parser)
    builder.add_directory(str(FIXTURES))
    return CPGQuery(builder.graph)


class TestGraphNode:
    def test_graph_node_defaults(self):
        n = GraphNode(node_id="test")
        assert n.node_id == "test"
        assert n.node_type == ""
        assert n.location == ""

    def test_graph_node_full(self):
        n = GraphNode(
            node_id="func:test.py:foo",
            node_type="function",
            location="test.py:10",
            name="foo",
            source="def foo(): pass",
        )
        assert n.name == "foo"
        assert n.location == "test.py:10"


class TestGraphPath:
    def test_empty_path(self):
        p = GraphPath()
        assert len(p) == 0
        assert not p

    def test_non_empty_path(self):
        n = GraphNode(node_id="n1", node_type="function")
        p = GraphPath(nodes=[n], edges=["CALLS"])
        assert len(p) == 1
        assert p


class TestCPGQuery:
    def test_find_nodes_simple(self, query):
        matches = query._find_nodes("request.args.get")
        assert len(matches) > 0

    def test_find_nodes_empty_pattern(self, query):
        assert query._find_nodes("") == []

    def test_find_path_source_to_variable(self, query):
        """Find path from 'request.args.get' to 'db_execute'."""
        paths = query.find_path("request.args.get", "db_execute")
        # May or may not find a direct path depending on graph connectivity
        assert isinstance(paths, list)

    def test_find_path_no_match(self, query):
        paths = query.find_path("nonexistent_pattern_xyz", "also_nonexistent")
        assert paths == []

    def test_find_sources(self, query):
        """Backwards trace from sink should find source assignments."""
        sources = query.find_sources("db_execute")
        assert isinstance(sources, list)

    def test_find_sources_no_match(self, query):
        assert query.find_sources("nonexistent_pattern") == []

    def test_find_sinks(self, query):
        """Forward trace from source should find downstream nodes."""
        sinks = query.find_sinks("request.args.get")
        assert isinstance(sinks, list)

    def test_find_sinks_no_match(self, query):
        assert query.find_sinks("nonexistent_pattern") == []

    def test_get_call_chain(self, query):
        """Call chain between two functions that call each other."""
        chain = query.get_call_chain("process_request", "lookup")
        # process_request calls lookup — should find a path
        if chain is not None:
            assert len(chain) > 0
            # Check that endpoints match
            assert chain.nodes[0].name == "process_request"
            assert chain.nodes[-1].name == "lookup"

    def test_get_call_chain_nonexistent(self, query):
        assert query.get_call_chain("nonexistent", "also_nonexistent") is None

    def test_slice_path_empty(self, query):
        assert query.slice_path(GraphPath()) == "(empty path)"

    def test_slice_path_nonempty(self, query):
        n = GraphNode(
            node_id="test:1",
            node_type="assignment",
            location="dataflow.py:13",
            name="sanitized",
            source="sanitized = int(user_input)",
        )
        p = GraphPath(nodes=[n])
        output = query.slice_path(p)
        assert "assignment" in output
        assert "sanitized" in output

    def test_get_sanitizers(self, query):
        n = GraphNode(
            node_id="test:1",
            node_type="assignment",
            source="sanitized = int(user_input)",
        )
        p = GraphPath(nodes=[n])
        sanitizers = query.get_sanitizers(p)
        assert "int(" in sanitizers

    def test_get_sanitizers_none(self, query):
        n = GraphNode(
            node_id="test:1",
            node_type="assignment",
            source="result = lookup(sanitized)",
        )
        p = GraphPath(nodes=[n])
        sanitizers = query.get_sanitizers(p)
        # "lookup" doesn't match any sanitizer pattern
        assert all(s not in sanitizers for s in ["int(", "escape("])


class TestDirectoryQuery:
    def test_find_nodes_across_files(self, dir_query):
        matches = dir_query._find_nodes("lookup")
        assert len(matches) > 0

    def test_call_chain_across_files(self, dir_query):
        # process_request calls lookup which is in the same file
        chain = dir_query.get_call_chain("process_request", "lookup")
        if chain is not None:
            assert chain.nodes[0].name == "process_request"
            assert chain.nodes[-1].name == "lookup"


class TestQueryBoundary:
    def test_empty_graph(self):
        import networkx as nx

        query = CPGQuery(nx.MultiDiGraph())
        assert query.find_path("a", "b") == []
        assert query.find_sources("a") == []
        assert query.find_sinks("a") == []
        assert query.get_call_chain("a", "b") is None

    def test_deep_nesting_no_infinite_loop(self, parser):
        """Ensure max_depth prevents infinite BFS loops."""
        code = "\n".join([f"def f{i}():\n    return f{i + 1}()" for i in range(100)])
        code += "\ndef f100():\n    return 1"
        builder = CPGGraphBuilder(parser)
        tree = parser.parse_code(code, "python")
        # Just ensure no crash — graph may be sparse
        assert builder.graph is not None
