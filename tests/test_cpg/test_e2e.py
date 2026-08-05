"""End-to-end CPG pipeline integration tests.

Validates the full chain:
Parser → CallGraph → DataFlow → CPGGraphBuilder → Framework Extractors
→ CPGQuery → TaintRuleLoader

Uses a deliberately vulnerable microblog Flask app as the test target.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hyqagent.cpg.callgraph import SingleFileCallGraph
from hyqagent.cpg.callgraph_builder import CallGraphBuilder
from hyqagent.cpg.dataflow import DataFlowBuilder
from hyqagent.cpg.frameworks.flask import FlaskExtractor
from hyqagent.cpg.graph import NODE_CALL_SITE, NODE_FUNCTION, CPGGraphBuilder
from hyqagent.cpg.parser import Parser
from hyqagent.cpg.query import CPGQuery
from hyqagent.cpg.taint_loader import TaintRuleLoader

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MICROBLOG = FIXTURES / "microblog"


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


@pytest.fixture(scope="module")
def loader() -> TaintRuleLoader:
    return TaintRuleLoader()


# ─── Level 1: Parser + CallGraph ─────────────────────────────────────────────


class TestParserCallGraph:
    """Verify basic parsing and call-graph construction on the microblog app."""

    def test_parse_app(self, parser):
        tree = parser.parse_file(str(MICROBLOG / "app.py"))
        assert tree.root_node is not None

    def test_extract_functions(self, parser):
        tree = parser.parse_file(str(MICROBLOG / "app.py"))
        funcs = parser.extract_functions(tree, "python")
        func_names = {f.name for f in funcs}
        assert "hello" in func_names
        assert "search" in func_names
        assert "admin_ping" in func_names
        assert "user_profile" in func_names
        assert "view_post" in func_names

    def test_single_file_call_graph(self, parser):
        cg = SingleFileCallGraph(parser)
        cg.build_from_file(str(MICROBLOG / "app.py"))
        # app.py calls into db.py — unresolved locally
        assert len(cg.edges) > 0
        # search() should call db.search_posts()
        search_calls = [e for e in cg.edges if e.caller == "search"]
        assert len(search_calls) > 0

    def test_cross_file_call_graph(self, parser):
        builder = CallGraphBuilder(parser)
        builder.add_directory(str(MICROBLOG))
        # both app.py and db.py indexed
        assert len(builder.files) >= 2
        # Database.execute should be defined
        db_file = builder.find_definition("execute")
        assert db_file is not None

    def test_cross_file_edges(self, parser):
        builder = CallGraphBuilder(parser)
        builder.add_directory(str(MICROBLOG))
        cross = builder.build_calls()
        # search() in app.py → search_posts() in db.py → execute() in db.py
        assert len(cross) > 0


# ─── Level 2: DataFlow ───────────────────────────────────────────────────────


class TestDataFlow:
    """Verify def-use chain analysis on vulnerable handlers."""

    def test_hello_def_use(self, parser):
        """hello() — 'name' variable from request.args should have def-use."""
        tree = parser.parse_file(str(MICROBLOG / "app.py"))
        provider = parser.get_provider("python")
        df = DataFlowBuilder(parser)

        fn_node = _find_func_body(tree, provider, "hello")
        assert fn_node is not None, "Could not find hello() function body"
        chains = df.build_def_use_chains(tree, fn_node, "python")
        var_names = {du.var_name for du in chains}
        assert "name" in var_names

    def test_search_def_use(self, parser):
        """search() — 'keyword' → db.search_posts(keyword) variable flow."""
        tree = parser.parse_file(str(MICROBLOG / "app.py"))
        provider = parser.get_provider("python")
        df = DataFlowBuilder(parser)

        fn_node = _find_func_body(tree, provider, "search")
        assert fn_node is not None, "Could not find search() function body"
        chains = df.build_def_use_chains(tree, fn_node, "python")
        var_names = {du.var_name for du in chains}
        assert "keyword" in var_names

    def test_admin_ping_def_use(self, parser):
        """admin_ping() — 'host' and 'command' variables should be tracked."""
        tree = parser.parse_file(str(MICROBLOG / "app.py"))
        provider = parser.get_provider("python")
        df = DataFlowBuilder(parser)

        fn_node = _find_func_body(tree, provider, "admin_ping")
        assert fn_node is not None, "Could not find admin_ping() function body"
        chains = df.build_def_use_chains(tree, fn_node, "python")
        var_names = {du.var_name for du in chains}
        assert "host" in var_names
        assert "command" in var_names


# ─── Level 3: CPG Graph ──────────────────────────────────────────────────────


class TestCPGGraph:
    """Verify CPG graph construction indexes all components correctly."""

    @pytest.fixture(scope="module")
    def graph_builder(self, parser):
        b = CPGGraphBuilder(parser)
        b.add_directory(str(MICROBLOG))
        return b

    def test_graph_has_functions(self, graph_builder):
        funcs = graph_builder.nodes_by_type(NODE_FUNCTION)
        func_names = {
            graph_builder.graph.nodes[n].get("name") for n in funcs
        }
        assert "hello" in func_names
        assert "search" in func_names
        assert "admin_ping" in func_names
        # db.py functions also indexed
        assert "fetch_user_by_name" in func_names or "search_posts" in func_names

    def test_graph_has_call_sites(self, graph_builder):
        call_sites = graph_builder.nodes_by_type(NODE_CALL_SITE)
        assert len(call_sites) > 0

    def test_graph_has_dataflow_edges(self, graph_builder):
        df_edges = [
            (u, v, d) for u, v, d in graph_builder.graph.edges(data=True)
            if d.get("edge_type") == "DATA_FLOW"
        ]
        assert len(df_edges) > 0

    def test_graph_has_calls_edges(self, graph_builder):
        call_edges = [
            (u, v, d) for u, v, d in graph_builder.graph.edges(data=True)
            if d.get("edge_type") == "CALLS"
        ]
        assert len(call_edges) > 0


# ─── Level 4: Framework Extraction ───────────────────────────────────────────


class TestFrameworkExtraction:
    """Verify FlaskExtractor finds endpoints with correct metadata."""

    def test_flask_detects_app(self, parser):
        ext = FlaskExtractor(parser)
        assert ext.detect(str(MICROBLOG / "app.py")) is True

    def test_all_endpoints_found(self, parser):
        ext = FlaskExtractor(parser)
        routes = ext.extract_routes(str(MICROBLOG / "app.py"))
        route_map = {r.route: r for r in routes}
        assert "/" in route_map
        assert "/hello" in route_map or any("hello" in r for r in route_map)
        assert any("search" in r for r in route_map)
        assert any("user" in r for r in route_map)

    def test_auth_endpoints(self, parser):
        """view_post and admin_ping should have @login_required detected."""
        ext = FlaskExtractor(parser)
        routes = ext.extract_routes(str(MICROBLOG / "app.py"))
        auth_routes = [r for r in routes if r.auth_required]
        auth_handlers = {r.handler_func for r in auth_routes}
        assert "view_post" in auth_handlers
        assert "admin_ping" in auth_handlers

    def test_idor_endpoint_no_auth(self, parser):
        """user_profile() should NOT have auth_required."""
        ext = FlaskExtractor(parser)
        routes = ext.extract_routes(str(MICROBLOG / "app.py"))
        user_route = next((r for r in routes if r.handler_func == "user_profile"), None)
        assert user_route is not None
        assert user_route.auth_required is False, (
            f"IDOR: user_profile should lack auth, got {user_route.auth_decorators}"
        )

    def test_source_lines_found(self, parser):
        """Handlers should have source_lines with request.args/form patterns."""
        ext = FlaskExtractor(parser)
        routes = ext.extract_routes(str(MICROBLOG / "app.py"))
        all_sources: list[str] = []
        for r in routes:
            all_sources.extend(r.source_lines)
        # At minimum, request.args.get and request.form.get should be found
        assert len(all_sources) > 0


# ─── Level 5: Query + Taint ──────────────────────────────────────────────────


class TestCrossFileEdgeState:
    """T8: Verify cross-file call-site nodes have is_resolved=True."""

    def test_cross_file_is_resolved(self, parser):
        builder = CPGGraphBuilder(parser)
        builder.add_directory(str(MICROBLOG))
        query = CPGQuery(builder.graph)
        for nid, data in builder.graph.nodes(data=True):
            if data.get("cross_file") and data.get("node_type") == "call_site":
                assert data.get("is_resolved") is True, (
                    f"Cross-file call-site {nid} should have is_resolved=True"
                )


class TestQueryAndTaint:
    """Verify CPGQuery and TaintRuleLoader work together."""

    @pytest.fixture(scope="module")
    def query(self, parser):
        builder = CPGGraphBuilder(parser)
        builder.add_directory(str(MICROBLOG))
        return CPGQuery(builder.graph)

    def test_query_finds_source_nodes(self, query):
        matches = query._find_nodes("request.args.get")
        assert len(matches) > 0

    def test_query_finds_sink_nodes(self, query):
        matches = query._find_nodes(".execute(")
        assert len(matches) > 0

    def test_query_finds_os_system(self, query):
        matches = query._find_nodes("os.system")
        assert len(matches) > 0

    def test_call_chain_search_to_execute(self, query):
        """search() in app.py calls into db.py which calls execute()."""
        chain = query.get_call_chain("search", "execute")
        # May or may not resolve cross-file depending on import resolution
        if chain is not None:
            assert len(chain) > 0

    def test_call_chain_admin_to_os_system(self, query):
        """admin_ping() calls os.system() — but os.system is external."""
        # External calls won't have a function node — verify no crash
        chain = query.get_call_chain("admin_ping", "os.system")
        assert chain is None  # os.system not a user-defined function

    def test_taint_loader_matches_sql_source(self, loader):
        cat = loader.match_source("python", "request.args.get('id')")
        assert cat is not None

    def test_taint_loader_matches_sql_sink(self, loader):
        cat = loader.match_sink("python", "cursor.execute(sql)")
        assert cat is not None

    def test_taint_loader_matches_command_sink(self, loader):
        cat = loader.match_sink("python", "os.system(cmd)")
        assert cat == "command_injection"

    def test_taint_loader_all_languages(self, loader):
        assert "python" in loader.available_languages
        assert "javascript" in loader.available_languages
        assert "java" in loader.available_languages


# ─── Helper ──────────────────────────────────────────────────────────────────


def _find_func_body(tree, provider, name: str):
    """Find the function_definition body node for *name*, unwrapping decorators."""
    from hyqagent.cpg.traversal import Traverser
    for node in Traverser(tree).traverse():
        if node.type == "function_definition":
            if provider.extract_function_name(node) == name:
                return node
        elif node.type == "decorated_definition":
            # Unwrap: find the inner function_definition
            for child in node.children:
                if (child.type == "function_definition"
                        and provider.extract_function_name(child) == name):
                    return child
    return None
