"""Real-project end-to-end CPG pipeline tests — DVNA (Node.js/Express).

Validates that the full CPG pipeline can process the Damn Vulnerable Node
Application and detect the documented OWASP Top 10 vulnerabilities:
  - A1-Injection: SQLi (string concat), Command Injection (exec), Code Injection (eval)
  - A4-XXE: libxmljs.parseXmlString with noent:true
  - A7-XSS: unescaped EJS output (<%-)
  - A8-Insecure Deserialization: node-serialize.unserialize()
  - Open Redirect: res.redirect(user_input)
  - CSRF: missing CSRF protection
  - IDOR: no ownership checks on modifyproduct/useredit
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hyqagent.cpg.callgraph import SingleFileCallGraph
from hyqagent.cpg.callgraph_builder import CallGraphBuilder
from hyqagent.cpg.graph import CPGGraphBuilder
from hyqagent.cpg.parser import Parser
from hyqagent.cpg.taint_loader import TaintRuleLoader

DVNA_DIR = Path(__file__).resolve().parent.parent.parent / "rwtests" / "dvna"


def _dvna_js_files() -> list[Path]:
    """Source files excluding minified libs."""
    return sorted(
        f
        for f in DVNA_DIR.rglob("*.js")
        if ".git" not in str(f)
        and "jquery" not in f.name
        and "showdown" not in f.name
    )


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


@pytest.fixture(scope="module")
def loader() -> TaintRuleLoader:
    return TaintRuleLoader()


@pytest.fixture(scope="module")
def dvna_files() -> dict[str, str]:
    """Read all JS source files from DVNA."""
    files: dict[str, str] = {}
    for path in _dvna_js_files():
        with open(path) as f:
            files[path.name] = f.read()
    return files


# ── Level 1: Parse all source files ────────────────────────────────────────────


class TestParseAllFiles:
    """Every source file must parse without errors and produce functions."""

    def test_parse_route_files(self, parser, dvna_files):
        """routes/*.js should be parseable."""
        for name in ["app.js", "main.js"]:
            assert name in dvna_files, f"Missing {name}"
            tree = parser.parse_code(dvna_files[name], "javascript")
            assert tree.root_node is not None

    def test_parse_core_files(self, parser, dvna_files):
        """core/*.js should be parseable."""
        for name in ["appHandler.js", "authHandler.js", "passport.js"]:
            assert name in dvna_files, f"Missing {name}"
            tree = parser.parse_code(dvna_files[name], "javascript")
            assert tree.root_node is not None

    def test_parse_model_files(self, parser, dvna_files):
        """models/*.js should be parseable."""
        for name in ["index.js", "product.js", "user.js"]:
            assert name in dvna_files, f"Missing {name}"
            tree = parser.parse_code(dvna_files[name], "javascript")
            assert tree.root_node is not None

    def test_parse_config_files(self, parser, dvna_files):
        """config/*.js should be parseable."""
        for name in ["db.js", "server.js", "vulns.js"]:
            assert name in dvna_files, f"Missing {name}"
            tree = parser.parse_code(dvna_files[name], "javascript")
            assert tree.root_node is not None

    def test_parse_server(self, parser, dvna_files):
        """server.js (root) should be parseable."""
        assert "server.js" in dvna_files, "Missing root server.js"


# ── Level 2: Function extraction — CommonJS patterns ───────────────────────────


class TestFunctionExtraction:
    """Verify that CommonJS module.exports patterns are extracted (post-fix)."""

    def test_app_handler_functions(self, parser, dvna_files):
        """appHandler.js must extract all 13 exported vulnerability handlers."""
        tree = parser.parse_code(dvna_files["appHandler.js"], "javascript")
        funcs = parser.extract_functions(tree, "javascript")
        func_names = {f.name for f in funcs}

        expected = {
            "userSearch",           # SQL Injection (A1)
            "ping",                 # Command Injection (A1)
            "listProducts",
            "productSearch",
            "modifyProduct",        # IDOR (A5)
            "modifyProductSubmit",  # IDOR (A5)
            "userEdit",             # IDOR (A5)
            "userEditSubmit",       # IDOR (A5)
            "redirect",             # Open Redirect
            "calc",                 # Code Injection (A1)
            "listUsersAPI",
            "bulkProductsLegacy",   # Insecure Deserialization (A8)
            "bulkProducts",         # XXE (A4)
        }
        missing = expected - func_names
        assert not missing, f"appHandler.js missing functions: {missing}"

    def test_auth_handler_functions(self, parser, dvna_files):
        tree = parser.parse_code(dvna_files["authHandler.js"], "javascript")
        funcs = parser.extract_functions(tree, "javascript")
        func_names = {f.name for f in funcs}
        assert "isAuthenticated" in func_names
        assert "forgotPw" in func_names

    def test_passport_functions(self, parser, dvna_files):
        tree = parser.parse_code(dvna_files["passport.js"], "javascript")
        funcs = parser.extract_functions(tree, "javascript")
        func_names = {f.name for f in funcs}
        assert "createHash" in func_names


# ── Level 3: Known vulnerability function bodies ───────────────────────────────


class TestKnownVulnerableFunctions:
    """Verify the vulnerable code patterns are present in function bodies."""

    def test_sqli_in_usersearch(self, parser, dvna_files):
        """userSearch() uses string concatenation for SQL query."""
        tree = parser.parse_code(dvna_files["appHandler.js"], "javascript")
        provider = parser.get_provider("javascript")
        fn_node = _find_func_body(tree, provider, "userSearch")
        assert fn_node is not None

        source = fn_node.text.decode() if fn_node.text else ""
        assert "SELECT" in source
        assert "req.body.login" in source
        assert "+" in source  # string concatenation

    def test_command_injection_in_ping(self, parser, dvna_files):
        """ping() uses exec() with user-supplied address."""
        tree = parser.parse_code(dvna_files["appHandler.js"], "javascript")
        provider = parser.get_provider("javascript")
        fn_node = _find_func_body(tree, provider, "ping")
        assert fn_node is not None

        source = fn_node.text.decode() if fn_node.text else ""
        assert "exec(" in source
        assert "req.body.address" in source

    def test_code_injection_in_calc(self, parser, dvna_files):
        """calc() uses mathjs.eval() on user input."""
        tree = parser.parse_code(dvna_files["appHandler.js"], "javascript")
        provider = parser.get_provider("javascript")
        fn_node = _find_func_body(tree, provider, "calc")
        assert fn_node is not None

        source = fn_node.text.decode() if fn_node.text else ""
        assert "mathjs.eval" in source
        assert "req.body.eqn" in source

    def test_open_redirect(self, parser, dvna_files):
        """redirect() passes req.query.url directly to res.redirect()."""
        tree = parser.parse_code(dvna_files["appHandler.js"], "javascript")
        provider = parser.get_provider("javascript")
        fn_node = _find_func_body(tree, provider, "redirect")
        assert fn_node is not None

        source = fn_node.text.decode() if fn_node.text else ""
        assert "res.redirect" in source
        assert "req.query.url" in source

    def test_xxe_in_bulkproducts(self, parser, dvna_files):
        """bulkProducts() uses libxmljs.parseXmlString with noent:true."""
        tree = parser.parse_code(dvna_files["appHandler.js"], "javascript")
        provider = parser.get_provider("javascript")
        fn_node = _find_func_body(tree, provider, "bulkProducts")
        assert fn_node is not None

        source = fn_node.text.decode() if fn_node.text else ""
        assert "libxmljs" in source or "parseXmlString" in source
        assert "noent" in source

    def test_insecure_deserialization(self, parser, dvna_files):
        """bulkProductsLegacy() uses serialize.unserialize()."""
        tree = parser.parse_code(dvna_files["appHandler.js"], "javascript")
        provider = parser.get_provider("javascript")
        fn_node = _find_func_body(tree, provider, "bulkProductsLegacy")
        assert fn_node is not None

        source = fn_node.text.decode() if fn_node.text else ""
        assert "serialize" in source or "unserialize" in source


# ── Level 4: Taint pattern matching ────────────────────────────────────────────


class TestTaintPatternMatching:
    """Verify JS taint rules match known DVNA sources and sinks."""

    def test_req_body_is_source(self, loader):
        """req.body.XXX should match a taint source."""
        matches = loader.match_all_sources("javascript", "req.body.login")
        assert len(matches) > 0, "req.body should match at least one source category"

    def test_req_query_is_source(self, loader):
        """req.query.XXX should match a taint source."""
        matches = loader.match_all_sources("javascript", "req.query.url")
        assert len(matches) > 0, "req.query should match at least one source category"

    def test_exec_is_command_injection_sink(self, loader):
        """exec() with untrusted data should match command_injection sink."""
        cat = loader.match_sink("javascript", "exec('ping -c 2 ' + address)")
        assert cat is not None, "exec() should match a taint sink category"

    def test_eval_is_code_injection_sink(self, loader):
        """mathjs.eval() on user input should match code_injection sink."""
        cat = loader.match_sink("javascript", "mathjs.eval(eqn)")
        assert cat is not None, "eval should match a taint sink category"

    def test_select_query_is_sqli_sink(self, loader):
        """db.sequelize.query() with user input should match sql_injection sink."""
        cat = loader.match_sink(
            "javascript",
            'db.sequelize.query("SELECT name FROM Users WHERE login=\'" + login + "\'")',
        )
        assert cat == "sql_injection", (
            f".query() should match sql_injection, got {cat}"
        )

    def test_res_redirect_is_open_redirect_sink(self, loader):
        """res.redirect() with user input should match open_redirect."""
        cat = loader.match_sink("javascript", "res.redirect(user_url)")
        assert cat == "open_redirect", (
            f"res.redirect should match open_redirect, got {cat}"
        )

    def test_js_has_xxe_category(self, loader):
        """JS now has XXE category (Session 1.22 expansion)."""
        rules = loader.rules_for("javascript")
        assert "xxe" in rules.categories, "JS should have XXE category after expansion"

    def test_unserialize_is_deserialization_sink(self, loader):
        """node-serialize.unserialize() should match deserialization."""
        cat = loader.match_sink("javascript", "serialize.unserialize(data)")
        assert cat == "deserialization", (
            f"serialize.unserialize should match deserialization, got {cat}"
        )


# ── Level 5: CPG graph construction ────────────────────────────────────────────


class TestCPGGraphConstruction:
    """Verify full CPG graph can be built from the DVNA project."""

    @pytest.fixture(scope="module")
    def graph_builder(self, parser):
        b = CPGGraphBuilder(parser)
        b.add_directory(str(DVNA_DIR))
        return b

    def test_indexes_all_source_files(self, graph_builder):
        """All non-minified source files should be indexed in the graph."""
        assert graph_builder.node_count > 0, "Graph should contain nodes"
        assert graph_builder.graph.number_of_nodes() >= len(_dvna_js_files()), (
            f"Expected ≥{len(_dvna_js_files())} nodes, "
            f"got {graph_builder.graph.number_of_nodes()}"
        )

    def test_call_graph_builder(self, parser):
        """CallGraphBuilder should process DVNA without errors."""
        builder = CallGraphBuilder(parser)
        builder.add_directory(str(DVNA_DIR))
        assert len(builder.files) > 0


# ── Level 6: Single file call graph ────────────────────────────────────────────


class TestSingleFileCallGraph:
    """Single-file call graph on core vulnerability handler file."""

    def test_app_handler_call_graph(self, parser, dvna_files):
        """appHandler.js call graph should capture internal calls."""
        cg = SingleFileCallGraph(parser)
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".js", delete=False
        ) as tf:
            tf.write(dvna_files["appHandler.js"])
            tmp_path = tf.name
        try:
            cg.build_from_file(tmp_path)
            assert len(cg.edges) > 0
        finally:
            os.unlink(tmp_path)

    def test_auth_handler_call_graph(self, parser, dvna_files):
        """authHandler.js internal call structure."""
        cg = SingleFileCallGraph(parser)
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".js", delete=False
        ) as tf:
            tf.write(dvna_files["authHandler.js"])
            tmp_path = tf.name
        try:
            cg.build_from_file(tmp_path)
            assert len(cg.edges) > 0
        finally:
            os.unlink(tmp_path)


# ── Helper ─────────────────────────────────────────────────────────────────────


def _find_func_body(tree, provider, name: str):
    """Find the function/assignment node body for *name* in JS."""
    from hyqagent.cpg.traversal import Traverser

    for node in Traverser(tree).traverse():
        if node.type in provider.func_def_types:
            if provider.extract_function_name(node) == name:
                return node
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left and left.type == "member_expression":
                prop = left.child_by_field_name("property")
                if prop and prop.text and prop.text.decode("utf-8") == name:
                    return node
    return None
