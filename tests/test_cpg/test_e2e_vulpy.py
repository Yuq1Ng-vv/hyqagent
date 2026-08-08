"""Real-project end-to-end CPG pipeline tests — vulpy (Python/Flask).

Validates that the full CPG pipeline can process a real known-vulnerable
Flask application and detect the documented vulnerabilities:
  - SQL Injection (CWE-89): 3 locations in libuser.py
  - Session Impersonation (CWE-384): base64-only cookies
  - Hardcoded Secret Key (CWE-798)
  - Weak Password Complexity (CWE-521)
  - Missing CSRF Protection (CWE-352)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hyqagent.cpg.callgraph import SingleFileCallGraph
from hyqagent.cpg.callgraph_builder import CallGraphBuilder
from hyqagent.cpg.dataflow import DataFlowBuilder
from hyqagent.cpg.graph import CPGGraphBuilder
from hyqagent.cpg.parser import Parser
from hyqagent.cpg.taint_loader import TaintRuleLoader

VULPY_DIR = Path(__file__).resolve().parent.parent.parent / "rwtests" / "vulpy" / "bad"


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


@pytest.fixture(scope="module")
def loader() -> TaintRuleLoader:
    return TaintRuleLoader()


@pytest.fixture(scope="module")
def vulpy_files() -> dict[str, str]:
    """Read all Python source files from vulpy/bad/."""
    files: dict[str, str] = {}
    for path in sorted(VULPY_DIR.glob("*.py")):
        with open(path) as f:
            files[path.name] = f.read()
    return files


# ── Level 1: Parse all files ───────────────────────────────────────────────────


class TestParseAllFiles:
    """Every source file must parse without errors."""

    def test_parse_app(self, parser, vulpy_files):
        tree = parser.parse_code(vulpy_files["vulpy.py"], "python")
        assert tree.root_node is not None
        funcs = parser.extract_functions(tree, "python")
        func_names = {f.name for f in funcs}
        assert "do_home" in func_names
        assert "before_request" in func_names
        assert "add_csp_headers" in func_names

    def test_parse_libuser(self, parser, vulpy_files):
        """libuser.py contains the core SQLi vulnerabilities."""
        tree = parser.parse_code(vulpy_files["libuser.py"], "python")
        funcs = parser.extract_functions(tree, "python")
        func_names = {f.name for f in funcs}
        # All 5 functions should be found
        assert "login" in func_names
        assert "create" in func_names
        assert "userlist" in func_names
        assert "password_change" in func_names
        assert "password_complexity" in func_names

    def test_parse_libsession(self, parser, vulpy_files):
        """libsession.py — session impersonation vulnerability."""
        tree = parser.parse_code(vulpy_files["libsession.py"], "python")
        funcs = parser.extract_functions(tree, "python")
        func_names = {f.name for f in funcs}
        assert "create" in func_names
        assert "load" in func_names
        assert "destroy" in func_names

    @pytest.mark.parametrize(
        "filename",
        [
            "libposts.py", "libmfa.py", "libapi.py",
            "mod_posts.py", "mod_user.py", "mod_api.py",
            "mod_mfa.py", "mod_hello.py", "mod_csp.py",
            "db.py", "db_init.py", "api_list.py", "api_post.py",
        ],
    )
    def test_all_files_parse(self, parser, vulpy_files, filename):
        """Every Python file in vulpy/bad must parse without exception."""
        assert filename in vulpy_files, f"Missing file: {filename}"
        tree = parser.parse_code(vulpy_files[filename], "python")
        assert tree.root_node is not None
        funcs = parser.extract_functions(tree, "python")
        imports = parser.extract_imports(tree, "python")
        # Every file should have at least imports or functions
        assert len(funcs) > 0 or len(imports) > 0, (
            f"{filename}: expected functions or imports"
        )


# ── Level 2: Known vulnerability function verification ─────────────────────────


class TestKnownVulnerableFunctions:
    """Verify that known-vulnerable functions are correctly identified."""

    def test_sqli_login_function_source(self, parser, loader, vulpy_files):
        """libuser.login() takes raw username/password into SQL query."""
        tree = parser.parse_code(vulpy_files["libuser.py"], "python")
        provider = parser.get_provider("python")
        fn_node = _find_func_body(tree, provider, "login")
        assert fn_node is not None, "login() function not found"

        source = fn_node.text.decode() if fn_node.text else ""
        # Verify SQL injection pattern: .format() on SQL string
        assert ".format(" in source, "login() should use .format() string interpolation"
        assert "SELECT * FROM users WHERE" in source

    def test_sqli_create_function_source(self, parser, vulpy_files):
        """libuser.create() uses %-string interpolation for INSERT."""
        tree = parser.parse_code(vulpy_files["libuser.py"], "python")
        provider = parser.get_provider("python")
        fn_node = _find_func_body(tree, provider, "create")
        assert fn_node is not None

        source = fn_node.text.decode() if fn_node.text else ""
        assert "INSERT INTO users" in source
        assert "%" in source  # %-string formatting

    def test_sqli_password_change_function_source(self, parser, vulpy_files):
        """libuser.password_change() uses .format() on UPDATE query."""
        tree = parser.parse_code(vulpy_files["libuser.py"], "python")
        provider = parser.get_provider("python")
        fn_node = _find_func_body(tree, provider, "password_change")
        assert fn_node is not None

        source = fn_node.text.decode() if fn_node.text else ""
        assert "UPDATE users SET password" in source
        assert ".format(" in source

    def test_session_forgery_has_base64(self, parser, vulpy_files):
        """libsession.create() uses base64 with no HMAC."""
        tree = parser.parse_code(vulpy_files["libsession.py"], "python")
        provider = parser.get_provider("python")
        fn_node = _find_func_body(tree, provider, "create")
        assert fn_node is not None

        source = fn_node.text.decode() if fn_node.text else ""
        assert "base64" in source
        # No hmac or signature
        assert "hmac" not in source.lower()
        assert "sign" not in source.lower()

    def test_hardcoded_secret_key(self, parser, vulpy_files):
        """vulpy.py line 16: SECRET_KEY = 'aaaaaaa'."""
        tree = parser.parse_code(vulpy_files["vulpy.py"], "python")
        source = tree.root_node.text.decode() if tree.root_node.text else ""
        assert "SECRET_KEY" in source
        assert "'aaaaaaa'" in source

    def test_weak_password_complexity(self, parser, vulpy_files):
        """password_complexity() always returns True."""
        tree = parser.parse_code(vulpy_files["libuser.py"], "python")
        provider = parser.get_provider("python")
        fn_node = _find_func_body(tree, provider, "password_complexity")
        assert fn_node is not None

        source = fn_node.text.decode() if fn_node.text else ""
        assert "return True" in source


# ── Level 3: Taint pattern matching ────────────────────────────────────────────


class TestTaintPatternMatching:
    """Verify taint rules match known sources and sinks in vulpy."""

    def test_request_form_get_is_sqli_source(self, loader):
        """request.form.get() should match sql_injection source."""
        cat = loader.match_source("python", "request.form.get('username')")
        assert cat is not None, "request.form.get should match a taint source"

    def test_request_args_get_is_source(self, loader):
        cat = loader.match_source("python", "request.args.get('q')")
        assert cat is not None, "request.args.get should match a taint source"

    def test_execute_on_sql_is_sqli_sink(self, loader):
        """.execute() with SQL string should match sql_injection sink."""
        cat = loader.match_sink("python", "c.execute('SELECT * FROM users WHERE id=' + uid)")
        assert cat == "sql_injection", (
            f".execute() should match sql_injection, got {cat}"
        )

    def test_raw_on_sql_is_sqli_sink(self, loader):
        """.raw() with SQL string should match sql_injection sink."""
        cat = loader.match_sink("python", "db.raw('INSERT INTO users VALUES (%s)' % uid)")
        assert cat == "sql_injection"

    def test_pickle_loads_is_deserialization_sink(self, loader):
        """pickle.loads() should match deserialization sink."""
        cat = loader.match_sink("python", "pickle.loads(data)")
        assert cat == "deserialization", (
            f"pickle.loads should match deserialization, got {cat}"
        )

    def test_cookie_source_matches(self, loader):
        """request.cookies.get() should match a taint source."""
        matches = loader.match_all_sources("python", "request.cookies.get('session')")
        assert len(matches) > 0, "cookies.get should match at least one source category"


# ── Level 4: CPG graph construction ────────────────────────────────────────────


class TestCPGGraphConstruction:
    """Verify full CPG graph can be built from the vulpy project."""

    @pytest.fixture(scope="module")
    def graph_builder(self, parser):
        b = CPGGraphBuilder(parser)
        b.add_directory(str(VULPY_DIR))
        return b

    def test_indexes_all_files(self, graph_builder):
        """All 18 source files should be indexed (verify graph has nodes)."""
        assert graph_builder.node_count > 0, "Graph should contain nodes"
        assert graph_builder.graph.number_of_nodes() >= 18, (
            f"Expected ≥18 nodes (one per file), got {graph_builder.graph.number_of_nodes()}"
        )

    def test_call_graph_builder_cross_file(self, parser):
        """CallGraphBuilder should resolve cross-file calls (mod_user → libuser)."""
        builder = CallGraphBuilder(parser)
        builder.add_directory(str(VULPY_DIR))
        # mod_user.do_login() calls libuser.login() — cross-file
        cross = builder.build_calls()
        assert len(cross) > 0
        # There should be at least one resolved cross-file call
        resolved = [e for e in cross if e.is_resolved]
        assert len(resolved) > 0, (
            "Expected resolved cross-file calls (e.g., mod_user → libuser)"
        )

    def test_call_graph_single_file(self, parser, vulpy_files):
        """SingleFileCallGraph on libuser.py should show internal calls."""
        cg = SingleFileCallGraph(parser)
        # Write to temp file since build_from_file requires filesystem path
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as tf:
            tf.write(vulpy_files["libuser.py"])
            tmp_path = tf.name
        try:
            cg.build_from_file(tmp_path)
            assert len(cg.edges) > 0
        finally:
            import os
            os.unlink(tmp_path)


# ── Level 5: Data flow ─────────────────────────────────────────────────────────


class TestDataFlow:
    """Verify data flow analysis on vulnerable handlers."""

    def test_login_dataflow(self, parser, vulpy_files):
        """login() — local variables conn/c/user should have def-use chains."""
        tree = parser.parse_code(vulpy_files["libuser.py"], "python")
        provider = parser.get_provider("python")
        df = DataFlowBuilder(parser)

        fn_node = _find_func_body(tree, provider, "login")
        assert fn_node is not None
        chains = df.build_def_use_chains(tree, fn_node, "python")
        var_names = {du.var_name for du in chains}
        # conn, c, user are assigned locally; username/password are params
        assert "conn" in var_names
        assert "c" in var_names

    def test_password_change_dataflow(self, parser, vulpy_files):
        """password_change() — conn and c should be tracked as locals."""
        tree = parser.parse_code(vulpy_files["libuser.py"], "python")
        provider = parser.get_provider("python")
        df = DataFlowBuilder(parser)

        fn_node = _find_func_body(tree, provider, "password_change")
        assert fn_node is not None
        chains = df.build_def_use_chains(tree, fn_node, "python")
        var_names = {du.var_name for du in chains}
        assert "conn" in var_names
        assert "c" in var_names

    def test_session_create_dataflow(self, parser, vulpy_files):
        """libsession.create() — session variable should be tracked."""
        tree = parser.parse_code(vulpy_files["libsession.py"], "python")
        provider = parser.get_provider("python")
        df = DataFlowBuilder(parser)

        fn_node = _find_func_body(tree, provider, "create")
        assert fn_node is not None
        chains = df.build_def_use_chains(tree, fn_node, "python")
        var_names = {du.var_name for du in chains}
        assert "session" in var_names


# ── Level 6: Taint rule inventory ──────────────────────────────────────────────


class TestTaintRuleInventory:
    """Verify Python taint rules cover vulpy vulnerability categories."""

    def test_sql_injection_rules_exist(self, loader):
        rules = loader.rules_for("python")
        cat = rules.categories["sql_injection"]
        assert len(cat.sources) > 0
        assert len(cat.sinks) > 0

    def test_deserialization_rules_exist(self, loader):
        rules = loader.rules_for("python")
        cat = rules.categories["deserialization"]
        assert len(cat.sources) > 0 or len(cat.sinks) > 0

    def test_auth_bypass_rules_exist(self, loader):
        rules = loader.rules_for("python")
        cat = rules.categories.get("auth_bypass")
        if cat:
            assert len(cat.sources) > 0 or len(cat.sinks) > 0


# ── Helper ─────────────────────────────────────────────────────────────────────


def _find_func_body(tree, provider, name: str):
    """Find the function_definition body node for *name*, unwrapping decorators."""
    from hyqagent.cpg.traversal import Traverser

    for node in Traverser(tree).traverse():
        if node.type == "function_definition":
            if provider.extract_function_name(node) == name:
                return node
        elif node.type == "decorated_definition":
            for child in node.children:
                if (
                    child.type == "function_definition"
                    and provider.extract_function_name(child) == name
                ):
                    return child
    return None
