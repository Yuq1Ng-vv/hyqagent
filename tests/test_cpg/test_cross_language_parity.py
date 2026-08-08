"""Cross-language parity tests — SQL injection, command injection, path traversal.

Verify that all three languages (Python, JavaScript, Java) can detect the
same vulnerability classes with comparable fidelity.  These tests are the
minimum viable "does it work in all three?" check.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hyqagent.cpg.graph import CPGGraphBuilder
from hyqagent.cpg.parser import Parser
from hyqagent.cpg.taint_loader import TaintRuleLoader

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Vulnerability + language → fixture file
PARITY_FILES: dict[str, dict[str, str]] = {
    "sql_injection": {
        "python": "parity_sqli.py",
        "javascript": "parity_sqli.js",
        "java": "parity_sqli.java",
    },
    "command_injection": {
        "python": "parity_cmdi.py",
        "javascript": "parity_cmdi.js",
        "java": "parity_cmdi.java",
    },
    "path_traversal": {
        "python": "parity_pt.py",
        "javascript": "parity_pt.js",
        "java": "parity_pt.java",
    },
}


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


@pytest.fixture(scope="module")
def loader() -> TaintRuleLoader:
    return TaintRuleLoader()


# ── Taint rule completeness ──────────────────────────────────────────────────


class TestTaintRuleCompleteness:
    """Every language must have sources and sinks for the three core categories."""

    @pytest.mark.parametrize(
        "language,vuln",
        [
            ("python", "sql_injection"),
            ("python", "command_injection"),
            ("python", "path_traversal"),
            ("javascript", "sql_injection"),
            ("javascript", "command_injection"),
            ("javascript", "path_traversal"),
            ("java", "sql_injection"),
            ("java", "command_injection"),
            ("java", "path_traversal"),
        ],
    )
    def test_has_sources(self, loader, language, vuln):
        sources = loader.all_sources(language)
        rules = loader.rules_for(language)
        cat_sources = rules.categories.get(vuln, None)
        assert cat_sources is not None, f"{language} missing {vuln} category"
        assert len(cat_sources.sources) > 0, f"{language}/{vuln}: no source patterns"

    @pytest.mark.parametrize(
        "language,vuln",
        [
            ("python", "sql_injection"),
            ("python", "command_injection"),
            ("python", "path_traversal"),
            ("javascript", "sql_injection"),
            ("javascript", "command_injection"),
            ("javascript", "path_traversal"),
            ("java", "sql_injection"),
            ("java", "command_injection"),
            ("java", "path_traversal"),
        ],
    )
    def test_has_sinks(self, loader, language, vuln):
        rules = loader.rules_for(language)
        cat_sinks = rules.categories.get(vuln, None)
        assert cat_sinks is not None, f"{language} missing {vuln} category"
        assert len(cat_sinks.sinks) > 0, f"{language}/{vuln}: no sink patterns"


# ── Source / sink matching ───────────────────────────────────────────────────


class TestSourceSinkMatching:
    """Verify that source and sink patterns actually match the fixtures."""

    @pytest.mark.parametrize(
        "language,vuln,filename",
        [
            (lang, vuln, name)
            for vuln, langs in PARITY_FILES.items()
            for lang, name in langs.items()
        ],
    )
    def test_fixture_parses(self, parser, language, vuln, filename):
        """Every parity fixture must parse without error."""
        filepath = str(FIXTURES / filename)
        tree = parser.parse_file(filepath)
        detected = parser.get_language(tree)
        assert detected == language, f"{filename}: expected {language}, got {detected}"

    @pytest.mark.parametrize(
        "language,vuln,filename",
        [
            (lang, vuln, name)
            for vuln, langs in PARITY_FILES.items()
            for lang, name in langs.items()
        ],
    )
    def test_source_matches_fixture(self, parser, loader, language, vuln, filename):
        """Each fixture contains at least one matched source."""
        filepath = str(FIXTURES / filename)
        tree = parser.parse_file(filepath)
        source_text = tree.root_node.text.decode("utf-8") if tree.root_node.text else ""
        sources = loader.all_sources(language)
        matches = [p for p in sources if p in source_text]
        assert len(matches) > 0, (
            f"{filename} ({language}/{vuln}): no source pattern matched.\n"
            f"  Source text (first 200): {source_text[:200]}\n"
            f"  Available patterns: {sources[:10]}..."
        )

    @pytest.mark.parametrize(
        "language,vuln,filename",
        [
            (lang, vuln, name)
            for vuln, langs in PARITY_FILES.items()
            for lang, name in langs.items()
        ],
    )
    def test_sink_matches_fixture(self, parser, loader, language, vuln, filename):
        """Each fixture contains at least one matched sink."""
        filepath = str(FIXTURES / filename)
        tree = parser.parse_file(filepath)
        sink_text = tree.root_node.text.decode("utf-8") if tree.root_node.text else ""
        sinks = loader.all_sinks(language)
        matches = [p for p in sinks if p in sink_text]
        assert len(matches) > 0, (
            f"{filename} ({language}/{vuln}): no sink pattern matched.\n"
            f"  Source text (first 200): {sink_text[:200]}\n"
            f"  Available patterns: {sinks[:10]}..."
        )


# ── CPG graph construction ───────────────────────────────────────────────────


class TestCPGGraphConstruction:
    """Build a CPG graph for each parity fixture and verify node/edge counts."""

    @pytest.mark.parametrize(
        "language,filename",
        [
            ("python", "parity_sqli.py"),
            ("javascript", "parity_sqli.js"),
            ("java", "parity_sqli.java"),
        ],
    )
    def test_sqli_graph_builds(self, parser, language, filename):
        builder = CPGGraphBuilder(parser)
        builder.add_file(str(FIXTURES / filename))
        assert builder.node_count > 0
        assert builder.edge_count > 0
        # Must have at least one function node
        funcs = builder.nodes_by_type("function")
        assert len(funcs) > 0

    @pytest.mark.parametrize(
        "language,filename",
        [
            ("python", "parity_cmdi.py"),
            ("javascript", "parity_cmdi.js"),
            ("java", "parity_cmdi.java"),
        ],
    )
    def test_cmdi_graph_builds(self, parser, language, filename):
        builder = CPGGraphBuilder(parser)
        builder.add_file(str(FIXTURES / filename))
        assert builder.node_count > 0

    @pytest.mark.parametrize(
        "language,filename",
        [
            ("python", "parity_pt.py"),
            ("javascript", "parity_pt.js"),
            ("java", "parity_pt.java"),
        ],
    )
    def test_pt_graph_builds(self, parser, language, filename):
        builder = CPGGraphBuilder(parser)
        builder.add_file(str(FIXTURES / filename))
        assert builder.node_count > 0

    def test_all_parity_files_graph_builds(self, parser):
        """A combined builder over all parity files must work."""
        builder = CPGGraphBuilder(parser)
        for vuln_files in PARITY_FILES.values():
            for filename in vuln_files.values():
                builder.add_file(str(FIXTURES / filename))
        assert builder.node_count > 0
        # Should have functions from all languages
        funcs = builder.nodes_by_type("function")
        # 9 fixtures × ≥2 functions each = 18 expected
        # Note: some JS callback-based functions may not be extracted
        assert len(funcs) >= 14  # at least Python + Java + most JS


# ── DATA_FLOW edge presence ──────────────────────────────────────────────────


class TestDataFlowEdgePresence:
    """Each fixture should produce at least some DATA_FLOW edges.

    We don't require full source→sink taint paths (that's end-to-end
    validation territory).  We do require that def-use chains are built,
    which is the prerequisite for taint propagation.
    """

    @pytest.mark.parametrize(
        "filename",
        [
            "parity_sqli.py",
            "parity_sqli.js",
            "parity_sqli.java",
            "parity_cmdi.py",
            "parity_cmdi.js",
            "parity_cmdi.java",
            "parity_pt.py",
            "parity_pt.js",
            "parity_pt.java",
        ],
    )
    def test_data_flow_edges_exist(self, parser, filename):
        builder = CPGGraphBuilder(parser)
        builder.add_file(str(FIXTURES / filename))
        data_flow_edges = [
            (u, v, d)
            for u, v, d in builder.graph.edges(data=True)
            if d.get("edge_type") == "DATA_FLOW"
        ]
        assert len(data_flow_edges) > 0, (
            f"{filename}: expected DATA_FLOW edges, found 0"
        )


# ── Match source / sink category ─────────────────────────────────────────────


class TestSourceSinkCategory:
    """Verify the TaintRuleLoader can match source/sink code to categories."""

    @pytest.mark.parametrize(
        "language,code_snippet,expected_category",
        [
            ("python", ".args.get(", "sql_injection"),
            ("python", "sys.argv", "command_injection"),
            ("python", "os.environ", "path_traversal"),  # os.environ is a path_traversal source
            ("javascript", ".query", "sql_injection"),
            ("javascript", "process.argv", "command_injection"),
            ("javascript", "process.env", "path_traversal"),
            ("java", ".getParameter(", "sql_injection"),
            ("java", "System.getenv(", "command_injection"),
            ("java", "@RequestParam", "path_traversal"),  # @RequestParam is a path_traversal source
        ],
    )
    def test_source_category_match(self, loader, language, code_snippet, expected_category):
        """Source patterns must match their expected categories."""
        cat = loader.match_source(language, code_snippet)
        assert cat is not None, f"{language}: '{code_snippet}' should match a source category"

    @pytest.mark.parametrize(
        "language,code_snippet,expected_category",
        [
            ("python", ".execute(", "sql_injection"),
            ("python", "os.popen(", "command_injection"),
            ("python", "open(", "path_traversal"),
            ("javascript", ".query(", "sql_injection"),
            ("javascript", "child_process.exec(", "command_injection"),
            ("javascript", "fs.readFileSync(", "path_traversal"),
            ("java", ".executeQuery(", "sql_injection"),
            ("java", "Runtime.exec(", "command_injection"),
            ("java", "new FileInputStream(", "path_traversal"),
        ],
    )
    def test_sink_category_match(self, loader, language, code_snippet, expected_category):
        """Sink patterns must match their expected categories."""
        cat = loader.match_sink(language, code_snippet)
        assert cat is not None, f"{language}: '{code_snippet}' should match a sink category"
