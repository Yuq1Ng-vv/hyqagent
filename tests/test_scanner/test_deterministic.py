"""Tests for scanner/deterministic.py — DeterministicScanner + Finding + ScanResult."""

from __future__ import annotations

import tempfile
from pathlib import Path

import networkx as nx

from hyqagent.cpg.query import CPGQuery, GraphNode, GraphPath
from hyqagent.scanner.annotator import (
    AnnotatedPath,
    PathLabel,
    SanitizerStatus,
)
from hyqagent.scanner.deterministic import DeterministicScanner, Finding, ScanResult

# ── Stubs ───────────────────────────────────────────────────────────────────


class _FakeCategory:
    def __init__(self, sanitizers=None):
        self.sanitizers = sanitizers or []


class _FakeRules:
    def __init__(self, sanitizers=None):
        self.categories = {
            "sql_injection": _FakeCategory(sanitizers=sanitizers or []),
        }


class _FakeTaintLoader:
    def __init__(self, sources=None, sinks=None, sanitizers=None):
        self._sources = sources or []
        self._sinks = sinks or []
        self._sanitizers = sanitizers or []
        self.available_languages = ["python"]

    def all_sinks(self, language: str) -> list[str]:
        return list(self._sinks)

    def all_sources(self, language: str) -> list[str]:
        return list(self._sources)

    def match_source(self, language: str, text: str) -> str | None:
        for pat in self._sources:
            if pat.lower() in text.lower():
                return "sql_injection"
        return None

    def match_sink(self, language: str, text: str) -> str | None:
        for pat in self._sinks:
            if pat.lower() in text.lower():
                return "sql_injection"
        return None

    def rules_for(self, language: str):
        return _FakeRules(sanitizers=self._sanitizers)


class _FakeSinkDiscoverer:
    def discover_heuristic_sinks(self, language, score_threshold=60):
        return []

    def is_potentially_dangerous(self, node_id, language=""):
        return False, 0


class _FakeSourceChecker:
    def find_exposed_no_source(self):
        return []

    def find_uncovered_sinks(self, language):
        return []


class _FakeFramework:
    """Stub Flask/Django-like extractor with endpoints."""

    def __init__(self, endpoints=None):
        self.endpoints = endpoints or []


class _FakeEndpoint:
    def __init__(
        self,
        route="/",
        handler_func="index",
        file_path="app.py",
        line=1,
        auth_required=True,
        framework="flask",
        methods=None,
    ):
        self.route = route
        self.handler_func = handler_func
        self.file_path = file_path
        self.line = line
        self.auth_required = auth_required
        self.framework = framework
        self.methods = methods or ["GET"]


class _FakeCoverageTracker:
    def __init__(self):
        self._endpoint_total = 10
        self._endpoint_analyzed = 8
        self._sink_total = 20
        self._sink_labeled = 14

    def compute_coverage(self):
        from hyqagent.cpg.types import CoverageReport

        return CoverageReport(
            endpoint_total=self._endpoint_total,
            endpoint_analyzed=self._endpoint_analyzed,
            endpoint_coverage_ratio=0.8,
            sink_total=self._sink_total,
            sink_labeled=self._sink_labeled,
            sink_coverage_ratio=0.7,
            blind_spots=[],
        )


class _FakeAnnotator:
    """Fake annotator that returns pre-built annotated paths."""

    def __init__(self, paths=None):
        self._paths = paths or []

    def annotate(self, language: str) -> list[AnnotatedPath]:
        return list(self._paths)


def _make_annotated_path(label: PathLabel, sanitizer_status=None, metadata=None) -> AnnotatedPath:
    """Build a minimal AnnotatedPath for testing."""
    node1 = GraphNode(
        node_id="src", node_type="assignment", location="app.py:2", source="request.args.get('id')"
    )
    node2 = GraphNode(
        node_id="sink", node_type="assignment", location="app.py:12", source="cursor.execute(sql)"
    )
    path = GraphPath(nodes=[node1, node2], edges=["DATA_FLOW"])
    return AnnotatedPath(
        path=path,
        label=label,
        sanitizer_status=sanitizer_status,
        metadata=metadata or {},
    )


# ── Finding dataclass ───────────────────────────────────────────────────────


class TestFinding:
    def test_fields_default(self):
        f = Finding(
            id="f1",
            rule_id="R-001",
            severity="high",
            title="Test",
            description="desc",
            file_path="app.py",
            line=42,
        )
        assert f.id == "f1"
        assert f.confidence == "high"
        assert f.category == ""
        assert f.remediation == ""
        assert f.code_snippet == ""
        assert f.metadata == {}

    def test_fields_full(self):
        f = Finding(
            id="f2",
            rule_id="R-002",
            severity="critical",
            title="Critical bug",
            description="Something bad",
            file_path="views.py",
            line=99,
            code_snippet="evil()",
            category="injection",
            confidence="medium",
            remediation="Use param binding",
            metadata={"cwe": "CWE-89"},
        )
        assert f.severity == "critical"
        assert f.category == "injection"
        assert f.confidence == "medium"
        assert f.metadata["cwe"] == "CWE-89"


# ── ScanResult dataclass ────────────────────────────────────────────────────


class TestScanResult:
    def test_defaults(self):
        r = ScanResult()
        assert r.findings == []
        assert r.annotated_paths == []
        assert r.coverage is None
        assert r.coverage_summary is None
        assert r.stats == {}

    def test_with_data(self):
        f = Finding(
            id="f1",
            rule_id="R-001",
            severity="high",
            title="T",
            description="D",
            file_path="a.py",
            line=1,
        )
        r = ScanResult(
            findings=[f],
            stats={"total_findings": 1, "secret": 1},
        )
        assert len(r.findings) == 1
        assert r.stats["total_findings"] == 1


# ── DeterministicScanner ────────────────────────────────────────────────────


class TestDeterministicScanner:
    """Integration tests for the full scanner."""

    def test_init(self):
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        fake_annotator = _FakeAnnotator()
        scanner = DeterministicScanner(g, query, tl, fake_annotator)
        assert scanner._graph is g
        assert scanner._rules_dir.name == "rules"

    def test_scan_cpg_taint_delegates_to_annotator(self):
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        ap = _make_annotated_path(PathLabel.CONFIRMED_TAINT)
        annotator = _FakeAnnotator(paths=[ap])
        scanner = DeterministicScanner(g, query, tl, annotator)

        result = scanner.scan_cpg_taint("python")
        assert len(result) == 1
        assert result[0].label == PathLabel.CONFIRMED_TAINT

    def test_scan_all_empty_graph(self):
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        annotator = _FakeAnnotator()
        scanner = DeterministicScanner(g, query, tl, annotator)

        result = scanner.scan_all([], "python")
        assert isinstance(result, ScanResult)
        assert len(result.findings) == 0

    def test_scan_all_with_taint_findings(self):
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        ap = _make_annotated_path(PathLabel.CONFIRMED_TAINT)
        annotator = _FakeAnnotator(paths=[ap])
        scanner = DeterministicScanner(g, query, tl, annotator)

        result = scanner.scan_all([], "python")
        # confirmed_taint → becomes a Finding
        assert len(result.findings) >= 1
        taint_finding = result.findings[0]
        assert taint_finding.rule_id == "TAINT-001"
        assert taint_finding.severity == "high"
        assert taint_finding.confidence == "high"

    def test_scan_all_with_cg_annotated_paths(self):
        """Conditional sanitized paths → medium confidence."""
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        ap = _make_annotated_path(
            PathLabel.CONDITIONAL_SANITIZED,
            sanitizer_status=SanitizerStatus.CONDITIONAL,
        )
        annotator = _FakeAnnotator(paths=[ap])
        scanner = DeterministicScanner(g, query, tl, annotator)

        result = scanner.scan_all([], "python")
        assert len(result.findings) >= 1
        cs_finding = [
            f for f in result.findings if f.rule_id == "TAINT-001" and f.confidence == "medium"
        ]
        assert len(cs_finding) >= 1

    def test_scan_all_with_sanitized_path_not_converted(self):
        """Sanitized (MUST_EXECUTE) paths should NOT become Findings."""
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        ap = _make_annotated_path(
            PathLabel.SANITIZED_TAINT,
            sanitizer_status=SanitizerStatus.MUST_EXECUTE,
        )
        annotator = _FakeAnnotator(paths=[ap])
        scanner = DeterministicScanner(g, query, tl, annotator)

        result = scanner.scan_all([], "python")
        taint_findings = [f for f in result.findings if f.rule_id == "TAINT-001"]
        assert len(taint_findings) == 0

    def test_scan_all_annotated_paths_preserved(self):
        """All annotated paths (even non-finding ones) go to annotated_paths."""
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        paths = [
            _make_annotated_path(PathLabel.CONFIRMED_TAINT),
            _make_annotated_path(PathLabel.SANITIZED_TAINT),
            _make_annotated_path(PathLabel.HEURISTIC_SINK),
        ]
        annotator = _FakeAnnotator(paths=paths)
        scanner = DeterministicScanner(g, query, tl, annotator)

        result = scanner.scan_all([], "python")
        assert len(result.annotated_paths) == 3

    def test_scan_all_generates_stats(self):
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        ap = _make_annotated_path(PathLabel.CONFIRMED_TAINT)
        annotator = _FakeAnnotator(paths=[ap])
        scanner = DeterministicScanner(g, query, tl, annotator)

        result = scanner.scan_all([], "python")
        assert "total_findings" in result.stats
        assert result.stats["total_findings"] >= 0


class TestDeterministicScannerMissingAuth:
    """Tests for scan_missing_auth()."""

    def test_no_frameworks_returns_empty(self):
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        annotator = _FakeAnnotator()
        scanner = DeterministicScanner(g, query, tl, annotator)

        findings = scanner.scan_missing_auth()
        assert findings == []

    def test_authenticated_endpoint_not_reported(self):
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        annotator = _FakeAnnotator()
        ep = _FakeEndpoint(auth_required=True)
        fw = _FakeFramework([ep])
        scanner = DeterministicScanner(g, query, tl, annotator, frameworks=[fw])

        findings = scanner.scan_missing_auth()
        assert len(findings) == 0

    def test_unauthenticated_endpoint_reported(self):
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        annotator = _FakeAnnotator()
        ep = _FakeEndpoint(
            auth_required=False,
            route="/admin",
            handler_func="admin_panel",
            file_path="admin.py",
            line=42,
        )
        fw = _FakeFramework([ep])
        scanner = DeterministicScanner(g, query, tl, annotator, frameworks=[fw])

        findings = scanner.scan_missing_auth()
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "AUTH-001"
        assert f.severity == "high"
        assert f.category == "missing_auth"
        assert "admin_panel" in f.description
        assert "/admin" in f.description

    def test_multiple_mixed_endpoints(self):
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        annotator = _FakeAnnotator()
        eps = [
            _FakeEndpoint(auth_required=True),
            _FakeEndpoint(
                auth_required=False,
                route="/api/v2",
                handler_func="api_v2",
                file_path="api.py",
                line=10,
            ),
            _FakeEndpoint(
                auth_required=False,
                route="/debug",
                handler_func="debug_view",
                file_path="debug.py",
                line=5,
            ),
        ]
        fw = _FakeFramework(eps)
        scanner = DeterministicScanner(g, query, tl, annotator, frameworks=[fw])

        findings = scanner.scan_missing_auth()
        assert len(findings) == 2

    def test_auth_none_not_reported(self):
        """auth_required=None means 'unknown' — don't report."""
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        annotator = _FakeAnnotator()
        ep = _FakeEndpoint(auth_required=None)
        fw = _FakeFramework([ep])
        scanner = DeterministicScanner(g, query, tl, annotator, frameworks=[fw])

        findings = scanner.scan_missing_auth()
        assert len(findings) == 0


class TestDeterministicScannerRegexScans:
    """Tests for scan_secrets(), scan_dangerous_calls(), scan_config_issues()."""

    def _make_scanner(self, frameworks=None):
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        annotator = _FakeAnnotator()
        return DeterministicScanner(g, query, tl, annotator, frameworks=frameworks or [])

    def test_scan_secrets_empty(self):
        scanner = self._make_scanner()
        findings = scanner.scan_secrets([])
        assert findings == []

    def test_scan_secrets_detects_hardcoded_password(self):
        scanner = self._make_scanner()
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write('password = "super_secret_123"\n')
            f.write('x = "safe stuff"\n')
            f.flush()
            fpath = f.name

        try:
            findings = scanner.scan_secrets([fpath])
            assert len(findings) >= 1
            # Should find a password assignment
            pw_findings = [f for f in findings if f.rule_id == "SECRET-001"]
            assert len(pw_findings) >= 1
            assert pw_findings[0].file_path == fpath
            assert pw_findings[0].line == 1
        finally:
            Path(fpath).unlink()

    def test_scan_secrets_detects_api_key(self):
        scanner = self._make_scanner()
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write("# config\n")
            f.write('API_KEY = "sk-abcdefgh12345678"\n')
            f.flush()
            fpath = f.name

        try:
            findings = scanner.scan_secrets([fpath])
            api_findings = [f for f in findings if f.rule_id == "SECRET-002"]
            assert len(api_findings) >= 1
            assert api_findings[0].line == 2
        finally:
            Path(fpath).unlink()

    def test_scan_dangerous_calls_detects_eval(self):
        scanner = self._make_scanner()
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write("result = eval(user_input)\n")
            f.flush()
            fpath = f.name

        try:
            findings = scanner.scan_dangerous_calls([fpath], "python")
            assert len(findings) >= 1
            assert findings[0].rule_id.startswith("DANGER-")
        finally:
            Path(fpath).unlink()

    def test_scan_dangerous_calls_language_filter(self):
        """Java-only rule should NOT match when language=python."""
        scanner = self._make_scanner()
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write("Runtime.getRuntime().exec(cmd)\n")
            f.flush()
            fpath = f.name

        try:
            findings = scanner.scan_dangerous_calls([fpath], "python")
            # DANGER-005 is Java-only, should NOT match for python
            java_exec_findings = [f for f in findings if f.rule_id == "DANGER-005"]
            assert len(java_exec_findings) == 0
        finally:
            Path(fpath).unlink()

    def test_scan_config_issues_detects_debug_true(self):
        scanner = self._make_scanner()
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write("DEBUG = True\n")
            f.flush()
            fpath = f.name

        try:
            findings = scanner.scan_config_issues([fpath], "python")
            assert len(findings) >= 1
            assert findings[0].rule_id == "CONFIG-001"
        finally:
            Path(fpath).unlink()

    def test_scan_dangerous_calls_subprocess(self):
        scanner = self._make_scanner()
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write("subprocess.call(['rm', '-rf', path])\n")
            f.flush()
            fpath = f.name

        try:
            findings = scanner.scan_dangerous_calls([fpath], "python")
            sub_findings = [f for f in findings if f.rule_id == "DANGER-004"]
            assert len(sub_findings) >= 1
        finally:
            Path(fpath).unlink()

    def test_scan_dangerous_calls_detects_stringsubstitutor(self):
        """DANGER-053 should flag Apache Commons Text interpolation (CVE-2022-42889)."""
        scanner = self._make_scanner()
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".java",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write("String out = StringSubstitutor.createInterpolator().replace(input);\n")
            f.flush()
            fpath = f.name

        try:
            findings = scanner.scan_dangerous_calls([fpath], "java")
            ss_findings = [f for f in findings if f.rule_id == "DANGER-053"]
            assert len(ss_findings) >= 1
            assert ss_findings[0].cwe_id == "CWE-94"
        finally:
            Path(fpath).unlink()

    def test_scan_config_issues_detects_xxljob_access_token(self):
        """CONFIG-042 should flag xxl-job default accessToken (CVE-2020-29204)."""
        scanner = self._make_scanner()
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".java",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write('    @Value("${xxl.job.accessToken}")\n')
            f.write("    private String accessToken;\n")
            f.flush()
            fpath = f.name

        try:
            findings = scanner.scan_config_issues([fpath], "java")
            xxl_findings = [f for f in findings if f.rule_id == "CONFIG-042"]
            assert len(xxl_findings) >= 1
            assert xxl_findings[0].cwe_id == "CWE-306"
        finally:
            Path(fpath).unlink()

    def test_scan_dangerous_calls_skips_comment_lines(self):
        """Comment lines mentioning a dangerous API must not be flagged."""
        scanner = self._make_scanner()
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".java",
            delete=False,
            encoding="utf-8",
        ) as f:
            # javadoc continuation + line comment — both must be ignored
            f.write(" * StringSubstitutor.createInterpolator().replace(input);\n")
            f.write("// StringSubstitutor.createInterpolator().replace(input);\n")
            f.write("String out = StringSubstitutor.createInterpolator().replace(input);\n")
            f.flush()
            fpath = f.name

        try:
            findings = scanner.scan_dangerous_calls([fpath], "java")
            ss_findings = [f for f in findings if f.rule_id == "DANGER-053"]
            # only the executable line (3) is reported, not the two comments
            assert len(ss_findings) == 1
            assert ss_findings[0].line == 3
        finally:
            Path(fpath).unlink()

    def test_scan_dangerous_calls_skips_test_directory(self):
        """Files under a test/ directory must not be scanned."""
        scanner = self._make_scanner()
        tmpdir = Path(tempfile.mkdtemp())
        try:
            src_file = tmpdir / "src" / "main" / "Foo.java"
            src_file.parent.mkdir(parents=True)
            src_file.write_text(
                "String out = StringSubstitutor.createInterpolator().replace(input);\n",
                encoding="utf-8",
            )
            test_file = tmpdir / "src" / "test" / "FooTest.java"
            test_file.parent.mkdir(parents=True)
            test_file.write_text(
                "String out = StringSubstitutor.createInterpolator().replace(input);\n",
                encoding="utf-8",
            )

            findings = scanner.scan_dangerous_calls([str(src_file), str(test_file)], "java")
            ss_findings = [f for f in findings if f.rule_id == "DANGER-053"]
            assert len(ss_findings) == 1
            assert ss_findings[0].file_path == str(src_file)
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)


class TestDeterministicScannerCoverage:
    """Tests for scan_all() integration with coverage tracker."""

    def test_scan_all_with_tracker_produces_coverage(self):
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        ap = _make_annotated_path(PathLabel.CONFIRMED_TAINT)
        annotator = _FakeAnnotator(paths=[ap])
        tracker = _FakeCoverageTracker()

        scanner = DeterministicScanner(g, query, tl, annotator, tracker=tracker)
        result = scanner.scan_all([], "python")

        assert result.coverage is not None
        assert result.coverage.endpoint_coverage_ratio == 0.8
        assert result.coverage.sink_coverage_ratio == 0.7
        assert result.coverage_summary is not None
        assert result.coverage_summary.endpoint_coverage_pct == 80.0
        assert result.coverage_summary.sink_coverage_pct == 70.0

    def test_scan_all_without_tracker_no_coverage(self):
        g = nx.MultiDiGraph()
        query = CPGQuery(g)
        tl = _FakeTaintLoader()
        annotator = _FakeAnnotator()
        scanner = DeterministicScanner(g, query, tl, annotator, tracker=None)

        result = scanner.scan_all([], "python")
        assert result.coverage is None
        assert result.coverage_summary is None


class TestParseLine:
    def test_parse_line_valid(self):
        assert DeterministicScanner._parse_line("app.py:42") == 42
        assert DeterministicScanner._parse_line("path/to/file.py:100") == 100

    def test_parse_line_no_colon(self):
        assert DeterministicScanner._parse_line("app.py") == 0

    def test_parse_line_empty(self):
        assert DeterministicScanner._parse_line("") == 0

    def test_parse_line_invalid(self):
        assert DeterministicScanner._parse_line("app.py:abc") == 0
