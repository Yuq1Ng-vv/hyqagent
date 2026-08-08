"""Tests for report/generator.py — JSON/Markdown/SARIF output."""

from __future__ import annotations

import json

import pytest

from hyqagent.scanner.annotator import AnnotatedPath, PathLabel
from hyqagent.scanner.deterministic import Finding, ScanResult
from hyqagent.cpg.query import GraphNode, GraphPath
from hyqagent.cpg.types import BlindSpot, CoverageReport
from hyqagent.report.generator import ReportGenerator


# ── Helpers ───────────────────────────────────────────────────────────────


def _make_finding(**kwargs) -> Finding:
    defaults = {
        "id": "f-001",
        "rule_id": "TAINT-001",
        "severity": "high",
        "title": "SQL Injection in login handler",
        "description": "从 request.args.get('user') 到 cursor.execute(sql) 的污点路径",
        "file_path": "app.py",
        "line": 42,
        "code_snippet": "cursor.execute(sql)",
        "category": "confirmed_taint",
        "confidence": "high",
        "remediation": "使用参数化查询",
        "metadata": {"cwe": "CWE-89"},
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def _make_annotated_path(label: PathLabel = PathLabel.CONFIRMED_TAINT) -> AnnotatedPath:
    n = GraphNode(node_id="n1", node_type="assignment",
                  location="app.py:10", source="x = request.args.get('id')")
    return AnnotatedPath(path=GraphPath(nodes=[n]), label=label)


def _make_coverage() -> CoverageReport:
    return CoverageReport(
        endpoint_total=10,
        endpoint_analyzed=8,
        endpoint_coverage_ratio=0.8,
        sink_total=20,
        sink_labeled=14,
        sink_coverage_ratio=0.7,
        blind_spots=[
            BlindSpot(
                location="admin.py:30",
                reason="exposed_no_source",
                recommendation="建议手工审计 IDOR/认证绕过",
                severity="high",
            ),
        ],
    )


# ── Tests ─────────────────────────────────────────────────────────────────


class TestReportGeneratorBasics:
    def test_init(self):
        g = ReportGenerator()
        assert g is not None

    def test_generate_json_empty(self):
        g = ReportGenerator()
        result = ScanResult()
        text = g.generate(result, fmt="json")
        data = json.loads(text)
        assert "scan_info" in data
        assert data["scan_info"]["mode"] == "quick"
        assert data["scan_info"]["version"] == "0.1.0"
        assert data["findings"] == []

    def test_generate_json_with_findings(self):
        g = ReportGenerator()
        f = _make_finding()
        result = ScanResult(
            findings=[f],
            annotated_paths=[_make_annotated_path()],
            stats={"total_findings": 1, "confirmed_taint": 1},
        )
        text = g.generate(
            result, fmt="json",
            scan_duration_ms=3200,
            files_scanned=10,
            language="python",
        )

        data = json.loads(text)
        assert data["scan_info"]["language"] == "python"
        assert data["scan_info"]["files_scanned"] == 10
        assert data["scan_info"]["duration_ms"] == 3200
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == "TAINT-001"
        assert data["findings"][0]["severity"] == "high"
        assert data["annotated_paths"][0]["label"] == "confirmed_taint"
        assert data["annotated_paths"][0]["count"] == 1
        assert data["stats"]["total_findings"] == 1

    def test_generate_json_with_coverage_and_blind_spots(self):
        g = ReportGenerator()
        result = ScanResult(
            findings=[],
            coverage=_make_coverage(),
        )
        text = g.generate(result, fmt="json")
        data = json.loads(text)

        assert data["coverage"]["endpoint_coverage_ratio"] == 0.8
        assert data["coverage"]["sink_coverage_ratio"] == 0.7
        assert len(data["blind_spot_manifest"]) == 1
        assert data["blind_spot_manifest"][0]["severity"] == "high"
        assert "admin.py:30" in data["blind_spot_manifest"][0]["location"]


class TestReportGeneratorMarkdown:
    """Markdown report generation tests."""

    def test_markdown_basic(self):
        g = ReportGenerator()
        result = ScanResult()
        text = g.generate(result, fmt="markdown", language="python",
                          scan_duration_ms=1500, files_scanned=5)

        assert "# HyqAgent 扫描报告" in text
        assert "**语言**: python" in text
        assert "quick" in text
        assert "✅ 未发现问题" in text

    def test_markdown_with_findings(self):
        g = ReportGenerator()
        f = _make_finding()
        result = ScanResult(
            findings=[f],
            coverage=_make_coverage(),
        )
        text = g.generate(result, fmt="markdown", language="python")

        assert "### 1. [HIGH] SQL Injection" in text
        assert "**规则**: TAINT-001" in text
        assert "app.py:42" in text
        assert "cursor.execute(sql)" in text
        assert "参数化查询" in text
        # Coverage section
        assert "## 📈 覆盖率" in text
        assert "80.0%" in text
        # Blind spots
        assert "## ⚠️ 盲区清单" in text
        assert "admin.py:30" in text
        assert "IDOR" in text

    def test_markdown_with_multiple_findings(self):
        g = ReportGenerator()
        findings = [
            _make_finding(id="f1", severity="critical", rule_id="TAINT-001",
                          title="RCE via eval"),
            _make_finding(id="f2", severity="high", rule_id="AUTH-001",
                          title="Missing auth on /admin"),
            _make_finding(id="f3", severity="medium", rule_id="CONFIG-001",
                          title="DEBUG=True in production"),
            _make_finding(id="f4", severity="low", rule_id="DANGER-010",
                          title="File open without path sanitization"),
        ]
        result = ScanResult(findings=findings)
        text = g.generate(result, fmt="markdown")

        assert "| 总发现数 | 4 |" in text
        assert "| critical | 1 |" in text
        assert "| high | 1 |" in text
        assert "| medium | 1 |" in text
        assert "| low | 1 |" in text

    def test_markdown_with_no_blind_spots(self):
        g = ReportGenerator()
        cov = CoverageReport(
            endpoint_total=5, endpoint_analyzed=5,
            endpoint_coverage_ratio=1.0,
            sink_total=10, sink_labeled=10,
            sink_coverage_ratio=1.0,
            blind_spots=[],
        )
        result = ScanResult(coverage=cov)
        text = g.generate(result, fmt="markdown", language="java")

        # No blind spot section when there are none
        assert "⚠️ 盲区清单" not in text
        assert "100.0%" in text


class TestReportGeneratorSARIF:
    """SARIF v2.1.0 output tests."""

    def test_sarif_basic(self):
        g = ReportGenerator()
        result = ScanResult()
        text = g.generate(result, fmt="sarif")
        data = json.loads(text)

        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert "sarif-schema-2.1.0" in data["$schema"]
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "HyqAgent"
        assert run["results"] == []

    def test_sarif_with_findings(self):
        g = ReportGenerator()
        f1 = _make_finding(id="f1", rule_id="TAINT-001", severity="critical",
                           title="RCE in eval", file_path="views.py", line=55)
        f2 = _make_finding(id="f2", rule_id="CONFIG-001", severity="medium",
                           title="DEBUG enabled", file_path="settings.py", line=3)
        result = ScanResult(findings=[f1, f2])

        text = g.generate(result, fmt="sarif")
        data = json.loads(text)

        run = data["runs"][0]
        results = run["results"]
        assert len(results) == 2
        assert results[0]["level"] == "error"  # critical → error
        assert results[1]["level"] == "warning"  # medium → warning
        assert results[0]["ruleId"] == "TAINT-001"
        assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "views.py"
        assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 55

        # Rules array
        rules = run["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert "TAINT-001" in rule_ids
        assert "CONFIG-001" in rule_ids

    def test_sarif_without_line(self):
        g = ReportGenerator()
        f = _make_finding(id="f1", rule_id="SECRET-001", severity="high",
                          file_path="", line=0, code_snippet="key = 'abc123'")
        result = ScanResult(findings=[f])

        text = g.generate(result, fmt="sarif")
        data = json.loads(text)

        location = data["runs"][0]["results"][0]["locations"][0]
        # Should not have a region when line=0
        assert "region" not in location["physicalLocation"]

    def test_sarif_security_severity_scores(self):
        g = ReportGenerator()
        findings = [
            _make_finding(id="f1", rule_id="TAINT-001", severity="critical"),
            _make_finding(id="f2", rule_id="TAINT-001", severity="high"),
            _make_finding(id="f3", rule_id="TAINT-001", severity="medium"),
            _make_finding(id="f4", rule_id="TAINT-001", severity="low"),
        ]
        result = ScanResult(findings=findings)
        text = g.generate(result, fmt="sarif")
        data = json.loads(text)

        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        # First finding is critical → security-severity should be 9.5
        assert rule["properties"]["security-severity"] == 9.5


class TestReportGeneratorFormats:
    """Cross-format consistency tests."""

    def test_json_is_valid(self):
        g = ReportGenerator()
        f = _make_finding()
        result = ScanResult(findings=[f], coverage=_make_coverage())
        text = g.generate(result, fmt="json", language="python",
                          scan_duration_ms=1000, files_scanned=5)
        data = json.loads(text)
        assert isinstance(data, dict)

        # Verify all expected keys present
        assert set(data.keys()) == {
            "scan_info", "findings", "annotated_paths",
            "coverage", "blind_spot_manifest", "stats",
        }

    def test_sarif_is_valid(self):
        g = ReportGenerator()
        result = ScanResult()
        text = g.generate(result, fmt="sarif")
        data = json.loads(text)
        assert "runs" in data
        assert "tool" in data["runs"][0]
        assert "results" in data["runs"][0]

    def test_md_format_alias(self):
        """The 'md' format should be treated as 'markdown'."""
        g = ReportGenerator()
        result = ScanResult()
        text = g.generate(result, fmt="md")
        assert "# HyqAgent 扫描报告" in text


class TestReportGeneratorHelpers:
    def test_to_json_serializable(self):
        g = ReportGenerator()
        f = _make_finding(metadata={"list": [1, 2], "nested": {"a": 1}})
        result = ScanResult(findings=[f])

        text = g.generate(result, fmt="json")
        data = json.loads(text)
        assert data["findings"][0]["metadata"]["list"] == [1, 2]
        assert data["findings"][0]["metadata"]["nested"] == {"a": 1}
