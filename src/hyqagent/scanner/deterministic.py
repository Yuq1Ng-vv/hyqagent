"""scanner/deterministic.py — Zero-LLM deterministic scanner.

Implements the five scanning methods from DESIGN-IMPLEMENTATION.md Section 3.1:
scan_cpg_taint, scan_secrets, scan_dangerous_calls, scan_missing_auth,
scan_config_issues — plus a unified scan_all() entry point.

All five methods are **zero-LLM** and produce :class:`Finding` objects
that can be fed directly into the report generator.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from hyqagent.cpg.types import CoverageReport
from hyqagent.scanner.coverage_metrics import CoverageMetrics, CoverageSummary

if TYPE_CHECKING:
    import networkx as nx

    from hyqagent.cpg.coverage import CoverageTracker
    from hyqagent.cpg.query import CPGQuery
    from hyqagent.cpg.taint_loader import TaintRuleLoader
    from hyqagent.scanner.annotator import AnnotatedPath, PathAnnotator


# ── Comment detection ──────────────────────────────────────────────────────

_COMMENT_PREFIXES = ("//", "/*", "*", "#", "<!--")

_TEST_DIR_NAMES = ("test", "tests", "testing", "__tests__")


def _is_comment_line(line: str) -> bool:
    """Return True if *line* is a pure comment line (no executable code).

    Covers Java (``//``, ``/* ... */`` and javadoc ``*`` continuations),
    Python (``#``), and JavaScript (``//``, ``/* ... */``).  Filtering these
    out of regex rule scans avoids flagging example calls in doc comments —
    a major false-positive source for library code like commons-text.
    """
    stripped = line.strip()
    if not stripped:
        return False
    return stripped.startswith(_COMMENT_PREFIXES)


def _is_test_path(file_path: str) -> bool:
    """Return True if *file_path* lives under a test directory.

    Excludes ``src/test/java/...`` (Java), ``tests/...`` (Python) and
    ``__tests__/...`` (JavaScript) so that rule scans report production
    findings rather than test-suite usage of the same dangerous APIs.
    """
    return any(part in _TEST_DIR_NAMES for part in Path(file_path).parts)


# ── Finding dataclass ──────────────────────────────────────────────────────


@dataclass
class Finding:
    """A single deterministic finding (no LLM involvement).

    Enriched during deep-mode audit orchestration with LLM hypothesis
    data (CWE, source/sink locations) and dynamic verification output (PoC).
    """

    id: str
    rule_id: str
    severity: str  # critical | high | medium | low
    title: str
    description: str
    file_path: str
    line: int
    code_snippet: str = ""
    category: str = ""
    confidence: str = "high"
    remediation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    # ── Enriched fields (populated by orchestrator during deep audit) ──
    cwe_id: str = ""  # CWE-89, CWE-79, etc.
    cvss_score: float = 0.0  # CVSS 3.1 base score
    cvss_vector: str = ""  # CVSS vector string
    endpoint: str = ""  # e.g. GET /api/users
    http_method: str = ""  # GET, POST, PUT, DELETE
    http_params: str = ""  # id, name, etc.
    impact: str = ""  # business impact description
    poc: str = ""  # curl command or PoC exploit code
    source_location: str = ""  # where taint enters (file.py:line)
    sink_location: str = ""  # where taint reaches sink (file.py:line)

    # ── LLM verification fields (populated by _phase_finding_verification) ──
    validation_verdict: str = ""  # confirmed | rejected | inconclusive
    validation_confidence: float = 0.0
    validation_reasoning: str = ""


@dataclass
class ScanResult:
    """Aggregate result from :meth:`DeterministicScanner.scan_all`."""

    findings: list[Finding] = field(default_factory=list)
    annotated_paths: list[AnnotatedPath] = field(default_factory=list)
    coverage: CoverageReport | None = None
    coverage_summary: CoverageSummary | None = None
    stats: dict[str, int] = field(default_factory=dict)


# ── DeterministicScanner ────────────────────────────────────────────────────


class DeterministicScanner:
    """Zero-LLM deterministic scanner — the heart of Phase 2.

    Usage::

        scanner = DeterministicScanner(
            graph, query, taint_loader, annotator, frameworks, tracker
        )
        result = scanner.scan_all(file_paths, "python")
        print(f"Found {len(result.findings)} issues")
    """

    def __init__(
        self,
        graph: nx.MultiDiGraph,
        query: CPGQuery,
        taint_loader: TaintRuleLoader,
        annotator: PathAnnotator,
        frameworks: list | None = None,
        tracker: CoverageTracker | None = None,
    ) -> None:
        self._graph = graph
        self._query = query
        self._taint_loader = taint_loader
        self._annotator = annotator
        self._frameworks = frameworks or []
        self._tracker = tracker

        # Resolve rules directory
        self._rules_dir = Path(__file__).parent / "rules"

    # ── Main entry point ────────────────────────────────────────────────

    def scan_all(self, file_paths: list[str], language: str) -> ScanResult:
        """Run all five scanners and return the unified result."""
        all_findings: list[Finding] = []

        # 1. CPG taint analysis (the big one)
        annotated = self.scan_cpg_taint(language)
        taint_findings = self._annotated_to_findings(annotated)
        all_findings.extend(taint_findings)

        # 2. Secrets
        all_findings.extend(self.scan_secrets(file_paths))

        # 3. Dangerous calls
        all_findings.extend(self.scan_dangerous_calls(file_paths, language))

        # 4. Config issues
        all_findings.extend(self.scan_config_issues(file_paths, language))

        # 5. Missing auth
        all_findings.extend(self.scan_missing_auth())

        # ── Coverage: collect active taint categories from CONFIRMED findings ─
        coverage = None
        coverage_summary = None
        if self._tracker:
            # Only count a category as "triggered" when it has a confirmed
            # source+sink+path — not just because a source node was labeled.
            # (getParameter matches 8 categories as source; we only care
            # about categories where an actual sink path was found.)
            active_categories: set[str] = set()
            for f in all_findings:
                cat = f.category
                if not cat:
                    continue
                # Skip PathLabel values and non-vuln scanner categories
                if cat in (
                    "confirmed_taint",
                    "conditional_sanitized",
                    "sanitized_taint",
                    "heuristic_sink",
                    "exposed_no_source",
                    "unreachable_sink",
                    "dangerous_call",
                    "secret",
                    "config_issue",
                    "missing_auth",
                ):
                    continue
                # Multi-category finding (e.g. "sql_injection,xxe")
                for single_cat in cat.split(","):
                    single_cat = single_cat.strip()
                    if single_cat:
                        active_categories.add(single_cat)

            if active_categories:
                self._tracker.set_active_categories(active_categories)

            metrics = CoverageMetrics(self._tracker)
            metrics.record_annotated_paths(annotated)
            metrics.record_findings(all_findings)
            coverage = self._tracker.compute_coverage()
            coverage_summary = metrics.summarize()

        # Stats
        stats: dict[str, int] = {"total_findings": len(all_findings)}
        for f in all_findings:
            key = f.category or f.rule_id.split("-")[0].lower()
            stats[key] = stats.get(key, 0) + 1

        return ScanResult(
            findings=all_findings,
            annotated_paths=annotated,
            coverage=coverage,
            coverage_summary=coverage_summary,
            stats=stats,
        )

    # ── scan_cpg_taint ──────────────────────────────────────────────────

    def scan_cpg_taint(self, language: str) -> list[AnnotatedPath]:
        """Run the full path annotation pipeline.

        Returns all annotated paths — nothing is discarded.
        Paths with CONFIRMED_TAINT or SANITIZED_TAINT labels are
        deterministic findings; others are informational until Phase 3.
        """
        return self._annotator.annotate(language)

    # ── scan_secrets ────────────────────────────────────────────────────

    def scan_secrets(self, file_paths: list[str]) -> list[Finding]:
        """Regex-scan source files for hardcoded secrets."""
        return self._scan_with_rules(
            file_paths,
            "secrets.yaml",
            "secret",
        )

    # ── scan_dangerous_calls ────────────────────────────────────────────

    def scan_dangerous_calls(self, file_paths: list[str], language: str) -> list[Finding]:
        """Regex-scan source files for dangerous function calls."""
        return self._scan_with_rules(
            file_paths,
            "dangerous_calls.yaml",
            "dangerous_call",
            language_filter=language,
        )

    # ── scan_config_issues ──────────────────────────────────────────────

    def scan_config_issues(self, file_paths: list[str], language: str) -> list[Finding]:
        """Regex-scan source files for configuration issues."""
        return self._scan_with_rules(
            file_paths,
            "config_issues.yaml",
            "config_issue",
            language_filter=language,
        )

    # ── scan_missing_auth ───────────────────────────────────────────────

    def scan_missing_auth(self) -> list[Finding]:
        """Detect HTTP endpoints that lack an authentication decorator/annotation.

        Uses the framework extractors' ``HttpEndpoint.auth_required`` field
        (populated by Flask/Django/FastAPI/Express/Spring extractors in Phase 1).
        """
        findings: list[Finding] = []
        for extractor in self._frameworks:
            endpoints = getattr(extractor, "endpoints", [])
            for ep in endpoints:
                auth = getattr(ep, "auth_required", None)
                if auth is False:
                    route = getattr(ep, "route", "")
                    handler = getattr(ep, "handler_func", "")
                    fpath = getattr(ep, "file_path", "")
                    line = getattr(ep, "line", 0)
                    framework = getattr(ep, "framework", "")
                    methods = getattr(ep, "methods", [])
                    method_str = ",".join(methods) if methods else "ANY"

                    findings.append(
                        Finding(
                            id=f"auth-{uuid.uuid4().hex[:8]}",
                            rule_id="AUTH-001",
                            severity="high",
                            title="缺失认证检查",
                            description=(
                                f"{framework} 端点 {method_str} {route} "
                                f"（handler: {handler}）缺少认证装饰器/注解。"
                                f"未认证的访问可能导致 IDOR、越权或数据泄漏。"
                            ),
                            file_path=fpath,
                            line=line,
                            category="missing_auth",
                            remediation=f"为 {handler} 添加认证装饰器（如 @login_required）。",
                            metadata={
                                "endpoint": route,
                                "handler": handler,
                                "framework": framework,
                                "methods": methods,
                            },
                        )
                    )

        return findings

    # ── Internal helpers ────────────────────────────────────────────────

    def _scan_with_rules(
        self,
        file_paths: list[str],
        rules_file: str,
        default_category: str,
        language_filter: str = "",
    ) -> list[Finding]:
        """Generic regex rule scanner.

        Loads *rules_file* from the :attr:`_rules_dir`, compiles each
        pattern as a regex, and scans *file_paths* line-by-line.
        """
        rules_path = self._rules_dir / rules_file
        if not rules_path.exists():
            return []

        try:
            rules_data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            return []

        rules = rules_data.get("rules", []) if isinstance(rules_data, dict) else []
        findings: list[Finding] = []

        for rule in rules:
            # Language filter
            rule_langs = rule.get("languages", [])
            if rule_langs and language_filter and language_filter not in rule_langs:
                continue

            patterns = rule.get("patterns", rule.get("pattern", []))
            if isinstance(patterns, str):
                patterns = [patterns]

            # Pre-check each pattern: try regex, fall back to substring
            compiled: list[tuple[str, object | None]] = []
            for pat in patterns:
                try:
                    compiled.append((pat, re.compile(pat, re.IGNORECASE)))
                except re.error:
                    # Not a valid regex — fall back to substring matching
                    compiled.append((pat, None))

            for file_path in file_paths:
                if _is_test_path(file_path):
                    continue
                try:
                    lines = (
                        Path(file_path).read_text(encoding="utf-8", errors="replace").splitlines()
                    )
                except OSError:
                    continue

                for lineno, line in enumerate(lines, start=1):
                    if _is_comment_line(line):
                        continue
                    for pat, regex in compiled:
                        matched = False
                        if regex is not None:
                            matched = bool(regex.search(line))
                        else:
                            # Substring fallback (case-insensitive)
                            matched = pat.lower() in line.lower()

                        if matched:
                            findings.append(
                                Finding(
                                    id=f"{rule['id']}-{uuid.uuid4().hex[:8]}",
                                    rule_id=rule["id"],
                                    severity=rule.get("severity", "medium"),
                                    title=rule.get("message", rule["id"]),
                                    description=(
                                        f"匹配规则 {rule['id']}: {rule.get('message', '')}"
                                    ),
                                    file_path=file_path,
                                    line=lineno,
                                    code_snippet=line.strip()[:200],
                                    category=rule.get("category", default_category),
                                    cwe_id=rule.get("cwe", ""),
                                    remediation="",
                                    metadata={
                                        "pattern": pat,
                                        "cwe": rule.get("cwe", ""),
                                    },
                                )
                            )
                            break  # one match per line

        return findings

    def _annotated_to_findings(self, annotated: list[AnnotatedPath]) -> list[Finding]:
        """Convert CONFIRMED_TAINT and CONDITIONAL_SANITIZED paths to Findings."""
        findings: list[Finding] = []

        from hyqagent.scanner.annotator import PathLabel

        for ap in annotated:
            if ap.label not in (
                PathLabel.CONFIRMED_TAINT,
                PathLabel.CONDITIONAL_SANITIZED,
            ):
                continue

            path = ap.path
            if not path or not path.nodes:
                continue

            # First node is the source, last node is the sink
            src_node = path.nodes[0]
            sink_node = path.nodes[-1]

            # ── Resolve actual vulnerability category from path nodes ──
            # 漏洞类型由 sink 决定(对齐 Session 1.45 参数标记语义): 源侧
            # injection_general 只是"有用户输入"的保守标记, 精确类别由 sink
            # 侧的具体类别决定. 当 sink 有具体类别时丢弃 injection_general,
            # 避免 primary_vuln 取到兜底类别.
            sink_cats = (
                set(sink_node.taint_category.split(",")) if sink_node.taint_category else set()
            )
            src_cats = set(src_node.taint_category.split(",")) if src_node.taint_category else set()
            vuln_cats = {c for c in sink_cats if c and c != "injection_general"} or sink_cats
            if not vuln_cats:
                vuln_cats = {c for c in src_cats if c and c != "injection_general"} or src_cats
            vuln_category = ",".join(sorted(vuln_cats)) if vuln_cats else "confirmed_taint"

            severity = "medium"
            if ap.label == PathLabel.CONFIRMED_TAINT:
                severity = "high"

            title = "确定性漏洞路径"
            if ap.label == PathLabel.CONDITIONAL_SANITIZED:
                title = "条件性消毒漏洞路径（需人工或 LLM 验证）"

            # ── Enriched fields from deterministic data ──
            # Lazy-import templates to avoid circular dependency at module level
            from hyqagent.report.templates import (
                lookup_cvss,
                lookup_cwe_from_vuln_type,
                lookup_impact,
            )

            src_loc = src_node.location
            sink_loc = sink_node.location
            primary_vuln = vuln_category.split(",")[0].strip() if vuln_category else ""
            cwe = lookup_cwe_from_vuln_type(primary_vuln)
            cvss_score, cvss_vector = lookup_cvss(primary_vuln, severity)
            impact_text = lookup_impact(primary_vuln)

            findings.append(
                Finding(
                    id=f"taint-{uuid.uuid4().hex[:8]}",
                    rule_id="TAINT-001",
                    severity=severity,
                    title=title,
                    description=(
                        f"从 {src_node.source[:80]} 到 {sink_node.source[:80]} 的"
                        f"数据流路径。类别: {vuln_category}。标签: {ap.label.value}。"
                        f"消毒器状态: "
                        f"{ap.sanitizer_status.value if ap.sanitizer_status else 'N/A'}。"
                    ),
                    file_path=sink_node.location.split(":")[0] if ":" in sink_node.location else "",
                    line=self._parse_line(sink_node.location),
                    code_snippet=sink_node.source[:200],
                    category=vuln_category,
                    confidence="high" if ap.label == PathLabel.CONFIRMED_TAINT else "medium",
                    # ── Enriched fields ──
                    source_location=src_loc,
                    sink_location=sink_loc,
                    cwe_id=cwe,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    impact=impact_text,
                    metadata={
                        "path_length": len(path.nodes),
                        "label": ap.label.value,
                        "sanitizer_status": (
                            ap.sanitizer_status.value if ap.sanitizer_status else None
                        ),
                        "taint_category": vuln_category,
                    },
                )
            )

        return findings

    @staticmethod
    def _parse_line(location: str) -> int:
        """Extract line number from ``"file.py:42"`` location string."""
        if ":" in location:
            try:
                return int(location.rsplit(":", 1)[-1])
            except (ValueError, IndexError):
                pass
        return 0
