"""report/generator.py — JSON, Markdown, and SARIF report generation.

Converts a :class:`ScanResult <scanner.deterministic.ScanResult>` into
human-readable (Markdown) or machine-readable (JSON, SARIF) output.

Usage::

    generator = ReportGenerator()
    text = generator.generate(result, fmt="json", scan_duration_ms=3200)
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC
from typing import Any

try:
    from hyqagent.scanner.deterministic import Finding, ScanResult
except ImportError:  # pragma: no cover
    Finding = Any  # type: ignore[assignment,misc]
    ScanResult = Any  # type: ignore[assignment,misc]


class ReportGenerator:
    """Generate scan reports in JSON, Markdown, or SARIF format."""

    # ── Public API ────────────────────────────────────────────────────

    def generate(
        self,
        result: ScanResult,
        fmt: str = "json",
        scan_duration_ms: int = 0,
        files_scanned: int = 0,
        language: str = "",
        mode: str = "quick",
        hypotheses: list[Any] | None = None,
        convergence: Any = None,
        cost_summary: Any = None,
        completeness_review: dict[str, Any] | None = None,
        coverage_audit: Any = None,
        phases_completed: list[str] | None = None,
        validations: list[Any] | None = None,
    ) -> str:
        """Generate a report in *fmt* format.

        Args:
            result: The :class:`ScanResult` from :meth:`DeterministicScanner.scan_all`.
            fmt: One of ``"json"``, ``"markdown"``, ``"sarif"``.
            scan_duration_ms: Total scan duration in milliseconds.
            files_scanned: Number of source files processed.
            language: Programming language scanned.
            mode: ``"quick"`` (deterministic only) or ``"deep"`` (LLM-augmented).
            hypotheses: LLM-generated hypotheses (deep mode only).
            convergence: :class:`ConvergenceReport` (deep mode only).
            cost_summary: :class:`CostSummary` (deep mode only).
            completeness_review: Completeness critic output (deep mode only).
            coverage_audit: :class:`CoverageAuditResult` (deep mode only).
            phases_completed: List of completed phase names (deep mode only).
            validations: :class:`ValidationResult` list (deep mode only).

        """
        # Build a deep-audit context dict for format methods
        deep_ctx: dict[str, Any] | None = None
        if mode == "deep":
            deep_ctx = {
                "mode": mode,
                "hypotheses": hypotheses or [],
                "convergence": convergence,
                "cost_summary": cost_summary,
                "completeness_review": completeness_review,
                "coverage_audit": coverage_audit,
                "phases_completed": phases_completed or [],
                "validations": validations or [],
            }

        if fmt in ("markdown", "md"):
            return self._to_markdown(
                result,
                scan_duration_ms,
                files_scanned,
                language,
                deep_ctx,
            )
        if fmt == "sarif":
            return self._to_sarif(
                result,
                scan_duration_ms,
                files_scanned,
                language,
            )
        return self._to_json(
            result,
            scan_duration_ms,
            files_scanned,
            language,
            deep_ctx,
        )

    # ── JSON ──────────────────────────────────────────────────────────

    def _to_json(
        self,
        result: ScanResult,
        scan_duration_ms: int,
        files_scanned: int,
        language: str,
        deep_ctx: dict[str, Any] | None = None,
    ) -> str:
        """Produce a rich JSON report."""
        # Build simplified annotated-path summaries
        path_summaries: list[dict] = []
        for ap in getattr(result, "annotated_paths", []) or []:
            label = ap.label.value if hasattr(ap.label, "value") else str(ap.label)
            ss = ap.sanitizer_status
            sanitizer_status = ss.value if hasattr(ss, "value") else str(ss) if ss else None
            path_summaries.append(
                {
                    "label": label,
                    "sanitizer_status": sanitizer_status,
                    "node_count": len(getattr(ap.path, "nodes", [])),
                }
            )

        # Count labels
        from collections import Counter

        label_counts = Counter(ps["label"] for ps in path_summaries)

        is_deep = deep_ctx is not None

        output: dict[str, Any] = {
            "scan_info": {
                "version": self._resolve_version(),
                "mode": deep_ctx["mode"] if deep_ctx is not None else "quick",
                "duration_ms": scan_duration_ms,
                "files_scanned": files_scanned,
                "language": language,
                "timestamp": self._timestamp(),
            },
            "findings": [self._finding_to_dict(f) for f in (getattr(result, "findings", []) or [])],
            "annotated_paths": [
                {"label": label, "count": count} for label, count in sorted(label_counts.items())
            ],
            "coverage": self._coverage_dict(result),
            "blind_spot_manifest": self._blind_spot_list(result),
            "stats": getattr(result, "stats", {}) or {},
        }

        # ── Deep audit sections ───────────────────────────────────
        if deep_ctx is not None:
            ctx: dict[str, Any] = deep_ctx

            # Hypotheses summary
            hypotheses: list[dict[str, Any]] = []
            for h in ctx.get("hypotheses", []):
                hypotheses.append({
                    "id": getattr(h, "id", ""),
                    "summary": getattr(h, "summary", str(h)[:200]),
                    "confidence": getattr(h, "confidence", 0.0),
                    "endpoint": getattr(h, "endpoint", ""),
                    "vuln_category": getattr(h, "vuln_category", ""),
                })
            output["hypotheses"] = hypotheses

            # Validations summary
            validations: list[dict[str, Any]] = []
            for v in ctx.get("validations", []):
                validations.append({
                    "hypothesis_id": getattr(v, "hypothesis_id", ""),
                    "verdict": str(getattr(v, "verdict", "")),
                    "evidence_strength": str(getattr(v, "evidence_strength", "")),
                })
            output["validations"] = validations

            # Convergence
            conv = ctx.get("convergence")
            if conv is not None:
                output["convergence"] = {
                    "summary": getattr(conv, "summary", str(conv)),
                    "rounds": getattr(conv, "round", 0),
                    "status": str(getattr(conv, "recommendation", "unknown")),
                }

            # Cost
            cost = ctx.get("cost_summary")
            if cost is not None:
                output["cost"] = {
                    "total_cost": getattr(cost, "total_cost", 0.0),
                    "prompt_tokens": getattr(cost, "total_input_tokens", 0),
                    "completion_tokens": getattr(cost, "total_output_tokens", 0),
                    "total_tokens": (
                        getattr(cost, "total_input_tokens", 0)
                        + getattr(cost, "total_output_tokens", 0)
                    ),
                }

            # Deep audit meta
            output["deep_audit"] = {
                "phases_completed": ctx.get("phases_completed", []),
                "hypotheses_count": len(hypotheses),
                "validations_count": len(validations),
                "convergence_rounds": (
                    getattr(conv, "round", 0) if conv is not None else 0
                ),
                "total_llm_cost": (
                    getattr(cost, "total_cost", 0.0) if cost is not None else 0.0
                ),
            }

        return json.dumps(output, ensure_ascii=False, indent=2)

    # ── Markdown ──────────────────────────────────────────────────────

    def _to_markdown(
        self,
        result: ScanResult,
        scan_duration_ms: int,
        files_scanned: int,
        language: str,
        deep_ctx: dict[str, Any] | None = None,
    ) -> str:
        """Produce a human-readable Markdown report."""
        lines: list[str] = []
        findings = getattr(result, "findings", []) or []
        is_deep = deep_ctx is not None
        mode_label = "deep (LLM enhanced)" if is_deep else "quick (zero-LLM deterministic)"

        # Header
        lines.append("# HyqAgent 扫描报告")
        lines.append("")
        lines.append(f"**版本**: {self._resolve_version()}  ")
        lines.append(f"**模式**: {mode_label}  ")
        lines.append(f"**语言**: {language or 'auto'}  ")
        lines.append(f"**文件数**: {files_scanned}  ")
        lines.append(f"**耗时**: {scan_duration_ms}ms  ")
        lines.append(f"**时间**: {self._timestamp()}  ")
        lines.append("")

        # Summary
        lines.append("## 📊 摘要")
        lines.append("")

        sev_counts: dict[str, int] = {}
        cat_counts: dict[str, int] = {}
        for f in findings:
            sev = getattr(f, "severity", "unknown")
            cat = getattr(f, "category", getattr(f, "rule_id", "unknown"))
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

        lines.append("| 指标 | 值 |")
        lines.append("|------|----|")
        lines.append(f"| 总发现数 | {len(findings)} |")
        for sev in ("critical", "high", "medium", "low"):
            c = sev_counts.get(sev, 0)
            if c:
                lines.append(f"| {sev} | {c} |")

        # Deep audit summary
        if deep_ctx is not None:
            ctx = deep_ctx
            hyp_count = len(ctx.get("hypotheses", []))
            val_count = len(ctx.get("validations", []))
            conv = ctx.get("convergence")
            cost = ctx.get("cost_summary")
            lines.append(f"| LLM 假设 | {hyp_count} |")
            lines.append(f"| LLM 验证 | {val_count} |")
            if conv is not None:
                lines.append(f"| 收敛轮次 | {getattr(conv, 'total_rounds', 0)} |")
            if cost is not None:
                lines.append(f"| LLM 成本 | ${getattr(cost, 'total_cost', 0.0):.4f} |")

        lines.append("")

        # Coverage
        coverage = getattr(result, "coverage", None)
        if coverage:
            lines.append("## 📈 覆盖率")
            lines.append("")
            ep_cov = getattr(coverage, "endpoint_coverage_ratio", 0.0)
            sk_cov = getattr(coverage, "sink_coverage_ratio", 0.0)
            lines.append("| 维度 | 覆盖率 |")
            lines.append("|------|--------|")
            lines.append(f"| 端点覆盖 | {ep_cov * 100:.1f}% |")
            lines.append(f"| Sink 覆盖 | {sk_cov * 100:.1f}% |")
            lines.append("")

        # LLM Hypotheses (deep only)
        if is_deep:
            hypotheses = ctx.get("hypotheses", [])
            if hypotheses:
                lines.append("## 🤖 LLM 假设")
                lines.append("")
                lines.append("| # | 摘要 | 置信度 | 端点 | 漏洞类别 |")
                lines.append("|---|------|--------|------|----------|")
                for i, h in enumerate(hypotheses, 1):
                    summary = str(getattr(h, "summary", str(h)[:80]))[:80]
                    conf = getattr(h, "confidence", 0.0)
                    endpoint = str(getattr(h, "endpoint", ""))[:40]
                    vuln_cat = str(getattr(h, "vuln_category", ""))[:20]
                    lines.append(f"| {i} | {summary} | {conf:.2f} | {endpoint} | {vuln_cat} |")
                lines.append("")

        # Convergence (deep only)
        if is_deep and conv is not None:
            lines.append("## 🔄 收敛信息")
            lines.append("")
            lines.append(f"- **轮次**: {getattr(conv, 'total_rounds', 0)}")
            lines.append(f"- **状态**: {getattr(conv, 'status', 'unknown')}")
            conv_summary = str(getattr(conv, "summary", ""))
            if conv_summary:
                lines.append(f"- **摘要**: {conv_summary}")
            lines.append("")

        # Blind spots
        blind_spots = self._blind_spot_list(result)
        if blind_spots:
            lines.append("## ⚠️ 盲区清单")
            lines.append("")
            lines.append("以下代码路径当前扫描未覆盖，可能存在遗漏的漏洞：")
            lines.append("")
            for bs in blind_spots:
                sev = bs.get("severity", "medium")
                lines.append(
                    f"- **[{sev.upper()}]** {bs.get('location', '?')}: {bs.get('reason', '')}"
                )
                rec = bs.get("recommendation", "")
                if rec:
                    lines.append(f"  → {rec}")
            lines.append("")

        # Findings
        if findings:
            lines.append("## 🔍 发现")
            lines.append("")

            for i, f in enumerate(findings, 1):
                title = getattr(f, "title", f"Finding {i}")
                sev = getattr(f, "severity", "medium")
                desc = getattr(f, "description", "")
                fpath = getattr(f, "file_path", "")
                line_num = getattr(f, "line", 0)
                code = getattr(f, "code_snippet", "")
                rule = getattr(f, "rule_id", "")
                conf = getattr(f, "confidence", "high")
                remediation = getattr(f, "remediation", "")

                lines.append(f"### {i}. [{sev.upper()}] {title}")
                lines.append("")
                lines.append(f"- **规则**: {rule}")
                lines.append(f"- **置信度**: {conf}")
                lines.append(f"- **位置**: `{fpath}:{line_num}`")
                lines.append("")
                lines.append(desc)
                lines.append("")

                if code:
                    lines.append("```python")
                    lines.append(code)
                    lines.append("```")
                    lines.append("")

                if remediation:
                    lines.append(f"**修复建议**: {remediation}")
                    lines.append("")

        else:
            lines.append("## ✅ 未发现问题")
            lines.append("")
            lines.append("该次扫描未发现任何确定性漏洞。")
            lines.append("")

        # Cost summary (deep only, at the end)
        if is_deep and cost is not None:
            lines.append("## 💰 LLM 成本")
            lines.append("")
            lines.append("| 指标 | 值 |")
            lines.append("|------|----|")
            lines.append(f"| 总成本 | ${getattr(cost, 'total_cost', 0.0):.4f} |")
            lines.append(f"| Prompt tokens | {getattr(cost, 'total_input_tokens', 0):,} |")
            lines.append(f"| Completion tokens | {getattr(cost, 'total_output_tokens', 0):,} |")
            lines.append("")

        # Phases completed (deep only)
        if is_deep:
            phases = ctx.get("phases_completed", [])
            if phases:
                lines.append("## 📋 执行阶段")
                lines.append("")
                for p in phases:
                    lines.append(f"- ✅ {p}")
                lines.append("")

        return "\n".join(lines)

    # ── SARIF ──────────────────────────────────────────────────────────

    def _to_sarif(
        self,
        result: ScanResult,
        scan_duration_ms: int,
        files_scanned: int,
        language: str,
    ) -> str:
        """Produce a SARIF v2.1.0 report (for GitHub Code Scanning)."""
        findings = getattr(result, "findings", []) or []

        # Build SARIF results
        sarif_results: list[dict] = []
        rules: dict[str, dict] = {}
        rule_index: dict[str, int] = {}

        for i, f in enumerate(findings):
            rid = getattr(f, "rule_id", f"UNKNOWN-{i}")
            if rid not in rule_index:
                rule_index[rid] = len(rule_index)
                rules[rid] = {
                    "id": rid,
                    "shortDescription": {
                        "text": getattr(f, "title", rid),
                    },
                    "help": {
                        "text": getattr(f, "remediation", ""),
                        "markdown": getattr(f, "description", ""),
                    },
                    "properties": {
                        "security-severity": _severity_score(getattr(f, "severity", "medium")),
                    },
                }

            sev = getattr(f, "severity", "medium")
            fpath = getattr(f, "file_path", "")
            line_num = getattr(f, "line", 0)
            code = getattr(f, "code_snippet", "")

            region = {"startLine": line_num} if line_num else {}

            location = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": fpath,
                    },
                },
            }
            if region:
                location["physicalLocation"]["region"] = region  # type: ignore[index]

            if code:
                location["physicalLocation"]["contextRegion"] = {  # type: ignore[index]
                    "snippet": {"text": code},
                }

            sarif_results.append(
                {
                    "ruleId": rid,
                    "ruleIndex": rule_index[rid],
                    "level": _sarif_level(sev),
                    "message": {
                        "text": f"{getattr(f, 'title', rid)}: {getattr(f, 'description', '')[:200]}",
                    },
                    "locations": [location],
                }
            )

        sarif = {
            "$schema": (
                "https://raw.githubusercontent.com/oasis-tcs/"
                "sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
            ),
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "HyqAgent",
                            "version": self._resolve_version(),
                            "informationUri": "https://github.com/hyqagent/hyqagent",
                            "rules": [rules[rid] for rid in sorted(rules)],
                        },
                    },
                    "results": sarif_results,
                },
            ],
        }

        return json.dumps(sarif, ensure_ascii=False, indent=2)

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _finding_to_dict(f: Finding) -> dict[str, Any]:
        """Convert a single Finding to a JSON-serializable dict."""
        return {
            "id": getattr(f, "id", str(uuid.uuid4())),
            "rule_id": getattr(f, "rule_id", ""),
            "severity": getattr(f, "severity", "medium"),
            "confidence": getattr(f, "confidence", "high"),
            "title": getattr(f, "title", ""),
            "description": getattr(f, "description", ""),
            "file_path": getattr(f, "file_path", ""),
            "line": getattr(f, "line", 0),
            "code_snippet": getattr(f, "code_snippet", ""),
            "category": getattr(f, "category", ""),
            "remediation": getattr(f, "remediation", ""),
            "metadata": getattr(f, "metadata", {}),
        }

    @staticmethod
    def _coverage_dict(result: ScanResult) -> dict | None:
        """Extract coverage data from result, if present."""
        coverage = getattr(result, "coverage", None)
        if coverage is None:
            return None
        return {
            "endpoint_total": getattr(coverage, "endpoint_total", 0),
            "endpoint_analyzed": getattr(coverage, "endpoint_analyzed", 0),
            "endpoint_coverage_ratio": getattr(coverage, "endpoint_coverage_ratio", 0.0),
            "sink_total": getattr(coverage, "sink_total", 0),
            "sink_labeled": getattr(coverage, "sink_labeled", 0),
            "sink_coverage_ratio": getattr(coverage, "sink_coverage_ratio", 0.0),
        }

    @staticmethod
    def _blind_spot_list(result: ScanResult) -> list[dict[str, Any]]:
        """Extract blind spots."""
        coverage = getattr(result, "coverage", None)
        if coverage is None:
            return []
        spots = getattr(coverage, "blind_spots", []) or []
        return [
            {
                "location": getattr(bs, "location", ""),
                "reason": getattr(bs, "reason", ""),
                "recommendation": getattr(bs, "recommendation", ""),
                "severity": getattr(bs, "severity", "medium"),
            }
            for bs in spots
        ]

    @staticmethod
    def _resolve_version() -> str:
        """Resolve the installed package version, defaulting to ``0.1.0``."""
        try:
            import importlib.metadata

            return importlib.metadata.version("hyqagent")
        except importlib.metadata.PackageNotFoundError:
            return "0.1.0"

    @staticmethod
    def _timestamp() -> str:
        """ISO-8601 UTC timestamp for the report."""
        from datetime import datetime

        return datetime.now(UTC).isoformat()


# ── SARIF helpers ────────────────────────────────────────────────────────


def _sarif_level(severity: str) -> str:
    """Map HyqAgent severity to SARIF `result.level`."""
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }.get(severity, "warning")


def _severity_score(severity: str) -> float:
    """Map severity string to the 0-10 `security-severity` float."""
    return {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
    }.get(severity, 5.0)
