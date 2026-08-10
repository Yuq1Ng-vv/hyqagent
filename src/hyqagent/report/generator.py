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
        dynamic_verification_results: list[Any] | None = None,
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
                "dynamic_verification_results": dynamic_verification_results or [],
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
                hypotheses.append(
                    {
                        "id": getattr(h, "id", ""),
                        "title": getattr(h, "title", ""),
                        "vuln_type": getattr(h, "vuln_type", ""),
                        "cwe_id": getattr(h, "cwe_id", ""),
                        "severity": getattr(h, "severity", ""),
                        "confidence": getattr(h, "confidence", 0.0),
                        "source_location": getattr(h, "source_location", ""),
                        "sink_location": getattr(h, "sink_location", ""),
                    }
                )
            output["hypotheses"] = hypotheses

            # Validations summary
            validations: list[dict[str, Any]] = []
            for v in ctx.get("validations", []):
                validations.append(
                    {
                        "hypothesis_id": getattr(v, "hypothesis_id", ""),
                        "verdict": str(getattr(v, "verdict", "")),
                        "evidence_strength": str(getattr(v, "evidence_strength", "")),
                    }
                )
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
                "convergence_rounds": (getattr(conv, "round", 0) if conv is not None else 0),
                "total_llm_cost": (getattr(cost, "total_cost", 0.0) if cost is not None else 0.0),
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
        """Produce a human-readable Markdown report.

        For deep mode, cross-references hypotheses, validations, and dynamic
        verification results to produce action-oriented findings with
        reproducible steps, PoC code, data flow traces, and CVSS scores.
        """
        lines: list[str] = []
        findings = getattr(result, "findings", []) or []
        is_deep = deep_ctx is not None
        mode_label = "deep (LLM enhanced)" if is_deep else "quick (zero-LLM deterministic)"

        # ── Header ───────────────────────────────────────────────────
        lines.append("# HyqAgent 安全审计报告")
        lines.append("")
        lines.append(f"**版本**: {self._resolve_version()}  ")
        lines.append(f"**模式**: {mode_label}  ")
        lines.append(f"**语言**: {language or 'auto'}  ")
        lines.append(f"**文件数**: {files_scanned}  ")
        lines.append(f"**耗时**: {scan_duration_ms}ms  ")
        lines.append(f"**时间**: {self._timestamp()}  ")
        lines.append("")

        # ── Executive Summary ────────────────────────────────────────
        lines.append("## 📊 摘要")
        lines.append("")

        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = getattr(f, "severity", "unknown")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        lines.append("| 指标 | 值 |")
        lines.append("|------|----|")
        lines.append(f"| 总发现数 | {len(findings)} |")
        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        for sev in ("critical", "high", "medium", "low"):
            c = sev_counts.get(sev, 0)
            if c:
                emoji = sev_emoji.get(sev, "")
                lines.append(f"| {emoji} {sev} | {c} |")

        # Deep audit summary
        if deep_ctx is not None:
            ctx = deep_ctx
            hyp_count = len(ctx.get("hypotheses", []))
            val_count = len(ctx.get("validations", []))
            conv = ctx.get("convergence")
            cost = ctx.get("cost_summary")
            dv_results = ctx.get("dynamic_verification_results", [])
            confirmed_dv = sum(
                1 for r in dv_results if r.get("verdict") == "confirmed"
            )
            lines.append(f"| LLM 假设 | {hyp_count} |")
            lines.append(f"| LLM 验证 | {val_count} |")
            if conv is not None:
                lines.append(f"| 收敛轮次 | {getattr(conv, 'round', '?')} |")
                lines.append(
                    f"| 收敛状态 | {getattr(conv, 'recommendation', 'unknown')} |"
                )
            if confirmed_dv:
                lines.append(f"| 🧪 沙箱确认 | {confirmed_dv} |")
            if cost is not None:
                lines.append(f"| LLM 成本 | ${getattr(cost, 'total_cost', 0.0):.4f} |")

        lines.append("")

        # ── Findings (the main section) ──────────────────────────────
        if findings:
            # Enrich findings with deep audit cross-reference data
            enriched = self._enrich_findings(findings, deep_ctx)

            lines.append("## 🔍 漏洞发现")
            lines.append("")

            for i, f in enumerate(enriched, 1):
                title = getattr(f, "title", f"Finding {i}")
                sev = getattr(f, "severity", "medium")
                sev_up = sev.upper()
                cwe_id = getattr(f, "cwe_id", "")
                cvss_score = getattr(f, "cvss_score", 0.0)
                endpoint = getattr(f, "endpoint", "")
                http_method = getattr(f, "http_method", "")
                source_loc = getattr(f, "source_location", "")
                sink_loc = getattr(f, "sink_location", "")
                desc = getattr(f, "description", "")
                code = getattr(f, "code_snippet", "")
                remediation = getattr(f, "remediation", "")
                impact = getattr(f, "impact", "")
                poc = getattr(f, "poc", "")
                confidence = getattr(f, "confidence", "high")
                validation_verdict = getattr(f, "validation_verdict", "")
                validation_confidence = getattr(f, "validation_confidence", 0.0)

                # Emoji per severity
                sev_icon = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢",
                }.get(sev, "⚪")

                # Title line
                endpoint_str = f" in {http_method} {endpoint}" if endpoint else ""
                lines.append(f"### {sev_icon} F-{i:03d}: [{sev_up}] {title}{endpoint_str}")
                lines.append("")

                # ── Info table ──
                lines.append("| 属性 | 值 |")
                lines.append("|------|-----|")
                if cwe_id:
                    from hyqagent.report.templates import lookup_cwe_name

                    cwe_name = lookup_cwe_name(cwe_id)
                    cwe_label = f"{cwe_id}: {cwe_name}" if cwe_name else cwe_id
                    lines.append(f"| **CWE** | {cwe_label} |")
                if cvss_score > 0:
                    cvss_vec = getattr(f, "cvss_vector", "")
                    from hyqagent.report.templates import cvss_severity_label

                    cvss_label = cvss_severity_label(cvss_score)
                    lines.append(
                        f"| **CVSS 3.1** | {cvss_score} ({cvss_label}) |"
                    )
                    if cvss_vec:
                        lines.append(f"| **CVSS 向量** | `{cvss_vec}` |")

                # Confidence with validation cross-reference
                conf_parts = [f"确定性: {confidence}"]
                if validation_verdict == "confirmed":
                    conf_parts.append(
                        f"LLM 验证: ✅ confirmed ({validation_confidence:.0%})"
                    )
                elif validation_verdict == "rejected":
                    conf_parts.append(
                        f"LLM 验证: ❌ rejected ({validation_confidence:.0%})"
                    )
                if poc:
                    conf_parts.append("沙箱 PoC: ✅ verified")
                lines.append(f"| **置信度** | {' · '.join(conf_parts)} |")

                loc_parts = []
                if source_loc:
                    loc_parts.append(f"源: `{source_loc}`")
                if sink_loc:
                    loc_parts.append(f"汇: `{sink_loc}`")
                if not loc_parts:
                    fpath = getattr(f, "file_path", "")
                    line_num = getattr(f, "line", 0)
                    loc_parts.append(f"`{fpath}:{line_num}`")
                lines.append(f"| **位置** | {' → '.join(loc_parts)} |")

                # HTTP endpoint info
                if endpoint:
                    ep_label = f"`{http_method} {endpoint}`" if http_method else f"`{endpoint}`"
                    lines.append(f"| **端点** | {ep_label} |")
                    http_params = getattr(f, "http_params", "")
                    if http_params:
                        lines.append(f"| **参数** | `{http_params}` |")

                lines.append("")

                # ── Description ──
                if desc:
                    lines.append("#### 📖 描述")
                    lines.append("")
                    lines.append(desc)
                    lines.append("")

                # ── Code ──
                if code:
                    lang = language or ""
                    lines.append(f"```{lang}")
                    lines.append(code.strip())
                    lines.append("```")
                    lines.append("")

                # ── Reproducible Steps ──
                steps = getattr(f, "reproducible_steps", "")
                if steps:
                    lines.append("#### 🧪 复现步骤")
                    lines.append("")
                    lines.append(steps)
                    lines.append("")
                elif endpoint and cwe_id:
                    # Auto-generate basic steps from template
                    steps = self._build_repro_steps(f)
                    if steps:
                        lines.append("#### 🧪 复现步骤")
                        lines.append("")
                        lines.append(steps)
                        lines.append("")

                # ── PoC ──
                if poc:
                    lines.append("#### 💉 概念验证 (PoC)")
                    lines.append("")
                    lang = language or "bash"
                    lines.append(f"```{lang}")
                    lines.append(poc[:2000])
                    lines.append("```")
                    lines.append("")

                # ── Impact ──
                if impact:
                    lines.append("#### 💥 影响")
                    lines.append("")
                    lines.append(impact)
                    lines.append("")

                # ── Remediation ──
                if remediation:
                    lines.append("#### 🛡 修复建议")
                    lines.append("")
                    lines.append(remediation)
                    lines.append("")

                lines.append("---")
                lines.append("")

        else:
            lines.append("## ✅ 未发现问题")
            lines.append("")
            lines.append("该次扫描未发现任何确定性漏洞。")
            lines.append("")

        # ── Coverage ─────────────────────────────────────────────────
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

        # ── Deep audit sections (after findings) ─────────────────────
        if is_deep and deep_ctx is not None:

            # LLM Hypotheses table
            hypotheses = ctx.get("hypotheses", [])
            if hypotheses:
                lines.append("## 🤖 LLM 假设详情")
                lines.append("")
                lines.append("| # | 类型 | CWE | 严重度 | 置信度 | 源 | 汇 |")
                lines.append("|---|------|-----|--------|--------|----|----|")
                for j, h in enumerate(hypotheses, 1):
                    vt = getattr(h, "vuln_type", "?")
                    cwe = getattr(h, "cwe_id", "")
                    sev_h = getattr(h, "severity", "?")
                    conf_h = getattr(h, "confidence", 0.0)
                    src_h = getattr(h, "source_location", "")[:30]
                    sink_h = getattr(h, "sink_location", "")[:30]
                    lines.append(
                        f"| {j} | {vt} | {cwe} | {sev_h} | {conf_h:.0%} | "
                        f"`{src_h}` | `{sink_h}` |"
                    )
                lines.append("")

            # Dynamic verification results
            dv_results = ctx.get("dynamic_verification_results", [])
            if dv_results:
                lines.append("## 🧪 动态验证 (沙箱)")
                lines.append("")
                lines.append("| # | 漏洞类型 | 严重度 | 验证结果 | 置信度 |")
                lines.append("|---|----------|--------|----------|--------|")
                for j, dv in enumerate(dv_results, 1):
                    vt = dv.get("vuln_type", "?")
                    sev_dv = dv.get("severity", "?")
                    verdict = dv.get("verdict", "?")
                    uconf = dv.get("updated_confidence", 0.0)
                    v_icon = {
                        "confirmed": "✅",
                        "rejected": "❌",
                        "inconclusive": "⚠️",
                    }.get(verdict, "❓")
                    lines.append(
                        f"| {j} | {vt} | {sev_dv} | {v_icon} {verdict} | {uconf:.0%} |"
                    )
                lines.append("")

            # Convergence
            conv = ctx.get("convergence")
            if conv is not None:
                lines.append("## 🔄 收敛信息")
                lines.append("")
                lines.append(f"- **轮次**: {getattr(conv, 'round', '?')}")
                lines.append(f"- **状态**: {getattr(conv, 'recommendation', 'unknown')}")
                if getattr(conv, "escalate_reason", ""):
                    lines.append(f"- **原因**: {conv.escalate_reason}")
                conv_summary = str(getattr(conv, "summary", ""))
                if conv_summary:
                    lines.append(f"- **指标**: {conv_summary}")
                lines.append("")

            # Cost
            cost = ctx.get("cost_summary")
            if cost is not None:
                lines.append("## 💰 LLM 成本")
                lines.append("")
                lines.append("| 指标 | 值 |")
                lines.append("|------|----|")
                lines.append(f"| 总成本 | ${getattr(cost, 'total_cost', 0.0):.4f} |")
                lines.append(
                    f"| Prompt tokens | {getattr(cost, 'total_input_tokens', 0):,} |"
                )
                lines.append(
                    f"| Completion tokens | {getattr(cost, 'total_output_tokens', 0):,} |"
                )
                lines.append("")

            # Phases completed
            phases = ctx.get("phases_completed", [])
            if phases:
                lines.append("## 📋 执行阶段")
                lines.append("")
                for p in phases:
                    lines.append(f"- ✅ {p}")
                lines.append("")

        # ── Blind spots (both modes) ─────────────────────────────────
        blind_spots = self._blind_spot_list(result)
        if blind_spots:
            lines.append("## ⚠️ 盲区清单")
            lines.append("")
            lines.append("以下代码路径当前扫描未覆盖，可能存在遗漏的漏洞：")
            lines.append("")
            for bs in blind_spots:
                sev_bs = bs.get("severity", "medium")
                lines.append(
                    f"- **[{sev_bs.upper()}]** {bs.get('location', '?')}: "
                    f"{bs.get('reason', '')}"
                )
                rec = bs.get("recommendation", "")
                if rec:
                    lines.append(f"  → {rec}")
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
        d: dict[str, Any] = {
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
        # Enriched fields (deep audit only — omit if empty to keep output lean)
        for key in (
            "cwe_id",
            "cvss_score",
            "cvss_vector",
            "endpoint",
            "http_method",
            "http_params",
            "impact",
            "poc",
            "source_location",
            "sink_location",
        ):
            val = getattr(f, key, "")
            if val:  # skip empty/zero for lean output
                d[key] = val
        return d

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
    def _enrich_findings(
        findings: list[Any],
        deep_ctx: dict[str, Any] | None,
    ) -> list[Any]:
        """Cross-reference findings with deep audit context.

        For each finding, attach validation verdict, PoC from dynamic
        verification, and matching hypothesis data.  Returns the same
        list — we mutate in place then return for chaining.
        """
        if not deep_ctx or not findings:
            return findings

        # Build lookup maps from deep audit data
        hypotheses = deep_ctx.get("hypotheses", [])
        validations = deep_ctx.get("validations", [])
        dv_results = deep_ctx.get("dynamic_verification_results", [])

        # Map source+sink → hypothesis (for finding enrichment)
        hyp_by_key: dict[str, Any] = {}
        for h in hypotheses:
            key = getattr(h, "stable_key", "")
            if not key:
                src = getattr(h, "source_location", "")
                sink = getattr(h, "sink_location", "")
                vt = getattr(h, "vuln_type", "")
                if src and sink:
                    key = f"{src}|{sink}|{vt}"
            if key:
                hyp_by_key[key] = h

        # Map hypothesis_id → validation result
        val_by_hyp: dict[str, Any] = {}
        for v in validations:
            hid = getattr(v, "hypothesis_id", "")
            if hid:
                val_by_hyp[hid] = v

        # Map vuln_type → dynamic verification (best-effort)
        dv_by_vuln: dict[str, Any] = {}
        for dv in dv_results:
            vt = dv.get("vuln_type", "")
            if vt:
                # Keep the most confident confirmed result
                existing = dv_by_vuln.get(vt)
                if (
                    existing is None
                    or dv.get("updated_confidence", 0)
                    > existing.get("updated_confidence", 0)
                ):
                    dv_by_vuln[vt] = dv

        # Enrich each finding
        for f in findings:
            # Try to match with a hypothesis via source+sink+cwe
            src = getattr(f, "source_location", "")
            sink = getattr(f, "sink_location", "")
            cwe = getattr(f, "cwe_id", "")
            category = getattr(f, "category", "")
            vuln_type = category.split(",")[0].strip() if category else ""

            # Build candidate keys ordered by specificity
            keys_to_try: list[str] = []
            if src and sink and vuln_type:
                keys_to_try.append(f"{src}|{sink}|{vuln_type}")
            if src and sink and cwe:
                keys_to_try.append(f"{src}|{sink}|{cwe}")
            if src and sink:
                # Partial match: any vuln_type at this location
                for k in hyp_by_key:
                    if k.startswith(f"{src}|{sink}|"):
                        keys_to_try.append(k)

            matched_hyp = None
            for k in keys_to_try:
                if k in hyp_by_key:
                    matched_hyp = hyp_by_key[k]
                    break

            if matched_hyp is not None:
                # Attach validation verdict
                hid = getattr(matched_hyp, "id", "")
                val = val_by_hyp.get(hid)
                if val is not None:
                    f.validation_verdict = getattr(val, "verdict", "")
                    f.validation_confidence = getattr(val, "confidence", 0.0)

                # Fill in empty enriched fields from hypothesis
                if not getattr(f, "cwe_id", ""):
                    f.cwe_id = getattr(matched_hyp, "cwe_id", "")
                if not getattr(f, "source_location", ""):
                    f.source_location = getattr(matched_hyp, "source_location", "")
                if not getattr(f, "sink_location", ""):
                    f.sink_location = getattr(matched_hyp, "sink_location", "")
                if not getattr(f, "endpoint", ""):
                    f.endpoint = getattr(matched_hyp, "endpoint", "")
                if not getattr(f, "http_method", ""):
                    f.http_method = getattr(matched_hyp, "http_method", "")
                if not getattr(f, "http_params", ""):
                    f.http_params = getattr(matched_hyp, "http_params", "")

            # Attach PoC from dynamic verification
            vuln_type = vuln_type or getattr(f, "category", "")
            if vuln_type and not getattr(f, "poc", ""):
                dv = dv_by_vuln.get(vuln_type)
                if dv is not None:
                    poc_code = dv.get("poc_code", "")
                    if poc_code:
                        f.poc = poc_code

            # Build reproducible steps from endpoint + cwe
            endpoint = getattr(f, "endpoint", "")
            cwe_id = getattr(f, "cwe_id", "")
            if endpoint and cwe_id and not getattr(f, "reproducible_steps", ""):
                steps = ReportGenerator._build_repro_steps(f)
                if steps:
                    f.reproducible_steps = steps

            # Fill impact from template if empty
            if not getattr(f, "impact", ""):
                vt = vuln_type or ""
                if vt:
                    from hyqagent.report.templates import lookup_impact

                    f.impact = lookup_impact(vt)

        return findings

    @staticmethod
    def _build_repro_steps(finding: Any) -> str:
        """Build reproducible steps from finding metadata.

        Uses endpoint, http_method, http_params, and cwe_id to construct
        a step-by-step reproduction guide.  Returns empty string if
        insufficient data is available.
        """
        endpoint = getattr(finding, "endpoint", "")
        http_method = getattr(finding, "http_method", "GET")
        http_params = getattr(finding, "http_params", "")
        cwe_id = getattr(finding, "cwe_id", "")

        if not endpoint:
            return ""

        lines: list[str] = []
        lines.append(f"**目标端点**: `{http_method} {endpoint}`")
        lines.append("")

        # Step 1: craft malicious payload
        from hyqagent.report.templates import lookup_cwe_name

        cwe_name = lookup_cwe_name(cwe_id) or cwe_id

        if "CWE-89" in cwe_id:
            payload = "1' OR '1'='1' --"
            lines.append(
                f"1. 构造 SQL 注入 payload，例如 `{payload}`"
            )
        elif "CWE-79" in cwe_id:
            payload = "<script>alert(document.cookie)</script>"
            lines.append(
                f"1. 构造 XSS payload，例如 `{payload}`"
            )
        elif "CWE-918" in cwe_id:
            lines.append(
                "1. 将目标 URL 参数替换为内部服务地址（如 `http://169.254.169.254/latest/meta-data/`）"
            )
        elif "CWE-78" in cwe_id or "CWE-77" in cwe_id:
            lines.append(
                "1. 在输入参数中注入命令分隔符（如 `;`, `|`, `&&`），后接系统命令"
            )
        elif "CWE-22" in cwe_id:
            lines.append(
                "1. 在文件路径参数中使用 `../` 跳出预期目录，如 `../../etc/passwd`"
            )
        elif "CWE-502" in cwe_id:
            lines.append(
                "1. 使用 `ysoserial` 或类似工具生成恶意序列化 payload"
            )
        else:
            lines.append(
                f"1. 构造针对 {cwe_name} 的恶意输入"
                if cwe_name
                else "1. 构造针对该漏洞类型的恶意输入"
            )

        # Step 2: send request
        param_str = ""
        if http_params:
            params = [p.strip() for p in http_params.split(",") if p.strip()]
            if params:
                param_str = "?" + "&".join(f"{p}=<payload>" for p in params)

        lines.append(
            f"2. 向 `{http_method} {endpoint}{param_str}` 发送恶意请求"
        )

        # Step 3: verify
        lines.append("3. 观察响应——确认是否存在预期外的数据泄露或行为")

        return "\n".join(lines)

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
