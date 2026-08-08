"""cpg/coverage.py — Coverage tracker and blind-spot manifest generator.

Provides quantitative visibility into what the analyser covered and what it
didn't — a capability that no mainstream SAST tool currently offers out of
the box.

All computation is **zero-LLM** — pure CPG graph statistics.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hyqagent.cpg.graph import NODE_ASSIGNMENT
from hyqagent.cpg.types import BlindSpot, CoverageReport

if TYPE_CHECKING:
    import networkx as nx


# ── Vulnerability category ↔ CWE mapping (informative labels for blind spots) ──

_CATEGORY_CWE_MAP: dict[str, str] = {
    "sql_injection": "CWE-89",
    "command_injection": "CWE-78",
    "xss": "CWE-79",
    "path_traversal": "CWE-22",
    "ssrf": "CWE-918",
    "deserialization": "CWE-502",
    "open_redirect": "CWE-601",
    "code_injection": "CWE-94",
    "auth_bypass": "CWE-287",
    "xxe": "CWE-611",
}

# Vulnerability categories that are NOT data-flow problems — they can never
# be detected by taint tracking alone, so they always appear as blind spots.
_STRUCTURAL_BLIND_SPOTS: list[dict[str, str]] = [
    {
        "reason": "idor_no_structural_signature",
        "recommendation": "IDOR (CWE-639) 无结构性签名——需人工审查所有权检查逻辑。"
                          "后续 Phase 3+ 的 blind_scan LLM 通道将自动审查此类端点。",
        "severity": "high",
    },
    {
        "reason": "business_logic_no_sink",
        "recommendation": "业务逻辑缺陷 (CWE-841) 无代码级 sink——需人工审查支付/优惠券/"
                          "工作流状态机逻辑。后续 Phase 3+ 将支持行为契约验证。",
        "severity": "medium",
    },
    {
        "reason": "race_condition_not_modeled",
        "recommendation": "竞态条件/TOCTOU (CWE-367) — CPG 无线程交错模型，无法检测。"
                          "建议人工审查共享状态访问。",
        "severity": "medium",
    },
    {
        "reason": "second_order_not_modeled",
        "recommendation": "二阶注入 — 污染跨越持久化边界（写请求 → 数据库 → 读请求），"
                          "当前单请求 CPG 模型无法追踪。",
        "severity": "medium",
    },
    {
        "reason": "prototype_pollution_not_modeled",
        "recommendation": "JS Prototype Pollution (CWE-1321) — 需要原型链感知分析，"
                          "当前未实现。建议对 JS 项目使用 npm audit 补充。",
        "severity": "low",
    },
]


class CoverageTracker:
    """Tracks analysis coverage and produces a blind-spot manifest.

    Three layers of metrics (per `COVERAGE-IMPROVEMENT-PLAN.md`):

    * **L1 — Graph connectivity**: endpoint_coverage_ratio — how many HTTP
      endpoints have at least one taint path?
    * **L2 — Detection rule coverage**: sink_coverage_ratio — how many
      potential sinks are matched by a YAML rule?
    * **L3 — Semantic dimension**: which CWE categories are structurally
      undetectable by the current analyser?

    Usage::

        tracker = CoverageTracker(builder.graph)
        tracker.set_endpoints(flask_extractor.endpoints)
        tracker.set_framework("Flask")
        report = tracker.compute_coverage()
        for bs in report.blind_spots:
            print(bs.location, bs.reason)
    """

    def __init__(self, graph: nx.MultiDiGraph) -> None:
        self._graph = graph
        self._endpoints: list = []
        self._framework: str = ""
        self._language: str = ""
        self._active_categories: set[str] = set()

    def set_endpoints(self, endpoints: list) -> None:
        """Register the framework-extracted HTTP endpoints."""
        self._endpoints = list(endpoints)

    def set_framework(self, framework: str) -> None:
        """Set the detected framework name (informational-only)."""
        self._framework = framework

    def set_language(self, language: str) -> None:
        """Set the detected language for better blind-spot recommendations."""
        self._language = language

    def set_active_categories(self, categories: set[str]) -> None:
        """Register which taint categories were actually detected in this scan."""
        self._active_categories = set(categories)

    # ── Public API ──────────────────────────────────────────────────────

    def compute_coverage(self) -> CoverageReport:
        """Run all three layers and return a complete :class:`CoverageReport`."""
        endpoint_total = len(self._endpoints)
        endpoint_analyzed = self._count_analyzed_endpoints()
        ep_ratio = endpoint_analyzed / endpoint_total if endpoint_total > 0 else 0.0

        sink_total = 0
        sink_labeled = 0
        for _nid, data in self._graph.nodes(data=True):
            if data.get("node_type") != NODE_ASSIGNMENT:
                continue
            src = data.get("source", "")
            if not src or "(" not in src:
                continue  # not a call-like sink candidate
            sink_total += 1
            if data.get("taint_category"):
                sink_labeled += 1

        sink_ratio = sink_labeled / sink_total if sink_total > 0 else 0.0

        blind_spots = self.generate_blind_spot_manifest()

        return CoverageReport(
            endpoint_total=endpoint_total,
            endpoint_analyzed=endpoint_analyzed,
            endpoint_coverage_ratio=round(ep_ratio, 3),
            sink_total=sink_total,
            sink_labeled=sink_labeled,
            sink_coverage_ratio=round(sink_ratio, 3),
            blind_spots=blind_spots,
        )

    def generate_blind_spot_manifest(self) -> list[BlindSpot]:
        """Generate a human-readable list of everything the analyser did NOT cover.

        Combines:
        * Data-driven gaps (endpoints without sources, sinks without rules)
        * Structural gaps (vuln categories impossible for taint analysis)
        """
        manifest: list[BlindSpot] = []

        # ── 1. Endpoints with no source coverage ──────────────────────
        for ep in self._endpoints:
            handler = getattr(ep, "handler_func", "")
            route = getattr(ep, "route", "")
            fpath = getattr(ep, "file_path", "")
            line = getattr(ep, "line", 0)
            auth = getattr(ep, "auth_required", None)

            if not handler:
                continue

            location = f"{fpath}:{line}" if fpath else f"func:{handler}"

            # Check whether this endpoint has any taint-source coverage
            if not self._endpoint_has_labeled_source(handler, fpath):
                msg = (
                    f"端点 {route or handler} 无已知污染源覆盖。"
                    f"可能包含 IDOR / 认证绕过 / 业务逻辑缺陷。"
                )
                manifest.append(
                    BlindSpot(
                        location=location,
                        reason="exposed_no_source",
                        recommendation=msg,
                        severity="high",
                    )
                )

            # Missing auth annotation
            if auth is False:
                manifest.append(
                    BlindSpot(
                        location=location,
                        reason="missing_auth_annotation",
                        recommendation=f"端点 {route or handler} 缺少认证装饰器/注解，"
                                        f"建议人工审查访问控制。",
                        severity="high",
                    )
                )

        # ── 2. Structural blind spots (always present) ─────────────────
        for sb in _STRUCTURAL_BLIND_SPOTS:
            manifest.append(
                BlindSpot(
                    location="(structural)",
                    reason=sb["reason"],
                    recommendation=sb["recommendation"],
                    severity=sb["severity"],
                )
            )

        # ── 3. Gap in category coverage ────────────────────────────────
        covered = self._active_categories
        all_known = set(_CATEGORY_CWE_MAP.keys())
        missing_cats = all_known - covered
        for cat in sorted(missing_cats):
            cwe = _CATEGORY_CWE_MAP.get(cat, "")
            manifest.append(
                BlindSpot(
                    location="(rule_gap)",
                    reason=f"category_not_triggered:{cat}",
                    recommendation=f"未触发 {cat} ({cwe}) 规则——该项目可能不存在此类漏洞，"
                                    f"或 YAML 规则需要扩展。",
                    severity="low",
                )
            )

        return manifest

    # ── Internal helpers ─────────────────────────────────────────────────

    def _count_analyzed_endpoints(self) -> int:
        """Count how many endpoints have at least one labelled assignment."""
        count = 0
        for ep in self._endpoints:
            handler = getattr(ep, "handler_func", "")
            fpath = getattr(ep, "file_path", "")
            if handler and self._endpoint_has_labeled_source(handler, fpath):
                count += 1
        return count

    def _endpoint_has_labeled_source(
        self, handler_func: str, file_path: str
    ) -> bool:
        """Check whether *handler_func* contains any ``taint_category``-labelled node."""
        for _nid, data in self._graph.nodes(data=True):
            if data.get("node_type") != NODE_ASSIGNMENT:
                continue
            if data.get("enclosing_function") != handler_func:
                continue
            if file_path and data.get("file_path") != file_path:
                continue
            if data.get("taint_category"):
                return True
        return False
