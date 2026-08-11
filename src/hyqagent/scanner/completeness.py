"""scanner/completeness.py — Completeness Critic for coverage gap detection.

方案 3 from COVERAGE-GAP-ANALYSIS.md §6.3:
After each analysis round, a strong model asks structured questions to
identify what was MISSED — vulnerability classes not checked, code paths
skipped, assumptions that might be wrong.

This is NOT a vulnerability detector. It's a meta-analyst that reviews
the analysis process itself and points out blind spots for the next round.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from hyqagent.core.protocols import LlmProvider

logger = structlog.get_logger(__name__)


# ── Output dataclass ─────────────────────────────────────────────────────────


@dataclass
class CompletenessReport:
    """Structured output from the completeness critic."""

    overall_assessment: str
    missed_vuln_classes: list[str] = field(default_factory=list)
    skipped_code_paths: list[dict[str, str]] = field(default_factory=list)
    questionable_assumptions: list[str] = field(default_factory=list)
    framework_specific_blind_spots: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    raw_response: str = ""


# ── Structured output schema ─────────────────────────────────────────────────

CRITIC_SCHEMA: dict[str, Any] = {
    "name": "report_completeness",
    "description": "Report completeness analysis of a security audit",
    "input_schema": {
        "type": "object",
        "properties": {
            "overall_assessment": {
                "type": "string",
                "description": "Overall assessment of audit completeness (1 paragraph)",
            },
            "missed_vuln_classes": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Vulnerability classes that were NOT checked in this audit. "
                    "Be specific: name the CWE and why it was likely missed."
                ),
            },
            "skipped_code_paths": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "location": {"type": "string"},
                        "reason_skipped": {"type": "string"},
                        "risk_if_missed": {"type": "string"},
                    },
                    "required": ["location", "reason_skipped", "risk_if_missed"],
                },
                "description": "Code paths/modules that were skipped or under-analyzed",
            },
            "questionable_assumptions": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Assumptions made during the audit that might be wrong. "
                    "e.g. 'assumed ORM always parameterizes', "
                    "'assumed framework middleware handles auth'"
                ),
            },
            "framework_specific_blind_spots": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Framework-specific vulnerability patterns that weren't checked. "
                    "e.g. 'Django: raw() queryset method not checked', "
                    "'Spring: SpEL injection in @Value annotations not checked'"
                ),
            },
            "recommendations": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Concrete, actionable recommendations for the next analysis round. "
                    "Order by priority: most critical blind spot first."
                ),
            },
        },
        "required": [
            "overall_assessment",
            "missed_vuln_classes",
            "recommendations",
        ],
    },
}

# ── Prompt templates ─────────────────────────────────────────────────────────

CRITIC_SYSTEM = """\
You are a senior security engineer performing a **completeness review** of an
automated code security audit.

Your job is NOT to find vulnerabilities. Your job is to find what the audit
MISSED — blind spots, untested assumptions, skipped code paths,
unchecked vulnerability classes.

Be specific and actionable. Every observation should help the next round
of analysis focus on the highest-risk blind spots.

Rules:
1. Ground every observation in the data provided — don't guess.
2. If the data is insufficient to assess a dimension, say so explicitly.
3. Prioritize: CRITICAL blind spots first, then HIGH, then MEDIUM.
4. For each skipped path, estimate the risk if the path contains a vulnerability.
5. Framework-specific patterns are a common blind spot — check for them."""


def build_critic_prompt(
    project_summary: str = "",
    findings_summary: str = "",
    label_breakdown: dict[str, int] | None = None,
    coverage: dict[str, Any] | None = None,
    hypotheses: list[dict[str, Any]] | None = None,
    language: str = "",
) -> str:
    """Build the user prompt for the completeness critic."""
    label_breakdown = label_breakdown or {}
    coverage = coverage or {}
    hypotheses = hypotheses or []

    parts: list[str] = []

    # ── Context ──────────────────────────────────────────────────────
    if project_summary:
        parts.append(f"## Project Context\n{project_summary[:1500]}\n")

    parts.append(f"**Language**: {language or 'unknown'}")

    # ── What was found ───────────────────────────────────────────────
    if findings_summary:
        parts.append(f"## Phase 2 Deterministic Findings\n{findings_summary}")

    # ── What was classified ──────────────────────────────────────────
    if label_breakdown:
        lb_text = "\n".join(f"- {k}: {v} paths" for k, v in sorted(label_breakdown.items()))
        parts.append(f"## Path Label Breakdown\n{lb_text}\n")
        parts.append(
            "Key: 'heuristic_sink' = looks dangerous but scanner couldn't classify; "
            "'exposed_no_source' = endpoint accepts input but data flow tracing failed; "
            "'uncovered_sink' = sink is reachable but no rule covers it."
        )

    # ── LLM-generated hypotheses ─────────────────────────────────────
    if hypotheses:
        hyp_text = "\n".join(
            f"- [{h.get('severity', '?')}] {h.get('vuln_type', '?')} "
            f"({h.get('confidence', 0):.0%} confidence): {h.get('title', '?')[:120]}"
            for h in hypotheses[:15]
        )
        parts.append(f"## Phase 3 LLM Hypotheses ({len(hypotheses)} total)\n{hyp_text}")

    # ── Coverage data ────────────────────────────────────────────────
    if coverage:
        cov_text = "\n".join(f"- {k}: {v}" for k, v in sorted(coverage.items()))
        parts.append(f"## Coverage Summary\n{cov_text}")

    # ── The questions ────────────────────────────────────────────────
    parts.append(
        "\n## Completeness Review Questions\n\n"
        "### 1. Missed Vulnerability Classes\n"
        "Which CWE categories were NOT checked in this audit? "
        "Compare against the OWASP Top 10 and common web vulnerability classes. "
        "For each missed class, explain why the current analysis pipeline "
        "likely missed it (e.g. 'no data flow pattern', 'requires semantic understanding', "
        "'no YAML rule exists').\n\n"
        "### 2. Skipped or Under-Analyzed Code\n"
        "Looking at the label breakdown and coverage data, which modules or code paths "
        "appear to have been skipped or received insufficient analysis? "
        "Are the skip reasons valid, or should these be re-examined?\n\n"
        "### 3. Questionable Assumptions\n"
        "What assumptions did the analysis pipeline make that might be wrong? "
        "Consider: 'the ORM always parameterizes queries', "
        "'the framework's CSRF middleware covers all endpoints', "
        "'the auth decorator is applied consistently'.\n\n"
        "### 4. Framework-Specific Blind Spots\n"
        "What framework-specific vulnerability patterns were NOT checked? "
        "Examples: Django raw() queryset, Spring SpEL injection, "
        "Express middleware bypass, Flask debug mode RCE.\n\n"
        "### 5. Prioritized Recommendations\n"
        "List 3-8 concrete actions for the next analysis round, "
        "ordered by risk (most dangerous blind spot first).\n\n"
        "Use the report_completeness tool to output your analysis."
    )

    return "\n".join(parts)


# ── CompletenessCritic ───────────────────────────────────────────────────────


class CompletenessCritic:
    """Post-analysis completeness reviewer.

    After each round of Phase 3 hypothesis generation, the critic reviews
    what was found and identifies blind spots for the next round.

    Usage::

        critic = CompletenessCritic(mid_provider, mid_model)
        report = await critic.review(
            project_summary=...,
            findings_summary=...,
            label_breakdown=...,
            coverage=...,
            hypotheses=...,
            language="python",
        )
        # Feed report.recommendations into next round of scanning
    """

    def __init__(
        self,
        provider: LlmProvider,
        model_id: str,
    ) -> None:
        """Initialize with a MID or STRONG tier provider for quality analysis."""
        self._provider = provider
        self._model_id = model_id

    async def review(
        self,
        project_summary: str = "",
        findings_summary: str = "",
        label_breakdown: dict[str, int] | None = None,
        coverage: dict[str, Any] | None = None,
        hypotheses: list[dict[str, Any]] | None = None,
        language: str = "",
    ) -> CompletenessReport:
        """Run the completeness review.

        Returns a :class:`CompletenessReport` with actionable recommendations
        for the next analysis round.
        """
        prompt = build_critic_prompt(
            project_summary=project_summary,
            findings_summary=findings_summary,
            label_breakdown=label_breakdown,
            coverage=coverage,
            hypotheses=hypotheses,
            language=language,
        )

        try:
            result = await self._provider.generate_structured(
                messages=[{"role": "user", "content": prompt}],
                model=self._model_id,
                output_schema=CRITIC_SCHEMA,
                system=CRITIC_SYSTEM,
                max_tokens=2048,
                temperature=0.3,
            )

            return CompletenessReport(
                overall_assessment=result.get("overall_assessment", ""),
                missed_vuln_classes=result.get("missed_vuln_classes", []),
                skipped_code_paths=result.get("skipped_code_paths", []),
                questionable_assumptions=result.get("questionable_assumptions", []),
                framework_specific_blind_spots=result.get("framework_specific_blind_spots", []),
                recommendations=result.get("recommendations", []),
                raw_response=str(result),
            )
        except Exception:
            logger.exception("completeness_critic_failed")
            return CompletenessReport(
                overall_assessment="Completeness critic failed — could not reach model.",
                recommendations=["Re-run completeness review when model is available."],
            )
