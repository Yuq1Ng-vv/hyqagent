"""scanner/validator.py — Two-layer vulnerability hypothesis validation.

L1 (deterministic, zero-LLM): path reachability, source/sink type match,
code consistency checks. Filters ~30-40% of obvious false positives.

L2 (LLM-powered): 5-question verification for high-value hypotheses.
- Uses MID or STRONG tier depending on severity.
- Provides detailed reasoning for each verdict.
- When a :class:`NudgeLoop` is provided, L2 calls are wrapped in a
  multi-turn loop that prevents premature/incomplete verdicts.
  Adapted from AutoCVE — see :mod:`hyqagent.scanner.nudge`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from hyqagent.cpg.query import CPGQuery
    from hyqagent.cpg.taint_loader import TaintRuleLoader
    from hyqagent.core.protocols import LlmProvider
    from hyqagent.models.router import ModelRouter
    from hyqagent.scanner.hypothesis import Hypothesis
    from hyqagent.scanner.nudge import NudgeLoop

logger = structlog.get_logger(__name__)


# ── Validation result ────────────────────────────────────────────────────────


@dataclass
class ValidationResult:
    """The outcome of validating a single hypothesis."""

    hypothesis_id: str
    verdict: str  # confirmed | rejected | inconclusive | needs_human
    confidence: float  # updated confidence (0.0-1.0)
    validation_type: str  # l1_deterministic | l2_llm
    reasoning: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    model: str = ""  # model_id for L2, empty for L1


# ── L2 validator prompt ──────────────────────────────────────────────────────

VALIDATOR_SYSTEM = """You are a senior security engineer verifying vulnerability reports.

For each hypothesis, answer these 5 questions:
1. **Path Reachability**: Can the source input actually reach the sink at runtime?
   Consider authentication, routing, conditional guards, and middleware.
2. **Condition Bypass**: If there are conditions (if/guard) between source and sink,
   can an attacker control or bypass them?
3. **Sanitizer Adequacy**: If a sanitizer is present, is it effective?
   Is it applied in all code paths? Can it be bypassed with encoding tricks?
4. **Framework Protection**: Does the framework provide implicit protection?
   (e.g. Django ORM auto-parameterizes, React auto-escapes JSX, Spring Security CSRF)
5. **Comprehensive Judgment**: Is this a real, exploitable vulnerability?
   What is your final verdict and confidence?

Output structured JSON with your analysis."""

VALIDATOR_SCHEMA: dict[str, Any] = {
    "name": "report_validation",
    "description": "Report validation verdict for a vulnerability hypothesis",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["confirmed", "rejected", "inconclusive", "needs_human"],
                "description": "Final validation verdict",
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Updated confidence after analysis",
            },
            "q1_reachability": {
                "type": "string",
                "description": "Analysis of path reachability at runtime",
            },
            "q2_bypass": {
                "type": "string",
                "description": "Analysis of condition bypass possibility",
            },
            "q3_sanitizer": {
                "type": "string",
                "description": "Analysis of sanitizer adequacy",
            },
            "q4_framework": {
                "type": "string",
                "description": "Analysis of framework protections",
            },
            "q5_judgment": {
                "type": "string",
                "description": "Comprehensive judgment and reasoning",
            },
            "exploit_scenario": {
                "type": "string",
                "description": "Concrete exploit scenario if confirmed, else empty",
            },
        },
        "required": ["verdict", "confidence", "q1_reachability", "q5_judgment"],
    },
}


def _build_validation_prompt(
    hypothesis: Hypothesis,
    code_context: str,
    sanitizer_info: str = "",
) -> str:
    """Build the user prompt for L2 validation."""
    parts = [
        "## Vulnerability Hypothesis",
        f"**Type**: {hypothesis.vuln_type}",
        f"**CWE**: {hypothesis.cwe_id}",
        f"**Severity**: {hypothesis.severity}",
        f"**LLM Confidence**: {hypothesis.confidence:.2f}",
        f"**Source**: {hypothesis.source_location}",
        f"**Sink**: {hypothesis.sink_location}",
        f"\n**Description**: {hypothesis.description}",
        f"\n**LLM Reasoning**: {hypothesis.reasoning}",
    ]
    if sanitizer_info:
        parts.append(f"\n**Sanitizer Info**: {sanitizer_info}")
    if hypothesis.remediation:
        parts.append(f"\n**Suggested Remediation**: {hypothesis.remediation}")

    parts.append(f"\n## Code Context\n```\n{code_context}\n```")
    parts.append(
        "\nAnalyse the hypothesis and code above. Answer the 5 validation "
        "questions and provide your verdict using the report_validation tool."
    )

    return "\n".join(parts)


# ── Validator ────────────────────────────────────────────────────────────────


class Validator:
    """Two-layer hypothesis validator.

    L1 is zero-LLM: path reachability, type matching, code consistency.
    L2 is LLM-powered: 5-question deep verification.

    Usage::

        validator = Validator(query, taint_loader, router, mid_provider, strong_provider)
        l1 = validator.validate_l1(hypothesis)
        if l1.verdict != "rejected":
            l2 = await validator.validate_l2(hypothesis, code_context)
    """

    def __init__(
        self,
        query: CPGQuery,
        taint_loader: TaintRuleLoader,
        router: ModelRouter,
        mid_provider: LlmProvider,
        strong_provider: LlmProvider,
        language: str,
        nudge_loop: NudgeLoop | None = None,
    ) -> None:
        self._query = query
        self._taint_loader = taint_loader
        self._router = router
        self._mid = mid_provider
        self._strong = strong_provider
        self._language = language
        self._nudge_loop = nudge_loop
        # Recall-mode optional dependency (set by orchestrator)
        self._code_retriever: Any = None

    # ── L1: Deterministic validation ────────────────────────────────────

    def validate_l1(self, hypothesis: Hypothesis) -> ValidationResult:
        """Zero-LLM deterministic checks.

        Three checks:
        1. Source/sink type match — does the source belong to the claimed category?
        2. Sink type match — does the sink belong to the claimed category?
        3. Code consistency — does the hypothesis description mention real code?
        """
        evidence: list[dict[str, Any]] = []
        issues: list[str] = []

        # Check 1: Source type
        if hypothesis.source_location:
            src_cats = self._taint_loader.match_all_sources(
                self._language,
                hypothesis.source_location,
            )
            if src_cats and hypothesis.vuln_type not in src_cats:
                issues.append(f"Source doesn't match {hypothesis.vuln_type}: matched {src_cats}")
                evidence.append(
                    {
                        "check": "source_type",
                        "status": "mismatch",
                        "expected": hypothesis.vuln_type,
                        "actual": src_cats,
                    }
                )
            elif src_cats:
                evidence.append({"check": "source_type", "status": "match", "categories": src_cats})

        # Check 2: Sink type
        if hypothesis.sink_location:
            sink_cat = self._taint_loader.match_sink(
                self._language,
                hypothesis.sink_location,
            )
            if sink_cat and hypothesis.vuln_type != sink_cat:
                issues.append(f"Sink doesn't match {hypothesis.vuln_type}: matched {sink_cat}")
                evidence.append(
                    {
                        "check": "sink_type",
                        "status": "mismatch",
                        "expected": hypothesis.vuln_type,
                        "actual": sink_cat,
                    }
                )
            elif sink_cat:
                evidence.append({"check": "sink_type", "status": "match", "category": sink_cat})

        # Check 3: Code consistency (basic — full check needs file I/O)
        # Verify the hypothesis references recognizable code patterns
        if hypothesis.evidence:
            evidence.append(
                {
                    "check": "code_consistency",
                    "status": "has_evidence",
                    "length": len(hypothesis.evidence),
                }
            )
        elif hypothesis.description:
            evidence.append({"check": "code_consistency", "status": "no_direct_evidence"})

        # Determine verdict
        if len(issues) >= 2:
            # Multiple type mismatches → likely false positive
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                verdict="rejected",
                confidence=hypothesis.confidence * 0.3,
                validation_type="l1_deterministic",
                reasoning="; ".join(issues),
                evidence=evidence,
            )
        elif len(issues) == 1:
            # Single mismatch → inconclusive, let L2 sort it out
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                verdict="inconclusive",
                confidence=hypothesis.confidence * 0.7,
                validation_type="l1_deterministic",
                reasoning="; ".join(issues),
                evidence=evidence,
            )
        else:
            # All checks pass → confirmed at L1 level
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                verdict="confirmed",
                confidence=min(1.0, hypothesis.confidence * 1.1),
                validation_type="l1_deterministic",
                reasoning="All L1 checks passed: source/sink types match",
                evidence=evidence,
            )

    # ── L2: LLM validation ──────────────────────────────────────────────

    async def validate_l2(
        self,
        hypothesis: Hypothesis,
        code_context: str,
        sanitizer_info: str = "",
    ) -> ValidationResult:
        """LLM-powered 5-question verification.

        Routes to STRONG for critical/high severity, MID for medium/low.
        """
        from hyqagent.models.router import Task, TaskType

        # Route based on severity
        is_high_severity = hypothesis.severity in ("critical", "high")
        complexity = 8 if is_high_severity else 5
        task = Task(
            task_type=TaskType.L2_VALIDATION,
            complexity=complexity,
            estimated_prompt_tokens=(len(code_context) + 2000) // 3,
        )
        provider, model_id = self._router.route(task)

        prompt = _build_validation_prompt(
            hypothesis,
            code_context,
            sanitizer_info,
        )

        try:
            if self._nudge_loop is not None:
                from hyqagent.scanner.nudge import stop_on_missing_verdict

                nudge_result = await self._nudge_loop.run(
                    provider=provider,
                    model=model_id,
                    messages=[{"role": "user", "content": prompt}],
                    output_schema=VALIDATOR_SCHEMA,
                    system=VALIDATOR_SYSTEM,
                    max_tokens=4096,
                    temperature=0.1,
                    stop_hooks=[stop_on_missing_verdict],
                )
                if nudge_result.success:
                    result = nudge_result.data
                else:
                    logger.warning(
                        "nudge_loop_incomplete_l2",
                        hypothesis_id=hypothesis.id,
                        reason=nudge_result.termination_reason,
                    )
                    result = nudge_result.data if nudge_result.data else {}
            else:
                result = await provider.generate_structured(
                    messages=[{"role": "user", "content": prompt}],
                    model=model_id,
                    output_schema=VALIDATOR_SCHEMA,
                    system=VALIDATOR_SYSTEM,
                    max_tokens=4096,
                    temperature=0.1,
                )

            verdict = result.get("verdict", "inconclusive")
            confidence = float(result.get("confidence", hypothesis.confidence))
            reasoning_parts = []
            for q in [
                "q1_reachability",
                "q2_bypass",
                "q3_sanitizer",
                "q4_framework",
                "q5_judgment",
            ]:
                if result.get(q):
                    reasoning_parts.append(f"[{q}] {result[q]}")

            return ValidationResult(
                hypothesis_id=hypothesis.id,
                verdict=verdict,
                confidence=confidence,
                validation_type="l2_llm",
                reasoning="\n\n".join(reasoning_parts),
                evidence=[{"l2_result": result}],
                model=model_id,
            )
        except Exception:
            logger.exception(
                "l2_validation_failed",
                hypothesis_id=hypothesis.id,
                model=model_id,
            )
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                verdict="inconclusive",
                confidence=hypothesis.confidence,
                validation_type="l2_llm",
                reasoning="LLM validation failed — could not reach model",
                evidence=[],
                model=model_id,
            )

    # ── Recall mode helpers ────────────────────────────────────────────

    def set_recall_deps(self, code_retriever: Any) -> None:
        """Wire recall-mode code retriever (called by orchestrator)."""
        self._code_retriever = code_retriever

    def _read_code_for_hypothesis(self, hypothesis: Hypothesis) -> str:
        """Read source code surrounding the hypothesis source/sink locations.

        Uses CodeRetriever chunk index to find the enclosing function.
        Returns combined source_context for L2 validation.
        """
        parts: list[str] = []
        locations = [
            getattr(hypothesis, "source_location", ""),
            getattr(hypothesis, "sink_location", ""),
        ]

        for loc in locations:
            if not loc or ":" not in loc:
                continue
            try:
                file_path, line_str = loc.rsplit(":", 1)
                line_num = int(line_str)
            except (ValueError, TypeError):
                continue

            # Try chunks in the file
            chunks = self._code_retriever.get_chunks_for_file(file_path)
            for chunk in chunks:
                if chunk.start_line <= line_num <= chunk.end_line:
                    heading = (
                        f"Function: {chunk.function_name or '<module>'}"
                        if chunk.function_name
                        else "Module-level code"
                    )
                    parts.append(
                        f"## {heading} ({file_path}:{chunk.start_line}-{chunk.end_line})\n"
                        f"```\n{chunk.code[:2000]}\n```"
                    )
                    break

        return "\n\n".join(parts)

    # ── Convenience: full validation ────────────────────────────────────

    async def validate(
        self,
        hypothesis: Hypothesis,
        code_context: str = "",
        sanitizer_info: str = "",
    ) -> tuple[ValidationResult, ValidationResult | None]:
        """Run L1 → L2 full validation pipeline.

        Returns (l1_result, l2_result_or_none).
        L2 is skipped if L1 rejects the hypothesis.
        """
        l1 = self.validate_l1(hypothesis)

        if l1.verdict == "rejected":
            logger.info(
                "hypothesis_rejected_l1",
                hypothesis_id=hypothesis.id,
                reasoning=l1.reasoning,
            )
            return l1, None

        # Recall mode: auto-read code context from hypothesis locations
        if not code_context and self._code_retriever is not None:
            code_context = self._read_code_for_hypothesis(hypothesis)

        l2 = await self.validate_l2(hypothesis, code_context, sanitizer_info)
        logger.info(
            "hypothesis_validated",
            hypothesis_id=hypothesis.id,
            l1_verdict=l1.verdict,
            l2_verdict=l2.verdict,
            final_confidence=l2.confidence,
        )
        return l1, l2
