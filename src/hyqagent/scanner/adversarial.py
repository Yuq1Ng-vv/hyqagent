"""scanner/adversarial.py — Adversarial review of rejected vulnerability hypotheses.

Implements Phase 4 Task 7: 对抗性审查 (Attacker's Lens).  The validator
concluded a path is safe — an independent model re-examines from the
attacker's perspective, systematically probing for bypasses.

Core design philosophy: **提出者 ≠ 裁决者** — the model that generates
or rejects hypotheses MUST differ from the model reviewing the rejections.

See COVERAGE-GAP-ANALYSIS.md §6 and LONG-RUNNING-AGENT-ARCHITECTURE.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

# ── Data model ──────────────────────────────────────────────────────────────


@dataclass
class AdversarialReviewResult:
    """Outcome of adversarial review for a single rejected hypothesis."""

    hypothesis_id: str
    original_verdict: str = "rejected"  # always "rejected" — we only review rejections
    review_verdict: str = "upheld"  # "upheld" | "overturned"
    confidence: float = 0.0  # updated confidence after adversarial review
    bypass_found: bool = False
    attack_vector: str = ""  # successful attack vector, empty if bypass_found=False
    reasoning: str = ""  # the adversarial reviewer's full attack analysis
    model: str = ""  # model_id used for this review


# ── Structured output schema ───────────────────────────────────────────────

ADVERSARIAL_SCHEMA: dict[str, Any] = {
    "name": "report_adversarial_review",
    "description": "Report adversarial review findings for a rejected hypothesis",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["upheld", "overturned"],
                "description": (
                    "upheld = the rejection was correct, path is safe. "
                    "overturned = the rejection was wrong, found a viable attack."
                ),
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Confidence in this adversarial finding",
            },
            "bypass_found": {
                "type": "boolean",
                "description": "Whether a concrete bypass of the defensive measures was found",
            },
            "attack_vector": {
                "type": "string",
                "description": (
                    "If bypass_found=true: the specific attack vector discovered. "
                    "Include encoding tricks, bypass technique, chained steps. "
                    "If bypass_found=false: empty string."
                ),
            },
            "reasoning": {
                "type": "string",
                "description": (
                    "Step-by-step reasoning: which attack vectors were tried, "
                    "why each worked or failed, and what the auditor missed."
                ),
            },
        },
        "required": ["verdict", "confidence", "bypass_found", "reasoning"],
    },
}

# ── Prompt templates ────────────────────────────────────────────────────────

ADVERSARIAL_SYSTEM = """\
You are an offensive security researcher conducting adversarial review of a code audit.

Your role: The auditor examined a code path and concluded it is SAFE (no
exploitable vulnerability). Your job is to PROVE THEM WRONG. Think like an
attacker. Find the cracks they missed.

## Review Framework
For each rejected path, systematically probe:

1. **Sanitizer Bypass**: Can the sanitizer be circumvented?
   - Encoding tricks (URL encoding, double encoding, UTF-7/16, Unicode normalization)
   - Null byte injection, newline injection, CRLF
   - Recursive/nested payloads, polyglots
   - Timing-based filter evasion

2. **Second-Order Attacks**: Does the data pass through intermediate storage?
   - Stored in database → later retrieved without re-sanitization
   - Cached (session/redis/memcached) → reused unsafely
   - Written to file → later included/executed

3. **Type-System Manipulation**: Can type boundaries be violated?
   - String→int coercion in dynamic languages
   - Deserialization gadgets (JSON, YAML, pickle, marshal)
   - Prototype pollution (JavaScript)
   - Duck typing weaknesses in Python

4. **Alternative Input Vectors**: Are there indirect paths?
   - HTTP headers (User-Agent, Referer, X-Forwarded-For, cookies)
   - File uploads (filename, MIME type, metadata)
   - WebSocket messages, Server-Sent Events
   - Query parameters that bypass routing middleware

5. **Timing Side Channels**: Does the code leak through timing?
   - String comparison timing differences
   - Early return vs. full processing
   - Database query timing (LIKE, regex patterns)

6. **Error Message Leaks**: Do error messages reveal internals?
   - Stack traces exposing file paths
   - Database error messages revealing schema
   - Validation details revealing business logic

## Rules
1. Be specific: cite exact code patterns, variable names where visible.
2. If you find a viable attack, explain the FULL exploit chain step by step.
3. If the auditor was correct, explain WHY each attack vector fails concretely.
4. Do NOT hallucinate — only report attack vectors that actually apply to this code.
5. Confidence: >0.8 for confirmed bypass, <0.3 if truly safe, 0.4-0.7 if uncertain.

Use the report_adversarial_review tool for your output."""


def _build_adversarial_prompt(
    hypothesis: dict[str, Any] | Any,
    validation: dict[str, Any] | Any,
    code_context: str = "",
    sanitizer_info: str = "",
) -> str:
    """Build the user prompt for adversarial review of one rejected hypothesis.

    Accepts both dataclass objects and dicts (for testability).
    """
    parts: list[str] = []

    def _get(obj: Any, key: str, default: str = "") -> str:
        if isinstance(obj, dict):
            return str(obj.get(key, default))
        return str(getattr(obj, key, default) or default)

    # ── Hypothesis details ──────────────────────────────────────────
    vuln_type = _get(hypothesis, "vuln_type", "unknown")
    severity = _get(hypothesis, "severity", "unknown")
    cwe = _get(hypothesis, "cwe_id", "?")
    title = _get(hypothesis, "title", "")
    description = _get(hypothesis, "description", "")
    source = _get(hypothesis, "source_location", "?")
    sink = _get(hypothesis, "sink_location", "?")

    parts.append("## Rejected Hypothesis")
    parts.append(f"- **Vulnerability Type**: {vuln_type} ({cwe})")
    parts.append(f"- **Severity**: {severity}")
    if title:
        parts.append(f"- **Title**: {title}")
    parts.append(f"- **Source**: {source}")
    parts.append(f"- **Sink**: {sink}")
    if description:
        parts.append(f"\n**Description**: {description[:800]}\n")

    # ── Auditor's rejection reasoning ───────────────────────────────
    rejection_reason = _get(validation, "reasoning", "No reasoning provided.")
    parts.append("## Auditor's Rejection Reasoning")
    msg = f"The auditor rejected this as NOT exploitable because:\n{rejection_reason[:1200]}\n"
    parts.append(msg)

    # ── Sanitizer information ───────────────────────────────────────
    if sanitizer_info:
        parts.append(f"## Sanitizer Context\n{sanitizer_info[:500]}\n")

    # ── Code context ────────────────────────────────────────────────
    if code_context:
        parts.append(f"## Code Context\n```\n{code_context[:2000]}\n```\n")

    # ── Attack directives ───────────────────────────────────────────
    parts.append("## Your Task")
    parts.append(
        "The auditor claims this code path is safe. Systematically probe:\n"
        "1. Can sanitizers (if any) be bypassed with encoding tricks?\n"
        "2. Is there a second-order attack path?\n"
        "3. Can the type system be subverted?\n"
        "4. Are there alternative input vectors the auditor missed?\n"
        "5. Do timing differences or error messages leak useful information?"
    )

    return "\n".join(parts)


# ── Reviewer class ─────────────────────────────────────────────────────────


class AdversarialReviewer:
    """Independent adversarial review of rejected vulnerability hypotheses.

    The model reviewing rejections must be stronger than the validator
    that rejected them — implementing the "提出者 ≠ 裁决者" principle.

    Usage::

        reviewer = AdversarialReviewer(
            provider=strong_provider,
            model="claude-opus-5",
            nudge_loop=nudge,
        )
        results = await reviewer.review(rejected, code_contexts={})
    """

    def __init__(
        self,
        provider: Any,  # AnthropicProvider
        model: str,
        nudge_loop: Any | None = None,  # NudgeLoop
    ) -> None:
        """Initialize with a STRONG-tier provider for adversarial analysis.

        Args:
            provider: AnthropicProvider (typically strong_provider for deep mode).
            model: Model ID string.
            nudge_loop: Optional NudgeLoop to prevent premature LLM termination.

        """
        self._provider = provider
        self._model = model
        self._nudge_loop = nudge_loop

    # ── Public API ──────────────────────────────────────────────────────

    async def review(
        self,
        rejected: list[tuple[Any, Any]],
        code_contexts: dict[str, str] | None = None,
    ) -> list[AdversarialReviewResult]:
        """Review a batch of rejected hypotheses.

        Args:
            rejected: List of (hypothesis, validation_result) tuples where
                      validation_result.verdict == "rejected".
            code_contexts: Optional dict mapping hypothesis_id → code snippet.

        Returns:
            One AdversarialReviewResult per rejected hypothesis.

        """
        if not rejected:
            return []

        code_contexts = code_contexts or {}
        results: list[AdversarialReviewResult] = []

        for hypothesis, validation in rejected:
            hid = _safe_id(hypothesis)
            ctx = code_contexts.get(hid, "")
            result = await self._review_one(hypothesis, validation, ctx)
            results.append(result)

        return results

    # ── Internals ───────────────────────────────────────────────────────

    async def _review_one(
        self,
        hypothesis: Any,
        validation: Any,
        code_context: str,
    ) -> AdversarialReviewResult:
        """Adversarially review a single rejected hypothesis."""
        hid = _safe_id(hypothesis)

        prompt = _build_adversarial_prompt(
            hypothesis=hypothesis,
            validation=validation,
            code_context=code_context,
        )

        try:
            if self._nudge_loop is not None:
                raw = await self._call_with_nudge(prompt)
            else:
                raw = await self._call_llm(prompt)
        except Exception:
            # On LLM failure, default to upholding the rejection
            return AdversarialReviewResult(
                hypothesis_id=hid,
                original_verdict="rejected",
                review_verdict="upheld",
                confidence=0.5,
                bypass_found=False,
                attack_vector="",
                reasoning="Adversarial review failed (LLM error). Defaulting to uphold.",
                model=self._model,
            )

        return self._parse_response(hid, raw)

    async def _call_llm(self, prompt: str) -> dict[str, Any]:
        """Direct LLM call without NudgeLoop."""
        return cast(
            dict[str, Any],
            await self._provider.generate_structured(
                messages=[{"role": "user", "content": prompt}],
                model=self._model,
                output_schema=ADVERSARIAL_SCHEMA,
                system=ADVERSARIAL_SYSTEM,
                max_tokens=4096,
                temperature=0.1,
            ),
        )

    async def _call_with_nudge(self, prompt: str) -> dict[str, Any]:
        """LLM call wrapped in NudgeLoop for resilience."""
        from hyqagent.scanner.nudge import stop_on_missing_verdict

        assert self._nudge_loop is not None  # only called when nudge_loop is set
        result = await self._nudge_loop.run(
            provider=self._provider,
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            output_schema=ADVERSARIAL_SCHEMA,
            system=ADVERSARIAL_SYSTEM,
            max_tokens=4096,
            temperature=0.1,
            stop_hooks=[stop_on_missing_verdict],
        )
        return cast(dict[str, Any], result.data)

    def _parse_response(
        self,
        hypothesis_id: str,
        raw: dict[str, Any],
    ) -> AdversarialReviewResult:
        """Parse LLM structured output into AdversarialReviewResult."""
        verdict = str(raw.get("verdict", "upheld"))
        confidence = float(raw.get("confidence", 0.5))
        bypass = bool(raw.get("bypass_found", False))
        attack_vector = str(raw.get("attack_vector", ""))
        reasoning = str(raw.get("reasoning", ""))

        return AdversarialReviewResult(
            hypothesis_id=hypothesis_id,
            original_verdict="rejected",
            review_verdict=verdict,
            confidence=max(0.0, min(1.0, confidence)),
            bypass_found=bypass,
            attack_vector=attack_vector if bypass else "",
            reasoning=reasoning,
            model=self._model,
        )


# ── Helpers ─────────────────────────────────────────────────────────────────


def _safe_id(obj: Any) -> str:
    """Extract hypothesis ID from either a dataclass or dict."""
    if isinstance(obj, dict):
        return str(obj.get("id", "unknown"))
    return str(getattr(obj, "id", "unknown"))
