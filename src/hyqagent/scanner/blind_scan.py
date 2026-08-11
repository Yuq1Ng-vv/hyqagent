"""scanner/blind_scan.py — Blind-scan LLM channel (通道2).

An exploratory LLM review that asks: "What would a pattern-based scanner
miss at this endpoint?"  Targets endpoints the CPG + forward analysis
couldn't link to known vulnerability patterns — especially useful for
logic bugs, IDOR, missing authorisation, and business-logic flaws.

Follows the same DI pattern as :class:`AdversarialReviewer`.

See docs/COVERAGE-IMPROVEMENT-PLAN.md §Phase C — C1.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

# ── Data model ──────────────────────────────────────────────────────────────


@dataclass
class BlindScanFinding:
    """A single finding from the blind-scan LLM review."""

    endpoint: str  # route or handler_func
    issue_type: str  # e.g. "idor", "missing_auth", "business_logic"
    severity: str = "medium"  # critical | high | medium | low
    confidence: float = 0.5
    title: str = ""
    description: str = ""
    evidence: str = ""  # relevant code snippet or observation
    reasoning: str = ""  # why the pattern scanner missed this
    remediation: str = ""
    cwe_id: str = ""


@dataclass
class BlindScanResult:
    """Aggregate result of a blind-scan session."""

    endpoints_reviewed: int = 0
    findings: list[BlindScanFinding] = field(default_factory=list)
    model: str = ""
    reasoning: str = ""


# ── Structured output schema ─────────────────────────────────────────────────

BLIND_SCAN_SCHEMA: dict[str, Any] = {
    "name": "report_blind_scan",
    "description": "Report findings from blind-scan exploratory review",
    "input_schema": {
        "type": "object",
        "properties": {
            "endpoints_reviewed": {
                "type": "integer",
                "description": "Number of endpoints reviewed in this batch",
            },
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "endpoint": {
                            "type": "string",
                            "description": "Route or handler function name",
                        },
                        "issue_type": {
                            "type": "string",
                            "description": (
                                "Type of issue: idor, missing_auth, business_logic, "
                                "race_condition, info_disclosure, parameter_pollution, "
                                "mass_assignment, rate_limit_missing, input_validation_gap, "
                                "error_handling_leak, or other"
                            ),
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low"],
                        },
                        "confidence": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                        },
                        "title": {
                            "type": "string",
                            "description": "Short finding title",
                        },
                        "description": {
                            "type": "string",
                            "description": "Detailed description of the issue",
                        },
                        "reasoning": {
                            "type": "string",
                            "description": "Why a pattern-based scanner would miss this",
                        },
                    },
                    "required": ["endpoint", "issue_type", "severity", "description"],
                },
            },
        },
        "required": ["endpoints_reviewed", "findings"],
    },
}

# ── Prompt templates ────────────────────────────────────────────────────────

BLIND_SCAN_SYSTEM = """\
You are an exploratory security auditor. Your job is to find what
pattern-based scanners (SAST, grep rules, taint analysis) MISS.

Pattern scanners are good at: SQL injection, XSS, command injection,
path traversal — things with known signatures.

Pattern scanners are BLIND to:
- **IDOR**: /users/123 → /users/124 without authorisation check
- **Missing auth**: endpoints with no authentication decorator
- **Business logic**: skipping payment steps, negative quantities
- **Race conditions**: TOCTOU on file operations, double-spend
- **Mass assignment**: updating fields the user shouldn't control
- **Parameter pollution**: overriding internal params via query string
- **Error leaks**: verbose stack traces, debug endpoints in production
- **Missing rate limiting**: brute-forceable login/reset endpoints

## Review Process
For each endpoint provided:
1. Look at the route pattern — what resource does it expose?
2. Check: is there an auth check?  Is it consistently applied?
3. Check: can a user access another user's data (IDOR)?
4. Check: are there state-changing operations without CSRF/validation?
5. Check: what does the error path reveal?

## Rules
1. Only report issues you can actually see in the provided context.
2. If you're unsure, mark confidence < 0.5 and explain why.
3. Prioritise: critical/high issues first, then medium, then low.
4. Explain WHY a grep/SAST/pattern tool would miss each issue.
5. Focus on semantic/logic issues, not syntax bugs.

Use the report_blind_scan tool for your output."""


def _build_blind_scan_prompt(
    endpoints: list[dict[str, Any]],
    code_contexts: dict[str, str] | None = None,
    language: str = "",
) -> str:
    """Build the user prompt for blind-scan review of exposed endpoints."""
    parts: list[str] = []

    parts.append(f"## Endpoints to Review ({len(endpoints)} total)\n")
    parts.append(
        "These are HTTP endpoints where the CPG-based taint analysis found "
        "NO known source→sink vulnerability path.  Review each one for "
        "issues that pattern-based scanners would miss.\n"
    )

    for i, ep in enumerate(endpoints, 1):
        route = ep.get("route", ep.get("handler_func", f"endpoint-{i}"))
        handler = ep.get("handler_func", "")
        methods = ep.get("methods", [])
        file_path = ep.get("file_path", "")
        line = ep.get("line", 0)
        auth = ep.get("auth_required", False)
        framework = ep.get("framework", "")

        parts.append(f"### Endpoint {i}: {route}")
        if handler:
            parts.append(f"- **Handler**: `{handler}`")
        if methods:
            parts.append(f"- **Methods**: {', '.join(methods)}")
        parts.append(f"- **Location**: {file_path}:{line}")
        parts.append(f"- **Auth required**: {auth}")
        if framework:
            parts.append(f"- **Framework**: {framework}")

        # Include code context if available
        if code_contexts and handler in code_contexts:
            ctx = code_contexts[handler]
            parts.append(f"\n```{language}\n{ctx[:1500]}\n```\n")

        parts.append("")

    if language:
        parts.insert(1, f"**Language**: {language}\n")

    parts.append("## Your Task")
    parts.append(
        "Review each endpoint above for: IDOR, missing auth, business logic "
        "flaws, race conditions, mass assignment, parameter pollution, error "
        "leaks, and missing rate limiting.  For each finding, explain WHY "
        "a pattern-based SAST scanner would miss it."
    )

    return "\n".join(parts)


# ── Reviewer class ──────────────────────────────────────────────────────────


class BlindScanReviewer:
    """LLM-based blind-scan review of endpoints without pattern matches.

    Asks a focused model to examine endpoints that the CPG + forward
    analysis couldn't classify, looking for semantic/logic issues
    invisible to pattern-based scanners.

    Usage::

        reviewer = BlindScanReviewer(provider=mid_provider, model="claude-sonnet-5")
        result = await reviewer.review(endpoints, code_contexts={})
    """

    def __init__(
        self,
        provider: Any,  # LlmProvider
        model: str,
        nudge_loop: Any | None = None,  # NudgeLoop
    ) -> None:
        self._provider = provider
        self._model = model
        self._nudge_loop = nudge_loop

    # ── Public API ──────────────────────────────────────────────────────

    async def review(
        self,
        endpoints: list[dict[str, Any]],
        code_contexts: dict[str, str] | None = None,
        language: str = "",
    ) -> BlindScanResult:
        """Review exposed endpoints for pattern-scanner blind spots.

        Args:
            endpoints: List of endpoint dicts.  Each dict should have keys
                       ``route``, ``handler_func``, ``methods``,
                       ``file_path``, ``line``, ``auth_required``,
                       ``framework``.  HttpEndpoint objects are converted
                       via ``_endpoint_to_dict()``.
            code_contexts: Optional mapping of handler_func → source code.
            language: Target language hint.

        Returns:
            Aggregated ``BlindScanResult`` with findings.

        """
        if not endpoints:
            return BlindScanResult(reasoning="No endpoints to review.")

        # Normalize endpoints to dicts
        ep_dicts = [_endpoint_to_dict(ep) for ep in endpoints]

        prompt = _build_blind_scan_prompt(ep_dicts, code_contexts, language)

        try:
            raw = await self._call_llm(prompt)
        except Exception:
            return BlindScanResult(
                endpoints_reviewed=len(endpoints),
                model=self._model,
                reasoning="Blind scan LLM call failed.",
            )

        return self._parse_response(len(endpoints), raw)

    # ── Internals ───────────────────────────────────────────────────────

    async def _call_llm(self, prompt: str) -> dict[str, Any]:
        """Call LLM with structured output."""
        result: Any = await self._provider.generate_structured(
            messages=[{"role": "user", "content": prompt}],
            model=self._model,
            output_schema=BLIND_SCAN_SCHEMA,
            system=BLIND_SCAN_SYSTEM,
            max_tokens=4096,
            temperature=0.2,
        )
        return cast(dict[str, Any], result)

    def _parse_response(
        self,
        endpoints_reviewed: int,
        raw: dict[str, Any],
    ) -> BlindScanResult:
        """Parse LLM structured output into BlindScanResult."""
        findings: list[BlindScanFinding] = []
        raw_findings = raw.get("findings", [])
        if not isinstance(raw_findings, list):
            raw_findings = []

        for f in raw_findings:
            findings.append(
                BlindScanFinding(
                    endpoint=str(f.get("endpoint", "")),
                    issue_type=str(f.get("issue_type", "unknown")),
                    severity=str(f.get("severity", "medium")),
                    confidence=float(f.get("confidence", 0.5)),
                    title=str(f.get("title", "")),
                    description=str(f.get("description", "")),
                    reasoning=str(f.get("reasoning", "")),
                )
            )

        return BlindScanResult(
            endpoints_reviewed=endpoints_reviewed,
            findings=findings,
            model=self._model,
            reasoning=(
                f"Blind scan reviewed {endpoints_reviewed} endpoint(s), "
                f"found {len(findings)} potential issue(s)."
            ),
        )


# ── Helpers ─────────────────────────────────────────────────────────────────


def _endpoint_to_dict(ep: Any) -> dict[str, Any]:
    """Convert HttpEndpoint or dict to a normalised dict."""
    if isinstance(ep, dict):
        return ep
    return {
        "route": getattr(ep, "route", ""),
        "handler_func": getattr(ep, "handler_func", ""),
        "methods": getattr(ep, "methods", []),
        "file_path": getattr(ep, "file_path", ""),
        "line": getattr(ep, "line", 0),
        "auth_required": getattr(ep, "auth_required", False),
        "framework": getattr(ep, "framework", ""),
    }


def exposed_endpoints_from_state(
    state: Any,  # PipelineState
) -> list[dict[str, Any]]:
    """Extract endpoints without source→sink coverage from pipeline state.

    Looks for endpoints in ``attack_surface`` or ``endpoints`` phase state.
    Returns those that do NOT appear in annotated paths.
    """
    annotated = state.phase_states.get("annotated_paths", []) or []
    endpoints_data = (
        state.phase_states.get("attack_surface") or state.phase_states.get("endpoints") or []
    )

    # Collect covered handler functions from annotated paths
    covered_handlers: set[str] = set()
    for ap in annotated:
        for node in getattr(getattr(ap, "path", None), "nodes", []) or []:
            ef = getattr(node, "enclosing_function", "") or getattr(node, "name", "")
            if ef:
                covered_handlers.add(ef)

    # Return endpoints whose handler_func isn't covered
    exposed: list[dict[str, Any]] = []
    for ep in endpoints_data:
        d = _endpoint_to_dict(ep)
        if d.get("handler_func") and d["handler_func"] not in covered_handlers:
            exposed.append(d)

    return exposed
