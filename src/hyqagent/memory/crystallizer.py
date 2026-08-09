"""memory/crystallizer.py — Context crystallization protocol for long-running sessions.

When working memory exceeds its budget or a turn threshold is reached,
the crystallizer compresses recent history into a structured summary
suitable for long-term memory M(t).

This is the deterministic summarization step — it extracts structured
metadata from turn records WITHOUT using an LLM (LLM summarization is
a Phase 5 feature).  The output is a markdown template following the
format defined in LONG-RUNNING-AGENT-ARCHITECTURE.md §2.3.

Reference: Factory AI Anchored Iterative Summarization (rated 3.70/5.0).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hyqagent.memory.context import ContextManager, TurnRecord


# ── Crystal summary data model ────────────────────────────────────────────────


@dataclass
class CrystalSummary:
    """Structured summary produced by one crystallization pass."""

    phase: str  # Current audit phase (e.g. "hypothesis_generation")
    files_analyzed: list[str] = field(default_factory=list)
    key_findings: list[dict[str, Any]] = field(default_factory=list)
    decisions_made: list[str] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    coverage_state: dict[str, float] = field(default_factory=dict)

    # Technical metadata
    turns_compressed: int = 0
    tokens_before: int = 0
    tokens_after: int = 0
    compression_ratio: float = 0.0

    def to_long_term_text(self) -> str:
        """Render the summary as a markdown block for long-term memory.

        Follows the template from LONG-RUNNING-AGENT-ARCHITECTURE.md §2.3:
        - 分析阶段摘要 (phase, files, findings)
        - 已做决策 (decisions)
        - 待解决问题 (open questions)
        """
        lines: list[str] = []

        # Phase header
        lines.append(f"## 分析阶段摘要 — {self.phase}")
        lines.append(f"- 已分析文件: {len(self.files_analyzed)} 个")

        if self.files_analyzed:
            listed = self.files_analyzed[:10]
            extra = len(self.files_analyzed) - 10
            suffix_long = f" ... (+{extra})" if extra > 0 else ""
            lines.append(f"- 文件列表: {', '.join(listed)}{suffix_long}")

        if self.key_findings:
            lines.append(f"- 关键发现: {len(self.key_findings)} 个")
            for f in self.key_findings[:5]:
                fid = f.get("id", "?")
                ftype = f.get("type", "?")
                verdict = f.get("verdict", "?")
                conf = f.get("confidence", 0)
                lines.append(f"  - {fid}: {ftype} → {verdict} (confidence {conf:.0%})")

        if self.coverage_state:
            cov_parts = [f"{k}: {v:.0%}" for k, v in self.coverage_state.items()]
            lines.append(f"- 覆盖状态: {', '.join(cov_parts)}")

        lines.append("")

        # Decisions section
        if self.decisions_made:
            lines.append("## 已做决策")
            for d in self.decisions_made:
                lines.append(f"- {d}")
            lines.append("")

        # Open questions section
        if self.open_questions:
            lines.append("## 待解决问题")
            for q in self.open_questions:
                lines.append(f"- {q}")
            lines.append("")

        # Compression stats footer
        if self.compression_ratio > 0:
            lines.append(
                f"_(压缩 {self.turns_compressed} 轮 → "
                f"{self.tokens_after} tokens, "
                f"{self.compression_ratio:.1f}x reduction)_"
            )

        return "\n".join(lines)


# ── Crystallizer ──────────────────────────────────────────────────────────────


class ContextCrystallizer:
    """Deterministic context compression for long-running sessions.

    Monitors working memory usage and produces structured summaries
    when the turn threshold or budget threshold is exceeded.

    Usage::

        crystallizer = ContextCrystallizer(turn_threshold=50)
        ctx = ContextManager()

        for hypothesis in hypotheses:
            ctx.add_to_working(turn)
            if crystallizer.should_crystallize(ctx):
                summary = crystallizer.crystallize(ctx.recent_turns(),
                                                    phase="hypothesis_gen")
                ctx.update_long_term(summary.to_long_term_text())
    """

    def __init__(
        self,
        turn_threshold: int = 50,
        budget_threshold: float = 0.8,
    ) -> None:
        self._turn_threshold = turn_threshold
        self._budget_threshold = budget_threshold
        self._turns_since_last: int = 0
        self._crystallization_count: int = 0

    # ── Trigger logic ──────────────────────────────────────────────────────

    def should_crystallize(self, context: ContextManager) -> bool:
        """Check whether crystallization should be triggered.

        Returns True if:
        1. The number of turns since last crystallization >= turn_threshold, OR
        2. Working memory exceeds budget_threshold of its allocation.
        """
        if self._turns_since_last >= self._turn_threshold:
            return True

        budget = context._budget
        working_tokens = context._estimated_working_tokens()
        return working_tokens > budget.working * self._budget_threshold

    # ── Crystallization ────────────────────────────────────────────────────

    def crystallize(
        self,
        turns: list[TurnRecord],
        *,
        phase: str = "",
        files_analyzed: list[str] | None = None,
        decisions: list[str] | None = None,
        open_questions: list[str] | None = None,
        coverage_state: dict[str, float] | None = None,
    ) -> CrystalSummary:
        """Compress recent turns into a structured summary.

        Extracts findings from turn content by scanning for hypothesis IDs,
        vulnerability types, verdicts, and confidence scores in text.

        Args:
            turns: Recent working-memory turns to compress.
            phase: Current audit phase name.
            files_analyzed: Files that have been analyzed in this phase.
            decisions: Decisions made (e.g. "skipped X because Y").
            open_questions: Questions still unresolved.
            coverage_state: Per-file or per-module coverage ratios.

        Returns:
            A ``CrystalSummary`` ready for insertion into long-term memory.

        """
        tokens_before = sum(t.estimate_tokens() for t in turns)
        findings = self._extract_findings(turns)

        summary = CrystalSummary(
            phase=phase,
            files_analyzed=list(files_analyzed or []),
            key_findings=findings,
            decisions_made=list(decisions or []),
            open_questions=list(open_questions or []),
            coverage_state=dict(coverage_state or {}),
            turns_compressed=len(turns),
            tokens_before=tokens_before,
        )

        # Compute compression stats
        text = summary.to_long_term_text()
        summary.tokens_after = max(1, len(text) // 4)
        summary.compression_ratio = (
            tokens_before / summary.tokens_after if summary.tokens_after > 0 else 0.0
        )

        # Update counters
        self._turns_since_last = 0
        self._crystallization_count += 1

        return summary

    # ── Finding extraction ─────────────────────────────────────────────────

    @staticmethod
    def _extract_findings(turns: list[TurnRecord]) -> list[dict[str, Any]]:
        """Scan turn content for hypothesis/finding mentions.

        Looks for patterns like:
        - "Hypothesis hyp_abc123: SQL injection → confirmed"
        - "verdict: confirmed, confidence: 0.95"
        - "[sqli] ... → confirmed (conf=0.92)"

        Returns a deduplicated list of finding summaries.
        """
        import re

        findings: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        # Pattern 1: hypothesis IDs (hyp_xxx or hyp-xxx)
        hyp_id_re = re.compile(r"\b(hyp[_-][a-zA-Z0-9]+)\b")

        # Pattern 2: verdict mentions
        verdict_re = re.compile(
            r"(?:verdict|判定|结论)\s*[:：]\s*(confirmed|rejected|inconclusive)",  # noqa: RUF001
            re.IGNORECASE,
        )

        # Pattern 3: confidence mentions
        confidence_re = re.compile(
            r"(?:confidence|置信度|conf)\s*[:：]\s*([\d.]+)",  # noqa: RUF001
            re.IGNORECASE,
        )

        # Pattern 4: vulnerability type
        vuln_type_re = re.compile(
            r"\b(sql[\s_-]?injection|sqli|XSS|cross[\s-]site|SSRF|IDOR|"
            r"command[\s-]?injection|path[\s-]?traversal|"
            r"SQL注入|命令注入|路径穿越)\b",
            re.IGNORECASE,
        )

        for turn in turns:
            text = turn.content

            # Find hypothesis IDs
            for match in hyp_id_re.finditer(text):
                hyp_id = match.group(1)
                if hyp_id in seen_ids:
                    continue
                seen_ids.add(hyp_id)

                # Try to find verdict and confidence nearby
                verdict_match = verdict_re.search(text)
                conf_match = confidence_re.search(text)
                vuln_match = vuln_type_re.search(text)

                findings.append(
                    {
                        "id": hyp_id,
                        "type": vuln_match.group(1) if vuln_match else "unknown",
                        "verdict": verdict_match.group(1) if verdict_match else "pending",
                        "confidence": float(conf_match.group(1)) if conf_match else 0.0,
                    }
                )

        return findings


# ── Phase boundary trigger ────────────────────────────────────────────────────


def should_crystallize_on_phase_change(
    current_phase: str,
    new_phase: str,
) -> bool:
    """Return True when crossing a phase boundary that warrants crystallization.

    Crystallization is recommended when transitioning from:
    - ``phase2_scan`` → ``understanding`` (evidence gathered, about to use LLM)
    - ``understanding`` → ``hypothesis_generation`` (context useful for prompting)
    - ``hypothesis_generation`` → ``validation`` (findings need to inform verification)
    """
    phase_order = [
        "init",
        "phase2_scan",
        "understanding",
        "hypothesis_generation",
        "validation",
        "coverage_audit",
        "completeness_review",
        "report",
    ]

    try:
        current_idx = phase_order.index(current_phase)
        new_idx = phase_order.index(new_phase)
    except ValueError:
        return False

    # Crystallize when moving forward across phase boundaries
    return new_idx > current_idx
