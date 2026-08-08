"""memory/context.py — Three-zone context model for long-running agent sessions.

Implements the context architecture from LONG-RUNNING-AGENT-ARCHITECTURE.md §2:

┌───────────────────┬──────────┬──────────────────────────────────┬──────────────┐
│ Zone              │ Tokens   │ Content                          │ Caching      │
├───────────────────┼──────────┼──────────────────────────────────┼──────────────┤
│ Fixed             │ ~5K      │ System prompt, rules, vuln types │ Cache break 1│
│ Long-term M(t)    │ ~30K     │ Crystallized phase summaries     │ Cache break 2│
│ Working I(k)(t)   │ ~60K     │ Recent N turns (sliding window)  │ Not cached   │
├───────────────────┼──────────┼──────────────────────────────────┼──────────────┤
│ **Total**         │ ~95K     │ ~47% of 200K window              │              │
└───────────────────┴──────────┴──────────────────────────────────┴──────────────┘
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

# ── Zone budget configuration ──────────────────────────────────────────────────


@dataclass
class ZoneBudget:
    """Token budgets for each context zone.

    Defaults keep total at ~95K tokens — well within 200K model windows
    and leaving ~105K headroom for code snippets in working memory.
    """

    fixed: int = 5_000
    long_term: int = 30_000
    working: int = 60_000
    total_limit: int = 200_000  # Model context window limit

    @property
    def total_used(self) -> int:
        """Sum of all zone budgets."""
        return self.fixed + self.long_term + self.working


# ── Turn record ────────────────────────────────────────────────────────────────


@dataclass
class TurnRecord:
    """One conversational turn stored in working memory."""

    role: str  # "user" | "assistant" | "tool"
    content: str
    token_estimate: int = 0
    timestamp: float = field(default_factory=time.monotonic)
    metadata: dict[str, Any] = field(default_factory=dict)

    def estimate_tokens(self) -> int:
        """Coarse character-based estimate (~4 chars/token)."""
        return max(1, len(self.content) // 4)


# ── ContextManager ─────────────────────────────────────────────────────────────


class ContextManager:
    """Three-zone context manager for long-running audit sessions.

    Usage::

        ctx = ContextManager()
        ctx.set_fixed(SYSTEM_PROMPT, audit_rules)
        ctx.update_long_term("Phase 1 complete: 23 files, 3 SQLi confirmed")

        for hypothesis in hypotheses:
            ctx.add_to_working(TurnRecord(
                role="assistant",
                content=f"Hypothesis: {hypothesis.title}",
            ))
            # ... LLM call using ctx.build_messages() ...

        if ctx.needs_crystallization():
            summary = summarizer.crystallize(ctx.recent_turns())
            ctx.update_long_term(summary)
    """

    def __init__(self, budget: ZoneBudget | None = None) -> None:
        self._budget = budget or ZoneBudget()

        # Zone contents
        self._fixed: list[dict[str, Any]] = []
        self._long_term: str = ""
        self._working: list[TurnRecord] = []

        # Stats
        self._turn_count: int = 0
        self._crystallization_count: int = 0

    # ── Zone management ────────────────────────────────────────────────────

    def set_fixed(self, system_prompt: str, *, rules: str = "", metadata: str = "") -> None:
        """Set the fixed zone content (stable throughout session).

        This content is eligible for Anthropic Prompt Cache breakpoint 1.
        """
        parts: list[str] = [system_prompt]
        if rules:
            parts.append(f"\n## Audit Rules\n{rules}")
        if metadata:
            parts.append(f"\n## Project Metadata\n{metadata}")
        self._fixed = [{"type": "text", "text": "\n".join(parts)}]

    def update_long_term(self, summary: str) -> None:
        """Replace long-term memory with a new crystallized summary.

        This content is eligible for Anthropic Prompt Cache breakpoint 2.
        Long-term memory accumulates: old summary is prepended as context.
        """
        if self._long_term:
            # Keep old summary as historical context (truncated)
            old_preview = self._long_term[:2000]
            self._long_term = f"{summary}\n\n## Prior Context (condensed)\n{old_preview}"
        else:
            self._long_term = summary

    def add_to_working(self, turn: TurnRecord) -> None:
        """Add a turn to working memory with sliding window eviction."""
        turn.token_estimate = turn.estimate_tokens()
        self._working.append(turn)
        self._turn_count += 1

        # Evict oldest turns until within budget
        while self._estimated_working_tokens() > self._budget.working and len(self._working) > 1:
            self._working.pop(0)

    # ── LLM message building ───────────────────────────────────────────────

    def build_messages(
        self,
        *,
        include_cache_control: bool = True,
    ) -> list[dict[str, Any]]:
        """Build the message list for an LLM call.

        Structure::

            [system content (fixed, cache break 1)]
            [system content (long-term, cache break 2)]
            [user/assistant turns from working memory]

        Args:
            include_cache_control: Insert ``cache_control`` breakpoints for
                Anthropic Prompt Caching. Set to ``False`` for non-Anthropic
                providers (e.g. DeepSeek).

        """
        messages: list[dict[str, Any]] = []

        # Fixed zone → system message with cache breakpoint 1
        if self._fixed:
            content = list(self._fixed)
            if include_cache_control:
                content[-1] = {**content[-1], "cache_control": {"type": "ephemeral"}}
            messages.append({"role": "user", "content": content})

        # Long-term memory → system message with cache breakpoint 2
        if self._long_term:
            lt_content: dict[str, Any] = {"type": "text", "text": self._long_term}
            if include_cache_control:
                lt_content["cache_control"] = {"type": "ephemeral"}
            messages.append({"role": "user", "content": [lt_content]})

        # Working memory → actual conversation turns
        for turn in self._working:
            messages.append({
                "role": turn.role,
                "content": turn.content,
            })

        return messages

    def build_simple_messages(
        self,
        user_message: str,
        *,
        system: str = "",
    ) -> list[dict[str, Any]]:
        """Build a simple message list for single-shot LLM calls.

        Includes fixed + long-term context as system prompt,
        then the user message as a single turn.
        """
        messages: list[dict[str, Any]] = []

        # Combine fixed + long-term into system prompt
        system_parts: list[str] = []
        if system:
            system_parts.append(system)
        for block in self._fixed:
            if isinstance(block, dict) and block.get("type") == "text":
                system_parts.append(str(block.get("text", "")))
        if self._long_term:
            system_parts.append(self._long_term)

        combined_system = "\n\n".join(system_parts)

        if combined_system:
            messages.append({"role": "system", "content": combined_system})

        messages.append({"role": "user", "content": user_message})
        return messages

    # ── Token estimation ───────────────────────────────────────────────────

    def estimate_tokens(self) -> dict[str, int]:
        """Estimate token usage per zone.

        Returns a dict with keys: ``fixed``, ``long_term``, ``working``, ``total``.
        """
        fixed_tokens = sum(
            len(str(b.get("text", ""))) // 4 for b in self._fixed if isinstance(b, dict)
        )
        lt_tokens = len(self._long_term) // 4 if self._long_term else 0
        work_tokens = self._estimated_working_tokens()

        return {
            "fixed": fixed_tokens,
            "long_term": lt_tokens,
            "working": work_tokens,
            "total": fixed_tokens + lt_tokens + work_tokens,
        }

    def _estimated_working_tokens(self) -> int:
        """Sum token estimates for all working memory turns."""
        return sum(t.estimate_tokens() for t in self._working)

    # ── Crystallization trigger ────────────────────────────────────────────

    def needs_crystallization(self, turn_threshold: int = 50) -> bool:
        """Check whether working memory should be crystallized.

        Triggers when:
        1. Working memory exceeds 80% of its budget, OR
        2. The number of turns since last crystallization exceeds *turn_threshold*.
        """
        if self._estimated_working_tokens() > self._budget.working * 0.8:
            return True
        return self._turn_count >= turn_threshold

    # ── Accessors ──────────────────────────────────────────────────────────

    def recent_turns(self, n: int | None = None) -> list[TurnRecord]:
        """Return the most recent *n* turns (default: all working memory)."""
        if n is None:
            return list(self._working)
        return self._working[-n:] if n < len(self._working) else list(self._working)

    @property
    def turn_count(self) -> int:
        """Total turns added to working memory since session start."""
        return self._turn_count

    @property
    def crystallization_count(self) -> int:
        """Number of times working memory has been crystallized."""
        return self._crystallization_count

    # ── Snapshot for checkpoint ────────────────────────────────────────────

    def snapshot(self) -> dict[str, Any]:
        """Export context state for checkpoint persistence."""
        return {
            "fixed_texts": [b.get("text", "") for b in self._fixed if isinstance(b, dict)],
            "long_term": self._long_term,
            "working_turn_count": len(self._working),
            "working_summary": [t.content[:200] for t in self._working[-5:]],
            "turn_count": self._turn_count,
            "crystallization_count": self._crystallization_count,
            "token_estimate": self.estimate_tokens(),
        }

    def restore(self, snapshot: dict[str, Any]) -> None:
        """Restore context state from a checkpoint snapshot."""
        if snapshot.get("long_term"):
            self._long_term = snapshot["long_term"]
        self._turn_count = snapshot.get("turn_count", 0)
        self._crystallization_count = snapshot.get("crystallization_count", 0)
