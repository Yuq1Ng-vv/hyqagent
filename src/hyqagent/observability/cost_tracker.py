"""observability/cost_tracker.py — Per-session LLM cost tracking.

Tracks cost per phase and per hypothesis, supports budget enforcement.
Uses in-memory state; costs are computed from model pricing tables.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── Pricing table (USD per 1K tokens) ────────────────────────────────────────


PRICING: dict[str, dict[str, float]] = {
    "deepseek-v4-flash-0731": {
        "input": 0.00014,  # ¥1/1M → ~$0.14/1M → $0.00014/1K
        "output": 0.00028,  # ¥2/1M → ~$0.28/1M → $0.00028/1K
        "cache_read": 0.000003,
    },
    "claude-sonnet-5": {
        "input": 0.003,
        "output": 0.015,
        "cache_read": 0.0003,
    },
    "claude-opus-5": {
        "input": 0.015,
        "output": 0.075,
        "cache_read": 0.0015,
    },
    # Fallback for unknown models
    "default": {
        "input": 0.003,
        "output": 0.015,
        "cache_read": 0.0003,
    },
}


# ── Data classes ─────────────────────────────────────────────────────────────


@dataclass
class CostEntry:
    """A single LLM call cost record."""

    phase: str
    model: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    hypothesis_id: str = ""


@dataclass
class CostSummary:
    """Aggregated cost summary."""

    total_cost: float = 0.0
    total_calls: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    by_phase: dict[str, float] = field(default_factory=dict)
    by_model: dict[str, float] = field(default_factory=dict)


# ── CostTracker ──────────────────────────────────────────────────────────────


class CostTracker:
    """Tracks LLM cost during a scan session.

    Usage::

        tracker = CostTracker(max_budget=5.0)
        tracker.record("hypothesis_gen", "deepseek-v4-flash-0731",
                        input_tokens=1200, output_tokens=300)
        if tracker.is_budget_exceeded():
            print("Budget exceeded!")
    """

    def __init__(self, max_budget: float = 5.0) -> None:
        self._max_budget = max_budget
        self._entries: list[CostEntry] = []

    # ── Recording ────────────────────────────────────────────────────────

    def record(
        self,
        phase: str,
        model: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_read_tokens: int = 0,
        latency_ms: float = 0.0,
        hypothesis_id: str = "",
    ) -> CostEntry:
        """Record a single LLM call and return its cost."""
        cost = self._compute_cost(model, input_tokens, output_tokens, cache_read_tokens)
        entry = CostEntry(
            phase=phase,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read_tokens,
            cost_usd=cost,
            latency_ms=latency_ms,
            hypothesis_id=hypothesis_id,
        )
        self._entries.append(entry)
        return entry

    # ── Queries ──────────────────────────────────────────────────────────

    def total_cost(self) -> float:
        """Total cost across all calls."""
        return sum(e.cost_usd for e in self._entries)

    def remaining_budget(self) -> float:
        """Budget remaining (floor at 0)."""
        return max(0.0, self._max_budget - self.total_cost())

    def is_budget_exceeded(self) -> bool:
        """Check if total cost exceeds the max budget."""
        return self.total_cost() >= self._max_budget

    def cost_by_phase(self) -> dict[str, float]:
        """Cost aggregated by phase."""
        result: dict[str, float] = {}
        for e in self._entries:
            result[e.phase] = result.get(e.phase, 0.0) + e.cost_usd
        return result

    def cost_by_model(self) -> dict[str, float]:
        """Cost aggregated by model."""
        result: dict[str, float] = {}
        for e in self._entries:
            result[e.model] = result.get(e.model, 0.0) + e.cost_usd
        return result

    def summary(self) -> CostSummary:
        """Return a comprehensive :class:`CostSummary`."""
        total_input = sum(e.input_tokens for e in self._entries)
        total_output = sum(e.output_tokens for e in self._entries)
        return CostSummary(
            total_cost=self.total_cost(),
            total_calls=len(self._entries),
            total_input_tokens=total_input,
            total_output_tokens=total_output,
            by_phase=self.cost_by_phase(),
            by_model=self.cost_by_model(),
        )

    @property
    def entries(self) -> list[CostEntry]:
        """Return all recorded entries."""
        return list(self._entries)

    # ── Internal ────────────────────────────────────────────────────────

    @staticmethod
    def _compute_cost(
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int = 0,
    ) -> float:
        """Compute USD cost from token counts and pricing table."""
        pricing = PRICING.get(model, PRICING["default"])
        input_k = input_tokens / 1000
        output_k = output_tokens / 1000
        cache_k = cache_read_tokens / 1000

        cost = input_k * pricing["input"]
        cost += output_k * pricing["output"]
        # Cache reads are much cheaper (subtract the diff)
        if cache_read_tokens > 0:
            cost -= cache_k * (pricing["input"] - pricing["cache_read"])
        return round(cost, 6)
