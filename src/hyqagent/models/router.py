"""models/router.py — Three-tier model routing for Phase 3 LLM integration.

Routes tasks to model tiers based on complexity assessment:
- Complexity 1-4 → CHEAP (DeepSeek-V4-Flash)
- Complexity 5-7 → MID   (Claude Sonnet 5)
- Complexity 8-10→ STRONG (Claude Opus 5)

Also supports budget-aware routing: when the budget is exhausted for a tier,
automatically degrades to the next cheaper tier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hyqagent.models.providers.anthropic_provider import (
        AnthropicProvider,
    )


# ── Enums ────────────────────────────────────────────────────────────────────


class ModelTier(StrEnum):
    """Three-tier model classification."""

    CHEAP = "cheap"
    MID = "mid"
    STRONG = "strong"


class TaskType(StrEnum):
    """What kind of analysis task is being routed."""

    HYPOTHESIS_GENERATION = "hypothesis_generation"
    L2_VALIDATION = "l2_validation"
    BLIND_SCAN = "blind_scan"


# ── Dataclasses ──────────────────────────────────────────────────────────────


@dataclass
class ModelSpec:
    """Describes one model option with its tier and estimated cost."""

    tier: ModelTier
    model_id: str
    provider_key: str  # "deepseek" | "anthropic"
    cost_per_1k_input: float = 0.0
    cost_per_1k_output: float = 0.0


@dataclass
class Task:
    """A work item to be routed to a model tier."""

    task_type: TaskType
    complexity: int  # 1-10
    estimated_prompt_tokens: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


# ── ModelRouter ──────────────────────────────────────────────────────────────


class ModelRouter:
    """Routes analysis tasks to the appropriate model tier.

    Usage::

        router = ModelRouter(providers={"deepseek": ds, "anthropic": claude})
        task = Task(TaskType.HYPOTHESIS_GENERATION, complexity=3)
        provider, model_id = router.route(task)
        result = await provider.generate(messages, model=model_id)
    """

    # Default model specs — overridable via HyqAgentConfig
    CHEAP_SPEC = ModelSpec(
        tier=ModelTier.CHEAP,
        model_id="deepseek-v4-flash",
        provider_key="deepseek",
        cost_per_1k_input=0.00014,  # ¥1/1M tokens ≈ $0.14/1M → $0.00014/1K
        cost_per_1k_output=0.00028,  # ¥2/1M tokens ≈ $0.28/1M → $0.00028/1K
    )
    MID_SPEC = ModelSpec(
        tier=ModelTier.MID,
        model_id="claude-sonnet-5",
        provider_key="anthropic",
        cost_per_1k_input=0.003,
        cost_per_1k_output=0.015,
    )
    STRONG_SPEC = ModelSpec(
        tier=ModelTier.STRONG,
        model_id="claude-opus-5",
        provider_key="anthropic",
        cost_per_1k_input=0.015,
        cost_per_1k_output=0.075,
    )

    def __init__(
        self,
        providers: dict[str, AnthropicProvider],
        cheap_model: str = "",
        mid_model: str = "",
        strong_model: str = "",
    ) -> None:
        """Store provider-key → AnthropicProvider mappings.

        *providers* maps provider_key to AnthropicProvider instance.
        Use ``"deepseek"`` and ``"anthropic"`` as keys. If only one provider
        is configured, it will be used for all tiers (with different models).
        """
        self._providers = providers
        # Create instance-level copies so customisation doesn't leak across tests
        self.CHEAP_SPEC = ModelSpec(
            tier=ModelTier.CHEAP,
            model_id=cheap_model or ModelRouter.CHEAP_SPEC.model_id,
            provider_key=ModelRouter.CHEAP_SPEC.provider_key,
            cost_per_1k_input=ModelRouter.CHEAP_SPEC.cost_per_1k_input,
            cost_per_1k_output=ModelRouter.CHEAP_SPEC.cost_per_1k_output,
        )
        self.MID_SPEC = ModelSpec(
            tier=ModelTier.MID,
            model_id=mid_model or ModelRouter.MID_SPEC.model_id,
            provider_key=ModelRouter.MID_SPEC.provider_key,
            cost_per_1k_input=ModelRouter.MID_SPEC.cost_per_1k_input,
            cost_per_1k_output=ModelRouter.MID_SPEC.cost_per_1k_output,
        )
        self.STRONG_SPEC = ModelSpec(
            tier=ModelTier.STRONG,
            model_id=strong_model or ModelRouter.STRONG_SPEC.model_id,
            provider_key=ModelRouter.STRONG_SPEC.provider_key,
            cost_per_1k_input=ModelRouter.STRONG_SPEC.cost_per_1k_input,
            cost_per_1k_output=ModelRouter.STRONG_SPEC.cost_per_1k_output,
        )

    # ── Public API ──────────────────────────────────────────────────────

    def route(self, task: Task) -> tuple[AnthropicProvider, str]:
        """Route *task* to the right (provider, model_id) pair.

        Budget-aware: if the task's complexity warrants MID but MID
        provider is unavailable, falls back to CHEAP.
        """
        spec = self._spec_for_complexity(task.complexity)
        provider = self._providers.get(spec.provider_key)
        if provider is None:
            # Fallback: use first available provider
            provider = next(iter(self._providers.values()))
        return provider, spec.model_id

    def route_with_budget(
        self,
        task: Task,
        remaining_budget: float,
    ) -> tuple[AnthropicProvider, str] | None:
        """Route with budget awareness. Returns ``None`` if budget exhausted."""
        spec = self._spec_for_complexity(task.complexity)

        estimated_cost = self._estimate_cost(task, spec)
        if estimated_cost > remaining_budget:
            # Try degrading tier by tier
            degraded = self._degrade(spec)
            while degraded is not None:
                estimated_cost = self._estimate_cost(task, degraded)
                if estimated_cost <= remaining_budget:
                    spec = degraded
                    break
                degraded = self._degrade(degraded)
            else:
                # Even CHEAP is too expensive → skip
                return None

        provider = self._providers.get(spec.provider_key)
        if provider is None:
            provider = next(iter(self._providers.values()))
        return provider, spec.model_id

    def get_spec(self, tier: ModelTier) -> ModelSpec:
        """Return the :class:`ModelSpec` for *tier*."""
        if tier == ModelTier.CHEAP:
            return self.CHEAP_SPEC
        elif tier == ModelTier.MID:
            return self.MID_SPEC
        return self.STRONG_SPEC

    # ── Complexity Assessment ───────────────────────────────────────────

    @staticmethod
    def assess_complexity(
        path_length: int = 0,
        cross_file_count: int = 0,
        has_async: bool = False,
        has_reflection: bool = False,
        nesting_depth: int = 0,
    ) -> int:
        """Score task complexity 1-10 based on CPG path characteristics.

        Factors:
        - Data flow hops: 1 pt per 3 hops, max 3
        - Cross-file edges: 1 pt per boundary, max 3
        - Async/reflection: 2 pts each
        - Control flow nesting: 1 pt per 2 levels, max 2
        """
        score = 1  # base

        # Data flow hops
        score += min(3, path_length // 3)

        # Cross-file boundaries
        score += min(3, cross_file_count)

        # Async and reflection are complexity multipliers
        if has_async:
            score += 2
        if has_reflection:
            score += 2

        # Nesting depth
        score += min(2, nesting_depth // 2)

        return min(10, max(1, score))

    # ── Internal ────────────────────────────────────────────────────────

    def _spec_for_complexity(self, complexity: int) -> ModelSpec:
        """Map 1-10 complexity to tier."""
        if complexity <= 4:
            return self.CHEAP_SPEC
        elif complexity <= 7:
            return self.MID_SPEC
        else:
            return self.STRONG_SPEC

    def _degrade(self, spec: ModelSpec) -> ModelSpec | None:
        """Step down one tier. STRONG→MID→CHEAP→None."""
        if spec.tier == ModelTier.STRONG:
            return self.MID_SPEC
        elif spec.tier == ModelTier.MID:
            return self.CHEAP_SPEC
        return None  # already at cheapest

    @staticmethod
    def _estimate_cost(task: Task, spec: ModelSpec) -> float:
        """Rough cost estimate for *task* on *spec*."""
        input_cost = (task.estimated_prompt_tokens / 1000) * spec.cost_per_1k_input
        # Assume output is ~20% of input
        output_tokens = max(100, task.estimated_prompt_tokens // 5)
        output_cost = (output_tokens / 1000) * spec.cost_per_1k_output
        return input_cost + output_cost
