"""Tests for models/router.py — ModelRouter routing logic and complexity assessment."""

from __future__ import annotations

import pytest

from hyqagent.models.router import (
    ModelRouter,
    ModelSpec,
    ModelTier,
    Task,
    TaskType,
)


class TestModelTier:
    def test_str_enum_values(self) -> None:
        assert ModelTier.CHEAP == "cheap"
        assert ModelTier.MID == "mid"
        assert ModelTier.STRONG == "strong"

    def test_str_comparison(self) -> None:
        assert ModelTier.CHEAP == "cheap"
        assert str(ModelTier.MID) == "mid"


class TestTaskType:
    def test_str_enum_values(self) -> None:
        assert TaskType.HYPOTHESIS_GENERATION == "hypothesis_generation"
        assert TaskType.L2_VALIDATION == "l2_validation"
        assert TaskType.BLIND_SCAN == "blind_scan"


class TestModelSpec:
    def test_defaults(self) -> None:
        spec = ModelSpec(tier=ModelTier.CHEAP, model_id="test-model", provider_key="test")
        assert spec.cost_per_1k_input == 0.0
        assert spec.cost_per_1k_output == 0.0


class TestTask:
    def test_defaults(self) -> None:
        task = Task(task_type=TaskType.HYPOTHESIS_GENERATION, complexity=3)
        assert task.estimated_prompt_tokens == 0
        assert task.metadata == {}

    def test_with_metadata(self) -> None:
        task = Task(
            task_type=TaskType.L2_VALIDATION,
            complexity=7,
            estimated_prompt_tokens=500,
            metadata={"label": "heuristic_sink"},
        )
        assert task.complexity == 7
        assert task.metadata["label"] == "heuristic_sink"


class TestComplexityAssessment:
    def test_trivial_path(self) -> None:
        score = ModelRouter.assess_complexity(path_length=2)
        assert 1 <= score <= 3

    def test_moderate_path(self) -> None:
        score = ModelRouter.assess_complexity(path_length=10, cross_file_count=2)
        assert 4 <= score <= 7

    def test_complex_path(self) -> None:
        score = ModelRouter.assess_complexity(
            path_length=15,
            cross_file_count=4,
            has_async=True,
            has_reflection=True,
            nesting_depth=5,
        )
        assert score >= 7  # should be high

    def test_score_clamped_to_10(self) -> None:
        score = ModelRouter.assess_complexity(
            path_length=100,
            cross_file_count=20,
            has_async=True,
            has_reflection=True,
            nesting_depth=50,
        )
        assert score <= 10

    def test_score_at_least_1(self) -> None:
        score = ModelRouter.assess_complexity()
        assert score >= 1

    def test_async_adds_score(self) -> None:
        base = ModelRouter.assess_complexity(path_length=2)
        with_async = ModelRouter.assess_complexity(path_length=2, has_async=True)
        assert with_async > base

    def test_reflection_adds_score(self) -> None:
        base = ModelRouter.assess_complexity(path_length=2)
        with_refl = ModelRouter.assess_complexity(path_length=2, has_reflection=True)
        assert with_refl > base


class TestRouting:
    @pytest.fixture
    def router(self) -> ModelRouter:
        return ModelRouter(providers={}, cheap_model="cheap-model",
                           mid_model="mid-model", strong_model="strong-model")

    def test_cheap_tier_low_complexity(self, router: ModelRouter) -> None:
        task = Task(TaskType.HYPOTHESIS_GENERATION, complexity=2)
        router._providers = {"deepseek": "fake-provider"}
        _provider, model = router.route(task)
        assert model == "cheap-model"

    def test_mid_tier_medium_complexity(self, router: ModelRouter) -> None:
        task = Task(TaskType.HYPOTHESIS_GENERATION, complexity=6)
        router._providers = {"deepseek": "fake-deepseek", "anthropic": "fake-claude"}
        _provider, model = router.route(task)
        assert model == "mid-model"

    def test_strong_tier_high_complexity(self, router: ModelRouter) -> None:
        task = Task(TaskType.L2_VALIDATION, complexity=9)
        router._providers = {"anthropic": "fake-claude"}
        _provider, model = router.route(task)
        assert model == "strong-model"

    def test_fallback_to_available_provider(self) -> None:
        """When the target provider is unavailable, fall back to any available."""
        router = ModelRouter(providers={"deepseek": "only-provider"},
                             cheap_model="cheap", mid_model="mid", strong_model="strong")
        task = Task(TaskType.L2_VALIDATION, complexity=9)  # wants anthropic
        provider, model = router.route(task)
        assert provider == "only-provider"  # fallback
        assert model == "strong"  # still tries strong model

    def test_route_with_budget_sufficient(self) -> None:
        router = ModelRouter(
            providers={"deepseek": "ds"},
            cheap_model="c", mid_model="m", strong_model="s",
        )
        result = router.route_with_budget(
            Task(TaskType.HYPOTHESIS_GENERATION, complexity=2, estimated_prompt_tokens=100),
            remaining_budget=10.0,
        )
        assert result is not None
        _provider, _model = result
        assert _provider == "ds"

    def test_route_with_budget_exhausted(self) -> None:
        router = ModelRouter(
            providers={"deepseek": "ds"},
            cheap_model="c", mid_model="m", strong_model="s",
        )
        result = router.route_with_budget(
            Task(TaskType.L2_VALIDATION, complexity=9, estimated_prompt_tokens=50000),
            remaining_budget=0.0,
        )
        assert result is None

    def test_spec_for_tier(self) -> None:
        router = ModelRouter(providers={})
        cheap = router.get_spec(ModelTier.CHEAP)
        assert cheap.tier == ModelTier.CHEAP
        mid = router.get_spec(ModelTier.MID)
        assert mid.tier == ModelTier.MID
        strong = router.get_spec(ModelTier.STRONG)
        assert strong.tier == ModelTier.STRONG

    def test_custom_model_names(self) -> None:
        router = ModelRouter(
            providers={},
            cheap_model="gpt-4o-mini",
            mid_model="gpt-4o",
            strong_model="gpt-4.5",
        )
        assert router.CHEAP_SPEC.model_id == "gpt-4o-mini"
        assert router.MID_SPEC.model_id == "gpt-4o"
        assert router.STRONG_SPEC.model_id == "gpt-4.5"

    def test_partial_custom_models(self) -> None:
        router = ModelRouter(providers={}, cheap_model="custom-cheap")
        assert router.CHEAP_SPEC.model_id == "custom-cheap"
        # MID and STRONG should keep defaults
        assert router.MID_SPEC.model_id == "claude-sonnet-5"
        assert router.STRONG_SPEC.model_id == "claude-opus-5"
