"""Tests for scanner/adversarial.py — AdversarialReviewer prompt, schema, and mock LLM."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock


from hyqagent.scanner.adversarial import (
    ADVERSARIAL_SCHEMA,
    ADVERSARIAL_SYSTEM,
    AdversarialReviewResult,
    AdversarialReviewer,
    _build_adversarial_prompt,
    _safe_id,
)


# ── Test data helpers ────────────────────────────────────────────────────────


def _mock_hypothesis(**overrides: object) -> MagicMock:
    defaults: dict[str, object] = {
        "id": "hyp-001",
        "vuln_type": "sql_injection",
        "cwe_id": "CWE-89",
        "severity": "high",
        "title": "SQLi in login handler",
        "description": "User input flows into SQL query without sanitization.",
        "source_location": "app.py:42:15",
        "sink_location": "app.py:58:10",
        "confidence": 0.85,
    }
    defaults.update(overrides)
    return MagicMock(**defaults)


def _mock_validation(**overrides: object) -> MagicMock:
    defaults: dict[str, object] = {
        "hypothesis_id": "hyp-001",
        "verdict": "rejected",
        "confidence": 0.90,
        "reasoning": "Input is sanitized by escape_string() before the SQL query.",
        "model": "claude-sonnet-5",
    }
    defaults.update(overrides)
    return MagicMock(**defaults)


# ── AdversarialReviewResult ─────────────────────────────────────────────────


class TestAdversarialReviewResult:
    def test_default_values(self) -> None:
        r = AdversarialReviewResult(hypothesis_id="hyp-001")
        assert r.hypothesis_id == "hyp-001"
        assert r.original_verdict == "rejected"
        assert r.review_verdict == "upheld"
        assert r.confidence == 0.0
        assert r.bypass_found is False
        assert r.attack_vector == ""
        assert r.reasoning == ""
        assert r.model == ""

    def test_all_fields_settable(self) -> None:
        r = AdversarialReviewResult(
            hypothesis_id="hyp-042",
            original_verdict="rejected",
            review_verdict="overturned",
            confidence=0.92,
            bypass_found=True,
            attack_vector="Double URL encoding bypass: %2527 → %27 → '",
            reasoning=(
                "Step 1: The sanitizer strips single quotes. "
                "Step 2: Double-encoding survives the first decode pass. "
                "Step 3: Second decode yields raw quote in SQL context."
            ),
            model="claude-opus-5",
        )
        assert r.hypothesis_id == "hyp-042"
        assert r.review_verdict == "overturned"
        assert r.confidence == 0.92
        assert r.bypass_found is True
        assert "Double URL encoding" in r.attack_vector
        assert "Step 1" in r.reasoning
        assert r.model == "claude-opus-5"


# ── Schema validation ───────────────────────────────────────────────────────


class TestAdversarialSchema:
    def test_schema_name(self) -> None:
        assert ADVERSARIAL_SCHEMA["name"] == "report_adversarial_review"

    def test_schema_properties(self) -> None:
        props = ADVERSARIAL_SCHEMA["input_schema"]["properties"]
        assert "verdict" in props
        assert props["verdict"]["enum"] == ["upheld", "overturned"]
        assert "confidence" in props
        assert props["confidence"]["minimum"] == 0.0
        assert props["confidence"]["maximum"] == 1.0
        assert "bypass_found" in props
        assert props["bypass_found"]["type"] == "boolean"
        assert "attack_vector" in props
        assert "reasoning" in props

    def test_required_fields(self) -> None:
        required = ADVERSARIAL_SCHEMA["input_schema"]["required"]
        assert "verdict" in required
        assert "confidence" in required
        assert "bypass_found" in required
        assert "reasoning" in required


# ── System prompt ───────────────────────────────────────────────────────────


class TestAdversarialSystemPrompt:
    def test_attacker_role(self) -> None:
        assert "offensive security researcher" in ADVERSARIAL_SYSTEM.lower()
        assert "attacker" in ADVERSARIAL_SYSTEM.lower()

    def test_sanitizer_bypass(self) -> None:
        assert "Sanitizer Bypass" in ADVERSARIAL_SYSTEM
        assert "URL encoding" in ADVERSARIAL_SYSTEM
        assert "double encoding" in ADVERSARIAL_SYSTEM.lower()

    def test_second_order_attacks(self) -> None:
        assert "Second-Order Attack" in ADVERSARIAL_SYSTEM
        assert "stored in database" in ADVERSARIAL_SYSTEM.lower()

    def test_type_system_manipulation(self) -> None:
        assert "Type-System Manipulation" in ADVERSARIAL_SYSTEM
        assert "deserialization" in ADVERSARIAL_SYSTEM.lower()

    def test_alternative_input_vectors(self) -> None:
        assert "Alternative Input Vectors" in ADVERSARIAL_SYSTEM
        assert "http headers" in ADVERSARIAL_SYSTEM.lower()
        assert "user-agent" in ADVERSARIAL_SYSTEM.lower()

    def test_timing_side_channels(self) -> None:
        assert "Timing Side Channels" in ADVERSARIAL_SYSTEM

    def test_error_message_leaks(self) -> None:
        assert "Error Message Leaks" in ADVERSARIAL_SYSTEM

    def test_uses_tool_output_instruction(self) -> None:
        assert "report_adversarial_review tool" in ADVERSARIAL_SYSTEM


# ── Prompt builder ──────────────────────────────────────────────────────────


class TestBuildAdversarialPrompt:
    def test_has_hypothesis_details(self) -> None:
        h = _mock_hypothesis()
        v = _mock_validation()
        prompt = _build_adversarial_prompt(h, v)
        assert "sql_injection" in prompt
        assert "CWE-89" in prompt
        assert "app.py:42:15" in prompt
        assert "app.py:58:10" in prompt

    def test_has_rejection_reasoning(self) -> None:
        h = _mock_hypothesis()
        v = _mock_validation()
        prompt = _build_adversarial_prompt(h, v)
        assert "escape_string()" in prompt
        assert "Rejection Reasoning" in prompt

    def test_has_attack_directives(self) -> None:
        h = _mock_hypothesis()
        v = _mock_validation()
        prompt = _build_adversarial_prompt(h, v)
        assert "Your Task" in prompt
        assert "encoding tricks" in prompt
        assert "second-order" in prompt.lower()

    def test_includes_code_context(self) -> None:
        h = _mock_hypothesis()
        v = _mock_validation()
        prompt = _build_adversarial_prompt(
            h, v, code_context="query = f\"SELECT * FROM users WHERE name='{input}'\""
        )
        assert "SELECT * FROM users" in prompt
        assert "Code Context" in prompt

    def test_includes_sanitizer_info(self) -> None:
        h = _mock_hypothesis()
        v = _mock_validation()
        prompt = _build_adversarial_prompt(
            h, v, sanitizer_info="escape_string() escapes single quotes, double quotes, backslashes"
        )
        assert "escape_string()" in prompt
        assert "Sanitizer Context" in prompt

    def test_works_with_dict_inputs(self) -> None:
        """Prompt builder should accept plain dicts for testability."""
        h_dict = {
            "id": "hyp-dict",
            "vuln_type": "xss",
            "cwe_id": "CWE-79",
            "severity": "medium",
            "title": "XSS in comment",
            "description": "Reflected XSS in comment field.",
            "source_location": "views.py:20",
            "sink_location": "template.html:5",
        }
        v_dict = {
            "hypothesis_id": "hyp-dict",
            "verdict": "rejected",
            "reasoning": "Output is HTML-escaped.",
        }
        prompt = _build_adversarial_prompt(h_dict, v_dict)
        assert "CWE-79" in prompt
        assert "HTML-escaped" in prompt

    def test_missing_fields_graceful(self) -> None:
        """Missing optional fields should not crash the prompt builder."""
        h = _mock_hypothesis(title="", description="", source_location="", sink_location="")
        v = _mock_validation(reasoning="")
        prompt = _build_adversarial_prompt(h, v)
        # Should still produce a prompt with the required headers
        assert "Rejected Hypothesis" in prompt
        assert "Rejection Reasoning" in prompt


# ── AdversarialReviewer (unit, mock LLM) ────────────────────────────────────


class TestAdversarialReviewerConstruction:
    def test_constructor(self) -> None:
        provider = MagicMock()
        reviewer = AdversarialReviewer(provider=provider, model="claude-opus-5")
        assert reviewer._provider is provider
        assert reviewer._model == "claude-opus-5"
        assert reviewer._nudge_loop is None

    def test_constructor_with_nudge(self) -> None:
        provider = MagicMock()
        nudge = MagicMock()
        reviewer = AdversarialReviewer(
            provider=provider, model="claude-sonnet-5", nudge_loop=nudge
        )
        assert reviewer._nudge_loop is nudge


class TestAdversarialReviewerMockLLM:
    """Review tests using mock LLM that returns controlled structured output."""

    def _mock_provider_with_response(self, response: dict[str, object]) -> MagicMock:
        """Create a mock provider whose generate_structured returns `response`."""
        provider = MagicMock()
        provider.generate_structured = AsyncMock(return_value=response)
        return provider

    async def test_review_empty_list(self) -> None:
        provider = MagicMock()
        reviewer = AdversarialReviewer(provider=provider, model="claude-opus-5")
        results = await reviewer.review([])
        assert results == []

    async def test_review_upholds_rejection(self) -> None:
        provider = self._mock_provider_with_response({
            "verdict": "upheld",
            "confidence": 0.88,
            "bypass_found": False,
            "attack_vector": "",
            "reasoning": "Sanitizer correctly escapes all special characters.",
        })
        reviewer = AdversarialReviewer(provider=provider, model="claude-opus-5")
        h = _mock_hypothesis(id="hyp-001")
        v = _mock_validation(hypothesis_id="hyp-001")

        results = await reviewer.review([(h, v)])

        assert len(results) == 1
        r = results[0]
        assert r.hypothesis_id == "hyp-001"
        assert r.review_verdict == "upheld"
        assert r.confidence == 0.88
        assert r.bypass_found is False
        assert r.attack_vector == ""
        assert r.model == "claude-opus-5"

    async def test_review_overturns_rejection(self) -> None:
        provider = self._mock_provider_with_response({
            "verdict": "overturned",
            "confidence": 0.93,
            "bypass_found": True,
            "attack_vector": "Null byte injection: admin%00.txt bypasses .txt check",
            "reasoning": (
                "Step 1: The extension check uses str.endswith('.txt'). "
                "Step 2: Null byte %00 causes C-level string truncation. "
                "Step 3: File is saved as admin.php while check sees .txt."
            ),
        })
        reviewer = AdversarialReviewer(provider=provider, model="claude-opus-5")
        h = _mock_hypothesis(id="hyp-042")
        v = _mock_validation(hypothesis_id="hyp-042")

        results = await reviewer.review([(h, v)])

        assert len(results) == 1
        r = results[0]
        assert r.hypothesis_id == "hyp-042"
        assert r.review_verdict == "overturned"
        assert r.confidence == 0.93
        assert r.bypass_found is True
        assert "Null byte" in r.attack_vector
        assert "Step 1" in r.reasoning

    async def test_review_multiple_rejected(self) -> None:
        call_count = 0
        responses = [
            {"verdict": "upheld", "confidence": 0.90, "bypass_found": False,
             "attack_vector": "", "reasoning": "Safe."},
            {"verdict": "overturned", "confidence": 0.85, "bypass_found": True,
             "attack_vector": "Unicode normalization bypass", "reasoning": "NFD normalization."},
        ]

        async def side_effect(**kwargs: object) -> dict[str, object]:
            nonlocal call_count
            r = responses[call_count]
            call_count += 1
            return r

        provider = MagicMock()
        provider.generate_structured = AsyncMock(side_effect=side_effect)
        reviewer = AdversarialReviewer(provider=provider, model="claude-opus-5")

        h1 = _mock_hypothesis(id="hyp-a")
        v1 = _mock_validation(hypothesis_id="hyp-a")
        h2 = _mock_hypothesis(id="hyp-b")
        v2 = _mock_validation(hypothesis_id="hyp-b")

        results = await reviewer.review([(h1, v1), (h2, v2)])

        assert len(results) == 2
        assert results[0].review_verdict == "upheld"
        assert results[1].review_verdict == "overturned"
        assert call_count == 2

    async def test_review_llm_failure_defaults_to_upheld(self) -> None:
        provider = MagicMock()
        provider.generate_structured = AsyncMock(
            side_effect=RuntimeError("API error")
        )
        reviewer = AdversarialReviewer(provider=provider, model="claude-opus-5")
        h = _mock_hypothesis(id="hyp-err")
        v = _mock_validation(hypothesis_id="hyp-err")

        results = await reviewer.review([(h, v)])

        assert len(results) == 1
        r = results[0]
        assert r.review_verdict == "upheld"
        assert r.confidence == 0.5
        assert r.bypass_found is False
        assert "LLM error" in r.reasoning

    async def test_review_with_code_contexts(self) -> None:
        """Code contexts dict maps hypothesis_id → snippet."""
        provider = self._mock_provider_with_response({
            "verdict": "upheld",
            "confidence": 0.80,
            "bypass_found": False,
            "attack_vector": "",
            "reasoning": "Reviewed with context.",
        })
        reviewer = AdversarialReviewer(provider=provider, model="claude-opus-5")
        h = _mock_hypothesis(id="hyp-ctx")
        v = _mock_validation(hypothesis_id="hyp-ctx")

        results = await reviewer.review(
            [(h, v)],
            code_contexts={"hyp-ctx": "x = request.args.get('q')"},
        )

        assert len(results) == 1
        # Verify the prompt was built with code context by checking the call
        call_args = provider.generate_structured.call_args
        sent_messages = call_args[1]["messages"]
        assert any("request.args.get" in str(m.get("content", "")) for m in sent_messages)

    async def test_review_with_nudge_loop(self) -> None:
        """When nudge_loop is provided, use _call_with_nudge instead of direct call."""
        nudge = MagicMock()
        nudge.run = AsyncMock(return_value=MagicMock(data={
            "verdict": "overturned",
            "confidence": 0.91,
            "bypass_found": True,
            "attack_vector": "Header injection via X-Forwarded-For",
            "reasoning": "The auditor only checked query params, not HTTP headers.",
        }))
        provider = MagicMock()
        reviewer = AdversarialReviewer(
            provider=provider, model="claude-opus-5", nudge_loop=nudge
        )
        h = _mock_hypothesis(id="hyp-nudge")
        v = _mock_validation(hypothesis_id="hyp-nudge")

        results = await reviewer.review([(h, v)])

        assert len(results) == 1
        assert results[0].review_verdict == "overturned"
        assert results[0].bypass_found is True
        # nudge.run should have been called, not provider.generate_structured
        nudge.run.assert_called_once()
        provider.generate_structured.assert_not_called()

    async def test_confidence_clamped_to_range(self) -> None:
        """Confidence values outside [0,1] should be clamped."""
        provider = self._mock_provider_with_response({
            "verdict": "upheld",
            "confidence": 1.5,  # > 1.0 → clamp to 1.0
            "bypass_found": False,
            "attack_vector": "",
            "reasoning": "Test clamping.",
        })
        reviewer = AdversarialReviewer(provider=provider, model="claude-opus-5")
        h = _mock_hypothesis(id="hyp-clamp")
        v = _mock_validation(hypothesis_id="hyp-clamp")

        results = await reviewer.review([(h, v)])
        assert results[0].confidence == 1.0

        # Negative confidence
        provider2 = self._mock_provider_with_response({
            "verdict": "upheld",
            "confidence": -0.3,  # < 0.0 → clamp to 0.0
            "bypass_found": False,
            "attack_vector": "",
            "reasoning": "Test clamping negative.",
        })
        reviewer2 = AdversarialReviewer(provider=provider2, model="claude-opus-5")
        results2 = await reviewer2.review([(h, v)])
        assert results2[0].confidence == 0.0

    async def test_attack_vector_cleared_when_no_bypass(self) -> None:
        """If bypass_found=False, attack_vector should be emptied regardless of input."""
        provider = self._mock_provider_with_response({
            "verdict": "upheld",
            "confidence": 0.75,
            "bypass_found": False,
            "attack_vector": "LLM hallucinated a vector but no bypass",
            "reasoning": "No viable bypass found.",
        })
        reviewer = AdversarialReviewer(provider=provider, model="claude-opus-5")
        h = _mock_hypothesis(id="hyp-clear")
        v = _mock_validation(hypothesis_id="hyp-clear")

        results = await reviewer.review([(h, v)])
        assert results[0].attack_vector == ""


# ── _safe_id ────────────────────────────────────────────────────────────────


class TestSafeId:
    def test_dataclass_with_id(self) -> None:
        from dataclasses import dataclass

        @dataclass
        class FakeHyp:
            id: str

        assert _safe_id(FakeHyp(id="my-id")) == "my-id"

    def test_object_with_id_attr(self) -> None:
        obj = MagicMock()
        obj.id = "magic-id"
        assert _safe_id(obj) == "magic-id"

    def test_dict_with_id(self) -> None:
        assert _safe_id({"id": "dict-id"}) == "dict-id"

    def test_missing_id(self) -> None:
        assert _safe_id({}) == "unknown"
        assert _safe_id(MagicMock(spec=[])) == "unknown"


# ── Orchestrator phase integration (mock) ───────────────────────────────────


class TestPhaseAdversarialReview:
    """Verify _phase_adversarial_review behaviour via a mock orchestrator."""

    async def test_skips_when_no_reviewer(self) -> None:
        """Phase should be a no-op if adversarial_reviewer is None."""
        from hyqagent.scanner.orchestrator import PhaseName, PipelineState

        state = PipelineState(
            session_id="test-s1",
            current_phase=PhaseName.ADVERSARIAL_REVIEW,
        )
        state.phase_states["hypotheses"] = [_mock_hypothesis(id="h1")]
        state.phase_states["validations"] = [
            _mock_validation(hypothesis_id="h1", verdict="rejected")
        ]

        # Orchestrator without adversarial_reviewer (the default)
        from hyqagent.scanner.orchestrator import Orchestrator

        orch = Orchestrator()
        await orch._phase_adversarial_review(state)

        # Should not have added adversarial_reviews
        assert "adversarial_reviews" not in state.phase_states

    async def test_skips_when_no_rejected(self) -> None:
        """Phase should skip if all validations are confirmed."""
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        provider = MagicMock()
        reviewer = AdversarialReviewer(provider=provider, model="claude-opus-5")
        orch = Orchestrator(adversarial_reviewer=reviewer)

        state = PipelineState(
            session_id="test-s2",
            current_phase=PhaseName.ADVERSARIAL_REVIEW,
        )
        state.phase_states["hypotheses"] = [_mock_hypothesis(id="h1")]
        state.phase_states["validations"] = [
            _mock_validation(hypothesis_id="h1", verdict="confirmed")
        ]

        await orch._phase_adversarial_review(state)
        # No rejected → no review call, no results
        assert "adversarial_reviews" not in state.phase_states

    async def test_processes_rejected_and_stores_results(self) -> None:
        """Orchestrator should call reviewer and store adversarial_reviews."""
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        provider = MagicMock()
        provider.generate_structured = AsyncMock(return_value={
            "verdict": "overturned",
            "confidence": 0.92,
            "bypass_found": True,
            "attack_vector": "Prototype pollution via __proto__",
            "reasoning": "The auditor missed that Object.assign is vulnerable.",
        })
        reviewer = AdversarialReviewer(provider=provider, model="claude-opus-5")
        orch = Orchestrator(adversarial_reviewer=reviewer)

        state = PipelineState(
            session_id="test-s2",
            current_phase=PhaseName.ADVERSARIAL_REVIEW,
        )
        state.phase_states["hypotheses"] = [
            _mock_hypothesis(id="h1", severity="high", confidence=0.8)
        ]
        state.phase_states["validations"] = [
            _mock_validation(hypothesis_id="h1", verdict="rejected")
        ]
        state.phase_states["mode"] = "deep"

        await orch._phase_adversarial_review(state)

        assert "adversarial_reviews" in state.phase_states
        results = state.phase_states["adversarial_reviews"]
        assert len(results) == 1
        assert results[0].review_verdict == "overturned"

    async def test_overturned_adds_confirmed_validation(self) -> None:
        """Overturned rejections should append ValidationResult(verdict=confirmed)."""
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        provider = MagicMock()
        provider.generate_structured = AsyncMock(return_value={
            "verdict": "overturned",
            "confidence": 0.88,
            "bypass_found": True,
            "attack_vector": "CRLF injection in redirect header",
            "reasoning": "The auditor missed that Location header is not sanitized.",
        })
        reviewer = AdversarialReviewer(provider=provider, model="claude-opus-5")
        orch = Orchestrator(adversarial_reviewer=reviewer)

        state = PipelineState(
            session_id="test-s2",
            current_phase=PhaseName.ADVERSARIAL_REVIEW,
        )
        state.phase_states["hypotheses"] = [
            _mock_hypothesis(id="h-crlf", severity="high", confidence=0.9)
        ]
        state.phase_states["validations"] = [
            _mock_validation(hypothesis_id="h-crlf", verdict="rejected")
        ]
        state.phase_states["mode"] = "deep"

        await orch._phase_adversarial_review(state)

        # Check the appended validation
        validations = state.phase_states.get("validations", [])
        # Original rejected + new confirmed = 2
        assert len(validations) == 2
        new_v = validations[1]
        assert new_v.hypothesis_id == "h-crlf"
        assert new_v.verdict == "confirmed"
        assert new_v.validation_type == "adversarial_review"

    async def test_standard_mode_filters_low_severity(self) -> None:
        """In standard mode, only HIGH+ severity rejected hypotheses are reviewed."""
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        provider = MagicMock()
        provider.generate_structured = AsyncMock(return_value={
            "verdict": "upheld",
            "confidence": 0.80,
            "bypass_found": False,
            "attack_vector": "",
            "reasoning": "Safe.",
        })
        reviewer = AdversarialReviewer(provider=provider, model="claude-sonnet-5")
        orch = Orchestrator(adversarial_reviewer=reviewer)

        state = PipelineState(
            session_id="test-s2",
            current_phase=PhaseName.ADVERSARIAL_REVIEW,
        )
        state.phase_states["hypotheses"] = [
            _mock_hypothesis(id="low", severity="low", confidence=0.6),
            _mock_hypothesis(id="medium", severity="medium", confidence=0.5),
            _mock_hypothesis(id="high", severity="high", confidence=0.8),
        ]
        state.phase_states["validations"] = [
            _mock_validation(hypothesis_id="low", verdict="rejected"),
            _mock_validation(hypothesis_id="medium", verdict="rejected"),
            _mock_validation(hypothesis_id="high", verdict="rejected"),
        ]
        state.phase_states["mode"] = "standard"

        await orch._phase_adversarial_review(state)

        results = state.phase_states.get("adversarial_reviews", [])
        # Only "high" should be reviewed
        reviewed_ids = {r.hypothesis_id for r in results}
        assert "high" in reviewed_ids
        assert "low" not in reviewed_ids
        assert "medium" not in reviewed_ids

    async def test_safeguard_no_provider_call(self) -> None:
        """Verify the test never makes a real API call — provider is a strict mock."""
        # This test implicitly validates: if generate_structured is called without
        # being mocked, MagicMock will silently succeed (no HTTP call).
        # The real safeguard is that tests don't import real providers.
        from hyqagent.scanner.adversarial import AdversarialReviewer

        provider = MagicMock()
        provider.generate_structured = AsyncMock(return_value={
            "verdict": "upheld",
            "confidence": 0.85,
            "bypass_found": False,
            "attack_vector": "",
            "reasoning": "Safe.",
        })
        reviewer = AdversarialReviewer(provider=provider, model="claude-opus-5")
        h = _mock_hypothesis()
        v = _mock_validation()

        results = await reviewer.review([(h, v)])
        assert len(results) == 1
        # Confirm it was our mock that was called
        provider.generate_structured.assert_called_once()
