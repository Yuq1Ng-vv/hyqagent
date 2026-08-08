"""Tests for session/belief.py — Bayesian belief update system."""

from __future__ import annotations

from hyqagent.session.belief import (
    EvidenceStrength,
    apply_evidence,
    bayes_update,
    new_belief_state,
)


class TestBayesUpdate:
    def test_confirming_evidence_increases_confidence(self) -> None:
        """L1 confirmed (P(E|H)=0.95, P(E|¬H)=0.10) should raise confidence."""
        prior = 0.5
        posterior = bayes_update(prior, *EvidenceStrength.L1_CONFIRMED)
        assert posterior > prior
        assert 0.9 < posterior < 0.91  # ~0.905

    def test_refuting_evidence_decreases_confidence(self) -> None:
        """L1 rejected evidence should drop confidence substantially."""
        prior = 0.5
        posterior = bayes_update(prior, *EvidenceStrength.L1_REJECTED)
        assert posterior < prior
        assert posterior < 0.1  # ~0.053

    def test_inconclusive_evidence_unchanged(self) -> None:
        """Inconclusive evidence (equal likelihoods) should not change belief."""
        prior = 0.6
        posterior = bayes_update(prior, *EvidenceStrength.L1_INCONCLUSIVE)
        assert posterior == prior

    def test_extreme_prior_near_zero(self) -> None:
        """Very low prior should resist confirmation slightly."""
        posterior = bayes_update(0.01, *EvidenceStrength.L1_CONFIRMED)
        assert posterior > 0.01

    def test_extreme_prior_near_one(self) -> None:
        """Very high prior should resist refutation."""
        posterior = bayes_update(0.99, *EvidenceStrength.L1_REJECTED)
        assert posterior < 0.99

    def test_clamped_to_zero_one(self) -> None:
        """Result always in [0, 1]."""
        for prior in (0.0, 0.25, 0.5, 0.75, 1.0):
            posterior = bayes_update(prior, 0.9, 0.1)
            assert 0.0 <= posterior <= 1.0

    def test_zero_division_safe(self) -> None:
        """When both likelihoods are 0, should return prior unchanged."""
        result = bayes_update(0.5, 0.0, 0.0)
        assert result == 0.5


class TestBeliefState:
    def test_new_state_stores_prior(self) -> None:
        state = new_belief_state("hyp-1", 0.7)
        assert state.hypothesis_id == "hyp-1"
        assert state.current_confidence == 0.7
        assert state.prior == 0.7
        assert state.updates_count == 0

    def test_prior_clamped_away_from_extremes(self) -> None:
        """Initial confidence cannot be 0.0 or 1.0 (prevents lock-in)."""
        s0 = new_belief_state("h", 0.0)
        assert s0.current_confidence > 0.0
        s1 = new_belief_state("h", 1.0)
        assert s1.current_confidence < 1.0

    def test_apply_evidence_updates_confidence(self) -> None:
        state = new_belief_state("hyp-1", 0.7)
        update = apply_evidence(state, "L1 confirmed", *EvidenceStrength.L1_CONFIRMED)
        assert state.current_confidence > 0.7
        assert update.prior == 0.7
        assert update.posterior == state.current_confidence

    def test_multiple_updates_accumulate(self) -> None:
        state = new_belief_state("hyp-1", 0.5)
        apply_evidence(state, "e1", *EvidenceStrength.L1_CONFIRMED)
        apply_evidence(state, "e2", *EvidenceStrength.L2_CONFIRMED)
        assert state.updates_count == 2
        assert state.current_confidence > 0.9

    def test_history_preserves_chain(self) -> None:
        state = new_belief_state("hyp-1", 0.5)
        apply_evidence(state, "first", *EvidenceStrength.L1_CONFIRMED)
        apply_evidence(state, "second", *EvidenceStrength.L2_REJECTED)
        assert state.history[0].evidence_summary == "first"
        assert state.history[1].evidence_summary == "second"
        assert state.history[0].posterior == state.history[1].prior


class TestEvidenceStrength:
    def test_l1_confirmed_is_strong_support(self) -> None:
        ph_e, pnh_e = EvidenceStrength.L1_CONFIRMED
        assert ph_e > 0.9
        assert pnh_e < 0.2

    def test_l2_confirmed_is_strong_support(self) -> None:
        ph_e, pnh_e = EvidenceStrength.L2_CONFIRMED
        assert ph_e > 0.85
        assert pnh_e < 0.1

    def test_adversarial_pass_is_moderate_support(self) -> None:
        ph_e, pnh_e = EvidenceStrength.ADVERSARIAL_PASS
        assert 0.8 <= ph_e <= 0.95

    def test_adversarial_fail_is_refutation(self) -> None:
        ph_e, pnh_e = EvidenceStrength.ADVERSARIAL_FAIL
        assert ph_e < 0.2
