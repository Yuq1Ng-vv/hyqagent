"""session/belief.py — Bayesian belief system for hypothesis confidence tracking.

Each finding starts with a prior P(H) (the LLM's initial confidence estimate).
As evidence accumulates (L1 deterministic checks, L2 LLM review, adversarial
challenges), we update P(H|E) via Bayes' theorem:

    P(H|E) = P(E|H) x P(H) / P(E)

where:
  - P(H)     = prior belief in the hypothesis
  - P(E|H)   = likelihood of observing evidence E if H is true
  - P(E)     = P(E|H)xP(H) + P(E|¬H)x(1-P(H))
  - P(H|E)   = posterior belief after incorporating E

See DESIGN-IMPLEMENTATION.md §3.3 Task 6.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BeliefUpdate:
    """One step in the evidence-accumulation chain."""

    prior: float  # P(H) before this observation
    likelihood: float  # P(E|H) — how expected is this evidence if H is true?
    posterior: float  # P(H|E) after update
    evidence_summary: str  # human-readable description of E


@dataclass
class BeliefState:
    """Current belief about a single hypothesis."""

    hypothesis_id: str
    current_confidence: float  # P(H | all evidence so far)
    prior: float  # original P(H) from LLM
    history: list[BeliefUpdate] = field(default_factory=list)

    @property
    def updates_count(self) -> int:
        """How many pieces of evidence have been incorporated."""
        return len(self.history)


# ── Likelihood presets ───────────────────────────────────────────────────────


class EvidenceStrength:
    """Pre-calibrated likelihood ratios for common evidence types.

    L1_CONFIRMED:   source/sink types match + path exists        → P(E|H)=0.95, P(E|¬H)=0.10
    L1_REJECTED:    source/sink types mismatch                   → P(E|H)=0.05, P(E|¬H)=0.90
    L1_INCONCLUSIVE: partial match, can't decide                 → P(E|H)=0.50, P(E|¬H)=0.50
    L2_CONFIRMED:   strong-model 5-question review confirms      → P(E|H)=0.90, P(E|¬H)=0.05
    L2_REJECTED:    strong-model review finds critical flaw      → P(E|H)=0.10, P(E|¬H)=0.85
    ADVERSARIAL_PASS: attack perspective couldn't find bypass    → P(E|H)=0.85, P(E|¬H)=0.20
    ADVSARIAL_FAIL: attack perspective found a bypass            → P(E|H)=0.15, P(E|¬H)=0.80
    """

    # (P(E|H), P(E|¬H))
    L1_CONFIRMED = (0.95, 0.10)
    L1_REJECTED = (0.05, 0.90)
    L1_INCONCLUSIVE = (0.50, 0.50)
    L2_CONFIRMED = (0.90, 0.05)
    L2_REJECTED = (0.10, 0.85)
    ADVERSARIAL_PASS = (0.85, 0.20)
    ADVERSARIAL_FAIL = (0.15, 0.80)


# ── Core update logic ────────────────────────────────────────────────────────


def bayes_update(prior: float, likelihood_given_h: float, likelihood_given_not_h: float) -> float:
    """Compute P(H|E) = P(E|H)xP(H) / [P(E|H)xP(H) + P(E|¬H)x(1-P(H))].

    Returns a float clamped to [0.0, 1.0].
    """
    if not (0 <= prior <= 1):
        raise ValueError(f"prior must be in [0,1], got {prior}")

    numerator = likelihood_given_h * prior
    denominator = numerator + likelihood_given_not_h * (1 - prior)

    if denominator == 0:
        return prior  # no information gained

    posterior = numerator / denominator
    return max(0.0, min(1.0, posterior))


def apply_evidence(
    state: BeliefState,
    evidence: str,
    likelihood_given_h: float,
    likelihood_given_not_h: float,
) -> BeliefUpdate:
    """Apply one piece of evidence to *state* and return the update record."""
    prior = state.current_confidence
    posterior = bayes_update(prior, likelihood_given_h, likelihood_given_not_h)

    update = BeliefUpdate(
        prior=prior,
        likelihood=likelihood_given_h,
        posterior=posterior,
        evidence_summary=evidence,
    )
    state.history.append(update)
    state.current_confidence = posterior
    return update


def new_belief_state(hypothesis_id: str, initial_confidence: float) -> BeliefState:
    """Create a fresh :class:`BeliefState` with the LLM's initial confidence as prior."""
    return BeliefState(
        hypothesis_id=hypothesis_id,
        current_confidence=max(0.01, min(0.99, initial_confidence)),
        prior=max(0.01, min(0.99, initial_confidence)),
    )
