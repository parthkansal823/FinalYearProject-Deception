"""
Tests for the value-of-information decision policy.

Several of these are not ordinary unit tests but checks on the mathematical
properties the paper will claim. If `test_information_is_never_harmful` fails,
the EVSI implementation is wrong and the central argument of the contribution
does not hold — that is worth catching in CI rather than in a viva.
"""

from __future__ import annotations

import math

import pytest

from adf.config import load_costs
from adf.policy import (
    BaitEffect,
    BaitLibrary,
    DecisionPolicy,
    choose_action,
    derive_bands,
    expected_value_of_information,
    fuse,
    posterior,
    probability_of_bite,
)
from adf.policy.engine import POLICY_VERSION

GRID = [i / 200.0 for i in range(201)]


@pytest.fixture(scope="module")
def table():
    return load_costs()


@pytest.fixture(scope="module")
def effect():
    return BaitEffect(bait_id="B-TEST", beta_attack=0.5, beta_benign=0.0005, category="sqli")


@pytest.fixture(scope="module")
def library():
    return BaitLibrary.load()


# ---------------------------------------------------------------------------
# The mathematics the contribution rests on
# ---------------------------------------------------------------------------


def test_information_is_never_harmful(table, effect):
    """EVSI >= 0 everywhere.

    `min` over linear cost functions is concave, so by Jensen the expected
    post-observation cost cannot exceed the pre-observation cost. This is the
    formal reason bait is defensible, and it is a stronger statement than
    "bait is cheap".
    """
    for p in GRID:
        assert expected_value_of_information(p, effect, table) >= 0.0


def test_repeated_refusal_stops_deferring_the_divert(table, effect):
    """Regression, found by the adaptive-adversary sweep (docs/DECISIONS.md).

    Offering a third action raises the divert threshold, so a bait-AWARE
    attacker who keeps p inside the gap and never bites was baited forever and
    never diverted -- caught by the passive baseline B2 but NOT by the full
    system. Discounting the EVSI by unrewarded exposures fixes it: after a
    refusal or two the information is priced at what it is actually worth, and
    the policy converges to the decision it would have made without bait.

    The guarantee this pins: **the full system is never worse than its own
    passive baseline**, whatever the adversary knows.
    """
    effects = [effect]
    # The deferral gap: beliefs where the two-action rule says DIVERT but the
    # VoI rule says BAIT. Computed from the fixture so the test does not depend
    # on any particular calibration.
    immediate_boundary = table.derive_thresholds()["pass_to_divert"]
    voi_boundary = derive_bands(table, effects)["bait_to_divert"]
    assert voi_boundary > immediate_boundary, "the third action should defer divert at all"
    p_gap = (immediate_boundary + voi_boundary) / 2

    first, _ = choose_action(p_gap, table, effects, {})
    assert first == "bait", "the first exposure should still buy information"

    # after repeated refusal the policy must stop waiting
    for n in (3, 5, 10):
        action, _ = choose_action(p_gap, table, effects, {effect.bait_id: n})
        assert action == "divert", (
            f"after {n} unrewarded exposures the policy still chose {action}; "
            "a bait-aware attacker would evade indefinitely"
        )

    # and it must agree with the no-bait (B2) decision at that belief
    assert table.best_action(p_gap) == "divert"


def test_evsi_decay_leaves_first_contact_untouched(table, effect):
    """The discount must not change behaviour before any exposure, or it would
    silently move the derived bands the paper reports."""
    for p in GRID:
        undiscounted, _ = choose_action(p, table, [effect], {})
        explicit_zero, _ = choose_action(p, table, [effect], {effect.bait_id: 0})
        assert undiscounted == explicit_zero


def test_information_is_worthless_when_already_certain(table, effect):
    """At p=0 and p=1 no observation can change the decision, so the value of
    making one is exactly zero. A non-zero value here would mean the
    implementation is rewarding bait for something other than information."""
    assert expected_value_of_information(0.0, effect, table) == pytest.approx(0.0, abs=1e-9)
    assert expected_value_of_information(1.0, effect, table) == pytest.approx(0.0, abs=1e-9)


def test_information_is_most_valuable_in_the_middle(table, effect):
    """EVSI should peak away from the certain ends -- that is what makes the
    bait band a band rather than a threshold."""
    values = [expected_value_of_information(p, effect, table) for p in GRID]
    peak = values.index(max(values))
    assert 0 < peak < len(GRID) - 1
    assert max(values) > 0.0


def test_a_more_effective_bait_is_worth_more(table):
    """Monotonicity in beta_attack: a bait attackers take more often carries
    more information, at every belief."""
    weak = BaitEffect(bait_id="weak", beta_attack=0.2, beta_benign=0.0005)
    strong = BaitEffect(bait_id="strong", beta_attack=0.8, beta_benign=0.0005)
    for p in [0.1, 0.2, 0.3, 0.5, 0.7]:
        assert (expected_value_of_information(p, strong, table)
                >= expected_value_of_information(p, weak, table))


def test_bite_raises_belief_and_no_bite_lowers_it(effect):
    for p in [0.05, 0.2, 0.5, 0.8]:
        assert posterior(p, effect, bite=True) > p
        assert posterior(p, effect, bite=False) < p


def test_posterior_obeys_total_probability(effect):
    """The two posteriors, weighted by their probabilities, must average back
    to the prior. A violation means the Bayes update is wrong."""
    for p in [0.05, 0.2, 0.5, 0.8]:
        pb = probability_of_bite(p, effect)
        recovered = pb * posterior(p, effect, bite=True) + (1 - pb) * posterior(p, effect, bite=False)
        assert recovered == pytest.approx(p, abs=1e-9)


def test_likelihood_ratio_replaces_the_hand_set_jump(effect):
    """Spec §5.2 leaves the bite update as 'jumps sharply'. It is derived
    here, and a bite must be strong evidence while a non-bite is weak."""
    assert effect.likelihood_ratio > 100
    assert 0.0 < effect.negative_likelihood_ratio < 1.0


def test_uninformative_bait_is_rejected_outright():
    """A bait benign users act on as often as attackers carries no evidence
    and must never enter the library."""
    with pytest.raises(ValueError, match="not informative"):
        BaitEffect(bait_id="useless", beta_attack=0.10, beta_benign=0.10)


# ---------------------------------------------------------------------------
# The decision rule
# ---------------------------------------------------------------------------


def test_bait_never_wins_on_immediate_cost_alone(table):
    """The honest position: baiting has no immediate benefit whatsoever. It
    costs strictly more than passing at every belief, and is chosen only once
    its information value is subtracted."""
    for p in GRID:
        immediate = {a: table.expected_cost(a, p) for a in ("pass", "bait", "divert")}
        assert immediate["bait"] > immediate["pass"] - 1e-12, \
            "bait has become immediately cheaper than pass; the cost table is double counting again"


def test_all_three_actions_are_reachable(table, library):
    """A policy that never baits has quietly collapsed to the two-outcome
    design this project exists to improve on (spec §4.3 contribution 1)."""
    effects = library.effects()
    chosen = {choose_action(p, table, effects)[0] for p in GRID}
    assert chosen == {"pass", "bait", "divert"}


def test_bands_are_ordered_and_derived(table, library):
    bands = derive_bands(table, library.effects())
    assert "pass_to_bait" in bands and "bait_to_divert" in bands
    assert 0.0 < bands["pass_to_bait"] < bands["bait_to_divert"] < 1.0


def test_divert_still_requires_overwhelming_evidence(table, library):
    """NFR-05: a benign user must almost never be diverted. Adding the
    information term must not have weakened that."""
    bands = derive_bands(table, library.effects())
    assert bands["bait_to_divert"] > 0.75


def test_no_bait_available_means_no_bait_chosen(table):
    """Baselines B0-B3 pass an empty effect list; with nothing to learn from,
    the policy must reduce exactly to the two-outcome rule."""
    chosen = {choose_action(p, table, [])[0] for p in GRID}
    assert "bait" not in chosen


def test_the_most_informative_bait_is_selected(table):
    """Spec §6.6 asks for a bait 'appropriate to' the attack; EVSI says which."""
    effects = [
        BaitEffect(bait_id="weak", beta_attack=0.15, beta_benign=0.0005),
        BaitEffect(bait_id="strong", beta_attack=0.75, beta_benign=0.0005),
    ]
    _, detail = choose_action(0.3, table, effects)
    assert detail["selected_bait"] == "strong"


# ---------------------------------------------------------------------------
# Score fusion
# ---------------------------------------------------------------------------


def test_default_fusion_uses_malice_only(table):
    """A price-comparison bot is fully automated and entirely harmless
    (spec §6.3), so automation alone must not imply hostility."""
    f = table.fusion
    assert fuse(automation=0.99, malice=0.02, fusion=f) == pytest.approx(0.02, abs=1e-4)
    assert fuse(automation=0.01, malice=0.02, fusion=f) == pytest.approx(0.02, abs=1e-4)


def test_fusion_is_monotone_in_malice(table):
    f = table.fusion
    values = [fuse(automation=0.5, malice=m, fusion=f) for m in [0.01, 0.2, 0.5, 0.8, 0.99]]
    assert values == sorted(values)


# ---------------------------------------------------------------------------
# The randomised holdout
# ---------------------------------------------------------------------------


def _policy(table, library, **kw) -> DecisionPolicy:
    return DecisionPolicy(cost_table=table, library=library, fusion=table.fusion, **kw)


def test_holdout_assignment_is_deterministic(table, library):
    """NFR-08: the same seed and traffic must reproduce identical results."""
    a = _policy(table, library, seed=42, holdout_fraction=0.5)
    b = _policy(table, library, seed=42, holdout_fraction=0.5)
    for i in range(200):
        assert a.in_holdout(f"s-{i}") == b.in_holdout(f"s-{i}")


def test_holdout_depends_on_the_seed(table, library):
    a = _policy(table, library, seed=1, holdout_fraction=0.5)
    b = _policy(table, library, seed=2, holdout_fraction=0.5)
    assignments_a = [a.in_holdout(f"s-{i}") for i in range(300)]
    assignments_b = [b.in_holdout(f"s-{i}") for i in range(300)]
    assert assignments_a != assignments_b


def test_holdout_hits_its_target_rate(table, library):
    policy = _policy(table, library, seed=7, holdout_fraction=0.1)
    n = 20_000
    rate = sum(policy.in_holdout(f"s-{i}") for i in range(n)) / n
    # ~4 standard errors of a binomial proportion at this n
    assert abs(rate - 0.1) < 0.01


def test_holdout_can_be_disabled(table, library):
    policy = _policy(table, library, seed=7, holdout_fraction=0.0)
    assert not any(policy.in_holdout(f"s-{i}") for i in range(500))


def test_held_out_sessions_are_recorded_as_such(table, library):
    """The holdout is only useful if the log distinguishes 'was not baited
    because the policy said pass' from 'was not baited because it was a
    control'. Without that, the causal estimate is not recoverable."""
    policy = _policy(table, library, seed=7, holdout_fraction=1.0)
    decision = policy.decide(session_id="s-1", automation=0.5, malice=0.5)

    assert decision.action == "pass"           # what the session received
    assert decision.bait_assignment == "holdout"   # why it received it
    assert decision.evsi > 0                   # and that bait was warranted

    treated = _policy(table, library, seed=7, holdout_fraction=0.0)
    assert treated.decide(session_id="s-1", automation=0.5, malice=0.5).bait_assignment == "policy"


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------


def test_baseline_modes_never_bait(table, library):
    """Spec §10.1: if a baseline baits, it has stopped being a baseline."""
    for mode in ("b0_no_defence", "b1_rules", "b2_passive", "b3_static"):
        policy = _policy(table, library, seed=1, holdout_fraction=0.0, mode=mode)
        for m in [0.1, 0.3, 0.5, 0.7, 0.9]:
            decision = policy.decide(session_id="s", automation=0.5, malice=m)
            assert decision.action in ("pass", "divert")
            assert decision.bait_assignment == "none"


def test_reporting_from_uncalibrated_priors_is_refused(table, library):
    """The beta values ship as priors. Presenting a result computed from them
    would be presenting a guess as a finding."""
    library.calibrated = False
    policy = _policy(table, library, seed=1, require_calibration=True)
    with pytest.raises(RuntimeError, match="calibrat"):
        policy.decide(session_id="s", automation=0.5, malice=0.5)


def test_every_decision_carries_its_reason(table, library):
    """NFR-07: every decision traceable to the features that produced it."""
    policy = _policy(table, library, seed=1, holdout_fraction=0.0)
    for m in [0.01, 0.3, 0.95]:
        decision = policy.decide(session_id="s", automation=0.4, malice=m)
        assert decision.reason
        assert any(r.feature == "p_attack" for r in decision.reason)
        assert decision.policy_version == POLICY_VERSION
        assert set(decision.immediate_costs) == {"pass", "bait", "divert"}
