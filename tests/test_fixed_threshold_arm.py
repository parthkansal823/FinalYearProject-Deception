"""The fixed-threshold ablation (b5_fixed).

The paper's central claim is not that three actions beat two. It is that the two
band edges are a CONSEQUENCE of the frozen cost table and the calibrated bite
rates, rather than parameters somebody tuned. That claim is only testable against
a policy identical in every other respect, differing only in where its edges came
from -- so these tests pin the two properties that make the comparison fair, and
the guard that stops the ablation quietly becoming the thing it ablates.
"""
from __future__ import annotations

import pytest

from adf.policy.engine import DecisionPolicy, _parse_fixed_bands
from adf.policy.voi import choose_action, choose_action_fixed


def _policy(mode="b5_fixed", bands=(0.30, 0.70)):
    p = DecisionPolicy.from_config()
    p.mode = mode
    p.fixed_bands = bands
    return p


def test_fixed_edges_are_obeyed_exactly():
    pol = _policy(bands=(0.30, 0.70))
    t, e = pol.cost_table, pol.library.effects()
    assert choose_action_fixed(0.29, t, e, pass_to_bait=0.30, bait_to_divert=0.70)[0] == "pass"
    assert choose_action_fixed(0.30, t, e, pass_to_bait=0.30, bait_to_divert=0.70)[0] == "bait"
    assert choose_action_fixed(0.69, t, e, pass_to_bait=0.30, bait_to_divert=0.70)[0] == "bait"
    assert choose_action_fixed(0.70, t, e, pass_to_bait=0.30, bait_to_divert=0.70)[0] == "divert"


def test_it_actually_differs_from_the_derived_policy():
    """If the two agreed everywhere the ablation would measure nothing."""
    pol = _policy()
    t, e = pol.cost_table, pol.library.effects()
    disagreements = sum(
        choose_action(p / 100, t, e)[0]
        != choose_action_fixed(p / 100, t, e, pass_to_bait=0.30, bait_to_divert=0.70)[0]
        for p in range(101))
    assert disagreements > 10, "fixed and derived policies must diverge to be comparable"


def test_bait_selection_is_shared_so_only_the_edges_differ():
    """The ablation isolates the EDGES. If it also changed which bait is planted,
    a difference in outcome could not be attributed to the derivation."""
    pol = _policy()
    t, e = pol.cost_table, pol.library.effects()
    for p in (0.35, 0.5, 0.65):
        _, dd = choose_action(p, t, e)
        _, fd = choose_action_fixed(p, t, e, pass_to_bait=0.30, bait_to_divert=0.70)
        assert dd["selected_bait"] == fd["selected_bait"]
        assert dd["evsi"] == fd["evsi"], "the EVSI is reported either way, just not acted on"


def test_the_fixed_arm_does_not_subtract_the_information_value():
    """That subtraction IS the contribution. An ablation that keeps it is the
    derived policy wearing a disguise."""
    pol = _policy()
    t, e = pol.cost_table, pol.library.effects()
    _, fd = choose_action_fixed(0.5, t, e, pass_to_bait=0.30, bait_to_divert=0.70)
    assert fd["effective_costs"] == fd["immediate_costs"]
    _, dd = choose_action(0.5, t, e)
    assert dd["effective_costs"]["bait"] < dd["immediate_costs"]["bait"]


def test_b5_refuses_to_run_without_edges():
    """Falling back to the derived policy would make the ablation report itself
    as the ablation -- the worst outcome, because the run still succeeds."""
    pol = _policy(bands=None)
    with pytest.raises(RuntimeError, match="fixed_bands"):
        pol.decide(session_id="s", automation=0.5, malice=0.5)


def test_b5_may_bait_or_it_is_not_a_three_action_arm():
    pol = _policy(bands=(0.10, 0.90))
    assert pol.decide(session_id="s", automation=0.5, malice=0.5).action in ("bait", "pass")
    seen = {pol.decide(session_id=f"s{i}", automation=0.5, malice=0.5).action
            for i in range(30)}
    assert "bait" in seen, "b5_fixed must be able to bait; otherwise it is just B2"


@pytest.mark.parametrize("raw,expected", [
    ("0.1,0.9", (0.1, 0.9)),
    ([0.2, 0.8], (0.2, 0.8)),
    (None, None),
    ("", None),
])
def test_band_parsing(raw, expected):
    assert _parse_fixed_bands(raw) == expected


@pytest.mark.parametrize("bad", ["0.9,0.1", "0.5", "0.1,0.5,0.9", "-0.1,0.5", "0.1,1.5"])
def test_bad_bands_are_rejected(bad):
    with pytest.raises(ValueError):
        _parse_fixed_bands(bad)
