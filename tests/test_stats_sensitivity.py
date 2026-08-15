"""
Tests for the statistical-rigour additions (multi-seed report + beta sweep).

These guard two things a reviewer would check by hand:
  * the confidence-interval maths is correct (Wilson), and the paired-test
    bookkeeping counts discordant pairs in the right direction;
  * the qualitative conclusions the paper claims are invariant to beta_attack
    actually are, across the whole admissible range -- not just at the point
    estimate (docs/LIMITATIONS.md §2, the reviewer's second-order concern).
"""

from __future__ import annotations

from adf.config import load_costs
from adf.policy.voi import BaitEffect, derive_bands
from tools.stats_report import wilson, _mcnemar
from tools.beta_sweep import cost_only_boundary, BETA_BENIGN
from tools.cost_sweep import RATIO_GRID as COST_RATIO_GRID, scaled_table


# ---------------------------------------------------------------------------
# Wilson interval
# ---------------------------------------------------------------------------


def test_wilson_matches_known_value():
    # 8/10 -> Wilson 95% CI is approximately [0.490, 0.943] (standard reference)
    p, lo, hi = wilson(8, 10)
    assert p == 0.8
    assert abs(lo - 0.490) < 0.01
    assert abs(hi - 0.943) < 0.01


def test_wilson_is_bounded_and_ordered():
    for k, n in [(0, 20), (20, 20), (3, 80), (120, 120)]:
        p, lo, hi = wilson(k, n)
        assert 0.0 <= lo <= p <= hi <= 1.0


def test_wilson_interval_shrinks_with_n():
    _, lo_small, hi_small = wilson(9, 10)
    _, lo_big, hi_big = wilson(900, 1000)
    assert (hi_big - lo_big) < (hi_small - lo_small)


# ---------------------------------------------------------------------------
# Paired McNemar bookkeeping
# ---------------------------------------------------------------------------


def _row(arm, seed, index, diverted, subcat="idor_html_scattered"):
    return {"arm": arm, "seed": seed, "index": index, "stream": "attack",
            "label": "attack", "subcategory": subcat, "diverted": diverted,
            "assignment": "policy", "category": "idor"}


def test_mcnemar_counts_discordant_pairs_directionally():
    # three matched pairs: B4 catches all, B2 catches none -> b=3, c=0
    rows = []
    for i in range(3):
        rows.append(_row("b2_passive", 1, i, diverted=False))
        rows.append(_row("b4_full", 1, i, diverted=True))
    mc = _mcnemar(rows, "b2_passive", "b4_full", stream="attack")
    assert mc["pairs"] == 3
    assert mc["b"] == 3        # B4 wins on every discordant pair
    assert mc["c"] == 0
    assert mc["p"] < 0.30      # 3-0 is not yet significant, but direction is clean


def test_mcnemar_ignores_concordant_pairs():
    # both arms catch: concordant, no discordant information
    rows = [_row("b2_passive", 1, 0, True), _row("b4_full", 1, 0, True)]
    mc = _mcnemar(rows, "b2_passive", "b4_full", stream="attack")
    assert mc["b"] == 0 and mc["c"] == 0
    assert mc["concordant"] == 1
    assert mc["p"] == 1.0


# ---------------------------------------------------------------------------
# beta_attack sensitivity: the invariants the paper claims
# ---------------------------------------------------------------------------


def test_bait_band_is_nonempty_for_every_admissible_beta():
    """The third action exists for any informative bait, not just at beta=0.59."""
    costs = load_costs()
    for ba in [0.05, 0.10, 0.30, 0.50, 0.70, 0.90, 0.99]:
        eff = BaitEffect(bait_id="s", beta_attack=ba, beta_benign=BETA_BENIGN, category="idor")
        bands = derive_bands(costs, [eff])
        lo, hi = bands.get("pass_to_bait"), bands.get("bait_to_divert")
        assert lo is not None and hi is not None and hi > lo, \
            f"bait band collapsed at beta_attack={ba}"


def test_divert_threshold_never_below_cost_only_boundary():
    """Bait only ever RAISES the divert threshold; it never makes the system
    divert earlier than cost accounting alone would. This, with the EVSI decay,
    is what underwrites never-worse-than-passive for all beta_attack."""
    costs = load_costs()
    boundary = cost_only_boundary(costs)
    for ba in [0.10, 0.30, 0.50, 0.59, 0.70, 0.90]:
        eff = BaitEffect(bait_id="s", beta_attack=ba, beta_benign=BETA_BENIGN, category="idor")
        bands = derive_bands(costs, [eff])
        assert bands["bait_to_divert"] >= boundary - 1e-6


def test_band_width_increases_with_beta_attack():
    """A more effective bait buys more information, so the region where probing
    is worthwhile is wider -- magnitude moves even though the conclusions do not."""
    costs = load_costs()

    def width(ba):
        eff = BaitEffect(bait_id="s", beta_attack=ba, beta_benign=BETA_BENIGN, category="idor")
        b = derive_bands(costs, [eff])
        return b["bait_to_divert"] - b["pass_to_bait"]

    assert width(0.30) < width(0.59) < width(0.90)


# ---------------------------------------------------------------------------
# Invariance to the COST TABLE (docs/LIMITATIONS.md §8)
#
# The costs are a reasoned estimate rather than a real organisation's incident
# data. These lock the same claim the beta sweep makes: the conclusions are a
# property of the decision rule, not of the particular numbers chosen. The
# frozen table is never modified -- each case builds a scaled copy.
# ---------------------------------------------------------------------------


def test_bait_band_is_nonempty_across_the_cost_range():
    """The third action exists whether a wrongly diverted user is priced at half
    a missed attacker or 128 times one."""
    base = load_costs()
    eff = BaitEffect(bait_id="B-IDOR-2", beta_attack=0.59,
                     beta_benign=BETA_BENIGN, category="idor")
    for ratio in COST_RATIO_GRID:
        bands = derive_bands(scaled_table(base, ratio), [eff])
        lo, hi = bands.get("pass_to_bait"), bands.get("bait_to_divert")
        assert lo is not None and hi is not None and hi > lo, \
            f"bait band collapsed at divert/miss ratio {ratio}"


def test_divert_threshold_never_below_cost_only_boundary_across_cost_range():
    """The safety half of the guarantee is structural too: at no cost ratio does
    offering bait make the system divert earlier than cost accounting alone."""
    base = load_costs()
    eff = BaitEffect(bait_id="B-IDOR-2", beta_attack=0.59,
                     beta_benign=BETA_BENIGN, category="idor")
    for ratio in COST_RATIO_GRID:
        table = scaled_table(base, ratio)
        bands = derive_bands(table, [eff])
        assert bands["bait_to_divert"] >= cost_only_boundary(table) - 1e-6, \
            f"divert threshold fell below the two-action boundary at ratio {ratio}"


def test_a_costlier_false_divert_makes_the_system_more_cautious():
    """The sweep must move something, or it is not testing anything. Pricing a
    wrongly diverted user higher should push BOTH boundaries up: the system waits
    for more evidence before probing and before diverting."""
    base = load_costs()
    eff = BaitEffect(bait_id="B-IDOR-2", beta_attack=0.59,
                     beta_benign=BETA_BENIGN, category="idor")

    def edges(ratio):
        b = derive_bands(scaled_table(base, ratio), [eff])
        return b["pass_to_bait"], b["bait_to_divert"]

    lo_cheap, hi_cheap = edges(1.0)
    lo_frozen, hi_frozen = edges(8.0)
    lo_dear, hi_dear = edges(64.0)
    assert lo_cheap < lo_frozen < lo_dear
    assert hi_cheap < hi_frozen < hi_dear


def test_the_frozen_table_is_not_mutated_by_sweeping():
    """The sweep builds scaled copies. If it ever edited the loaded table in
    place, every result computed after it would be silently wrong."""
    base = load_costs()
    before = base.cost("benign", "divert")
    for ratio in COST_RATIO_GRID:
        scaled_table(base, ratio)
    assert base.cost("benign", "divert") == before
