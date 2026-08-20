"""
Sensitivity of the derived bands to beta_attack (reviewer ask: sweep the one
parameter chosen in the attacker simulator and show which conclusions survive).

beta_attack -- the rate at which a hostile session takes the bait -- is estimated
against an attacker-curiosity model the researcher chose (docs/LIMITATIONS.md §2).
It sets BOTH the width of the bait band AND the magnitude of the measured recall
gain, so a reviewer is right to ask what depends on it. This sweep answers that
analytically: it recomputes the derived bands (adf.policy.voi.derive_bands) across
a grid of beta_attack, holding the *measured* beta_benign fixed, and reports what
moves and what does not.

The invariants it demonstrates (state these in the paper, not the point estimate):

  1. The middle (BAIT) band is NON-EMPTY for every beta_attack > beta_benign --
     i.e. for every bait admissible at all. The existence of a third action does
     not depend on the value of beta_attack, only on the bait being informative.
  2. The DIVERT threshold with bait is always >= the cost-only boundary (0.816):
     bait only ever raises it. Combined with the EVSI survival-discount, this is
     what makes the never-worse-than-passive guarantee hold for ALL beta_attack
     (the guarantee is structural, not a property of the point estimate).
  3. What DOES move with beta_attack is the band WIDTH and the informativeness
     (likelihood ratio) of a bite -- i.e. the *magnitude* of the gain, never its
     direction or the safety guarantee.

    python -m tools.beta_sweep
"""

from __future__ import annotations

import json
from pathlib import Path

from adf.config import load_costs
from adf.policy.engine import BaitLibrary
from adf.policy.voi import BaitEffect, cost_only_boundary, derive_bands   # noqa: F401  (re-exported: tests import it from here)

OUT = Path("data/eval/beta_sweep.json")


def _live_calibration():
    """beta_benign and the calibrated beta_attack values, read off the live library.

    These were once literals (0.0037 / 0.59). The library was re-calibrated and
    re-frozen; the literals were not, so the sweep kept reporting the parameters of
    a library that no longer exists -- plausible, parseable and wrong. Read them.
    """
    effects = BaitLibrary.load().effects()
    betas = sorted(e.beta_attack for e in effects)
    beta_benign = sorted(e.beta_benign for e in effects)[len(effects) // 2]
    return beta_benign, betas


#: The measured benign bite rate the sweep holds fixed, and the calibrated
#: attacker-side rates, both read from the frozen library rather than pinned here.
#: `tests/test_stats_sensitivity.py` imports BETA_BENIGN, so the sensitivity tests
#: run against whatever library is actually frozen.
BETA_BENIGN, CALIBRATED_BETAS = _live_calibration()
POINT = CALIBRATED_BETAS[len(CALIBRATED_BETAS) // 2]


def main() -> None:
    costs = load_costs()
    boundary = cost_only_boundary(costs)
    calibrated = CALIBRATED_BETAS

    # the fixed grid plus every calibrated bait, so the sweep shows where the
    # real library actually sits rather than only where we chose to sample
    grid = sorted({0.10, 0.20, 0.30, 0.40, 0.50, 0.70, 0.80, 0.90, *calibrated})
    rows = []
    print("=" * 74)
    print("SENSITIVITY OF THE DERIVED BANDS TO beta_attack")
    print(f"(beta_benign fixed at the measured {BETA_BENIGN}; cost-only PASS/DIVERT "
          f"boundary = {boundary:.4f})")
    print(f"(calibrated baits: {', '.join(f'{b:.4f}' for b in calibrated)})")
    print("=" * 74)
    print(f"  {'beta_attack':>11}  {'LR(bite)':>9}  {'PASS<':>8}  {'BAIT band':>18}  "
          f"{'width':>7}  {'band?':>6}  {'divert>=0.816?':>13}")
    for ba in grid:
        eff = BaitEffect(bait_id="sweep", beta_attack=ba, beta_benign=BETA_BENIGN, category="idor")
        bands = derive_bands(costs, [eff])
        pass_to_bait = bands.get("pass_to_bait")
        bait_to_divert = bands.get("bait_to_divert")
        # a non-empty BAIT band means both edges exist and are ordered
        has_band = (pass_to_bait is not None and bait_to_divert is not None
                    and bait_to_divert > pass_to_bait)
        width = (bait_to_divert - pass_to_bait) if has_band else 0.0
        divert_ge = (bait_to_divert is not None and bait_to_divert >= boundary - 1e-6)
        lr = eff.likelihood_ratio
        tag = "  <-- calibrated bait" if any(abs(ba - b) < 1e-9 for b in calibrated) else ""
        band_str = (f"[{pass_to_bait:.4f}, {bait_to_divert:.4f})" if has_band else "(none)")
        print(f"  {ba:>11.2f}  {lr:>9.1f}  {(pass_to_bait or 0):>8.4f}  {band_str:>18}  "
              f"{width:>7.4f}  {'yes' if has_band else 'NO':>6}  {'yes' if divert_ge else 'NO':>13}{tag}")
        rows.append({"beta_attack": ba, "likelihood_ratio": round(lr, 2),
                     "pass_to_bait": pass_to_bait, "bait_to_divert": bait_to_divert,
                     "band_width": round(width, 4), "band_nonempty": has_band,
                     "divert_ge_cost_only": divert_ge,
                     "is_calibrated_bait": bool(tag)})

    invariant = (all(r["band_nonempty"] for r in rows)
                 and all(r["divert_ge_cost_only"] for r in rows))
    print("\nInvariant across the whole sweep:")
    print(f"  * BAIT band non-empty for every beta_attack > beta_benign : "
          f"{'CONFIRMED' if all(r['band_nonempty'] for r in rows) else 'VIOLATED'}")
    print(f"  * DIVERT threshold never below the cost-only boundary     : "
          f"{'CONFIRMED' if all(r['divert_ge_cost_only'] for r in rows) else 'VIOLATED'}")
    print("  * never-worse-than-passive holds for ALL beta_attack (EVSI decay,")
    print("    adf.policy.voi.survival_discount -> V=0 as exposures grow, so the")
    print("    policy converges to the two-action rule regardless of beta_attack).")
    print("\nWhat MOVES with beta_attack: band width and LR(bite) -- the *magnitude*")
    print("of the gain, never its direction or the safety guarantee.")

    OUT.write_text(json.dumps({
        "beta_benign": BETA_BENIGN, "cost_only_boundary": round(boundary, 6),
        "point_estimate": POINT, "calibrated_betas": calibrated, "sweep": rows,
        "conclusions_invariant": invariant,
    }, indent=2), encoding="utf-8")
    print(f"\nwritten -> {OUT}")


if __name__ == "__main__":
    main()
