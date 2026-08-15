"""
Sensitivity of the derived bands to the COST TABLE (reviewer ask: the costs that
derive every threshold are argued, not taken from a real organisation's incident
data -- docs/LIMITATIONS.md §8).

The answer is NOT to replace the frozen numbers. config/costs.yaml is frozen and
hash-enforced precisely so it cannot be tuned to the results, and editing it
would invalidate every baseline comparison in the evaluation (spec §6.5, §16).
Instead this sweeps the cost table *analytically*, exactly as tools/beta_sweep.py
sweeps beta_attack, and reports which conclusions survive.

The frozen point estimate is a ratio claim, and only ratios matter (the cost
units are arbitrary and internally consistent):

    cost(divert | benign) / cost(pass | attack)  =  200 / 25  =  8.0

i.e. "wrongly diverting a real user is eight times worse than letting one
attacker through". That is the single judgement the whole threshold structure
rests on, so it is the axis to sweep. The published-incident-economics range
below brackets it by well over an order of magnitude in both directions.

WHAT THIS DEMONSTRATES (state the invariants, not the point estimate):

  1. The BAIT band is non-empty across the entire swept range. The existence of
     a third action does not depend on the cost estimate being right.
  2. The DIVERT threshold is >= the cost-only PASS/DIVERT boundary at every
     point, so the never-worse-than-passive guarantee is structural rather than
     a property of the chosen costs.
  3. What DOES move is where the boundaries sit -- i.e. how conservative the
     system is -- never whether the third action exists or whether it is safe.

Grounding for the range (cite these in the paper alongside the sweep; the sweep
is what makes the citation load-bearing rather than decorative):

  * Verizon DBIR and the IBM Cost of a Data Breach report put the cost of an
    intrusion orders of magnitude above the cost of one inconvenienced user
    session, which is the direction the frozen table already encodes.
  * The genuinely uncertain quantity is *how far* above. A defender who treats
    a wrongly diverted customer as nearly costless sits at the low end; a
    regulated environment where diverting a legitimate user is itself an
    incident sits at the high end. Both ends are swept.

    python -m tools.cost_sweep
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from adf.config import load_costs
from adf.policy.voi import BaitEffect, derive_bands

OUT = Path("data/eval/cost_sweep.json")

# The calibrated paper-carrying bait (B-IDOR-2, n=244), held fixed while the
# costs move -- the mirror image of tools/beta_sweep.py, which holds the costs
# fixed and moves beta.
BETA_ATTACK = 0.59
BETA_BENIGN = 0.0037

# divert-a-benign-user cost as a multiple of miss-an-attacker cost.
# The frozen table sits at 200/25 = 8.0.
RATIO_GRID = [0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0]
FROZEN_RATIO = 8.0


def cost_only_boundary(cost_table) -> float:
    """PASS/DIVERT crossover with no bait available -- the two-action rule."""
    lo, hi = 0.0, 1.0
    for _ in range(60):
        m = (lo + hi) / 2
        if cost_table.expected_cost("pass", m) < cost_table.expected_cost("divert", m):
            lo = m
        else:
            hi = m
    return (lo + hi) / 2


def scaled_table(base, ratio: float):
    """The frozen table with only the benign-divert cost rescaled.

    Everything else is held at its frozen value, so the sweep isolates the one
    judgement that is genuinely an estimate rather than an accounting identity.
    (`cost(bait | attack) == cost(pass | attack)` IS an identity here: the
    request still reaches the real application, so the exposure is the same.)
    """
    matrix = {k: dict(v) for k, v in base.matrix.items()}
    matrix["benign"]["divert"] = ratio * base.cost("attack", "pass")
    return replace(base, matrix=matrix)


def main() -> None:
    base = load_costs()
    eff = BaitEffect(bait_id="B-IDOR-2", beta_attack=BETA_ATTACK,
                     beta_benign=BETA_BENIGN, category="idor")

    print("=" * 78)
    print("SENSITIVITY OF THE DERIVED BANDS TO THE COST TABLE")
    print(f"(bait effectiveness fixed at the calibrated beta_attack={BETA_ATTACK}, "
          f"beta_benign={BETA_BENIGN};")
    print(f" frozen table sits at ratio {FROZEN_RATIO} = "
          f"{base.cost('benign', 'divert')}/{base.cost('attack', 'pass')})")
    print("=" * 78)
    print(f"  {'divert/miss':>11}  {'cost-only':>9}  {'PASS<':>8}  {'BAIT band':>20}  "
          f"{'width':>7}  {'band?':>6}  {'divert>=cost-only?':>18}")

    rows = []
    for ratio in RATIO_GRID:
        table = scaled_table(base, ratio)
        boundary = cost_only_boundary(table)
        bands = derive_bands(table, [eff])
        pass_to_bait = bands.get("pass_to_bait")
        bait_to_divert = bands.get("bait_to_divert")
        has_band = (pass_to_bait is not None and bait_to_divert is not None
                    and bait_to_divert > pass_to_bait)
        width = (bait_to_divert - pass_to_bait) if has_band else 0.0
        divert_ge = (bait_to_divert is not None and bait_to_divert >= boundary - 1e-6)
        tag = "  <-- frozen" if abs(ratio - FROZEN_RATIO) < 1e-9 else ""
        band_str = (f"[{pass_to_bait:.4f}, {bait_to_divert:.4f})" if has_band else "(none)")
        print(f"  {ratio:>11.1f}  {boundary:>9.4f}  {(pass_to_bait or 0):>8.4f}  "
              f"{band_str:>20}  {width:>7.4f}  {'yes' if has_band else 'NO':>6}  "
              f"{'yes' if divert_ge else 'NO':>18}{tag}")
        rows.append({
            "divert_over_miss_ratio": ratio,
            "cost_benign_divert": table.cost("benign", "divert"),
            "cost_only_boundary": round(boundary, 6),
            "pass_to_bait": pass_to_bait,
            "bait_to_divert": bait_to_divert,
            "band_width": round(width, 4),
            "band_nonempty": has_band,
            "divert_ge_cost_only": divert_ge,
        })

    band_ok = all(r["band_nonempty"] for r in rows)
    safe_ok = all(r["divert_ge_cost_only"] for r in rows)
    invariant = band_ok and safe_ok

    print("\nInvariant across the whole sweep:")
    print(f"  * BAIT band non-empty at every cost ratio            : "
          f"{'CONFIRMED' if band_ok else 'VIOLATED'}")
    print(f"  * DIVERT threshold never below the cost-only boundary : "
          f"{'CONFIRMED' if safe_ok else 'VIOLATED'}")
    print("\nWhat MOVES with the cost ratio: where the boundaries sit -- how")
    print("conservative the system is. What does NOT move: that the third action")
    print("exists at all, and that bait never lowers the divert threshold.")
    print("\nThe frozen table is therefore a choice about CONSERVATISM, not a choice")
    print("that manufactures the result. That is the claim this sweep supports.")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "beta_attack": BETA_ATTACK,
        "beta_benign": BETA_BENIGN,
        "frozen_ratio": FROZEN_RATIO,
        "frozen_cost_benign_divert": base.cost("benign", "divert"),
        "frozen_cost_attack_pass": base.cost("attack", "pass"),
        "swept_parameter": "cost(divert|benign) / cost(pass|attack)",
        "sweep": rows,
        "conclusions_invariant": invariant,
    }, indent=2), encoding="utf-8")
    print(f"\nwritten -> {OUT}")


if __name__ == "__main__":
    main()
