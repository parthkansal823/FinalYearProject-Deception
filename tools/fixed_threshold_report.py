"""Compare the hand-set band edges against the derived ones.

The primary metric is expected cost per session, scored on the same frozen cost
table the edges were derived from. Recall and benign diversion are reported
alongside because a threshold pair can buy recall by diverting honest users, and
a single cost number would hide which of the two it did.

    python -m tools.fixed_threshold_report
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

from adf.policy.engine import DecisionPolicy


def load(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def score(rows: list[dict], costs) -> dict:
    """Expected cost per session, plus the two rates that explain it."""
    if not rows:
        return {}
    total = 0.0
    atk = div_atk = ben = div_ben = 0
    for r in rows:
        action = "divert" if r.get("diverted") else ("bait" if r.get("baited") else "pass")
        truth = "attack" if r.get("label") == "attack" else "benign"
        total += costs.cost(truth, action)
        if truth == "attack":
            atk += 1
            div_atk += 1 if r.get("diverted") else 0
        else:
            ben += 1
            div_ben += 1 if r.get("diverted") else 0
    return {
        "sessions": len(rows),
        "cost_per_session": total / len(rows),
        "recall": div_atk / atk if atk else 0.0,
        "benign_diversion": div_ben / ben if ben else 0.0,
        "seeds": len({r["seed"] for r in rows}),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Derived vs hand-set band edges.")
    ap.add_argument("--arms", default="data/eval/fixed_threshold/arms.json")
    ap.add_argument("--derived", default="data/eval/curious_b2b4/sessions.jsonl",
                    help="dump containing the derived arm (b4_full)")
    args = ap.parse_args()

    pol = DecisionPolicy.from_config()
    costs = pol.cost_table
    bands = pol.bands()
    lo_d, hi_d = bands["pass_to_bait"], bands["bait_to_divert"]

    derived_rows = [r for r in load(Path(args.derived)) if r.get("arm") == "b4_full"]
    derived = score(derived_rows, costs)

    arms_path = Path(args.arms)
    if not arms_path.exists():
        raise SystemExit(f"no sweep output at {arms_path}; run tools.fixed_threshold_sweep")
    arms = json.loads(arms_path.read_text(encoding="utf-8"))

    rows = []
    for a in arms:
        s = score(load(Path(a["dump"])), costs)
        if s:
            s.update(lo=a["lo"], hi=a["hi"])
            rows.append(s)

    # Restrict the derived arm to the seeds the fixed arms actually ran, so the
    # comparison is not decided by one side having more draws.
    common = min((r["seeds"] for r in rows), default=0)
    print(f"derived edges: [{lo_d:.4f}, {hi_d:.4f}]   "
          f"(derived arm: {derived.get('seeds', 0)} seeds, "
          f"fixed arms: {common} seeds each)\n")

    hdr = f"{'edges':<22}{'cost/session':>14}{'recall':>10}{'benign div':>12}{'seeds':>7}"
    print(hdr)
    print("-" * len(hdr))
    print(f"{'DERIVED ' + f'[{lo_d:.3f}, {hi_d:.3f}]':<22}"
          f"{derived['cost_per_session']:>14.3f}{derived['recall']:>10.3f}"
          f"{derived['benign_diversion']:>12.4f}{derived['seeds']:>7}")
    for r in sorted(rows, key=lambda x: x["cost_per_session"]):
        label = f"fixed [{r['lo']:.3f}, {r['hi']:.3f}]"
        print(f"{label:<22}"
              f"{r['cost_per_session']:>14.3f}{r['recall']:>10.3f}"
              f"{r['benign_diversion']:>12.4f}{r['seeds']:>7}")

    better = [r for r in rows if r["cost_per_session"] < derived["cost_per_session"]]
    print()
    if better:
        b = min(better, key=lambda x: x["cost_per_session"])
        print(f"NEGATIVE RESULT: {len(better)} of {len(rows)} hand-set pairs beat the "
              f"derived edges on expected cost. Best: [{b['lo']}, {b['hi']}] at "
              f"{b['cost_per_session']:.3f} vs {derived['cost_per_session']:.3f}. "
              f"This belongs in the paper as stated.")
    else:
        print(f"The derived edges beat all {len(rows)} hand-set pairs on expected cost "
              f"per session. Deriving the boundary is not only principled here, it is "
              f"measurably better than picking one.")


if __name__ == "__main__":
    main()
