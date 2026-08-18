"""Does DERIVING the band edges beat picking them?

This is the ablation for the paper's central claim. The claim is not that a third
action helps; it is that the two edges follow from the frozen cost table and the
calibrated bite rates rather than from anyone's judgement. A reviewer will ask the
obvious question -- "what if I just set 0.05 and 0.88 by hand?" -- and until now
the paper argued the answer instead of showing it.

So this runs the SAME evaluation, on the same frozen model and the same traffic
seeds, with `b5_fixed` arms whose edges are hand-set to a spread of plausible
choices, and compares them against the derived arm on the primary metric: expected
cost per session.

What makes the comparison fair, and what would make it worthless:

  * Fair: the fixed arms share the bait library, the bait-selection logic, the
    holdout and every feature. Only the edges differ.
  * Worthless: scoring bait as cost-minus-EVSI and then overriding the boundary.
    That is the derived policy in a disguise, and it would flatter the ablation.
    `choose_action_fixed` therefore does not subtract the information value.

Read the outcome honestly in either direction. If a hand-set pair matches or beats
the derived edges on expected cost, that is a real negative result about the
contribution and belongs in the paper.

    python -m tools.fixed_threshold_sweep --seeds 20
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

OUT = Path("data/eval/fixed_threshold")

#: Hand-set pairs a reasonable person might choose, spanning the space:
#: cautious (bait late, divert late), eager (bait early, divert early), the
#: cost-only boundary as the divert edge, and a wide "always bait" band.
DEFAULT_GRID = [
    (0.05, 0.95),
    (0.10, 0.90),
    (0.20, 0.80),
    (0.30, 0.70),
    (0.05, 0.8163),   # the cost-only boundary, which is what a careful reader
                      # would pick if they priced costs but not information
]


def main() -> None:
    ap = argparse.ArgumentParser(description="Fixed-threshold ablation sweep.")
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--base-seed", type=int, default=20260913)
    ap.add_argument("--attack", type=int, default=120)
    ap.add_argument("--benign", type=int, default=80)
    ap.add_argument("--port-base", type=int, default=9600)
    ap.add_argument("--grid", default="",
                    help="semicolon-separated lo,hi pairs; empty uses the default grid")
    args = ap.parse_args()

    grid = DEFAULT_GRID
    if args.grid.strip():
        grid = []
        for pair in args.grid.split(";"):
            lo, hi = (float(x) for x in pair.split(","))
            grid.append((lo, hi))

    OUT.mkdir(parents=True, exist_ok=True)
    done = []
    for i, (lo, hi) in enumerate(grid):
        tag = f"{lo:.4f}_{hi:.4f}"
        run_dir = OUT / tag
        port = args.port_base + i * 3
        env = dict(
            os.environ,
            ADF_MODE="b5_fixed",
            ADF_BAIT__FIXED_BANDS=f"{lo},{hi}",
            ADF_NETWORK__PROXY_PORT=str(port),
            ADF_NETWORK__TARGET_PORT=str(port + 1),
            ADF_NETWORK__DECOY_PORT=str(port + 2),
            ADF_LOGGING__LOG_DIR=f"{run_dir}/logs",
            ADF_LOGGING__LABEL_DIR=f"{run_dir}/labels",
            ADF_DATABASES__TARGET_DSN=f"sqlite:///{run_dir}/target.sqlite3",
            ADF_DATABASES__FACT_NOTEBOOK_DSN=f"sqlite:///{run_dir}/notebook.sqlite3",
            PYTHONUNBUFFERED="1",
        )
        print(f"\n=== fixed edges [{lo}, {hi}]  ports {port}-{port+2} ===")
        rc = subprocess.run(
            [sys.executable, "-m", "tools.multiseed_eval",
             "--seeds", str(args.seeds), "--base-seed", str(args.base_seed),
             "--attack", str(args.attack), "--benign", str(args.benign),
             "--arms", "b5_fixed", "--out-dir", str(run_dir)],
            env=env, check=False).returncode
        if rc == 0 and (run_dir / "sessions.jsonl").exists():
            done.append({"lo": lo, "hi": hi, "dump": str(run_dir / "sessions.jsonl")})
        else:
            print(f"  !! [{lo}, {hi}] failed (exit {rc}); omitted rather than "
                  f"carried over from an earlier run")

    if not done:
        raise SystemExit("no fixed-threshold arm completed; nothing to compare")

    (OUT / "arms.json").write_text(json.dumps(done, indent=2), encoding="utf-8")
    print(f"\nwrote {len(done)} arm(s) -> {OUT / 'arms.json'}")
    print("now run:  python -m tools.fixed_threshold_report")


if __name__ == "__main__":
    main()
