"""Generate a calibration split that the evaluation never sees.

The suspicion meter's weights were set by hand, not fitted, so nothing has ever
checked whether its output behaves like a probability. The decision rule consumes
it as one: every band edge is a probability threshold derived from the cost table.
If the belief is not calibrated, those edges do not land where the derivation
intends, and the whole rule is being judged on an input it was never given.

Measuring that needs labelled scores from traffic the evaluation does not use.
The eval draws run on seeds 20260913 and upward; these run far away from that
range, so nothing fitted here can leak into a reported result.

Each draw goes to its own directory because `multiseed_eval` wipes the proxy log
between draws -- only the last one survives per directory, and one draw is a thin
basis for a fit.

    python -m tools.calibration_split --draws 4
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

OUT = Path("data/eval/calibration")

#: Deliberately far from the evaluation seeds (20260913-20261012). A fit made on
#: eval traffic and then reported on eval traffic is a fit on the test set.
BASE_SEED = 20250401


def main() -> None:
    ap = argparse.ArgumentParser(description="Held-out calibration split.")
    ap.add_argument("--draws", type=int, default=4)
    ap.add_argument("--attack", type=int, default=120)
    ap.add_argument("--benign", type=int, default=80)
    ap.add_argument("--base-seed", type=int, default=BASE_SEED)
    ap.add_argument("--port-base", type=int, default=9700)
    args = ap.parse_args()

    if args.base_seed + args.draws > 20260913:
        raise SystemExit(
            "calibration seeds would overlap the evaluation range starting at "
            "20260913. Fitting on evaluation traffic and then reporting on it is "
            "fitting on the test set; pick a lower --base-seed.")

    OUT.mkdir(parents=True, exist_ok=True)
    ok = 0
    for k in range(args.draws):
        seed = args.base_seed + k
        run_dir = OUT / f"s{k + 1}"
        port = args.port_base + k * 3
        env = dict(
            os.environ,
            ADF_MODE="b4_full",
            ADF_NETWORK__PROXY_PORT=str(port),
            ADF_NETWORK__TARGET_PORT=str(port + 1),
            ADF_NETWORK__DECOY_PORT=str(port + 2),
            ADF_LOGGING__LOG_DIR=f"{run_dir}/logs",
            ADF_LOGGING__LABEL_DIR=f"{run_dir}/labels",
            ADF_DATABASES__TARGET_DSN=f"sqlite:///{run_dir}/target.sqlite3",
            ADF_DATABASES__FACT_NOTEBOOK_DSN=f"sqlite:///{run_dir}/notebook.sqlite3",
            PYTHONUNBUFFERED="1",
        )
        print(f"\n=== calibration draw {k + 1}/{args.draws}  seed {seed}  "
              f"ports {port}-{port + 2} ===")
        rc = subprocess.run(
            [sys.executable, "-m", "tools.multiseed_eval",
             "--seeds", "1", "--base-seed", str(seed),
             "--attack", str(args.attack), "--benign", str(args.benign),
             "--arms", "b4_full", "--out-dir", str(run_dir)],
            env=env, check=False).returncode
        if rc == 0 and (run_dir / "sessions.jsonl").exists():
            ok += 1
        else:
            print(f"  !! draw {seed} failed (exit {rc}); omitted rather than "
                  f"silently counted")

    if not ok:
        raise SystemExit("no calibration draw completed; nothing to fit on")
    print(f"\n{ok}/{args.draws} draws written under {OUT}")
    print("now run:  python -m tools.fit_calibration")


if __name__ == "__main__":
    main()
