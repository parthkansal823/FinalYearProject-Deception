"""Regenerate every measurement under the browser-driven adversary.

The round-2 attacker never fetched a page sub-resource. The benign generator
always did, and its own comment calls that "the strongest single automation
signal in the whole feature set". So no attack session in the corpus fetched an
asset and 96.5% of human-paced benign ones did, and a classifier fitted on the
automation features separated the classes at AUC 0.9935 without learning anything
about hostility.

The shipped system was never fooled by it -- automation carries weight zero in the
belief, verified against 12,954 logged requests -- but the corpus was easier than
reality. A great deal of current tooling drives a real browser, and a browser
fetches sub-resources whatever the person at the keyboard intends.

`attack_traffic_round2` now draws a browser-driven fraction per session, so the
traffic differs from every traffic these numbers were measured on. A five-seed
check said the corpus gets harder and the contribution gets larger:

    B2 recall   0.918 -> 0.885
    B4 recall   0.962 -> 0.938
    B4 - B2     +0.043 -> +0.053
    benign diverted   0/400 -> 0/400

which is the right direction to be wrong in, and the reason for re-running rather
than caveating.

Everything runs to fresh directories. Nothing overwrites a result that the paper
currently cites, so the old and new numbers can be compared rather than swapped.

    python -m tools.rerun_all
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("data/eval")


def run(label: str, cmd: list[str], env: dict | None = None,
        log: Path | None = None) -> int:
    print("\n" + "=" * 70)
    print(label)
    print("=" * 70, flush=True)
    t0 = time.time()
    if log is not None:
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("w", encoding="utf-8") as fh:
            rc = subprocess.run(cmd, env=env, stdout=fh,
                                stderr=subprocess.STDOUT).returncode
    else:
        rc = subprocess.run(cmd, env=env).returncode
    print("  -> exit %d after %.0f min" % (rc, (time.time() - t0) / 60), flush=True)
    return rc


def draw_env(run_dir: Path, port: int, mode: str) -> dict:
    return dict(
        os.environ,
        ADF_MODE=mode,
        ADF_NETWORK__PROXY_PORT=str(port),
        ADF_NETWORK__TARGET_PORT=str(port + 1),
        ADF_NETWORK__DECOY_PORT=str(port + 2),
        ADF_LOGGING__LOG_DIR=f"{run_dir}/logs",
        ADF_LOGGING__LABEL_DIR=f"{run_dir}/labels",
        ADF_DATABASES__TARGET_DSN=f"sqlite:///{run_dir}/target.sqlite3",
        ADF_DATABASES__FACT_NOTEBOOK_DSN=f"sqlite:///{run_dir}/notebook.sqlite3",
        PYTHONUNBUFFERED="1",
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Full re-measurement under the new adversary.")
    ap.add_argument("--seeds", type=int, default=99, help="seeds for the main evaluation")
    ap.add_argument("--ablation-seeds", type=int, default=20)
    ap.add_argument("--skip", default="", help="comma-separated stage names to skip")
    args = ap.parse_args()
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    failed: list[str] = []

    # --- 1. calibration split, on seeds the evaluation never uses ------------
    if "calibration" not in skip:
        rc = run("1/5  calibration split (4 draws, held out by seed range)",
                 [sys.executable, "-m", "tools.calibration_split",
                  "--draws", "4", "--port-base", "9700"],
                 log=ROOT / "rerun" / "calibration.log")
        if rc:
            failed.append("calibration split")

    # --- 2. undefended traffic for the WAF replay ---------------------------
    if "waf" not in skip:
        ok = 0
        for k in range(1, 4):
            d = ROOT / "waf_v2" / f"s{k}"
            d.mkdir(parents=True, exist_ok=True)
            rc = run(f"2/5  undefended draw {k}/3 (for the OWASP CRS replay)",
                     [sys.executable, "-m", "tools.multiseed_eval",
                      "--seeds", "1", "--base-seed", str(20260912 + k),
                      "--attack", "120", "--benign", "80",
                      "--arms", "b0_no_defence", "--out-dir", str(d)],
                     # 9850+ deliberately: the CRS replay setup occupies 9760
                     # (dummy backend) and 9761 (container), and an earlier
                     # version of this line started at 9760 and lost its first
                     # draw to the collision.
                     env=draw_env(d, 9840 + k * 10, "b0_no_defence"),
                     log=ROOT / "rerun" / f"waf_s{k}.log")
            ok += rc == 0
        if ok < 3:
            failed.append(f"undefended draws ({ok}/3)")

    # --- 3. the main evaluation ---------------------------------------------
    if "main" not in skip:
        d = ROOT / "curious_v2"
        d.mkdir(parents=True, exist_ok=True)
        rc = run(f"3/5  main evaluation, {args.seeds} seeds x 3 arms  (the long one)",
                 [sys.executable, "-m", "tools.multiseed_eval",
                  "--seeds", str(args.seeds), "--base-seed", "20260913",
                  "--attack", "120", "--benign", "80",
                  "--arms", "b1_rules,b2_passive,b4_full", "--out-dir", str(d)],
                 env=draw_env(d, 9820, "b4_full"),
                 log=ROOT / "rerun" / "main.log")
        if rc:
            failed.append("main evaluation")

    # --- 4. refit the calibration map on the new corpus ----------------------
    # The map is a property of the belief, and the belief now sees different
    # traffic. Reusing the old fit would apply a map estimated on one corpus to
    # another, which is the same error as fitting on the evaluation.
    if "fit" not in skip:
        rc = run("4/5  refit the calibration map on the new corpus",
                 [sys.executable, "-m", "tools.fit_calibration"],
                 log=ROOT / "rerun" / "fit.log")
        if rc:
            failed.append("calibration fit")

    # --- 5. the ablation, including the recalibrated arm ---------------------
    if "ablation" not in skip:
        grid = "0.05,0.95;0.10,0.90;0.20,0.80;0.30,0.70;0.05,0.8163"
        try:
            import json
            cal = json.loads((ROOT / "calibration" / "calibration.json")
                             .read_text(encoding="utf-8"))
            e = cal["equivalent_raw_edges"]
            grid += ";%.4f,%.4f" % (e["pass_to_bait"], e["bait_to_divert"])
            print("\ncalibrated-equivalent edges from the new fit: %.4f, %.4f"
                  % (e["pass_to_bait"], e["bait_to_divert"]))
        except (OSError, ValueError, KeyError) as exc:
            # Better to run five honest arms than six with one silently carrying
            # edges derived from a corpus that no longer exists.
            print("\ncalibrated arm omitted: %s" % exc)
            failed.append("calibrated arm edges unavailable")

        rc = run(f"5/5  fixed-threshold ablation, {args.ablation_seeds} seeds",
                 [sys.executable, "-m", "tools.fixed_threshold_sweep",
                  "--seeds", str(args.ablation_seeds), "--port-base", "9600",
                  "--grid", grid],
                 log=ROOT / "rerun" / "ablation.log")
        if rc:
            failed.append("ablation")

    print("\n" + "=" * 70)
    if failed:
        print("FINISHED WITH FAILURES: " + "; ".join(failed))
        print("Read the stage logs under " + str(ROOT / "rerun") + " before")
        print("reporting anything from this run. A stage that failed leaves the")
        print("previous run's numbers on disk, which look completely normal.")
        raise SystemExit(1)
    print("all stages completed. Now:")
    print("  python -m tools.calibration_report")
    print("  python -m tools.waf_sweep --runs 'data/eval/waf_v2/s*'")
    print("  python -m tools.stats_report --in data/eval/curious_v2/sessions.jsonl")


if __name__ == "__main__":
    main()
