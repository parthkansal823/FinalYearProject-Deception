"""Run the fixed-threshold ablation arms concurrently instead of one after another.

`fixed_threshold_sweep` runs its arms in sequence, which on this corpus is about
2.7 hours for six arms. The arms are completely independent -- different edges,
different directories, different ports, the same frozen model and the same seeds --
so there is nothing to serialise except the machine.

A draw is latency-bound rather than CPU-bound: the generator sends one request and
waits for it. Measured on the main evaluation, sixteen concurrent shards gave 7.4x
aggregate throughput rather than 16x, so running six arms at once should recover
most of what is available here without oversubscribing.

Output goes to a separate root by default, so the ablation the paper currently
cites is not overwritten while its replacement is still being measured.

    python -m tools.parallel_ablation --grid "0.05,0.95;0.20,0.80;0.1867,0.6186"
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_GRID = "0.05,0.95;0.10,0.90;0.20,0.80;0.30,0.70;0.05,0.8163"
PORT_BASE = 10100


def main() -> None:
    ap = argparse.ArgumentParser(description="Concurrent fixed-threshold ablation.")
    ap.add_argument("--out", default="data/eval/fixed_threshold_v2")
    ap.add_argument("--grid", default=DEFAULT_GRID,
                    help="semicolon-separated lo,hi pairs")
    ap.add_argument("--calibrated", default="data/eval/calibration/calibration.json",
                    help="append the calibrated-equivalent edges from this fit; "
                         "pass an empty string to omit that arm")
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--base-seed", type=int, default=20260913)
    ap.add_argument("--attack", type=int, default=120)
    ap.add_argument("--benign", type=int, default=80)
    ap.add_argument("--port-base", type=int, default=PORT_BASE)
    args = ap.parse_args()

    grid = []
    for pair in args.grid.split(";"):
        if pair.strip():
            lo, hi = (float(x) for x in pair.split(","))
            grid.append((lo, hi))

    if args.calibrated:
        try:
            cal = json.loads(Path(args.calibrated).read_text(encoding="utf-8"))
            e = cal["equivalent_raw_edges"]
            pair = (round(e["pass_to_bait"], 4), round(e["bait_to_divert"], 4))
            if pair in grid:
                print("calibrated arm %s already in the grid" % (pair,))
            else:
                grid.append(pair)
                print("calibrated-equivalent edges from %s: %.4f, %.4f"
                      % (cal.get("selected", "?"), pair[0], pair[1]))
        except (OSError, ValueError, KeyError) as exc:
            # Running five honest arms beats six with one silently carrying edges
            # from a fit that no longer matches the corpus.
            raise SystemExit(
                "could not read calibrated edges from " + args.calibrated + ": "
                + str(exc) + "\nRun tools.fit_calibration first, or pass "
                "--calibrated '' to omit that arm deliberately.")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    print("\n%d arm(s), %d seeds each, into %s\n" % (len(grid), args.seeds, out))

    procs = []
    for i, (lo, hi) in enumerate(grid):
        tag = "%.4f_%.4f" % (lo, hi)
        d = out / tag
        d.mkdir(parents=True, exist_ok=True)
        port = args.port_base + i * 3
        env = dict(
            os.environ,
            ADF_MODE="b5_fixed",
            ADF_BAIT__FIXED_BANDS=f"{lo},{hi}",
            ADF_NETWORK__PROXY_PORT=str(port),
            ADF_NETWORK__TARGET_PORT=str(port + 1),
            ADF_NETWORK__DECOY_PORT=str(port + 2),
            ADF_LOGGING__LOG_DIR=f"{d}/logs",
            ADF_LOGGING__LABEL_DIR=f"{d}/labels",
            ADF_DATABASES__TARGET_DSN=f"sqlite:///{d}/target.sqlite3",
            ADF_DATABASES__FACT_NOTEBOOK_DSN=f"sqlite:///{d}/notebook.sqlite3",
            PYTHONUNBUFFERED="1",
        )
        log = (d / "arm.log").open("w", encoding="utf-8")
        cmd = [sys.executable, "-m", "tools.multiseed_eval",
               "--seeds", str(args.seeds), "--base-seed", str(args.base_seed),
               "--attack", str(args.attack), "--benign", str(args.benign),
               "--arms", "b5_fixed", "--out-dir", str(d)]
        procs.append((tag, lo, hi, subprocess.Popen(cmd, env=env, stdout=log,
                                                    stderr=subprocess.STDOUT), log, d))
        print("  [%.4f, %.4f]  ports %d-%d" % (lo, hi, port, port + 2))

    print("\nall arms launched; waiting ...", flush=True)
    t0 = time.time()
    done, failed = [], []
    for tag, lo, hi, p, log, d in procs:
        rc = p.wait()
        log.close()
        dump = d / "sessions.jsonl"
        ok = rc == 0 and dump.exists() and dump.stat().st_size > 0
        print("  [%.4f, %.4f] %-16s [%.0f min]"
              % (lo, hi, "ok" if ok else "FAILED (exit %d)" % rc,
                 (time.time() - t0) / 60), flush=True)
        if ok:
            done.append({"lo": lo, "hi": hi, "dump": str(dump)})
        else:
            failed.append(tag)

    if not done:
        raise SystemExit("no arm completed; nothing to compare")

    from tools.fixed_threshold_sweep import merge_index
    index = out / "arms.json"
    merged, carried = merge_index(index, done)
    index.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    print("\nwrote %d arm(s), carried over %d -> %s" % (len(done), carried, index))

    short = list(out.glob("*/short_draws.json"))
    if short:
        print("\n!! short draws recorded in %d arm(s):" % len(short))
        for s in short:
            print("   " + str(s))
        print("   A short draw lost sessions mid-flight; read these before")
        print("   trusting any pooled proportion from this run.")

    if failed:
        print("\n%d arm(s) failed and are absent from arms.json: %s"
              % (len(failed), ", ".join(failed)))
        raise SystemExit(1)
    if short:
        raise SystemExit(1)
    print("\nnow run:  python -m tools.calibration_report --fixed %s" % out)


if __name__ == "__main__":
    main()
