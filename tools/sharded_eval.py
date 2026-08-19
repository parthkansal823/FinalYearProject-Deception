"""Run the multi-seed evaluation as concurrent shards over disjoint seed ranges.

A draw is serial by construction -- the generator sends one request, the proxy
scores it, the target answers -- so a single draw keeps roughly one core busy and
leaves the rest of a 16-core machine idle. Splitting the seed range across shards
turns a 6.6-hour run into well under an hour without changing a single number:
pairing in `stats_report` is on (seed, stream, index), the seed ranges are disjoint,
and every shard runs the same frozen model.

What makes this safe, and what would make it worthless:

  * Each shard gets its own ports, log directory, label directory and databases.
    Sharing any of those is what broke the first attempt at this: `multiseed_eval`
    wipes the label file between draws, so two shards sharing a label directory
    delete each other's ground truth and every draw joins zero sessions.
  * `merge_shards` refuses to merge overlapping seed ranges, so a mistake in the
    split fails loudly instead of double-counting sessions.
  * Oversubscribing is the real risk, and it is not a slow-run risk -- it is a
    wrong-answer risk. Under contention a draw times out, and a lost draw looks
    exactly like a draw with no detections. `multiseed_eval` retries three times
    and writes `short_draws.json`, which is the backstop; the default shard count
    here is the physical core count, not the logical one, to stay well inside it.

    python -m tools.sharded_eval --tag curious_v2 --seeds 99 --shards 16
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("data/eval")

#: Clear of every other range this project uses: 9600 ablation, 9700 calibration,
#: 9760-9761 the CRS replay, 9780-9800 undefended draws, 9820 a single main run.
PORT_BASE = 10000


def physical_cores() -> int:
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_Processor | "
             "Measure-Object -Sum NumberOfCores).Sum"],
            capture_output=True, text=True, timeout=30).stdout.strip()
        return max(1, int(out))
    except (OSError, ValueError, subprocess.SubprocessError):
        return max(1, (os.cpu_count() or 2) // 2)


def main() -> None:
    cores = physical_cores()
    ap = argparse.ArgumentParser(description="Sharded multi-seed evaluation.")
    ap.add_argument("--tag", required=True, help="output goes to data/eval/<tag>/shard*/")
    ap.add_argument("--seeds", type=int, default=99)
    ap.add_argument("--base-seed", type=int, default=20260913)
    ap.add_argument("--attack", type=int, default=120)
    ap.add_argument("--benign", type=int, default=80)
    ap.add_argument("--arms", default="b1_rules,b2_passive,b4_full")
    ap.add_argument("--shards", type=int, default=cores)
    ap.add_argument("--port-base", type=int, default=PORT_BASE)
    args = ap.parse_args()

    if args.shards > cores:
        print("note: %d shards on %d physical cores oversubscribes the machine. "
              "Draws that time out are retried, but a run that keeps timing out "
              "wastes more time than the extra shards save."
              % (args.shards, cores))

    root = ROOT / args.tag
    if (root / "sessions.jsonl").exists():
        raise SystemExit(
            str(root / "sessions.jsonl") + " already exists. Merging into a "
            "directory that already holds a merged dump would leave a file that "
            "looks current and mixes two runs; move it aside first.")

    # Blocks must be CONTIGUOUS, because `multiseed_eval` takes a base seed and a
    # count and generates the run of seeds from there. Round-robin blocks would be
    # balanced but would make every shard run base..base+n-1 instead of the seeds
    # it was assigned, so the shards would overlap almost completely. merge_shards
    # would catch that, but only after the whole run had finished.
    seeds = [args.base_seed + k for k in range(args.seeds)]
    n_shards = min(args.shards, len(seeds))
    per = len(seeds) // n_shards
    extra = len(seeds) % n_shards
    blocks: list[list[int]] = []
    start = 0
    for i in range(n_shards):
        size = per + (1 if i < extra else 0)
        blocks.append(seeds[start:start + size])
        start += size
    assert sum(len(b) for b in blocks) == len(seeds)
    assert len({s for b in blocks for s in b}) == len(seeds), "shards overlap"

    print("tag    %s" % args.tag)
    print("seeds  %d across %d shard(s), %d physical cores"
          % (len(seeds), len(blocks), cores))
    print("arms   %s" % args.arms)
    print()

    procs = []
    for i, block in enumerate(blocks):
        d = root / ("shard%02d" % i)
        d.mkdir(parents=True, exist_ok=True)
        port = args.port_base + i * 3
        env = dict(
            os.environ,
            ADF_NETWORK__PROXY_PORT=str(port),
            ADF_NETWORK__TARGET_PORT=str(port + 1),
            ADF_NETWORK__DECOY_PORT=str(port + 2),
            ADF_LOGGING__LOG_DIR=f"{d}/logs",
            ADF_LOGGING__LABEL_DIR=f"{d}/labels",
            ADF_DATABASES__TARGET_DSN=f"sqlite:///{d}/target.sqlite3",
            ADF_DATABASES__FACT_NOTEBOOK_DSN=f"sqlite:///{d}/notebook.sqlite3",
            PYTHONUNBUFFERED="1",
        )
        assert block == list(range(block[0], block[0] + len(block))), (
            "shard %d's seeds are not contiguous; multiseed_eval would run a "
            "different range from the one assigned" % i)
        log = (d / "shard.log").open("w", encoding="utf-8")
        cmd = [sys.executable, "-m", "tools.multiseed_eval",
               "--seeds", str(len(block)), "--base-seed", str(block[0]),
               "--attack", str(args.attack), "--benign", str(args.benign),
               "--arms", args.arms, "--out-dir", str(d)]
        procs.append((i, block, subprocess.Popen(cmd, env=env, stdout=log,
                                                 stderr=subprocess.STDOUT), log))
        print("  shard%02d  seeds %d..%d  ports %d-%d"
              % (i, block[0], block[-1], port, port + 2))

    print("\nall shards launched; waiting ...", flush=True)
    t0 = time.time()
    failed = []
    for i, block, p, log in procs:
        rc = p.wait()
        log.close()
        mark = "ok" if rc == 0 else "FAILED (exit %d)" % rc
        print("  shard%02d %s   [%.0f min elapsed]"
              % (i, mark, (time.time() - t0) / 60), flush=True)
        if rc != 0:
            failed.append(i)

    if failed:
        print("\n%d shard(s) failed: %s" % (len(failed), failed))
        print("Their seeds are simply absent from the merge, which makes the run")
        print("smaller rather than wrong -- but check data/eval/%s/shard*/shard.log"
              % args.tag)
        print("before reporting, and re-run the failed shards to get them back.")

    short = list(root.glob("shard*/short_draws.json"))
    if short:
        print("\n!! %d shard(s) recorded short draws:" % len(short))
        for s in short:
            print("   " + str(s))
        print("   A short draw lost sessions mid-flight. Read these before")
        print("   trusting any pooled proportion from this run.")

    print()
    rc = subprocess.run([sys.executable, "-m", "tools.merge_shards",
                         "--tag", args.tag]).returncode
    raise SystemExit(rc or (1 if failed or short else 0))


if __name__ == "__main__":
    main()
