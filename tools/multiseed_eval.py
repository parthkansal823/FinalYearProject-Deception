"""
Multi-seed evaluation (statistical-power upgrade to Phase 7).

The single-seed run in `tools/run_evaluation.py` reports one draw of the round-2
traffic per arm. A reviewer correctly objects that recall 0.87 -> 0.90 on n=120
is a single sample with wide, overlapping confidence intervals. This driver
re-runs the SAME frozen model against K independent seeded traffic draws per arm,
dumping one row per session so that `tools/stats_report.py` can compute pooled
Wilson intervals and PAIRED significance tests (McNemar) that exploit the fact
that, for a given seed, every arm sees byte-identical traffic.

It does not retrain or refreeze anything: the model is frozen once (spec §7.2),
and only the evaluation *traffic seed* varies. That is exactly the quantity whose
sampling variability the reviewer asked us to characterise.

Pairing. Within one seed the traffic is generated in a fixed order, so attack
session i under B2 is the same attacker (same sub-seed, same subcategory) as
attack session i under B4. We recover i from the label file's order and tag every
session with (arm, seed, stream, index). `stats_report.py` pairs on
(seed, stream, index), which is robust even if session ids were to differ.

    python -m tools.multiseed_eval --seeds 20 --attack 120 --benign 80
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

from adf.config import system
from adf.freeze import require_frozen

# B0 is omitted from the seed sweep: with no scoring its recall is identically 0
# and its cost identically the pass-everything constant, so extra draws add no
# information. It is reported as an analytical reference row instead.
DEFAULT_ARMS = ["b1_rules", "b2_passive", "b4_full"]

OUT_DIR = Path("data/eval/multiseed")


def _wait(url: str, name: str, tries: int = 80) -> bool:
    for _ in range(tries):
        try:
            httpx.get(url, timeout=1.0)
            return True
        except Exception:
            time.sleep(0.3)
    print(f"  !! {name} did not come up at {url}")
    return False


def _uvicorn(app_path: str, port: int, host: str, env: dict) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", app_path, "--host", host, "--port", str(port),
         "--log-level", "warning"], env=env)


def _order_index(labels_path: str) -> dict:
    """session_id -> (stream, index): the generation order within its stream,
    read straight off the label file (labels are written in generation order).
    This is the stable key we pair arms on."""
    idx: dict[str, tuple[str, int]] = {}
    counters = {"attack": 0, "benign": 0}
    for line in open(labels_path, encoding="utf-8"):
        if not line.strip():
            continue
        e = json.loads(line)
        stream = "attack" if e["ground_truth"] == "attack" else "benign"
        idx[e["session_id"]] = (stream, counters[stream])
        counters[stream] += 1
    return idx


def main() -> None:
    cfg = system()
    ap = argparse.ArgumentParser(description="Multi-seed evaluation (spec §10 + statistical power).")
    ap.add_argument("--seeds", type=int, default=20, help="number of independent traffic draws per arm")
    ap.add_argument("--base-seed", type=int, default=cfg.seed + 100)
    ap.add_argument("--attack", type=int, default=120)
    ap.add_argument("--benign", type=int, default=80)
    ap.add_argument("--arms", default=",".join(DEFAULT_ARMS))
    ap.add_argument("--host", default=cfg.get("network.bind_host", "127.0.0.1"))
    args = ap.parse_args()

    require_frozen()   # spec §7.2 — one frozen model, only the traffic seed varies
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    seeds = [args.base_seed + k for k in range(args.seeds)]

    # import the single-arm traffic + scoring machinery and drive it in-process,
    # so we get the full per-session dict (not just the aggregate JSON).
    from tools.evaluate import _run_traffic, _sessionise

    host = args.host
    tp, dp, pp = (cfg.get("network.target_port", 8001), cfg.get("network.decoy_port", 8002),
                  cfg.get("network.proxy_port", 8000))
    base_env = dict(os.environ)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sessions_path = OUT_DIR / "sessions.jsonl"
    sessions_path.unlink(missing_ok=True)
    dump = open(sessions_path, "w", encoding="utf-8")
    n_written = 0

    print("seeding the target world ...")
    subprocess.run([sys.executable, "-m", "target_app.seed"], env=base_env, check=False)
    print("starting target + decoy (shared across all arms) ...")
    target = _uvicorn("target_app.main:app", tp, host, base_env)
    decoy = _uvicorn("decoy_app.main:app", dp, host, base_env)
    _wait(f"http://{host}:{tp}/healthz", "target")
    _wait(f"http://{host}:{dp}/healthz", "decoy")

    t0 = time.time()
    try:
        for arm in arms:
            print(f"\n{'='*66}\nARM: {arm}   ({len(seeds)} seeds)\n{'='*66}")
            env = dict(base_env, ADF_MODE=arm)
            proxy = _uvicorn("adf.proxy:app", pp, host, env)
            if not _wait(f"http://{host}:{pp}/", "proxy"):
                proxy.terminate()
                continue
            for k, seed in enumerate(seeds):
                # isolate this (arm, seed): wipe labels + proxy log so only this
                # draw's traffic is measured (mirrors tools/evaluate.py).
                Path(cfg.label_dir / "eval_labels.jsonl").unlink(missing_ok=True)
                for f in glob.glob(str(cfg.log_dir / "proxy.*.jsonl")):
                    os.remove(f)

                labels_path = _run_traffic(f"http://{host}:{pp}", args.attack, args.benign, seed)
                time.sleep(0.6)
                order = _order_index(labels_path)
                sessions = _sessionise(str(cfg.log_dir / "proxy.*.jsonl"), labels_path)

                seen = 0
                for sid, s in sessions.items():
                    stream, index = order.get(sid, ("?", -1))
                    dump.write(json.dumps({
                        "arm": arm, "seed": seed, "session_id": sid,
                        "stream": stream, "index": index,
                        "label": s["label"], "category": s["category"],
                        "subcategory": s["subcategory"], "diverted": s["diverted"],
                        "baited": s["baited"], "bit": s["bit"],
                        "assignment": s["assignment"], "reqs_to_divert": s["reqs_to_divert"],
                    }) + "\n")
                    seen += 1
                n_written += seen
                dump.flush()
                atk = [s for s in sessions.values() if s["label"] == "attack"]
                rec = (sum(1 for s in atk if s["diverted"]) / len(atk)) if atk else 0.0
                print(f"  seed {seed} (draw {k+1}/{len(seeds)}): {seen} sessions, "
                      f"attack recall {rec:.3f}   [{time.time()-t0:6.0f}s elapsed]")
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
    finally:
        dump.close()
        for p in (target, decoy):
            p.terminate()
        for p in (target, decoy):
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()

    print(f"\nwrote {n_written} session rows -> {sessions_path}  ({time.time()-t0:.0f}s total)")
    print("now run:  python -m tools.stats_report")


if __name__ == "__main__":
    main()
