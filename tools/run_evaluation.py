"""
Phase 7 driver — run every baseline arm on identical traffic (spec §10, §13).

Brings up target + decoy once, then for each mode restarts ONLY the proxy in
that mode and replays the same seeded round-2 + benign traffic through it
(tools/evaluate.py). Because the traffic is seeded, every arm sees byte-identical
input; the only thing that changes is the mode. Finally it prints the comparison
table that is the paper's results section.

Arms run (each differs in DETECTION behaviour):
  b0_no_defence  — proxy forwards, no scoring. The ceiling on attacker success.
  b1_rules       — a signature WAF (adf/proxy/rules.py). What a conventional
                   off-the-shelf defence achieves; brittle to obfuscation and
                   blind to IDOR (no signature for accessing an object by id).
  b2_passive     — full scoring, no bait, no decoy. The honest baseline to beat.
  b4_full        — bait + dual meter + cost policy + decoy. The contribution.

Not a separate DETECTION arm, and why:
  b3_static — passive scoring + static decoy. Its DETECTION is identical to b2
              (the decoy only matters after a divert); the decoy's quality is
              measured separately by the contradiction rate, not here.

The model must be frozen before this runs (spec §7.2); evaluate.py enforces it.

    python -m tools.run_evaluation --attack 48 --benign 60
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

from adf.config import system

ARMS = ["b0_no_defence", "b1_rules", "b2_passive", "b4_full"]


def _wait(url: str, name: str, tries: int = 60) -> bool:
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


def main() -> None:
    cfg = system()
    ap = argparse.ArgumentParser(description="Phase 7 driver — all baseline arms (spec §10).")
    ap.add_argument("--attack", type=int, default=48)
    ap.add_argument("--benign", type=int, default=60)
    ap.add_argument("--seed", type=int, default=cfg.seed + 7)
    ap.add_argument("--host", default=cfg.get("network.bind_host", "127.0.0.1"))
    args = ap.parse_args()

    host = args.host
    tp, dp, pp = (cfg.get("network.target_port", 8001), cfg.get("network.decoy_port", 8002),
                  cfg.get("network.proxy_port", 8000))
    base_env = dict(os.environ)

    print("seeding the target world ...")
    subprocess.run([sys.executable, "-m", "target_app.seed"], env=base_env, check=False)

    print("starting target + decoy (shared across all arms) ...")
    target = _uvicorn("target_app.main:app", tp, host, base_env)
    decoy = _uvicorn("decoy_app.main:app", dp, host, base_env)
    _wait(f"http://{host}:{tp}/healthz", "target")
    _wait(f"http://{host}:{dp}/healthz", "decoy")

    results = {}
    try:
        for mode in ARMS:
            print(f"\n{'='*60}\nARM: {mode}\n{'='*60}")
            env = dict(base_env, ADF_MODE=mode)
            proxy = _uvicorn("adf.proxy:app", pp, host, env)
            if not _wait(f"http://{host}:{pp}/", "proxy"):
                proxy.terminate()
                continue
            out = f"data/eval/{mode}.json"
            subprocess.run(
                [sys.executable, "-m", "tools.evaluate", "--mode", mode, "--out", out,
                 "--attack", str(args.attack), "--benign", str(args.benign),
                 "--seed", str(args.seed), "--proxy", f"http://{host}:{pp}"],
                env=env, check=False)
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
            if Path(out).exists():
                results[mode] = json.loads(Path(out).read_text(encoding="utf-8"))
            time.sleep(1.0)
    finally:
        for p in (target, decoy):
            p.terminate()
        for p in (target, decoy):
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()

    _print_table(results)
    Path("data/eval/summary.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("\nsummary -> data/eval/summary.json")


def _print_table(results: dict) -> None:
    print(f"\n{'='*78}\nPHASE 7 RESULTS — baselines on identical round-2 traffic\n{'='*78}")
    cols = [("recall", "recall"), ("precision", "precision"), ("f1", "F1"),
            ("median_requests_to_decision", "req-decide"),
            ("benign_diversion_rate", "benign-divert"),
            ("benign_bait_exposure_rate", "benign-bait"),
            ("expected_cost_per_session", "E[cost]/sess")]
    header = f"{'arm':>14}" + "".join(f"{label:>14}" for _, label in cols)
    print(header)
    for mode in ARMS:
        if mode not in results:
            continue
        m = results[mode]
        row = f"{mode:>14}"
        for key, _ in cols:
            v = m.get(key)
            row += f"{('' if v is None else v):>14}"
        print(row)

    if "b4_full" in results:
        h = results["b4_full"]["holdout"]
        print("\nRandomised holdout (b4, causal effect of bait on requests-to-decision):")
        print(f"  baited arm : n={h['baited_arm_n']:>3}  divert_rate={h['baited_divert_rate']}  "
              f"median req-decide={h['baited_median_r2d']}")
        print(f"  holdout arm: n={h['holdout_arm_n']:>3}  divert_rate={h['holdout_divert_rate']}  "
              f"median req-decide={h['holdout_median_r2d']}")

    if {"b2_passive", "b4_full"} <= set(results):
        b2, b4 = results["b2_passive"], results["b4_full"]
        print("\nHeadline comparison (the two that carry the paper):")
        print(f"  recall               B2 {b2['recall']:.2f}  ->  B4 {b4['recall']:.2f}")
        print(f"  median req-decide    B2 {b2['median_requests_to_decision']}  ->  "
              f"B4 {b4['median_requests_to_decision']}")
        print(f"  benign diversion     B2 {b2['benign_diversion_rate']}  ->  B4 {b4['benign_diversion_rate']}  "
              f"(NFR-05 target 0)")


if __name__ == "__main__":
    main()
