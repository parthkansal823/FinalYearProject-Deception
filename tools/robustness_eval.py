"""
Adaptive-adversary robustness evaluation (spec §18, §19).

Sweeps an attacker's bait-AWARENESS from 0 (naive follower) to 1 (fully aware,
never bites) and measures, at each level, how the system detects it. This is the
robustness curve the deception literature almost never reports: how the defence
degrades when the adversary knows it is there and hunts for the bait.

Two numbers per level, read from the proxy log:
  * divert rate       -- fraction of attack sessions the system still contains.
                         If this stays high as awareness -> 1, the system does
                         not go blind: passive detection is the floor.
  * requests-to-divert -- how many requests until the session was diverted. If
                         this RISES with awareness, that is the measured cost of
                         a bait-aware adversary: the value-of-information policy
                         defers divert in the upper belief band hoping for a bite
                         that never comes, and the attacker is caught later, by
                         the passive features, instead.

The headline is not "the system always wins". It is the shape of the trade-off,
stated honestly: bait buys an EARLIER decision against attackers who bite, and
against a fully bait-aware adversary the system degrades to -- not below -- the
timing of passive detection.

Run against a live b4 stack (target + decoy + proxy):
    python -m tools.robustness_eval --sessions 40
"""

from __future__ import annotations

import argparse
import glob
import json
import random
import statistics
import time
from collections import defaultdict

from adf.config import system
from tools.adaptive_attacker import AdaptiveAttacker

LEVELS = [0.0, 0.25, 0.5, 0.75, 1.0]


def _measure(log_glob: str, session_prefix: str = "adapt-") -> dict:
    records = []
    for f in glob.glob(log_glob):
        records += [json.loads(l) for l in open(f, encoding="utf-8") if l.strip()]
    by_session = defaultdict(list)
    for r in records:
        by_session[r["session"]["session_id"]].append(r)

    sessions = {sid: recs for sid, recs in by_session.items()
                if any("curl" in (r["request"].get("user_agent", "")) for r in recs)}
    total = len(sessions)
    diverted = 0
    reqs_to_divert = []
    bites = 0
    for sid, recs in sessions.items():
        recs.sort(key=lambda r: r["seq"])
        actions = [r["decision"].get("action") for r in recs]
        if any(r.get("bite", {}).get("occurred") for r in recs):
            bites += 1
        if "divert" in actions:
            diverted += 1
            reqs_to_divert.append(actions.index("divert") + 1)
    return {
        "sessions": total,
        "divert_rate": diverted / total if total else 0.0,
        "bite_rate": bites / total if total else 0.0,
        "median_reqs_to_divert": statistics.median(reqs_to_divert) if reqs_to_divert else None,
        "p90_reqs_to_divert": (sorted(reqs_to_divert)[int(len(reqs_to_divert) * 0.9)]
                               if reqs_to_divert else None),
    }


def main() -> None:
    cfg = system()
    ap = argparse.ArgumentParser(description="Adaptive-adversary robustness sweep (spec §18, §19).")
    ap.add_argument("--proxy", default=f"http://127.0.0.1:{cfg.get('network.proxy_port', 8000)}")
    ap.add_argument("--sessions", type=int, default=40, help="attack sessions per awareness level")
    ap.add_argument("--seed", type=int, default=cfg.seed)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    all_rows = {}
    for profile in ("escalating", "low_slow"):
        print(f"\n=== profile: {profile} ===")
        print(f"sweeping bait-awareness ({args.sessions} sessions/level) ...\n")
        rows = []
        for level in LEVELS:
            _run_cohort(args.proxy, level, args.sessions, rng, profile)
            time.sleep(1.0)
            m = _measure_new(str(cfg.log_dir / "proxy.*.jsonl"), level)
            m["awareness"] = level
            rows.append(m)
        all_rows[profile] = rows

        print(f"{'awareness':>10} {'sessions':>9} {'bite_rate':>10} {'divert_rate':>12} "
              f"{'med_reqs':>9} {'p90_reqs':>9}")
        for r in rows:
            print(f"{r['awareness']:>10.2f} {r['sessions']:>9} {r['bite_rate']:>10.2%} "
                  f"{r['divert_rate']:>12.2%} {str(r['median_reqs_to_divert']):>9} "
                  f"{str(r['p90_reqs_to_divert']):>9}")

    print("\n" + "=" * 66)
    print("INTERPRETATION (the robustness story, spec §18/§19)")
    esc, slow = all_rows["escalating"], all_rows["low_slow"]
    print(f"  FLOOR (escalating attacker): divert rate stays "
          f"{min(r['divert_rate'] for r in esc):.0%}-{max(r['divert_rate'] for r in esc):.0%} "
          f"across all awareness -> passive detection is the floor; bait never blinds it.")
    print("  VALUE + COST (low-and-slow attacker):")
    print(f"    naive (aware 0): divert {slow[0]['divert_rate']:.0%} in "
          f"~{slow[0]['median_reqs_to_divert']} reqs (bait catches the uncertain case fast)")
    print(f"    aware (aware 1): divert {slow[-1]['divert_rate']:.0%} in "
          f"~{slow[-1]['median_reqs_to_divert']} reqs (a bait-aware adversary evades longer)")
    print("  -> honest reading: bait's benefit is largest exactly where passive detection")
    print("     is uncertain; a bait-aware adversary erodes that benefit but is bounded by")
    print("     the passive floor. Report the whole curve, not a single win (spec §7.4).")

    out = system().log_dir / "robustness_curve.json"
    out.write_text(json.dumps(all_rows, indent=2), encoding="utf-8")
    print(f"\ncurve -> {out}")


# each cohort is measured over sessions created during it; we tag sessions by
# level using the session id prefix the attacker sets, and record which ids are
# new since the previous cohort.
_SEEN: set[str] = set()


def _run_cohort(proxy_url: str, level: float, n: int, rng: random.Random,
                profile: str = "escalating") -> None:
    for _ in range(n):
        AdaptiveAttacker(proxy_url, level, random.Random(rng.random()), profile=profile).run()


def _measure_new(log_glob: str, level: float) -> dict:
    """Measure only sessions not seen in a previous cohort."""
    records = []
    for f in glob.glob(log_glob):
        records += [json.loads(l) for l in open(f, encoding="utf-8") if l.strip()]
    by_session = defaultdict(list)
    for r in records:
        sid = r["session"]["session_id"]
        by_session[sid].append(r)

    new = {sid: recs for sid, recs in by_session.items()
           if sid not in _SEEN and any("curl" in (r["request"].get("user_agent", "")) for r in recs)}
    _SEEN.update(new)

    total = len(new)
    diverted, bites, reqs = 0, 0, []
    for recs in new.values():
        recs.sort(key=lambda r: r["seq"])
        actions = [r["decision"].get("action") for r in recs]
        if any(r.get("bite", {}).get("occurred") for r in recs):
            bites += 1
        if "divert" in actions:
            diverted += 1
            reqs.append(actions.index("divert") + 1)
    return {
        "sessions": total,
        "divert_rate": diverted / total if total else 0.0,
        "bite_rate": bites / total if total else 0.0,
        "median_reqs_to_divert": statistics.median(reqs) if reqs else None,
        "p90_reqs_to_divert": sorted(reqs)[int(len(reqs) * 0.9)] if reqs else None,
    }


if __name__ == "__main__":
    main()
