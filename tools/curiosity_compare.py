"""Did making the attacker read responses reach the probe?

One subcategory, `sqli_obfuscated`, had a bite rate of exactly 0.000 while ~90% of
its sessions were shown a probe, and it was half of all remaining misses. The cause
was in the attacker simulation rather than the defence: those profiles fired
payloads and never read the response body, so a response-side probe could not reach
them by construction (see `tools/attack_traffic_round2.py`).

This compares a run produced under the response-reading attacker against the blind
baseline, per subcategory, and reports the one number that settles it: whether the
bite rate moved off zero, and whether recall followed.

    python -m tools.curiosity_compare \
        --curious data/eval/quick/sessions.jsonl \
        --blind   data/eval/multiseed/sessions.jsonl

Both dumps must come from the SAME frozen model; only the attacker differs. The
comparison is per subcategory because the aggregate hides it -- obfuscated SQLi is
a third of the attack corpus, so a real change there is diluted to near-nothing in
a pooled recall figure.
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path


def load(path: Path, arm: str) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if r.get("arm") == arm and r.get("label") == "attack":
            rows.append(r)
    return rows


def summarise(rows: list[dict]) -> dict[str, dict]:
    by: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for r in rows:
        c = by[r.get("subcategory") or r.get("category") or "?"]
        c["n"] += 1
        c["div"] += 1 if r.get("diverted") else 0
        c["baited"] += 1 if r.get("baited") else 0
        c["bit"] += 1 if r.get("bit") else 0
    out = {}
    for sub, c in by.items():
        n = c["n"] or 1
        out[sub] = {
            "n": c["n"],
            "recall": c["div"] / n,
            "baited": c["baited"] / n,
            "bite": c["bit"] / n,
            "seeds": 0,
        }
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Blind vs response-reading attacker, per subcategory.")
    ap.add_argument("--curious", default="data/eval/quick/sessions.jsonl")
    ap.add_argument("--blind", default="data/eval/multiseed/sessions.jsonl")
    ap.add_argument("--arm", default="b4_full")
    args = ap.parse_args()

    cur = summarise(load(Path(args.curious), args.arm))
    bl = summarise(load(Path(args.blind), args.arm))

    if not cur:
        raise SystemExit(f"no {args.arm} attack sessions in {args.curious} yet — "
                         "the run has not reached that arm")

    seeds_c = len({r["seed"] for r in load(Path(args.curious), args.arm)})
    seeds_b = len({r["seed"] for r in load(Path(args.blind), args.arm)})
    print(f"arm {args.arm}:  curious {seeds_c} seeds   blind {seeds_b} seeds")
    # ASCII only: this prints to whatever console the operator has, and a Windows
    # cp1252 terminal raises UnicodeEncodeError on the first non-ASCII character,
    # killing the tool after the run it was meant to report on.
    print("(different seed counts - read the direction and size of the change, "
          "not a significance test)\n")

    hdr = (f"{'subcategory':24s}{'bite blind':>11s}{'bite curious':>14s}"
           f"{'recall blind':>14s}{'recall curious':>16s}{'d recall':>10s}")
    print(hdr)
    print("-" * len(hdr))
    for sub in sorted(set(cur) | set(bl)):
        c, b = cur.get(sub), bl.get(sub)
        if not c or not b:
            print(f"{sub:24s}{'(only in one dump)':>64s}")
            continue
        d = c["recall"] - b["recall"]
        print(f"{sub:24s}{b['bite']:>11.3f}{c['bite']:>14.3f}"
              f"{b['recall']:>14.3f}{c['recall']:>16.3f}{d:>+10.3f}")

    key = "sqli_obfuscated"
    if key in cur and key in bl:
        print()
        cb, bb = cur[key]["bite"], bl[key]["bite"]
        if bb == 0.0 and cb > 0.0:
            print(f"RESULT: {key} bite rate moved {bb:.3f} -> {cb:.3f}. The probe was "
                  f"unreachable under the blind attacker, not ineffective; recall there "
                  f"moved {bl[key]['recall']:.3f} -> {cur[key]['recall']:.3f}.")
        elif cb == 0.0:
            print(f"RESULT: {key} bite rate is still {cb:.3f}. Reading the response was "
                  f"not the blocker — look for another reason the probe cannot reach "
                  f"this subcategory (bait selection, surface, or injection channel).")
        else:
            print(f"RESULT: {key} bite {bb:.3f} -> {cb:.3f}.")


if __name__ == "__main__":
    main()
