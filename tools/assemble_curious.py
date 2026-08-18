"""Assemble the response-reading evaluation from the parts it was run in.

The run was interrupted twice, so its arms live in two dumps: `b1_rules` finished
before a crash and was preserved on its own, and `b2_passive` + `b4_full` were
re-run afterwards. Both used the same base seed, the same per-draw session counts
and the same frozen model, so they concatenate -- but only after two checks that
are easy to skip and expensive to get wrong.

  1. No seed may appear twice for the same arm. Concatenating an overlap would
     double-count sessions in every pooled proportion, and nothing downstream
     would notice.
  2. Seeds that lost sessions are dropped from EVERY arm, not just the one that
     lost them. A seed whose b2 side recorded 31 sessions and whose b4 side
     recorded 200 is not a matched pair, and the paired McNemar test assumes it is.

    python -m tools.assemble_curious
    python -m tools.stats_report --in data/eval/curious/sessions.jsonl
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path


def read(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit(f"missing input: {path}")
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Merge the split curious-run dumps.")
    ap.add_argument("--parts", nargs="+", default=[
        "data/eval/curious/sessions_b1_only.jsonl",
        "data/eval/curious_b2b4/sessions.jsonl",
    ])
    ap.add_argument("--out", default="data/eval/curious/sessions.jsonl")
    ap.add_argument("--expected", type=int, default=200,
                    help="sessions per draw; seeds under 90%% of this are dropped")
    args = ap.parse_args()

    rows: list[dict] = []
    seen_arm_seed: dict[tuple, str] = {}
    for part in args.parts:
        p = Path(part)
        chunk = read(p)
        arms_here = {r["arm"] for r in chunk}
        for r in chunk:
            key = (r["arm"], r["seed"])
            if key in seen_arm_seed and seen_arm_seed[key] != str(p):
                raise SystemExit(
                    f"seed {r['seed']} appears for arm {r['arm']} in both "
                    f"{seen_arm_seed[key]} and {p}. Merging would double-count it.")
            seen_arm_seed[key] = str(p)
        rows += chunk
        print(f"  {p}: {len(chunk)} rows, arms {sorted(arms_here)}")

    counts = collections.Counter((r["arm"], r["seed"]) for r in rows)
    short = {seed for (arm, seed), n in counts.items() if n < args.expected * 0.9}
    arms = sorted({r["arm"] for r in rows})

    if short:
        print(f"\n  dropping {len(short)} seed(s) that lost sessions, from ALL "
              f"{len(arms)} arms, so the pairing stays matched:")
        for seed in sorted(short):
            detail = ", ".join(f"{a}={counts[(a, seed)]}" for a in arms if (a, seed) in counts)
            print(f"    seed {seed}: {detail}")
        rows = [r for r in rows if r["seed"] not in short]

    per_arm = collections.defaultdict(set)
    for r in rows:
        per_arm[r["arm"]].add(r["seed"])
    print()
    for a in arms:
        print(f"  {a:12s} {len(per_arm[a]):4d} seeds")
    sizes = {len(v) for v in per_arm.values()}
    if len(sizes) > 1:
        print("\n  !! arms have unequal seed counts; the paired tests will use only "
              "the seeds present in both.")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    print(f"\nwrote {len(rows)} rows -> {out}")
    print(f"now run:  python -m tools.stats_report --in {out}")


if __name__ == "__main__":
    main()
