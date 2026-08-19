"""Combine ablation runs that cover disjoint seed ranges into one dump per arm.

The first ablation ran twenty seeds. That is enough for recall, whose interval is
driven by thousands of sessions, but not for expected cost: a single benign
diversion costs 200 units, so one such session moves a seed's mean by a whole
point and the per-seed interval stays wide. The arms that divert benign users are
exactly the ones the comparison turns on, so their intervals are the ones worth
narrowing, and more seeds is the only honest way to do it.

Concatenation is valid because the runs use disjoint seed ranges and the same
frozen model; every pooled proportion and every per-seed mean is computed over the
union. A repeated seed would double-count sessions into all of them, so this
refuses rather than warns.

    python -m tools.merge_ablation --into data/eval/fixed_threshold_all \\
        data/eval/fixed_threshold_v2 data/eval/fixed_threshold_v3
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser(description="Merge disjoint ablation runs.")
    ap.add_argument("runs", nargs="+", help="run directories holding <arm>/sessions.jsonl")
    ap.add_argument("--into", required=True)
    args = ap.parse_args()

    out = Path(args.into)
    out.mkdir(parents=True, exist_ok=True)

    by_arm: dict[str, list[Path]] = collections.defaultdict(list)
    for r in args.runs:
        root = Path(r)
        if not root.exists():
            raise SystemExit("no such run directory: " + str(root))
        for d in sorted(root.iterdir()):
            dump = d / "sessions.jsonl"
            if d.is_dir() and dump.exists() and dump.stat().st_size:
                by_arm[d.name].append(dump)

    if not by_arm:
        raise SystemExit("no arm dumps found under " + ", ".join(args.runs))

    index = []
    for arm, dumps in sorted(by_arm.items()):
        if len(dumps) < 2:
            print("  %-16s only one run has it; carried over unmerged" % arm)
        seen: dict[tuple, str] = {}
        rows: list[str] = []
        seeds: set[int] = set()
        for dump in dumps:
            for line in dump.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                r = json.loads(line)
                key = (r.get("arm"), r.get("seed"), r.get("stream"), r.get("index"))
                if key in seen:
                    raise SystemExit(
                        "duplicate session %s\n  first in : %s\n  also in  : %s\n"
                        "The runs must cover disjoint seed ranges; merging these "
                        "would double-count sessions into every pooled proportion."
                        % (key, seen[key], dump))
                seen[key] = str(dump)
                rows.append(line)
                seeds.add(r.get("seed"))

        d = out / arm
        d.mkdir(parents=True, exist_ok=True)
        (d / "sessions.jsonl").write_text("\n".join(rows) + "\n", encoding="utf-8")
        try:
            lo, hi = (float(x) for x in arm.split("_"))
        except ValueError:
            print("  %-16s cannot parse edges from the directory name; skipped "
                  "in arms.json" % arm)
            continue
        index.append({"lo": lo, "hi": hi, "dump": str(d / "sessions.jsonl")})
        print("  %-16s %6d rows over %3d seeds  (%d run(s))"
              % (arm, len(rows), len(seeds), len(dumps)))

    (out / "arms.json").write_text(json.dumps(sorted(
        index, key=lambda a: (a["lo"], a["hi"])), indent=2), encoding="utf-8")
    print("\nwrote %d arm(s) -> %s" % (len(index), out / "arms.json"))
    print("now run:  python -m tools.calibration_report --fixed %s \\" % out)
    print("              --derived data/eval/curious_v2/sessions.jsonl")


if __name__ == "__main__":
    main()
