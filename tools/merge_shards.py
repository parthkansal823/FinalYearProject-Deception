"""Merge sharded multi-seed dumps into one sessions.jsonl.

`run_sharded_eval.ps1` splits the seed range across concurrent processes, each
writing its own dump. Pairing in `stats_report.py` is on (seed, stream, index),
which is why the shards can simply be concatenated: the seed ranges are disjoint
by construction, so no key collides.

Refuses to merge if that assumption is violated, because a duplicated seed would
silently double-count sessions in every pooled proportion.

    python -m tools.merge_shards --tag curious
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser(description="Merge sharded evaluation dumps.")
    ap.add_argument("--tag", required=True, help="the tag passed to run_sharded_eval.ps1")
    ap.add_argument("--root", default="data/eval", help="directory holding <tag>/shard*/")
    args = ap.parse_args()

    root = Path(args.root) / args.tag
    shards = sorted(root.glob("shard*/sessions.jsonl"))
    if not shards:
        raise SystemExit(f"no shard dumps under {root}/shard*/sessions.jsonl")

    seen_by_arm: dict[str, set] = collections.defaultdict(set)
    owner: dict[tuple, str] = {}
    rows: list[str] = []
    per_shard = []

    for path in shards:
        n = 0
        seeds = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            key = (r.get("arm"), r.get("seed"), r.get("stream"), r.get("index"))
            if key in owner:
                raise SystemExit(
                    f"duplicate session key {key}\n"
                    f"  first seen in : {owner[key]}\n"
                    f"  also in       : {path}\n"
                    "Shards must cover disjoint seed ranges; merging these would "
                    "double-count sessions in every pooled proportion.")
            owner[key] = str(path)
            seen_by_arm[r.get("arm")].add(r.get("seed"))
            rows.append(line)
            n += 1
            seeds.add(r.get("seed"))
        per_shard.append((path.parent.name, n, len(seeds)))

    out = root / "sessions.jsonl"
    out.write_text("\n".join(rows) + "\n", encoding="utf-8")

    print(f"merged {len(shards)} shards -> {out}")
    for name, n, s in per_shard:
        print(f"  {name:10s} {n:7d} rows  {s:4d} seeds")
    print(f"  {'TOTAL':10s} {len(rows):7d} rows")
    print()
    counts = {a: len(s) for a, s in seen_by_arm.items()}
    for arm, k in sorted(counts.items()):
        print(f"  {arm:14s} {k:4d} seeds")
    if len(set(counts.values())) > 1:
        print("\n  !! arms have unequal seed counts -- the paired tests will only use "
              "the seeds present in both arms.")
    print(f"\nnow run:  python -m tools.stats_report --in {out}")


if __name__ == "__main__":
    main()
