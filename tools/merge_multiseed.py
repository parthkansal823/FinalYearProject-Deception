"""
Merge multi-seed session dumps into one analysable file.

`tools/multiseed_eval.py` truncates `sessions.jsonl` at start, so re-running a
single arm (to extend a stalled one to more seeds) discards the other arms. The
working practice is therefore: back the dump up, re-run the one arm, merge.
This makes that merge explicit and repeatable instead of a shell one-liner
nobody can audit later.

Merge rule: rows are keyed by (arm, seed); when the same key appears in more
than one input, the LAST input wins. So put the fresh re-run last:

    python -m tools.merge_multiseed \\
        data/eval/multiseed/sessions_b1b2_backup.jsonl \\
        data/eval/multiseed/sessions.jsonl

It refuses to write a merge in which the arms do not share seeds, because the
paired McNemar test in `tools/stats_report.py` silently loses all its power if
the arms were run on different draws -- a failure that looks like a result.
"""

from __future__ import annotations

import argparse
import json
import shutil
from collections import defaultdict
from pathlib import Path

DEFAULT_OUT = Path("data/eval/multiseed/sessions.jsonl")


def _read(path: Path) -> list[dict]:
    rows = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue      # a partially-flushed final line from a live run
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="Merge multi-seed dumps (last input wins per arm+seed).")
    ap.add_argument("inputs", nargs="+", help="jsonl dumps, oldest first")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--allow-unpaired", action="store_true",
                    help="write even if the arms do not share seeds (paired tests will be weak)")
    args = ap.parse_args()

    # (arm, seed) -> rows, later inputs overwriting earlier ones
    bucket: dict[tuple[str, int], list[dict]] = {}
    for src in args.inputs:
        p = Path(src)
        if not p.exists():
            raise SystemExit(f"missing input: {p}")
        staged: dict[tuple[str, int], list[dict]] = defaultdict(list)
        for r in _read(p):
            staged[(r.get("arm", "?"), r.get("seed", -1))].append(r)
        for key, rows in staged.items():
            bucket[key] = rows          # last input wins
        print(f"  {p.name}: {sum(len(v) for v in staged.values())} rows, {len(staged)} arm-seed groups")

    arms: dict[str, set] = defaultdict(set)
    for (arm, seed) in bucket:
        arms[arm].add(seed)
    print("\nmerged:")
    for arm in sorted(arms):
        print(f"  {arm}: {len(arms[arm])} seeds")

    # the pairing check that protects the McNemar test
    if len(arms) > 1:
        shared = set.intersection(*arms.values())
        print(f"  seeds shared by every arm: {len(shared)}")
        if not shared and not args.allow_unpaired:
            raise SystemExit(
                "refusing to write: the arms share no seeds, so every paired test "
                "would silently drop to zero matched pairs. Re-run the arms on the "
                "same --base-seed, or pass --allow-unpaired if that is intended.")

    out = Path(args.out)
    if out.exists():
        backup = out.with_suffix(".jsonl.bak")
        shutil.copy2(out, backup)
        print(f"\nexisting dump backed up -> {backup.name}")
    out.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(out, "w", encoding="utf-8") as fh:
        for key in sorted(bucket, key=lambda k: (k[0], k[1])):
            for r in bucket[key]:
                fh.write(json.dumps(r) + "\n")
                n += 1
    print(f"wrote {n} rows -> {out}")
    print("now run:  python -m tools.stats_report")


if __name__ == "__main__":
    main()
