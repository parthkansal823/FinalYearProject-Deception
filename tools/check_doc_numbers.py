"""Check the numbers written in the documentation against the numbers on disk.

Prose drifts from data silently. Today the paper claimed a +0.104 subcategory gain
where the data said +0.188, a McNemar of b=390/c=182 where the data said b=444/c=71,
11,221 concordant sessions where 11,880 - 628 - 218 is 11,034, and a holdout table
whose two rows differed by +0.028 while the sentence beneath them said +0.051. None
of those looked wrong. Every one of them would have gone to a reviewer.

So this recomputes the headline quantities from a session dump and reports every
documented figure that disagrees. It does not edit anything: a number can differ
legitimately (a historical comparison, a different arm, a superseded run kept on
purpose for context), and deciding that is a judgement the tool should not make.

    python -m tools.check_doc_numbers --dump data/eval/curious/sessions.jsonl
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import math
import re
from pathlib import Path

DOCS = ["README.md", "docs/*.md", "docs/paper/*.md"]
ARMS = ("b1_rules", "b2_passive", "b4_full")


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    ph = k / n
    d = 1 + z * z / n
    c = (ph + z * z / (2 * n)) / d
    h = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def canonical(dump: Path) -> dict:
    rows = collections.defaultdict(dict)
    for line in dump.open(encoding="utf-8"):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        rows[r.get("arm")][(r["seed"], r["stream"], r["index"])] = r

    facts: dict[str, float | int] = {}
    for arm in ARMS:
        R = rows.get(arm)
        if not R:
            continue
        att = [r for r in R.values() if r["label"] == "attack"]
        ben = [r for r in R.values() if r["label"] == "benign"]
        k = sum(bool(r["diverted"]) for r in att)
        lo, hi = wilson(k, len(att))
        facts[arm + ".recall"] = round(k / len(att), 4)
        facts[arm + ".recall_lo"] = round(lo, 4)
        facts[arm + ".recall_hi"] = round(hi, 4)
        facts[arm + ".benign_diverted"] = sum(bool(r["diverted"]) for r in ben)
        facts[arm + ".n_attack"] = len(att)
        facts[arm + ".n_benign"] = len(ben)
        facts[arm + ".seeds"] = len({k2[0] for k2 in R})

    if "b2_passive" in rows and "b4_full" in rows:
        keys = [k for k in rows["b4_full"]
                if k in rows["b2_passive"] and rows["b4_full"][k]["label"] == "attack"]
        b = sum(1 for k in keys if rows["b4_full"][k]["diverted"]
                and not rows["b2_passive"][k]["diverted"])
        c = sum(1 for k in keys if not rows["b4_full"][k]["diverted"]
                and rows["b2_passive"][k]["diverted"])
        facts["mcnemar.b"] = b
        facts["mcnemar.c"] = c
        facts["mcnemar.concordant"] = len(keys) - b - c
        facts["mcnemar.pairs"] = len(keys)
        seeds = sorted({k[0] for k in keys})
        wins = sum(1 for s in seeds
                   if sum(rows["b4_full"][k]["diverted"] for k in keys if k[0] == s)
                   > sum(rows["b2_passive"][k]["diverted"] for k in keys if k[0] == s))
        facts["seeds.b4_ahead"] = wins
        facts["seeds.total"] = len(seeds)

    R4 = rows.get("b4_full") or {}
    g = collections.Counter()
    d = collections.Counter()
    for r in R4.values():
        if r["label"] == "attack" and r.get("assignment") in ("policy", "holdout"):
            g[r["assignment"]] += 1
            d[r["assignment"]] += bool(r["diverted"])
    if g["policy"] and g["holdout"]:
        facts["holdout.policy_n"] = g["policy"]
        facts["holdout.policy_diverted"] = d["policy"]
        facts["holdout.holdout_n"] = g["holdout"]
        facts["holdout.holdout_diverted"] = d["holdout"]
        facts["holdout.effect"] = round(d["policy"] / g["policy"]
                                        - d["holdout"] / g["holdout"], 4)
    ben4 = [r for r in R4.values() if r["label"] == "benign"]
    if ben4:
        facts["b4.benign_baited"] = sum(bool(r["baited"]) for r in ben4)
        facts["b4.benign_bit"] = sum(bool(r["bit"]) for r in ben4)
    return facts


#: Documented quantities and the fact each should equal. The pattern captures the
#: number as written, so a doc that spells it differently still gets checked.
CHECKS = [
    ("B2 recall", r"0\.9\d{2}", "b2_passive.recall",
     r"(?:B2|passive)[^\n]{0,60}?(0\.9\d{2})"),
    ("B4 recall", r"0\.9\d{2}", "b4_full.recall",
     r"(?:B4|full)[^\n]{0,60}?(0\.9\d{2})"),
    ("holdout effect", r"\+0\.0\d{2}", "holdout.effect",
     r"(?:holdout|causal)[^\n]{0,80}?\+(0\.0\d{2})"),
    ("benign sessions per arm", r"[\d,]+", "b4_full.n_benign",
     r"([\d,]{4,7})\s+benign sessions"),
    ("attack sessions per arm", r"[\d,]+", "b4_full.n_attack",
     r"([\d,]{4,7})\s+attack (?:and|sessions)"),
    ("seeds", r"\d+", "seeds.total", r"(?:over|across)\s+(\d{2,3})\s+(?:paired\s+)?seeds"),
    # "recall rises from 0.889 to 0.943" names both arms without naming either,
    # so the B2/B4 patterns above never see it. The abstract carried the old pair
    # this way through three rounds of edits.
    # \s+ rather than a literal space: the paper is hard-wrapped, so a claim
    # regularly straddles a line break and a space-only pattern misses most of
    # the prose it was written to check.
    ("B2 recall (rises-from)", r"0\.9\d{2}", "b2_passive.recall",
     r"recall\s+(?:rises\s+|lifts\s+|goes\s+)?from\s+(0\.\d{3})\s+to\s+0\.\d{3}"),
    ("B4 recall (rises-to)", r"0\.9\d{2}", "b4_full.recall",
     r"recall\s+(?:rises\s+|lifts\s+|goes\s+)?from\s+0\.\d{3}\s+to\s+(0\.\d{3})"),
]

#: An estimate outside its own confidence interval is arithmetically impossible,
#: and it survived several passes here because every individual number looked
#: plausible. Unlike the checks above this needs no data to verify.
INTERVAL = re.compile(r"([+-]?0\.\d{2,4})\s*(?:,\s*95%\s*CI)?\s*"
                      r"\[\s*([+-]?0\.\d{2,4})\s*,\s*([+-]?0\.\d{2,4})\s*\]")


#: A decision log records what was believed at the time, so its old numbers are
#: the point rather than a mistake.
SKIP_FILES = {"DECISIONS.md"}

#: An explicit, visible escape for a line that legitimately quotes a different
#: measurement -- a five-seed sanity check, a superseded run named on purpose, a
#: figure from another arm. It has to be deliberate and greppable, because the
#: alternative is a tool that reports known-good lines until everyone ignores it.
ESCAPE = "<!-- not-the-headline -->"


def strip_historical(text: str) -> str:
    """Blank out regions that quote a superseded number on purpose.

    HTML comments carry the "these numbers are pending refresh" notes, and
    blockquotes carry the supersession banners; both deliberately name the old
    figure so a reader can tell what changed. Flagging them would train the
    reader to ignore this tool, which is worse than not having it.

    Regions are blanked rather than deleted so reported line numbers stay true.
    """
    out = []
    in_comment = False
    for line in text.splitlines():
        stripped = line.lstrip()
        if "<!--" in line:
            in_comment = True
        keep = not in_comment and not stripped.startswith(">")
        if "-->" in line:
            in_comment = False
        out.append(line if keep else "")
    return chr(10).join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description="Docs vs data consistency check.")
    ap.add_argument("--dump", default="data/eval/curious/sessions.jsonl")
    ap.add_argument("--quiet", action="store_true",
                    help="only print disagreements")
    args = ap.parse_args()

    dump = Path(args.dump)
    if not dump.exists():
        raise SystemExit("no session dump at " + str(dump))
    facts = canonical(dump)

    if not args.quiet:
        print("canonical values from " + str(dump))
        for k in sorted(facts):
            print("  %-28s %s" % (k, facts[k]))
        print()

    files = []
    for pat in DOCS:
        files.extend(sorted(glob.glob(pat)))

    problems = 0
    for f in files:
        if Path(f).name in SKIP_FILES:
            continue
        text = strip_historical(Path(f).read_text(encoding="utf-8"))

        for m in INTERVAL.finditer(text):
            est, lo, hi = (float(x) for x in m.groups())
            if lo > hi or not (lo <= est <= hi):
                line = text[:m.start()].count("\n") + 1
                print("  %s:%d  estimate %s lies outside its own interval [%s, %s]"
                      % (f, line, m.group(1), m.group(2), m.group(3)))
                problems += 1

        for label, _shape, fact, pattern in CHECKS:
            if fact not in facts:
                continue
            want = facts[fact]
            for m in re.finditer(pattern, text, re.I):
                raw = m.group(1).replace(",", "")
                try:
                    got = float(raw)
                except ValueError:
                    continue
                tol = 0.0006 if got < 10 else 0.5
                ok = abs(got - float(want)) < tol

                # "recall 0.917 vs 0.951" and "0.917 -> 0.951" name both arms on
                # one line, and the pattern lands on whichever comes first.
                # Accept the line if the value we expect appears anywhere on it:
                # the question is whether the line is stale, not which half the
                # regex happened to reach.
                ls = text.rfind(chr(10), 0, m.start()) + 1
                le = text.find(chr(10), m.end())
                whole = text[ls:le if le >= 0 else len(text)]
                if ESCAPE in whole:
                    continue
                if not ok:
                    for v in re.findall(r"\d[\d,]*\.?\d*", whole):
                        try:
                            if abs(float(v.replace(",", "")) - float(want)) < tol:
                                ok = True
                                break
                        except ValueError:
                            continue

                # A seed count far below the evaluation's is a different quantity
                # -- the ablation pairs over 19 seeds -- not a stale copy of this
                # one. Flagging it teaches the reader to ignore the tool.
                if not ok and fact == "seeds.total" and got < float(want) / 2:
                    ok = True

                if not ok:
                    line = text[:m.start()].count("\n") + 1
                    print("  %s:%d  %s written as %s, data says %s"
                          % (f, line, label, m.group(1), want))
                    problems += 1

    print()
    if problems:
        print("%d disagreement(s). Each is either a stale number or a deliberate"
              % problems)
        print("historical reference -- read the line before changing it.")
        raise SystemExit(1)
    print("no disagreements found between the documentation and " + str(dump))


if __name__ == "__main__":
    main()
