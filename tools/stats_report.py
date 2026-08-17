"""
Statistical report over the multi-seed session dump (tools/multiseed_eval.py).

This is the answer to the single most important reviewer objection: the headline
numbers were single draws with no intervals and no significance tests. Here we:

  * pool every seed's sessions per arm and report recall with a **Wilson 95%
    confidence interval** (correct for proportions near 0/1, unlike normal-approx);
  * report the per-seed recall distribution (mean +/- sd) so run-to-run stability
    is visible, not just the pooled point;
  * run a **paired McNemar exact test** for B2 vs B4. The pairing is legitimate
    and powerful because, for a given seed, both arms see byte-identical traffic
    (spec §7.3) -- so each attack session is one matched pair, and only the
    discordant pairs (one arm catches, the other misses) carry information;
  * run a **Fisher exact test** on the randomised holdout (baited vs withheld),
    the one result that is significant and is the paper's actual contribution;
  * bootstrap a CI for the holdout effect size.

No new experiment is run here -- it only analyses `sessions.jsonl`. Re-runnable
in a second, so the tests can evolve without recomputing traffic.

    python -m tools.stats_report

**Why this refuses to write a partial report.** `multiseed_eval.py` truncates
`sessions.jsonl` at start and fills it arm by arm (outer loop), so a run that is
still in flight -- or that died partway, which has happened twice -- leaves a
dump with the later arms missing entirely. Analysing that dump silently yields a
report with no B4, no McNemar and no holdout, and *overwrites the report.json
that every number in README/RESULTS is quoted from*. The loss is invisible: the
file still parses, still looks like a result. So the completeness of the dump is
checked BEFORE the canonical file is touched, and a dump that cannot support the
paired tests is analysed to stdout but not written. Pass `--allow-partial` to
write anyway (it stamps `partial: true` into the report so the provenance of a
salvaged number is never in doubt).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from scipy import stats

IN = Path("data/eval/multiseed/sessions.jsonl")
OUT = Path("data/eval/multiseed/report.json")

ARMS = ["b1_rules", "b2_passive", "b4_full"]
ARM_LABEL = {"b0_no_defence": "B0 no-defence", "b1_rules": "B1 signature-WAF",
             "b2_passive": "B2 passive", "b4_full": "B4 full"}


def wilson(k: int, n: int, z: float = 1.959963985) -> tuple[float, float, float]:
    """Wilson score interval for a binomial proportion. Returns (phat, lo, hi)."""
    if n == 0:
        return 0.0, 0.0, 0.0
    phat = k / n
    denom = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))
    lo, hi = max(0.0, centre - half), min(1.0, centre + half)
    # The Wilson interval always contains phat, but at k=0 or k=n the bound is
    # only equal to phat in exact arithmetic -- in floating point it lands a few
    # ulps the wrong side, which yields a tiny NEGATIVE error bar downstream.
    # Enforce the bracketing invariant rather than papering over it at each use.
    return phat, min(lo, phat), max(hi, phat)


def load(path: Path = IN) -> list[dict]:
    if not path.exists():
        raise SystemExit(f"no session dump at {path}; run `python -m tools.multiseed_eval` first")
    rows = []
    for n, line in enumerate(open(path, encoding="utf-8"), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            # A live run flushes per seed; the final line can be half-written.
            # Dropping it is right, but say so -- silence here once cost a day.
            print(f"  !! {path.name}: line {n} is not valid JSON (truncated?); skipped")
    return rows


def audit(rows: list[dict]) -> tuple[list[str], dict]:
    """Structural defects that would make a written report misleading.

    Returns (problems, per-arm seed counts). Empty problems == the dump can
    support every test this script claims to run.
    """
    problems: list[str] = []
    seeds_by_arm = {a: {r["seed"] for r in rows if r["arm"] == a} for a in ARMS}
    counts = {a: len(s) for a, s in seeds_by_arm.items() if s}

    missing = [a for a in ARMS if not seeds_by_arm[a]]
    if missing:
        problems.append(f"arm(s) absent from the dump: {', '.join(missing)} "
                        f"(present: {', '.join(counts) or 'none'})")

    if len(set(counts.values())) > 1:
        detail = ", ".join(f"{a}={n}" for a, n in counts.items())
        problems.append(f"arms have unequal seed counts ({detail}) -- a run cut short; "
                        f"the shorter arm's CI is not comparable to the longer one's")

    # The pairing is the whole basis of the McNemar test (spec §7.3).
    if seeds_by_arm["b2_passive"] and seeds_by_arm["b4_full"]:
        shared = seeds_by_arm["b2_passive"] & seeds_by_arm["b4_full"]
        if not shared:
            problems.append("B2 and B4 share no seeds -- every paired test would "
                            "silently drop to zero matched pairs")
        elif len(shared) < max(len(seeds_by_arm["b2_passive"]), len(seeds_by_arm["b4_full"])):
            problems.append(f"B2/B4 overlap on only {len(shared)} seeds "
                            f"(B2={len(seeds_by_arm['b2_passive'])}, B4={len(seeds_by_arm['b4_full'])}); "
                            f"unmatched seeds contribute nothing to the paired test")

    # A seed killed mid-write leaves fewer sessions than its neighbours.
    per_key = Counter((r["arm"], r["seed"]) for r in rows)
    if per_key:
        modal = Counter(per_key.values()).most_common(1)[0][0]
        short = [k for k, n in per_key.items() if n != modal]
        if short:
            worst = sorted(short, key=lambda k: per_key[k])[:3]
            detail = ", ".join(f"{a}/{s}={per_key[(a, s)]}" for a, s in worst)
            problems.append(f"{len(short)} arm-seed group(s) have != {modal} sessions "
                            f"(e.g. {detail}) -- likely interrupted mid-seed")
    return problems, counts


def _file_sha256(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def frozen_artefacts() -> dict:
    """Digests of the three frozen inputs a result depends on.

    The dump digest alone is not enough to trace a number. A dump is produced
    *under* a cost table, a calibrated bait library and a fitted meter, and when
    the library was re-frozen after a calibration fix, `report.json` kept quoting
    the old run while `config/` held the new library. Nothing linked the two, so
    the mismatch was invisible. Stamping all three here lets a reader -- and
    `make_figures` -- detect that a report predates the artefacts it is plotted
    against.
    """
    out: dict = {}
    try:
        from adf.config import load_costs
        out["cost_digest"] = load_costs().digest
    except Exception as exc:  # noqa: BLE001 - provenance must never break the report
        out["cost_digest_error"] = f"{type(exc).__name__}: {exc}"
    out["bait_library_sha256"] = _file_sha256(Path("config/bait_library.yaml"))
    out["meter_sha256"] = _file_sha256(Path("data/models/meter.json"))
    try:
        from adf.policy.engine import BaitLibrary
        lib = BaitLibrary.load()
        out["bait_library_calibrated"] = lib.calibrated
        out["baits"] = {e.bait_id: {"beta_attack": round(e.beta_attack, 4),
                                    "beta_benign": round(e.beta_benign, 5)}
                        for e in lib.effects()}
    except Exception as exc:  # noqa: BLE001
        out["bait_library_error"] = f"{type(exc).__name__}: {exc}"
    return out


def provenance(path: Path, rows: list[dict]) -> dict:
    """Which bytes produced this report. Without it, a number in the paper
    cannot be traced back to the dump it came from (and this project has had
    four session dumps coexisting at once)."""
    return {
        "source": str(path).replace("\\", "/"),
        "sha256": _file_sha256(path),
        "rows": len(rows),
        "source_mtime_utc": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
                                    .isoformat(timespec="seconds") if path.exists() else None,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "frozen_artefacts": frozen_artefacts(),
    }


def _fmt_ci(k: int, n: int) -> str:
    p, lo, hi = wilson(k, n)
    return f"{p:.3f} [{lo:.3f}, {hi:.3f}]  (n={n})"


def main() -> None:
    ap = argparse.ArgumentParser(description="Statistics over the multi-seed session dump.")
    ap.add_argument("--in", dest="inp", default=str(IN), help="session dump to analyse")
    ap.add_argument("--out", default=str(OUT), help="report to write")
    ap.add_argument("--allow-partial", action="store_true",
                    help="write the report even if the dump is incomplete "
                         "(stamps partial:true and the reason into it)")
    args = ap.parse_args()
    in_path, out_path = Path(args.inp), Path(args.out)

    rows = load(in_path)
    problems, seed_counts = audit(rows)
    seeds = sorted({r["seed"] for r in rows})
    arms = [a for a in ARMS if any(r["arm"] == a for r in rows)]
    # Seed count is PER ARM: a run interrupted partway leaves later arms with
    # fewer draws than earlier ones, and reporting the pooled maximum for every
    # arm would overstate the sample behind the last one.
    seeds_per_arm = {a: len({r["seed"] for r in rows if r["arm"] == a}) for a in arms}
    report: dict = {"seeds": max(seeds_per_arm.values(), default=0),
                    "seeds_per_arm": seeds_per_arm, "arms": {}}

    print("=" * 78)
    spa = ", ".join(f"{ARM_LABEL.get(a, a)}={n}" for a, n in seeds_per_arm.items())
    print(f"MULTI-SEED STATISTICAL REPORT   (independent traffic draws: {spa})")
    print("=" * 78)

    # ---- per-arm pooled recall + Wilson CI, plus per-seed distribution --------
    print("\nATTACK RECALL  (pooled across seeds, Wilson 95% CI)")
    print(f"  {'arm':>18}   recall  95% CI                per-seed mean +/- sd")
    for arm in arms:
        atk = [r for r in rows if r["arm"] == arm and r["label"] == "attack"]
        k = sum(1 for r in atk if r["diverted"])
        n = len(atk)
        p, lo, hi = wilson(k, n)
        # per-seed recalls
        per_seed = []
        for s in seeds:
            g = [r for r in atk if r["seed"] == s]
            if g:
                per_seed.append(sum(1 for r in g if r["diverted"]) / len(g))
        mean = sum(per_seed) / len(per_seed) if per_seed else 0.0
        sd = (sum((x - mean) ** 2 for x in per_seed) / (len(per_seed) - 1)) ** 0.5 if len(per_seed) > 1 else 0.0
        print(f"  {ARM_LABEL.get(arm, arm):>18}   {p:.3f}   [{lo:.3f}, {hi:.3f}]   n={n:<5}   {mean:.3f} +/- {sd:.3f}")
        report["arms"][arm] = {
            "recall_pooled": round(p, 4), "recall_ci95": [round(lo, 4), round(hi, 4)],
            "n_attack": n, "recall_per_seed_mean": round(mean, 4), "recall_per_seed_sd": round(sd, 4),
        }

    # ---- benign diversion (false-positive) rate per arm -----------------------
    print("\nBENIGN DIVERSION (false positive) rate  (pooled, Wilson 95% CI)")
    for arm in arms:
        ben = [r for r in rows if r["arm"] == arm and r["label"] == "benign"]
        k = sum(1 for r in ben if r["diverted"])
        print(f"  {ARM_LABEL.get(arm, arm):>18}   {_fmt_ci(k, len(ben))}")
        report["arms"][arm]["benign_diversion"] = {"k": k, "n": len(ben),
                                                    "rate_ci95": list(wilson(k, len(ben))[1:])}

    # ---- PAIRED McNemar: B2 vs B4 on attack detection -------------------------
    print("\nPAIRED TEST  B2 vs B4 attack detection  (McNemar exact; pairs = (seed, index))")
    mc = _mcnemar(rows, "b2_passive", "b4_full", stream="attack")
    if mc:
        print(f"  matched attack pairs      : {mc['pairs']}")
        print(f"  B4 catches, B2 misses (b) : {mc['b']}")
        print(f"  B2 catches, B4 misses (c) : {mc['c']}")
        print(f"  concordant                : {mc['concordant']}")
        print(f"  McNemar exact p           : {mc['p']:.4f}  {'(significant)' if mc['p'] < 0.05 else '(NOT significant)'}")
        report["mcnemar_b2_b4_attack"] = mc

    # ---- PAIRED McNemar on the uncertain subcategory --------------------------
    print("\nPAIRED TEST  B2 vs B4 on idor_html_scattered  (the uncertain band)")
    mcs = _mcnemar(rows, "b2_passive", "b4_full", stream="attack", subcat="idor_html_scattered")
    if mcs:
        print(f"  matched pairs             : {mcs['pairs']}")
        print(f"  B4 catches, B2 misses (b) : {mcs['b']}")
        print(f"  B2 catches, B4 misses (c) : {mcs['c']}")
        print(f"  McNemar exact p           : {mcs['p']:.4f}  {'(significant)' if mcs['p'] < 0.05 else '(NOT significant)'}")
        report["mcnemar_b2_b4_idor_html"] = mcs

    # ---- Randomised holdout: Fisher exact (the significant contribution) ------
    print("\nRANDOMISED HOLDOUT  baited vs withheld divert rate  (Fisher exact, pooled)")
    hd = _holdout(rows)
    if hd:
        print(f"  baited     : {hd['baited_div']}/{hd['baited_n']}  = {hd['baited_rate']:.3f}")
        print(f"  withheld   : {hd['holdout_div']}/{hd['holdout_n']} = {hd['holdout_rate']:.3f}")
        print(f"  effect     : {hd['effect']:+.3f}  bootstrap 95% CI [{hd['effect_ci'][0]:+.3f}, {hd['effect_ci'][1]:+.3f}]")
        print(f"  odds ratio : {hd['odds_ratio']:.2f}")
        print(f"  Fisher p   : {hd['p']:.5f}  {'(SIGNIFICANT)' if hd['p'] < 0.05 else '(not significant)'}")
        report["holdout_fisher"] = hd

    report["provenance"] = provenance(in_path, rows)

    # ---- the guard: never silently replace the canonical numbers ------------
    if problems:
        print("\n" + "!" * 78)
        print("DUMP IS NOT COMPLETE -- the analysis above cannot back the paper's claims:")
        for p in problems:
            print(f"  * {p}")
        print("!" * 78)
        if not args.allow_partial:
            print(f"\nREFUSING to overwrite {out_path} (it is what README/RESULTS quote).")
            print("A run may still be in flight -- check before assuming it died:")
            print("    python -m tools.stats_report --in <dump> --out /tmp/partial.json --allow-partial")
            print("To salvage a genuinely dead run into the canonical file, re-run with "
                  "--allow-partial.")
            raise SystemExit(2)
        report["partial"] = True
        report["partial_reasons"] = problems
        print("\n--allow-partial given: writing anyway, stamped partial:true.")

    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nwritten -> {out_path}")


def _pairs(rows: list[dict], arm_a: str, arm_b: str, stream: str, subcat: str | None = None):
    """Match sessions of two arms on (seed, index) within a stream."""
    def key(r):
        return (r["seed"], r["index"])
    A, B = {}, {}
    for r in rows:
        if r["stream"] != stream or r["index"] < 0:
            continue
        if subcat is not None and r["subcategory"] != subcat:
            continue
        if r["arm"] == arm_a:
            A[key(r)] = r
        elif r["arm"] == arm_b:
            B[key(r)] = r
    return [(A[k], B[k]) for k in A.keys() & B.keys()]


def _mcnemar(rows, arm_a, arm_b, stream, subcat=None) -> dict | None:
    pairs = _pairs(rows, arm_a, arm_b, stream, subcat)
    if not pairs:
        return None
    b = sum(1 for a, bb in pairs if (not a["diverted"]) and bb["diverted"])   # B wins
    c = sum(1 for a, bb in pairs if a["diverted"] and (not bb["diverted"]))   # A wins
    concordant = len(pairs) - b - c
    # McNemar exact: under H0 discordant pairs split 50/50 -> binomial test
    p = stats.binomtest(b, b + c, 0.5, alternative="two-sided").pvalue if (b + c) else 1.0
    return {"pairs": len(pairs), "b": b, "c": c, "concordant": concordant, "p": round(float(p), 6)}


def _holdout(rows) -> dict | None:
    baited = [r for r in rows if r["arm"] == "b4_full" and r["label"] == "attack" and r["assignment"] == "policy"]
    holdout = [r for r in rows if r["arm"] == "b4_full" and r["label"] == "attack" and r["assignment"] == "holdout"]
    if not baited or not holdout:
        return None
    bd = sum(1 for r in baited if r["diverted"])
    hd = sum(1 for r in holdout if r["diverted"])
    bn, hn = len(baited), len(holdout)
    # 2x2: rows = {baited, withheld}, cols = {diverted, not}
    table = [[bd, bn - bd], [hd, hn - hd]]
    odds, p = stats.fisher_exact(table, alternative="two-sided")
    effect = bd / bn - hd / hn
    lo, hi = _boot_diff([r["diverted"] for r in baited], [r["diverted"] for r in holdout])
    return {"baited_n": bn, "baited_div": bd, "baited_rate": round(bd / bn, 4),
            "holdout_n": hn, "holdout_div": hd, "holdout_rate": round(hd / hn, 4),
            "effect": round(effect, 4), "effect_ci": [round(lo, 4), round(hi, 4)],
            "odds_ratio": round(float(odds), 4), "p": round(float(p), 6)}


def _boot_diff(a: list[bool], b: list[bool], iters: int = 20000, seed: int = 7) -> tuple[float, float]:
    import random
    rng = random.Random(seed)
    a = [1 if x else 0 for x in a]
    b = [1 if x else 0 for x in b]
    diffs = []
    for _ in range(iters):
        sa = sum(a[rng.randrange(len(a))] for _ in range(len(a))) / len(a)
        sb = sum(b[rng.randrange(len(b))] for _ in range(len(b))) / len(b)
        diffs.append(sa - sb)
    diffs.sort()
    return diffs[int(0.025 * iters)], diffs[int(0.975 * iters)]


if __name__ == "__main__":
    main()
