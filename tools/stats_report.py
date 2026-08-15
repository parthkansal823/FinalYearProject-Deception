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
"""

from __future__ import annotations

import json
import math
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
    return phat, max(0.0, centre - half), min(1.0, centre + half)


def load() -> list[dict]:
    if not IN.exists():
        raise SystemExit(f"no session dump at {IN}; run `python -m tools.multiseed_eval` first")
    return [json.loads(l) for l in open(IN, encoding="utf-8") if l.strip()]


def _fmt_ci(k: int, n: int) -> str:
    p, lo, hi = wilson(k, n)
    return f"{p:.3f} [{lo:.3f}, {hi:.3f}]  (n={n})"


def main() -> None:
    rows = load()
    seeds = sorted({r["seed"] for r in rows})
    arms = [a for a in ARMS if any(r["arm"] == a for r in rows)]
    report: dict = {"seeds": len(seeds), "arms": {}}

    print("=" * 78)
    print(f"MULTI-SEED STATISTICAL REPORT   ({len(seeds)} independent traffic draws per arm)")
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

    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nwritten -> {OUT}")


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
