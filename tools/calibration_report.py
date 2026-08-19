"""Compare the derived policy against hand-set edges and against itself calibrated.

Three things are being separated here, and conflating any two of them produces a
misleading verdict:

  1. Is the belief a probability?  Measured on a held-out split by
     `tools.fit_calibration`, and it is not: the meter is over-confident below
     about 0.6 and under-confident above it.
  2. Do the derived edges beat hand-set ones?  The fixed-threshold sweep.
  3. Would fixing (1) fix (2)?  This report, which measures the derived edges
     applied to a calibrated belief.

(3) needs no change to any frozen artefact. A calibration map is monotone, so
running the derived edges on a calibrated belief is arithmetically the same policy
as running the inverse-mapped edges on the raw belief -- which the existing
`b5_fixed` arm already implements. The calibrated arm is therefore an ordinary
member of the sweep, run on the same seeds as every other arm.

Everything is paired: the ablation arms and the derived arm share seeds, and
within a seed the traffic is generated in a fixed order, so session i of a stream
is the same session in every arm.

    python -m tools.calibration_report
"""
from __future__ import annotations

import json
import math
from pathlib import Path

FIXED = Path("data/eval/fixed_threshold")
DERIVED_DUMP = Path("data/eval/curious/sessions.jsonl")
DERIVED_ARM = "b4_full"
CALIBRATION = Path("data/eval/calibration/calibration.json")

COST = {("attack", "divert"): -20.0, ("attack", "bait"): 25.0, ("attack", "pass"): 25.0,
        ("benign", "divert"): 200.0, ("benign", "bait"): 1.0, ("benign", "pass"): 0.0}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    ph = k / n
    d = 1 + z * z / n
    c = (ph + z * z / (2 * n)) / d
    h = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact binomial p on the discordant pairs."""
    n = b + c
    if n == 0:
        return 1.0
    from math import comb
    obs = min(b, c)
    tail = sum(comb(n, k) for k in range(0, obs + 1)) / (2.0 ** n)
    return min(1.0, 2.0 * tail)


def action_of(r: dict) -> str:
    if r.get("diverted"):
        return "divert"
    return "bait" if r.get("baited") else "pass"


def load(path: Path, arm: str | None = None, seeds: set[int] | None = None):
    """(seed, stream, index) -> row, for one arm."""
    out = {}
    if not path.exists():
        return out
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if arm is not None and r.get("arm") != arm:
                continue
            if seeds is not None and r.get("seed") not in seeds:
                continue
            out[(r["seed"], r["stream"], r["index"])] = r
    return out


def summarise(rows: dict) -> dict:
    per_seed: dict[int, list[float]] = {}
    n_att = n_ben = caught = ben_div = ben_bait = 0
    for (seed, _, _), r in rows.items():
        g = r["label"]
        per_seed.setdefault(seed, []).append(COST[(g, action_of(r))])
        if g == "attack":
            n_att += 1
            caught += bool(r.get("diverted"))
        else:
            n_ben += 1
            ben_div += bool(r.get("diverted"))
            ben_bait += bool(r.get("baited")) and not bool(r.get("diverted"))
    means = [sum(v) / len(v) for v in per_seed.values()]
    mu = sum(means) / len(means)
    sd = (math.sqrt(sum((m - mu) ** 2 for m in means) / (len(means) - 1))
          if len(means) > 1 else 0.0)
    se = sd / math.sqrt(len(means)) if means else 0.0
    return {"n_seeds": len(per_seed), "cost": mu, "cost_lo": mu - 1.96 * se,
            "cost_hi": mu + 1.96 * se, "recall": caught / n_att if n_att else 0.0,
            "recall_ci": wilson(caught, n_att), "n_att": n_att, "n_ben": n_ben,
            "ben_div": ben_div, "ben_div_ci": wilson(ben_div, n_ben),
            "ben_bait": ben_bait / n_ben if n_ben else 0.0}


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="Derived vs hand-set vs calibrated edges.")
    ap.add_argument("--fixed", default=str(FIXED),
                    help="directory holding arms.json and the per-arm dumps")
    ap.add_argument("--derived", default=str(DERIVED_DUMP),
                    help="session dump containing the derived arm")
    ap.add_argument("--calibration", default=str(CALIBRATION),
                    help="calibration.json, used to label the calibrated arm")
    args = ap.parse_args()

    fixed_root = Path(args.fixed)
    derived_dump = Path(args.derived)
    calibration = Path(args.calibration)

    index = fixed_root / "arms.json"
    if not index.exists():
        raise SystemExit("no " + str(index) + "; run tools.parallel_ablation "
                         "(or tools.fixed_threshold_sweep) first")
    arms = json.loads(index.read_text(encoding="utf-8"))

    cal_edges = None
    if calibration.exists():
        cal = json.loads(calibration.read_text(encoding="utf-8"))
        e = cal["equivalent_raw_edges"]
        cal_edges = (e["pass_to_bait"], e["bait_to_divert"])

    loaded = {}
    for a in arms:
        rows = load(Path(a["dump"]))
        if rows:
            loaded[(a["lo"], a["hi"])] = rows
    if not loaded:
        raise SystemExit("no arm dumps could be read")

    # Pair on seeds every arm actually completed, the derived arm included. The
    # main evaluation discarded one seed to a resource fault, so the derived arm
    # has 19 where the ablation has 20; comparing per-seed cost across a
    # different set of draws is a comparison of the draws as much as of the arms.
    derived_all = load(derived_dump, DERIVED_ARM)
    if not derived_all:
        raise SystemExit(
            "the derived arm is missing from " + str(derived_dump) + ". Without it "
            "there is nothing to compare the hand-set edges against, and reporting "
            "the fixed arms alone would compare them only to each other.")
    seeds = set.intersection(*[{k[0] for k in r} for r in loaded.values()],
                             {k[0] for k in derived_all})
    dropped = set.union(*[{k[0] for k in r} for r in loaded.values()]) - seeds
    if dropped:
        print("dropping %d seed(s) not present in every arm: %s"
              % (len(dropped), ", ".join(str(s) for s in sorted(dropped))))
    derived = {k: v for k, v in derived_all.items() if k[0] in seeds}

    rows_out = []
    for (lo, hi), rows in loaded.items():
        rows = {k: v for k, v in rows.items() if k[0] in seeds}
        tag = "fixed"
        if cal_edges and abs(lo - cal_edges[0]) < 1e-4 and abs(hi - cal_edges[1]) < 1e-4:
            tag = "DERIVED, calibrated belief"
        rows_out.append((summarise(rows), "[%.4f, %.4f]" % (lo, hi), tag))
    rows_out.append((summarise(derived), "[derived edges]", "DERIVED, as shipped"))
    rows_out.sort(key=lambda t: t[0]["cost"])

    print("paired over %d seeds, %d sessions per arm"
          % (len(seeds), len(derived)))
    print()
    print("  edges (raw belief)   note                        cost/session"
          "        recall            benign diverted")
    print("  " + "-" * 108)
    for s, edges, tag in rows_out:
        print("  %-20s %-27s %7.3f [%7.3f,%7.3f]  %.4f [%.4f,%.4f]  %3d/%d"
              % (edges, tag, s["cost"], s["cost_lo"], s["cost_hi"],
                 s["recall"], s["recall_ci"][0], s["recall_ci"][1],
                 s["ben_div"], s["n_ben"]))

    # --- paired test: derived as shipped vs derived on a calibrated belief ----
    cal_rows = None
    if cal_edges:
        for (lo, hi), rows in loaded.items():
            if abs(lo - cal_edges[0]) < 1e-4 and abs(hi - cal_edges[1]) < 1e-4:
                cal_rows = {k: v for k, v in rows.items() if k[0] in seeds}
    if cal_rows:
        keys = [k for k in derived if k in cal_rows]
        b = sum(1 for k in keys
                if derived[k]["label"] == "attack"
                and derived[k]["diverted"] and not cal_rows[k]["diverted"])
        c = sum(1 for k in keys
                if derived[k]["label"] == "attack"
                and not derived[k]["diverted"] and cal_rows[k]["diverted"])
        print()
        print("paired McNemar on attack sessions, shipped vs calibrated belief:")
        print("  caught by shipped only   : %d" % b)
        print("  caught by calibrated only: %d" % c)
        print("  exact two-sided p        : %.3g" % mcnemar_exact(b, c))

        d_s = summarise(derived)
        d_c = summarise(cal_rows)
        print()
        print("break-even on the one price this verdict turns on:")
        att = d_s["n_att"] / (d_s["n_att"] + d_s["n_ben"])
        ben = 1.0 - att

        def cost_at(s, price):
            return (att * (s["recall"] * -20.0 + (1 - s["recall"]) * 25.0)
                    + ben * (s["ben_div"] / s["n_ben"] * price + s["ben_bait"] * 1.0))

        lo_p, hi_p = 0.0, 100000.0
        for _ in range(200):
            mid = (lo_p + hi_p) / 2
            if cost_at(d_c, mid) < cost_at(d_s, mid):
                lo_p = mid
            else:
                hi_p = mid
        print("  benign diversion is priced at 200.0 in the frozen table.")
        print("  calibrating wins whenever that price is below %.1f." % lo_p)
        print("  margin: %.1f%%" % (100 * (200.0 - lo_p) / lo_p))


if __name__ == "__main__":
    main()
