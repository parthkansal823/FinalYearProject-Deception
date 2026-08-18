"""Fit and report a calibration map for the suspicion meter's belief.

The policy treats `p_attack` as a probability: every band edge is a probability
threshold derived from the frozen cost table. The meter that produces it is a
hand-weighted logistic model that was never fitted to labels, so whether its
output is calibrated is an open empirical question -- and if it is not, the edges
do not land where the derivation intends.

Three maps are fitted and compared, because picking a method by preference is how
a calibration study talks itself into whichever answer it started with:

  * Platt      sigmoid(a*logit(p) + b).  Two parameters, and the same functional
               form the fusion block already declares, so adopting it would be a
               change of two numbers rather than a new layer.
  * Beta       sigmoid(a*log(p) - b*log(1-p) + c).  Three parameters; unlike
               Platt it can bend the two tails by different amounts, which is
               what a belief that is over-confident low and under-confident high
               actually needs.
  * Isotonic   the non-parametric monotone fit. Strictly the most expressive, and
               strictly the most able to memorise a small split.

Selection is by leave-one-draw-out held-out ECE, never by fit on the data the
number is quoted from. Expressiveness that does not survive a withheld draw is
memorisation and is reported as such.

Nothing here is written back into a frozen artefact. The map is reported, and its
consequence is measured through the existing `b5_fixed` arm: every candidate map
is monotone, so running the derived edges on a calibrated belief is arithmetically
identical to running inverse-mapped edges on the raw belief. That equivalence lets
the calibrated policy be evaluated without re-freezing anything.

    python -m tools.fit_calibration
"""
from __future__ import annotations

import glob
import json
import math
from pathlib import Path

import numpy as np
from scipy.optimize import minimize
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression

from adf.config import load_costs
from adf.policy.engine import BaitLibrary
from adf.policy.voi import derive_bands

SPLIT = Path("data/eval/calibration")
EPS = 1e-6


def _clip(p):
    return np.clip(np.asarray(p, dtype=float), EPS, 1.0 - EPS)


def logit(p):
    p = _clip(p)
    return np.log(p / (1.0 - p))


def sigmoid(z):
    # Branch on the sign rather than exponentiating a large positive number:
    # a slope near 3 applied to logit(1e-6) overflows the naive form, and the
    # RuntimeWarning it raises is easy to scroll past in a long fit log.
    z = np.asarray(z, dtype=float)
    out = np.empty_like(z)
    pos = z >= 0
    out[pos] = 1.0 / (1.0 + np.exp(-z[pos]))
    e = np.exp(z[~pos])
    out[~pos] = e / (1.0 + e)
    return out


# ---------------------------------------------------------------------------
# Candidate maps. Each fit_* returns a callable raw belief -> calibrated belief.
# ---------------------------------------------------------------------------


def fit_identity(p, y):
    """What the system ships: the meter's output used as-is."""
    return lambda q: _clip(q)


def fit_platt(p, y):
    lr = LogisticRegression(C=1e10, solver="lbfgs")
    lr.fit(logit(p).reshape(-1, 1), y)
    a = float(lr.coef_[0][0])
    b = float(lr.intercept_[0])
    f = lambda q: sigmoid(a * logit(q) + b)
    f.params = {"w_malice": a, "bias": b}
    return f


def fit_beta(p, y):
    """Kull, Silva Filho & Flach (2017): a logistic in (log p, log(1-p)).

    The extra parameter buys independent control of the two tails, which is the
    degree of freedom Platt lacks and this belief appears to need.
    """
    lp = np.log(_clip(p))
    l1p = np.log(1.0 - _clip(p))
    yv = np.asarray(y, dtype=float)

    def nll(t):
        a, b, c = t
        z = a * lp - b * l1p + c
        # log-sum-exp form: stable for the large |z| this belief produces
        return float(np.mean(np.logaddexp(0.0, z) - yv * z))

    best = None
    for start in ([1.0, 1.0, 0.0], [2.0, 2.0, 0.0], [0.5, 0.5, 0.0]):
        r = minimize(nll, start, method="Nelder-Mead",
                     options={"maxiter": 20000, "xatol": 1e-10, "fatol": 1e-12})
        if best is None or r.fun < best.fun:
            best = r
    a, b, c = (float(v) for v in best.x)
    f = lambda q: sigmoid(a * np.log(_clip(q)) - b * np.log(1.0 - _clip(q)) + c)
    f.params = {"a": a, "b": b, "c": c}
    return f


def fit_isotonic(p, y):
    iso = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip")
    iso.fit(np.asarray(p, dtype=float), np.asarray(y, dtype=float))
    f = lambda q: np.clip(iso.predict(np.atleast_1d(np.asarray(q, dtype=float))),
                          EPS, 1.0 - EPS)
    f.params = {"knots": int(len(np.unique(iso.f_.x)))}
    return f


METHODS = [("shipped (identity)", fit_identity),
           ("Platt", fit_platt),
           ("Beta", fit_beta),
           ("Isotonic", fit_isotonic)]


# ---------------------------------------------------------------------------


def ece_brier(p, y, f, nbins: int = 15):
    q = np.atleast_1d(f(p))
    y = np.asarray(y, dtype=float)
    idx = np.minimum((q * nbins).astype(int), nbins - 1)
    ece = 0.0
    for k in range(nbins):
        m = idx == k
        n = int(m.sum())
        if n:
            ece += n / len(q) * abs(float(y[m].mean()) - float(q[m].mean()))
    return ece, float(np.mean((q - y) ** 2))


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 1.0)
    ph = k / n
    d = 1 + z * z / n
    c = (ph + z * z / (2 * n)) / d
    h = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def load_draw(run_dir: Path):
    """(belief, is_attack) for every scored request in one COMPLETED draw.

    The proxy log is appended to while a draw is still running, so a directory
    that is mid-flight parses perfectly and yields a truncated, unrepresentative
    sample -- weighted towards the early requests of every session, which is
    exactly where the belief has not moved yet. `sessions.jsonl` is written once
    at the end of a draw, so its presence is what marks the draw as finished.
    """
    logs = sorted(glob.glob(str(run_dir / "logs" / "proxy.*.jsonl")))
    lab = run_dir / "labels" / "eval_labels.jsonl"
    done = run_dir / "sessions.jsonl"
    if not logs or not lab.exists():
        return []
    if not done.exists() or done.stat().st_size == 0:
        print("  skipping " + run_dir.name + ": still running (no sessions.jsonl). "
              "Fitting on a partial draw would bias the map toward early requests.")
        return []
    truth = {}
    with lab.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            truth[r["session_id"]] = r["ground_truth"]

    out = []
    with open(logs[-1], encoding="utf-8") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("source") != "proxy":
                continue
            p = r.get("scores", {}).get("p_attack")
            g = truth.get(r.get("session", {}).get("provenance_id", ""))
            if p is None or g is None:
                continue
            out.append((float(p), 1 if g == "attack" else 0))
    return out


def invert(f, edge: float) -> float:
    """Smallest raw belief whose calibrated value reaches `edge`.

    Written for a general monotone map rather than by algebra, so it holds for
    the isotonic fit and its flat regions as well as for the parametric ones.
    """
    grid = np.linspace(EPS, 1.0 - EPS, 200001)
    vals = np.atleast_1d(f(grid))
    hit = np.searchsorted(vals, edge, side="left")
    if hit >= len(grid):
        return float("nan")
    return float(grid[hit])


def main() -> None:
    draws = {}
    for run_dir in sorted(SPLIT.glob("s*")):
        pairs = load_draw(run_dir)
        if pairs:
            draws[run_dir.name] = pairs
    if not draws:
        raise SystemExit(
            "no calibration draws found under " + str(SPLIT) + ". "
            "Run `python -m tools.calibration_split` first.")

    arrays = {k: (np.array([p for p, _ in v]), np.array([y for _, y in v]))
              for k, v in draws.items()}
    P = np.concatenate([a for a, _ in arrays.values()])
    Y = np.concatenate([b for _, b in arrays.values()])

    print("calibration split: %d draw(s), %d scored requests" % (len(draws), len(P)))
    print("base rate P(attack) = %.4f" % Y.mean())
    print("held out from the evaluation by construction: these draws use seeds")
    print("far below the evaluation range, so nothing fitted here is reported on.")
    print()

    # --- method selection, by leave-one-draw-out held-out ECE -----------------
    if len(draws) < 2:
        raise SystemExit(
            "only one calibration draw is present. Selecting a calibration map "
            "needs at least two, or the more expressive map wins by memorising "
            "the single draw it was fitted on. Re-run calibration_split.")

    print("leave-one-draw-out selection (lower is better, held-out only):")
    print("  method               held-out ECE     held-out Brier")
    cv = {}
    for name, fit in METHODS:
        eces, briers = [], []
        for held in sorted(arrays):
            tp = np.concatenate([arrays[k][0] for k in arrays if k != held])
            ty = np.concatenate([arrays[k][1] for k in arrays if k != held])
            f = fit(tp, ty)
            e, b = ece_brier(*arrays[held], f)
            eces.append(e)
            briers.append(b)
        cv[name] = (float(np.mean(eces)), float(np.mean(briers)),
                    float(np.std(eces)))
        print("  %-18s %.4f +- %.4f    %.4f"
              % (name, cv[name][0], cv[name][2], cv[name][1]))

    chosen = min((n for n, _ in METHODS if n != "shipped (identity)"),
                 key=lambda n: cv[n][0])
    shipped_ece = cv["shipped (identity)"][0]
    print()
    print("  selected: %s  (held-out ECE %.4f vs %.4f as shipped, %+.1f%%)"
          % (chosen, cv[chosen][0], shipped_ece,
             100 * (cv[chosen][0] - shipped_ece) / shipped_ece))

    fit_fn = dict((n, f) for n, f in METHODS)[chosen]
    f = fit_fn(P, Y)
    print("  refitted on all %d draws: %s" % (len(draws), getattr(f, "params", {})))
    print()

    # --- reliability of what the system currently ships -----------------------
    EDGES = [0.0, 0.05, 0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70,
             0.80, 0.85, 0.90, 0.95, 1.01]
    print("reliability of the shipped belief:")
    print("  belief bin          n    mean belief   actual   95% CI on actual")
    for k in range(len(EDGES) - 1):
        m = (P >= EDGES[k]) & (P < EDGES[k + 1])
        n = int(m.sum())
        if not n:
            continue
        mp = float(P[m].mean())
        na = int(Y[m].sum())
        lo, hi = wilson(na, n)
        flag = "OVER" if hi < mp else ("UNDER" if lo > mp else "")
        print("  [%.2f, %.2f) %8d      %.4f     %.4f   [%.3f, %.3f] %s"
              % (EDGES[k], EDGES[k + 1], n, mp, na / n, lo, hi, flag))
    print()

    # --- what this means for the derived edges --------------------------------
    bands = derive_bands(load_costs(), BaitLibrary.load().effects())
    lo_e, hi_e = bands["pass_to_bait"], bands["bait_to_divert"]
    raw_lo, raw_hi = invert(f, lo_e), invert(f, hi_e)

    print("the derived edges are thresholds on a probability. Applied to a")
    print("calibrated belief they sit at these RAW meter values, which is what")
    print("the b5_fixed arm needs in order to measure the calibrated policy:")
    print("  PASS->BAIT     %.4f  ->  raw %.4f" % (lo_e, raw_lo))
    print("  BAIT->DIVERT   %.4f  ->  raw %.4f" % (hi_e, raw_hi))
    print()
    print("measure it with:")
    print("  python -m tools.fixed_threshold_sweep --seeds 20 --port-base 9700 \\")
    print("      --grid " + chr(34) + "%.4f,%.4f" % (raw_lo, raw_hi) + chr(34))

    out = {
        "selected": chosen,
        "params": getattr(f, "params", {}),
        "selection": {n: {"heldout_ece": cv[n][0], "heldout_ece_sd": cv[n][2],
                          "heldout_brier": cv[n][1]} for n in cv},
        "split": {"draws": len(draws), "requests": int(len(P)),
                  "dirs": sorted(draws)},
        "derived_edges": {"pass_to_bait": lo_e, "bait_to_divert": hi_e},
        "equivalent_raw_edges": {"pass_to_bait": raw_lo, "bait_to_divert": raw_hi},
        "note": "Reported, not applied. config/costs.yaml is unchanged; the "
                "calibrated policy is measured through b5_fixed at the "
                "equivalent raw edges, which is arithmetically the same policy "
                "because every candidate map is monotone.",
    }
    (SPLIT / "calibration.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print()
    print("wrote " + str(SPLIT / "calibration.json"))


if __name__ == "__main__":
    main()
