"""How much is the hand-set suspicion meter leaving on the table?

The meter is a logistic model over 18 features whose weights were written by
hand, from judgement about what hostile traffic looks like. That was the right
way to start -- it meant no label ever touched the detector, so nothing could be
tuned into the result. It also means nobody has ever checked what the same
features are capable of when the weights are fitted instead of asserted.

This measures that gap and nothing else. It fits standard models on the same
logged feature vectors, scores them on a draw they never saw, and compares them
against the shipped meter on the same requests. It does not modify the meter,
re-freeze anything, or touch a reported number. The output is one question
answered with a number: is refitting worth re-running the evaluation for?

Read the result carefully in one respect. A fitted model has seen labels and the
hand-set meter has not, so this is not a fair fight and is not meant to be. It is
an upper bound on what refitting could buy, measured honestly out-of-sample.

    python -m tools.meter_headroom
"""
from __future__ import annotations

import glob
import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

SPLIT = Path("data/eval/calibration")


def ece(y, q, nbins: int = 15) -> float:
    q = np.asarray(q, dtype=float)
    y = np.asarray(y, dtype=float)
    idx = np.minimum((q * nbins).astype(int), nbins - 1)
    out = 0.0
    for k in range(nbins):
        m = idx == k
        n = int(m.sum())
        if n:
            out += n / len(q) * abs(float(y[m].mean()) - float(q[m].mean()))
    return out


def load_draw(run_dir: Path, feature_names: list[str] | None):
    """Feature vectors, shipped belief and label for one COMPLETED draw."""
    logs = sorted(glob.glob(str(run_dir / "logs" / "proxy.*.jsonl")))
    lab = run_dir / "labels" / "eval_labels.jsonl"
    done = run_dir / "sessions.jsonl"
    if not logs or not lab.exists() or not done.exists() or done.stat().st_size == 0:
        return None, feature_names

    truth = {}
    with lab.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            truth[r["session_id"]] = r["ground_truth"]

    rows, ships, ys = [], [], []
    with open(logs[-1], encoding="utf-8") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("source") != "proxy":
                continue
            feats = r.get("features") or {}
            p = r.get("scores", {}).get("p_attack")
            g = truth.get(r.get("session", {}).get("provenance_id", ""))
            if p is None or g is None or not feats:
                continue
            if feature_names is None:
                feature_names = sorted(feats)
            # A draw that logged a different feature set is not comparable, and
            # padding it with zeros would quietly invent values for the missing
            # ones. Skip the request rather than fabricate it.
            if sorted(feats) != feature_names:
                continue
            rows.append([float(feats[k]) for k in feature_names])
            ships.append(float(p))
            ys.append(1 if g == "attack" else 0)

    if not rows:
        return None, feature_names
    return (np.array(rows), np.array(ships), np.array(ys)), feature_names


def main() -> None:
    draws, names = {}, None
    for run_dir in sorted(SPLIT.glob("s*")):
        d, names = load_draw(run_dir, names)
        if d is not None:
            draws[run_dir.name] = d

    if len(draws) < 2:
        raise SystemExit(
            "need at least two completed calibration draws: one to fit on and "
            "one the fitted model has never seen. Run tools.calibration_split.")

    print("draws: %s   features: %d   requests: %d"
          % (", ".join(sorted(draws)), len(names),
             sum(len(y) for _, _, y in draws.values())))
    print()

    MODELS = {
        "logistic (fitted)": lambda: make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=5000, C=1.0)),
        "gradient boosting": lambda: HistGradientBoostingClassifier(
            max_iter=300, learning_rate=0.1, random_state=0),
    }

    scores = {k: {"auc": [], "ece": [], "brier": []}
              for k in ["meter (shipped)", *MODELS]}

    for held in sorted(draws):
        Xtr = np.vstack([draws[k][0] for k in draws if k != held])
        ytr = np.concatenate([draws[k][2] for k in draws if k != held])
        Xte, ship_te, yte = draws[held]
        if len(np.unique(yte)) < 2:
            continue

        scores["meter (shipped)"]["auc"].append(roc_auc_score(yte, ship_te))
        scores["meter (shipped)"]["ece"].append(ece(yte, ship_te))
        scores["meter (shipped)"]["brier"].append(brier_score_loss(yte, ship_te))

        for name, build in MODELS.items():
            m = build()
            m.fit(Xtr, ytr)
            q = m.predict_proba(Xte)[:, 1]
            scores[name]["auc"].append(roc_auc_score(yte, q))
            scores[name]["ece"].append(ece(yte, q))
            scores[name]["brier"].append(brier_score_loss(yte, q))

    print("leave-one-draw-out, scored only on the withheld draw:")
    print("  model                  AUC       ECE      Brier")
    print("  " + "-" * 48)
    for name in ["meter (shipped)", *MODELS]:
        s = scores[name]
        if not s["auc"]:
            continue
        print("  %-20s %.4f    %.4f    %.4f"
              % (name, np.mean(s["auc"]), np.mean(s["ece"]), np.mean(s["brier"])))

    base = np.mean(scores["meter (shipped)"]["auc"])
    best = max(np.mean(scores[n]["auc"]) for n in MODELS)
    print()
    print("  headroom in AUC: %.4f -> %.4f  (%+.4f)" % (base, best, best - base))
    if best - base < 0.01:
        print("  The hand-set weights are already close to what these features")
        print("  support. Refitting the meter would not repay re-running the")
        print("  evaluation, and the honest report is that the gap is small.")
    else:
        print("  The features carry more signal than the hand-set weights extract.")
        print("  Refitting is worth doing -- and costs a re-freeze of the meter")
        print("  plus a full re-run of every arm, because every reported number")
        print("  was produced under the current weights.")


if __name__ == "__main__":
    main()
