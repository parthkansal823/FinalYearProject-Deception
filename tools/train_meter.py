"""
Train the dual suspicion meter on the round-1 corpus (spec §13 Phase 3, §6.4).

This is the fitting step for baseline B2 -- the passive classifier the whole
project must beat. It:

  1. assembles the labelled corpus and keeps ONLY the `train` round (spec §7.2:
     the meter is fit on round 1 and nothing else; touching `eval` here would
     invalidate every reported number);
  2. replays each session through the streaming feature extractor to get the
     per-request cumulative vectors the live proxy would see;
  3. broadcasts each session's ground truth to its requests and fits the two
     heads;
  4. reports interpretable weights and train-set separation, and saves the
     frozen model.

The train-set numbers printed here are a sanity check, NOT a result. Real
precision/recall come from the held-out `eval` round in Phase 7, against a
model frozen before it ever sees that traffic.
"""

from __future__ import annotations

import argparse
import glob as globmod

from adf.config import system
from adf.dataset import build, iter_sessions
from adf.features import SessionFeatureExtractor
from adf.meter import DualMeter

TRAIN_ROUND = "train"


def build_training_matrix(corpus):
    """Return (vectors, automation_labels, malice_labels) at per-request
    granularity. Labels are session truth broadcast to each request."""
    vectors, autos, malices = [], [], []
    n_sessions = 0
    for _, session in iter_sessions(corpus):
        head = session[0]
        if head.labels.ground_truth == "unknown":
            continue
        if head.labels.automation_label not in ("human", "scripted"):
            continue  # hybrid/unknown carry no clean automation target
        n_sessions += 1
        malice_label = 1 if head.labels.ground_truth == "attack" else 0
        automation_label = 1 if head.labels.automation_label == "scripted" else 0

        extractor = SessionFeatureExtractor()
        for record in session:
            vectors.append(extractor.observe(record))
            autos.append(automation_label)
            malices.append(malice_label)
    return vectors, autos, malices, n_sessions


def _axis_accuracy(meter, vectors, labels, axis: str) -> float:
    correct = 0
    for v, y in zip(vectors, labels, strict=True):
        s = meter.score(v)
        p = s.automation if axis == "automation" else s.malice
        correct += int((p >= 0.5) == bool(y))
    return correct / len(labels) if labels else 0.0


def _print_top_weights(head, title: str, k: int = 8) -> None:
    print(f"\n  {title} — most influential features (standardised weight):")
    ranked = sorted(zip(head.feature_names, head.weights, strict=True),
                    key=lambda t: abs(t[1]), reverse=True)
    for name, w in ranked[:k]:
        arrow = "-> hostile/scripted" if w > 0 else "-> benign/human"
        print(f"    {name:26} {w:+7.3f}  {arrow}")


def main() -> None:
    cfg = system()
    ap = argparse.ArgumentParser(description="Fit the dual suspicion meter (baseline B2).")
    ap.add_argument("--logs", default=str(cfg.log_dir / "*.jsonl"))
    ap.add_argument("--labels", default=str(cfg.label_dir / "*.jsonl"))
    ap.add_argument("--out", default="data/models/meter.json")
    ap.add_argument("--C", type=float, default=1.0, help="inverse L2 regularisation strength")
    ap.add_argument("--seed", type=int, default=cfg.seed)
    ap.add_argument("--allow-nontrain", action="store_true",
                    help="DANGER: fit on rounds other than `train`; violates spec §7.2")
    args = ap.parse_args()

    corpus, coverage = build(sorted(globmod.glob(args.logs)),
                             sorted(globmod.glob(args.labels)), strict=False)

    # Round hygiene: keep only the training round unless explicitly overridden.
    kept = [r for r in corpus if r.run.round == TRAIN_ROUND]
    dropped_rounds = {r.run.round for r in corpus} - {TRAIN_ROUND}
    if args.allow_nontrain:
        kept = corpus
        print("!! --allow-nontrain: fitting on ALL rounds; this violates spec §7.2\n")
    elif dropped_rounds:
        print(f"keeping round='{TRAIN_ROUND}' only; dropped rounds {sorted(dropped_rounds)} (spec §7.2)")

    vectors, autos, malices, n_sessions = build_training_matrix(kept)
    if not vectors:
        raise SystemExit("no training data found. Generate the corpus first "
                         "(python -m tools.generate_corpus).")

    print(f"training on {n_sessions} sessions, {len(vectors)} request-level examples")
    print(f"  automation: {sum(autos)} scripted / {len(autos) - sum(autos)} human")
    print(f"  malice    : {sum(malices)} attack / {len(malices) - sum(malices)} benign")

    meter = DualMeter()
    meter.fit(vectors, autos, malices, C=args.C, seed=args.seed)

    if not meter.fitted:
        print("\n!! at least one axis had a single class; the meter is only partially fit.")

    _print_top_weights(meter.automation, "AUTOMATION axis")
    _print_top_weights(meter.malice, "MALICE axis")

    auto_acc = _axis_accuracy(meter, vectors, autos, "automation")
    mal_acc = _axis_accuracy(meter, vectors, malices, "malice")
    print(f"\n  train-set accuracy (sanity only, NOT a result):")
    print(f"    automation {auto_acc:.3f}   malice {mal_acc:.3f}")

    meter.save(args.out)
    print(f"\nfrozen meter written to {args.out}")
    print("This is baseline B2. Do not refit it on eval data (spec §7.2).")


if __name__ == "__main__":
    main()
