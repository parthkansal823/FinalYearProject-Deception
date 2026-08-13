"""
Corpus characterisation — the evidence for Phase 1's exit condition.

Spec §13 Phase 1 requires that benign traffic be *verified* to look realistic
in the logs, not merely generated. "Looks realistic" has to be turned into
numbers to be checkable, so this reports the distributions that the Phase 3
feature extractor will later depend on, split by ground truth and automation
label.

The headline table is inter-request timing regularity. Spec §6.3 asserts that
"Humans are irregular; scripts are metronomic" and makes it the first
automation feature. If that separation is not visible here, the feature will
not work in Phase 3 either, and it is far cheaper to discover now.

This is also the reusable skeleton for the Phase 7 figures, so the statistics
are computed per class rather than in aggregate.
"""

from __future__ import annotations

import argparse
import glob as globmod
import statistics
from collections import Counter, defaultdict
from datetime import datetime

from adf.config import system
from adf.dataset import build, iter_sessions
from adf.schema import Record

STATIC_PREFIX = "/static/"


def _parse_ts(value: str) -> float:
    return datetime.fromisoformat(value).timestamp()


def _gaps(session: list[Record]) -> list[float]:
    times = sorted(_parse_ts(r.ts) for r in session if r.ts)
    return [b - a for a, b in zip(times, times[1:])]


def _cv(values: list[float]) -> float | None:
    """Coefficient of variation: stdev / mean.

    This, rather than the mean gap alone, is what separates a human from a
    script. A fast human and a slow script can share a mean; they cannot
    easily share a CV, because a scheduler ticks and a person does not.
    """
    usable = [v for v in values if v > 0]
    if len(usable) < 3:
        return None
    mean = statistics.fmean(usable)
    if mean <= 0:
        return None
    return statistics.pstdev(usable) / mean


def _summary(values: list[float]) -> str:
    if not values:
        return "n/a"
    values = sorted(values)
    return (f"median={statistics.median(values):6.3f}  "
            f"p10={values[int(0.1 * (len(values) - 1))]:6.3f}  "
            f"p90={values[int(0.9 * (len(values) - 1))]:6.3f}  n={len(values)}")


def report(corpus: list[Record]) -> None:
    by_class: dict[tuple[str, str], list[list[Record]]] = defaultdict(list)
    for _, session in iter_sessions(corpus):
        head = session[0]
        by_class[(head.labels.ground_truth, head.labels.automation_label)].append(session)

    print("=" * 78)
    print("CORPUS CHARACTERISATION")
    print("=" * 78)

    print(f"\nrecords : {len(corpus)}")
    print(f"sessions: {sum(len(v) for v in by_class.values())}")
    print("\nby class:")
    for (truth, automation), sessions in sorted(by_class.items()):
        n_req = sum(len(s) for s in sessions)
        print(f"  {truth:<8} / {automation:<8}  {len(sessions):>4} sessions, {n_req:>6} requests")

    # ---------------------------------------------------------------
    # The claim of spec §6.3, made checkable
    # ---------------------------------------------------------------
    print("\n" + "-" * 78)
    print("TIMING REGULARITY  (spec §6.3: humans are irregular, scripts are metronomic)")
    print("-" * 78)
    print("Coefficient of variation of inter-request gaps. HIGHER = more irregular.")
    print("A clear separation here is what makes the automation axis learnable.\n")

    cv_by_class: dict[str, list[float]] = {}
    for (truth, automation), sessions in sorted(by_class.items()):
        cvs = [c for c in (_cv(_gaps(s)) for s in sessions) if c is not None]
        cv_by_class[f"{truth}/{automation}"] = cvs
        print(f"  {truth:<8} / {automation:<8}  CV  {_summary(cvs)}")

    human = cv_by_class.get("benign/human", [])
    scripted = cv_by_class.get("benign/scripted", [])
    if human and scripted:
        h, s = statistics.median(human), statistics.median(scripted)
        print(f"\n  human median CV = {h:.3f}   scripted median CV = {s:.3f}")
        if h > s * 1.5:
            print("  -> SEPARATED: irregularity distinguishes humans from scripts, as spec §6.3 predicts.")
        else:
            print("  -> NOT SEPARATED. Either the generators pace too similarly, or the corpus")
            print("     was generated with --no-dwell, in which case timing features are")
            print("     meaningless and Phase 3 must not be trained on it.")

    print("\n  inter-request gap, seconds:")
    for (truth, automation), sessions in sorted(by_class.items()):
        allgaps = [g for s in sessions for g in _gaps(s)]
        print(f"    {truth:<8} / {automation:<8}  {_summary(allgaps)}")

    # ---------------------------------------------------------------
    # Asset fetching -- the other strong automation signal (§6.1)
    # ---------------------------------------------------------------
    print("\n" + "-" * 78)
    print("STATIC ASSET FETCHING  (spec §6.1: browsers fetch assets, tools usually do not)")
    print("-" * 78)
    for (truth, automation), sessions in sorted(by_class.items()):
        ratios = []
        for s in sessions:
            assets = sum(1 for r in s if r.request.path.startswith(STATIC_PREFIX))
            pages = len(s) - assets
            if pages:
                ratios.append(assets / pages)
        print(f"  {truth:<8} / {automation:<8}  assets/page  {_summary(ratios)}")

    # ---------------------------------------------------------------
    # Sequential id access -- the IDOR signal, and its hard negative
    # ---------------------------------------------------------------
    print("\n" + "-" * 78)
    print("SEQUENTIAL ID ACCESS  (the IDOR signal — and its benign look-alike)")
    print("-" * 78)
    print("Longest run of consecutive ids touched within a session.")
    print("The reporting-integration agent scores high here while being entirely")
    print("benign; that is deliberate, and it is what stops the meter from")
    print("learning 'sequential = hostile' (spec §6.3).\n")

    import re

    for (truth, automation), sessions in sorted(by_class.items()):
        runs = []
        for s in sessions:
            ids = []
            for r in s:
                m = re.search(r"/(?:api/)?(?:records|profile)/(\d+)", r.request.path)
                if m:
                    ids.append(int(m.group(1)))
            best = current = 1 if ids else 0
            for a, b in zip(ids, ids[1:]):
                current = current + 1 if b == a + 1 else 1
                best = max(best, current)
            runs.append(float(best))
        print(f"  {truth:<8} / {automation:<8}  longest run  {_summary(runs)}")

    # ---------------------------------------------------------------
    # Session shape and outcomes
    # ---------------------------------------------------------------
    print("\n" + "-" * 78)
    print("SESSION SHAPE AND RESPONSES")
    print("-" * 78)
    for (truth, automation), sessions in sorted(by_class.items()):
        lengths = [float(len(s)) for s in sessions]
        print(f"  {truth:<8} / {automation:<8}  requests/session  {_summary(lengths)}")

    statuses = Counter(r.response.status for r in corpus)
    print("\n  status codes: " + ", ".join(f"{k}={v}" for k, v in sorted(statuses.items())))

    errors = sum(v for k, v in statuses.items() if k >= 400)
    print(f"  error ratio : {errors / max(len(corpus), 1):.3%}")

    ua = Counter(r.request.user_agent.split("/")[0][:38] for r in corpus if r.request.user_agent)
    print("\n  user agents:")
    for name, count in ua.most_common(8):
        print(f"    {count:>6}  {name}")

    # ---------------------------------------------------------------
    # Verdict
    # ---------------------------------------------------------------
    print("\n" + "=" * 78)
    print("PHASE 1 EXIT CONDITION")
    print("=" * 78)

    checks: list[tuple[bool, str]] = []
    benign_sessions = sum(len(v) for (t, _), v in by_class.items() if t == "benign")
    checks.append((benign_sessions >= 50,
                   f"substantial benign corpus (>=50 sessions): {benign_sessions}"))
    checks.append((bool(scripted),
                   f"benign-but-automated traffic present (makes the automation axis "
                   f"falsifiable): {len(scripted)} sessions"))
    checks.append((bool(human and scripted and statistics.median(human) > statistics.median(scripted) * 1.5),
                   "timing separates humans from scripts"))
    unlabelled = sum(1 for r in corpus if r.labels.ground_truth == "unknown")
    checks.append((unlabelled == 0, f"every record carries a ground-truth label: {unlabelled} unlabelled"))

    for ok, text in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {text}")

    if all(ok for ok, _ in checks):
        print("\n  Phase 1 exit condition met.")
    else:
        print("\n  Phase 1 exit condition NOT met — do not begin Phase 2 (spec §13).")


def main() -> None:
    cfg = system()
    ap = argparse.ArgumentParser(description="Characterise a labelled corpus (spec §13 Phase 1).")
    ap.add_argument("--logs", default=str(cfg.log_dir / "*.jsonl"))
    ap.add_argument("--labels", default=str(cfg.label_dir / "*.jsonl"))
    ap.add_argument("--lenient", action="store_true")
    args = ap.parse_args()

    corpus, coverage = build(
        sorted(globmod.glob(args.logs)),
        sorted(globmod.glob(args.labels)),
        strict=not args.lenient,
    )
    print(coverage.describe())
    print()
    report([r for r in corpus if r.labels.ground_truth != "unknown"])


if __name__ == "__main__":
    main()
