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
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime

from adf.config import system
from adf.dataset import build, iter_sessions
from adf.schema import Record

STATIC_PREFIX = "/static/"


def _parse_ts(value: str) -> float:
    return datetime.fromisoformat(value).timestamp()


def _gaps(session: list[Record], *, navigation_only: bool = False) -> list[float]:
    """Inter-request gaps within a session.

    `navigation_only` excludes static sub-resources. This matters: a browser
    fires the CSS, JS and logo of a page in a rapid burst regardless of how
    human the user is, so those micro-gaps (a few ms) dominate the raw gap
    stream and bury the think-times that actually distinguish a person from a
    script. The timing FEATURE §6.3 describes is the gap between navigations,
    which is what the Phase 3 extractor will compute -- so the diagnostic
    measures the same thing here.
    """
    records = session
    if navigation_only:
        records = [r for r in session if not r.request.path.startswith(STATIC_PREFIX)]
    times = sorted(_parse_ts(r.ts) for r in records if r.ts)
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


# Malice primitives come from adf.features so the numbers this diagnostic
# reports are computed by the SAME code the meter trains on. If they diverged,
# the Phase 1/2 evidence would describe a different feature than the one the
# system actually uses (see adf/features/extractor.py "single source of truth").
from adf.features.extractor import (               # noqa: E402
    client_inputs as _client_inputs,
    special_char_ratio as _special_char,
    db_keyword_hits as _db_keyword,
)


def _special_char_ratio(session: list[Record]) -> float:
    """Median special-character density across the session's inputs."""
    ratios = [_special_char(_client_inputs(r)) for r in session if _client_inputs(r)]
    return statistics.median(ratios) if ratios else 0.0


def _db_keyword_hits(session: list[Record]) -> float:
    """Total database-keyword matches across the session's inputs."""
    return float(sum(_db_keyword(_client_inputs(r)) for r in session))


def _failed_auth(session: list[Record]) -> int:
    """Count of failed authentication responses (401 on a login/otp POST)."""
    n = 0
    for r in session:
        if r.request.method == "POST" and r.request.path in ("/login", "/otp") and r.response.status == 401:
            n += 1
    return n


def _persona(record: Record) -> str:
    """Recover the fine-grained profile from the label notes. Personas are
    kept out of the class labels on purpose (an awkward honest user is still
    benign), but the analysis is allowed to break them out."""
    note = record.labels.notes
    for tag in ("monitor", "crawler", "integration", "apostrophe", "forgetful"):
        if tag in note:
            return tag
    return "normal"


def _by_class_stat(by_class, fn, *, aggregate: str = "median") -> dict:
    """Aggregate a per-session metric per class, keyed by "truth/automation"
    to match the other by-class dictionaries in this module."""
    out = {}
    for (truth, automation), sessions in by_class.items():
        values = [v for s in sessions for v in fn(s) if v > 0]
        if values:
            out[f"{truth}/{automation}"] = (
                statistics.median(values) if aggregate == "median" else statistics.fmean(values)
            )
    return out


def _percentile(sorted_values: list[float], pct: float) -> float:
    """Nearest-rank percentile of an already-sorted list; 0.0 if empty."""
    if not sorted_values:
        return 0.0
    idx = int((pct / 100.0) * (len(sorted_values) - 1))
    return sorted_values[idx]


def _summary(values: list[float]) -> str:
    if not values:
        return "n/a"
    values = sorted(values)
    return (f"median={statistics.median(values):6.3f}  "
            f"p10={_percentile(values, 10):6.3f}  "
            f"p90={_percentile(values, 90):6.3f}  n={len(values)}")


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
    print("NAVIGATION TIMING  (spec §6.3: time between requests, and how regular)")
    print("-" * 78)
    print("Measured over navigations only (static sub-resources excluded), because a")
    print("browser bursts a page's assets regardless of the user, which buries the")
    print("think-times. Two complementary views: the GAP (how long between actions)")
    print("and the CV (how regular). No single one separates every case — that is the")
    print("point of having two axes rather than one.\n")

    human_gap = _by_class_stat(by_class, lambda s: _gaps(s, navigation_only=True), aggregate="median")
    print("  navigation think-time, seconds (human pauses; scripts tick):")
    for (truth, automation), sessions in sorted(by_class.items()):
        gaps = [g for s in sessions for g in _gaps(s, navigation_only=True)]
        print(f"    {truth:<8} / {automation:<8}  {_summary(gaps)}")

    cv_by_class: dict[str, list[float]] = {}
    print("\n  navigation regularity, CV (higher = more irregular = more human):")
    for (truth, automation), sessions in sorted(by_class.items()):
        cvs = [c for c in (_cv(_gaps(s, navigation_only=True)) for s in sessions) if c is not None]
        cv_by_class[f"{truth}/{automation}"] = cvs
        print(f"    {truth:<8} / {automation:<8}  {_summary(cvs)}")

    human_cv = cv_by_class.get("benign/human", [])
    scripted_cv = cv_by_class.get("benign/scripted", [])
    if human_cv and scripted_cv:
        print(f"\n  human median CV = {statistics.median(human_cv):.3f}   "
              f"scripted median CV = {statistics.median(scripted_cv):.3f}   "
              f"(humans more irregular: {'yes' if statistics.median(human_cv) > statistics.median(scripted_cv) else 'NO'})")

    # ---------------------------------------------------------------
    # Asset fetching -- the other strong automation signal (§6.1)
    # ---------------------------------------------------------------
    print("\n" + "-" * 78)
    print("STATIC ASSET FETCHING  (spec §6.1: browsers fetch assets, tools usually do not)")
    print("-" * 78)
    asset_ratio_by_class: dict[str, float] = {}
    for (truth, automation), sessions in sorted(by_class.items()):
        ratios = []
        for s in sessions:
            assets = sum(1 for r in s if r.request.path.startswith(STATIC_PREFIX))
            pages = len(s) - assets
            if pages:
                ratios.append(assets / pages)
        if ratios:
            asset_ratio_by_class[f"{truth}/{automation}"] = statistics.median(ratios)
        print(f"  {truth:<8} / {automation:<8}  assets/page  {_summary(ratios)}")

    # Per-profile, so the hard cases are visible. The crawler fetches some
    # assets AND polls at human-like intervals: it is the genuine "automated
    # but harmless" case of §6.3, separable mainly by regularity and by the
    # behavioural markers (no login, hits /robots.txt), not by rate or assets.
    print("\n  by profile (assets/page, navigation gap): the hard cases live here")
    by_profile: dict[str, list[list[Record]]] = defaultdict(list)
    for _, session in iter_sessions(corpus):
        by_profile[_persona(session[0])].append(session)
    for profile, sessions in sorted(by_profile.items()):
        ratios, gaps = [], []
        for s in sessions:
            assets = sum(1 for r in s if r.request.path.startswith(STATIC_PREFIX))
            pages = len(s) - assets
            if pages:
                ratios.append(assets / pages)
            gaps += _gaps(s, navigation_only=True)
        ar = statistics.median(ratios) if ratios else 0.0
        ng = statistics.median([g for g in gaps if g > 0]) if any(g > 0 for g in gaps) else 0.0
        print(f"    {profile:<12}  {len(sessions):>3} sessions   assets/page={ar:5.2f}   nav-gap={ng:6.3f}s")

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
    # Malice signal -- the second axis (spec §6.3). Only meaningful once
    # attack traffic exists, so this whole block is skipped for a benign-only
    # corpus (Phase 1) and appears from Phase 2 onward.
    # ---------------------------------------------------------------
    has_attack = any(t == "attack" for (t, _) in by_class)
    malice_by_class: dict[str, dict[str, float]] = {}
    if has_attack:
        print("\n" + "-" * 78)
        print("MALICE SIGNAL  (spec §6.3: is this hostile? — independent of automation)")
        print("-" * 78)
        print("Malice is CATEGORY-SPECIFIC: SQLi lights up special-characters, auth lights")
        print("up failed-logins, IDOR neither — so a median across a mixed attack class")
        print("washes each signal out. Reported instead as the malice-positive fraction")
        print("(any strong indicator tripped) plus the 90th percentile of each feature,")
        print("which is where a sparse-but-strong signal actually lives.\n")

        def _malice_positive(s: list[Record]) -> bool:
            # A session is malice-positive if it trips any single strong
            # indicator. Deliberately simple: this is a diagnostic proxy, not
            # the meter. The hard-negative benign personas (apostrophe search,
            # forgetful login) are EXPECTED to trip it — that is precisely why
            # benign bait exposure is not trivially zero (spec §10.3, NFR-05).
            return (_special_char_ratio(s) > 0.15
                    or _db_keyword_hits(s) > 0
                    or _failed_auth(s) >= 3)

        for (truth, automation), sessions in sorted(by_class.items()):
            key = f"{truth}/{automation}"
            sc = sorted(_special_char_ratio(s) for s in sessions)
            kw = [_db_keyword_hits(s) for s in sessions]
            fa = sorted(float(_failed_auth(s)) for s in sessions)
            pos = sum(_malice_positive(s) for s in sessions)
            malice_by_class[key] = {
                "positive_frac": pos / len(sessions) if sessions else 0.0,
                "db_keywords": max(kw) if kw else 0.0,   # any hit in the class
                "special_char_p90": _percentile(sc, 90),
                "failed_auth_p90": _percentile(fa, 90),
            }
            m = malice_by_class[key]
            print(f"  {truth:<8} / {automation:<8}  "
                  f"malice-positive={m['positive_frac']:5.0%}  "
                  f"special-char.p90={m['special_char_p90']:.3f}  "
                  f"failed-auth.p90={m['failed_auth_p90']:.0f}  "
                  f"db-kw(any)={m['db_keywords']:.0f}")

        # Attack category coverage
        cat = Counter()
        sub = Counter()
        for r in corpus:
            if r.labels.ground_truth == "attack":
                cat[r.labels.attack_category] += 1
                sub[r.labels.attack_subcategory] += 1
        cat_sessions = Counter()
        sub_sessions = Counter()
        for (truth, _), sessions in by_class.items():
            if truth != "attack":
                continue
            for s in sessions:
                cat_sessions[s[0].labels.attack_category] += 1
                sub_sessions[s[0].labels.attack_subcategory] += 1
        print("\n  attack categories (sessions): "
              + ", ".join(f"{k}={v}" for k, v in sorted(cat_sessions.items())))
        print("  subcategories (sessions)    : "
              + ", ".join(f"{k}={v}" for k, v in sorted(sub_sessions.items())))

    # ---------------------------------------------------------------
    # The 2x2: automation × malice (spec §6.3). The whole justification for
    # two scores instead of one is that all four cells are populated and that
    # automation and malice are NOT perfectly correlated.
    # ---------------------------------------------------------------
    if has_attack:
        print("\n" + "-" * 78)
        print("AUTOMATION × MALICE COVERAGE  (spec §6.3: why two scores, not one)")
        print("-" * 78)
        cell = {(t, a): len(v) for (t, a), v in by_class.items()}
        autos = ["human", "scripted"]
        print(f"    {'':<10}" + "".join(f"{a:>12}" for a in autos))
        for truth in ("benign", "attack"):
            row = f"    {truth:<10}"
            for a in autos:
                row += f"{cell.get((truth, a), 0):>12}"
            print(row)
        print("\n  A single combined score suffices only if these cells collapse onto a")
        print("  diagonal. Off-diagonal mass — benign/scripted and attack/human — is")
        print("  exactly what a one-score model cannot represent (contribution #2).")

    # ---------------------------------------------------------------
    # Verdict
    # ---------------------------------------------------------------
    print("\n" + "=" * 78)
    print("PHASE 1 EXIT CONDITION")
    print("=" * 78)

    checks: list[tuple[bool, str]] = []
    benign_sessions = sum(len(v) for (t, _), v in by_class.items() if t == "benign")
    n_scripted = len(cv_by_class.get("benign/scripted", []))
    checks.append((benign_sessions >= 50,
                   f"substantial benign corpus (>=50 sessions): {benign_sessions}"))
    checks.append((n_scripted > 0,
                   f"benign-but-automated traffic present (makes the automation axis "
                   f"falsifiable): {n_scripted} sessions"))

    # The corpus must carry LEARNABLE automation signal. It does not require any
    # single feature to be a silver bullet -- that is exactly what §6.3 argues
    # against, and the per-profile table above shows why (a 2-second poller has
    # a human-like gap; a fast integration job does not fetch assets). What it
    # requires is that the strong signal §6.1 names -- asset fetching -- clearly
    # separates humans from pure scripts, and that human think-times are present
    # and human-plausible so the timing feature is not empty.
    ha = asset_ratio_by_class.get("benign/human", 0.0)
    sa = asset_ratio_by_class.get("benign/scripted", 1.0)
    checks.append((ha > 0.5 and sa < ha / 2,
                   f"asset-fetching separates humans from scripts (§6.1): "
                   f"human={ha:.2f} vs scripted={sa:.2f} assets/page"))

    hg = human_gap.get("benign/human", 0.0)
    checks.append((0.4 <= hg <= 5.0,
                   f"human think-times present and plausible: median navigation gap {hg:.2f}s"))

    hcv = statistics.median(human_cv) if human_cv else 0.0
    scv = statistics.median(scripted_cv) if scripted_cv else 0.0
    checks.append((hcv > scv,
                   f"humans are more irregular than scripts (supporting signal): "
                   f"CV {hcv:.2f} vs {scv:.2f}"))

    unlabelled = sum(1 for r in corpus if r.labels.ground_truth == "unknown")
    checks.append((unlabelled == 0, f"every record carries a ground-truth label: {unlabelled} unlabelled"))

    for ok, text in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {text}")

    phase1_ok = all(ok for ok, _ in checks)
    if phase1_ok:
        print("\n  Phase 1 exit condition MET. The corpus carries learnable automation")
        print("  signal (asset-fetching clean; think-times present), the automation axis")
        print("  is falsifiable, and every record is labelled.")
    else:
        print("\n  Phase 1 exit condition NOT met — do not begin Phase 2 (spec §13).")

    # -----------------------------------------------------------------
    # Phase 2 exit condition (spec §13 Phase 2, §7.2). Only assessed once
    # attack traffic is present.
    # -----------------------------------------------------------------
    if not has_attack:
        return

    print("\n" + "=" * 78)
    print("PHASE 2 EXIT CONDITION  (attack round 1 — the training corpus)")
    print("=" * 78)

    attack_by_auto = {a: len(v) for (t, a), v in by_class.items() if t == "attack"}
    attack_sessions = sum(attack_by_auto.values())
    cats_present = {r.labels.attack_category for r in corpus
                    if r.labels.ground_truth == "attack"} - {"none", "unknown"}

    p2: list[tuple[bool, str]] = []
    p2.append((attack_sessions >= 24,
               f"substantial attack corpus (>=24 sessions): {attack_sessions}"))
    p2.append(({"sqli", "idor", "auth"} <= cats_present,
               f"all three attack categories present: {sorted(cats_present)}"))

    # The §6.3 hard cell: attack traffic that is NOT automated. Without it,
    # automation and malice stay correlated and the second axis is indefensible.
    p2.append((attack_by_auto.get("human", 0) > 0 and attack_by_auto.get("scripted", 0) > 0,
               f"attack traffic in BOTH automation classes (the §6.3 hard cell): "
               f"human={attack_by_auto.get('human', 0)}, scripted={attack_by_auto.get('scripted', 0)}"))

    # All four automation×malice cells populated.
    cells = {(t, a) for (t, a), v in by_class.items() if v}
    four = {("benign", "human"), ("benign", "scripted"), ("attack", "human"), ("attack", "scripted")}
    p2.append((four <= cells, f"all four automation×malice cells populated: {len(four & cells)}/4"))

    # Malice must separate attack from benign, else the second axis has no
    # signal to learn. Compare the strongest malice proxy per side.
    benign_kw = max((malice_by_class.get(f"benign/{a}", {}).get("db_keywords", 0.0)
                     for a in ("human", "scripted")), default=0.0)
    attack_kw = max((malice_by_class.get(f"attack/{a}", {}).get("db_keywords", 0.0)
                     for a in ("human", "scripted")), default=0.0)
    p2.append((attack_kw > benign_kw,
               f"malice separates attack from benign (db-keywords): "
               f"attack={attack_kw:.1f} vs benign={benign_kw:.1f}"))

    # Every attack record must carry a subcategory (spec §11 label completeness).
    attack_unsub = sum(1 for r in corpus
                       if r.labels.ground_truth == "attack"
                       and r.labels.attack_subcategory in ("unknown", ""))
    p2.append((attack_unsub == 0, f"every attack record has a subcategory: {attack_unsub} missing"))

    # Rounds must not be mixed: the training corpus must contain no eval data
    # (spec §7.2 — the rule the whole evaluation depends on).
    rounds = {r.run.round for r in corpus if r.labels.ground_truth == "attack"}
    p2.append(("eval" not in rounds,
               f"no eval-round data leaked into the training corpus (§7.2): rounds={sorted(rounds)}"))

    for ok, text in p2:
        print(f"  [{'PASS' if ok else 'FAIL'}] {text}")

    if phase1_ok and all(ok for ok, _ in p2):
        print("\n  Phase 2 exit condition MET. All three categories, both automation")
        print("  classes, and every 2×2 cell are present and labelled; malice separates")
        print("  from benign; rounds are clean. Ready for Phase 3 (train the meter).")
    else:
        print("\n  Phase 2 exit condition NOT met — do not begin Phase 3 (spec §13).")


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
