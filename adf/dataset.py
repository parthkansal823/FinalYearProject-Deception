"""
Corpus assembly: join traffic records to their ground-truth labels.

Labels live in a sidecar, physically separate from the traffic log, so that
the detection path cannot read the answer key even by accident (spec §7.3,
docs/DECISIONS.md). That separation has a cost: the two files have to be
joined before anything can be trained or evaluated, and the join has to be
*verified* rather than assumed.

That is not a theoretical concern. The first version of this pipeline joined
on `session_id` -- but the generator names a session before its first request
(which is what allows the label to be written in advance) while the
application names the same session independently via its own cookie. Two
namespaces, zero overlap, and a corpus that looked complete while being
entirely unlabelled. Nothing failed; the numbers were simply meaningless.

So this module reports join coverage as a first-class result and refuses to
emit a corpus that falls below a stated threshold.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from adf.logstore import LabelSidecar, LogStore
from adf.schema import NEVER_FEATURE_FIELDS, Record

#: Below this, something is structurally wrong with the join rather than
#: merely untidy, and continuing would produce a silently broken corpus.
MIN_COVERAGE = 0.95


class JoinError(RuntimeError):
    pass


@dataclass
class CoverageReport:
    total_records: int = 0
    labelled_records: int = 0
    total_sessions: int = 0
    labelled_sessions: int = 0
    unlabelled_sessions: int = 0
    labels_never_matched: int = 0
    by_ground_truth: Counter = field(default_factory=Counter)
    by_automation: Counter = field(default_factory=Counter)
    by_round: Counter = field(default_factory=Counter)

    @property
    def record_coverage(self) -> float:
        return self.labelled_records / self.total_records if self.total_records else 0.0

    @property
    def session_coverage(self) -> float:
        return self.labelled_sessions / self.total_sessions if self.total_sessions else 0.0

    def describe(self) -> str:
        lines = [
            f"records          : {self.total_records}",
            f"  labelled       : {self.labelled_records} ({self.record_coverage:.1%})",
            f"sessions         : {self.total_sessions}",
            f"  labelled       : {self.labelled_sessions} ({self.session_coverage:.1%})",
            f"  unlabelled     : {self.unlabelled_sessions}",
            f"labels unmatched : {self.labels_never_matched}",
        ]
        if self.by_ground_truth:
            lines.append("ground truth     : " + ", ".join(
                f"{k}={v}" for k, v in sorted(self.by_ground_truth.items())))
        if self.by_automation:
            lines.append("automation       : " + ", ".join(
                f"{k}={v}" for k, v in sorted(self.by_automation.items())))
        if self.by_round:
            lines.append("rounds           : " + ", ".join(
                f"{k}={v}" for k, v in sorted(self.by_round.items())))
        return "\n".join(lines)


def _label_key(record: Record) -> str:
    """How a record finds its label.

    `provenance_id` is the generator's own name for the session, carried in a
    header and recorded outside `request.headers` so it can never become a
    feature. Falling back to `session_id` covers traffic from tools that
    cannot set a custom header (sqlmap, Hydra), which will instead be labelled
    by the application-side session id captured at generation time.
    """
    return record.session.provenance_id or record.session.session_id


def join(
    records: Iterable[Record],
    labels: dict[str, dict],
) -> tuple[list[Record], CoverageReport]:
    """Attach labels to records, returning the corpus and a coverage report."""
    report = CoverageReport()
    out: list[Record] = []
    seen_sessions: dict[str, bool] = {}
    matched_label_keys: set[str] = set()

    for record in records:
        report.total_records += 1
        key = _label_key(record)
        entry = labels.get(key)

        if entry is not None:
            matched_label_keys.add(key)
            record.labels.ground_truth = entry.get("ground_truth", "unknown")
            record.labels.attack_category = entry.get("attack_category", "unknown")
            record.labels.attack_subcategory = entry.get("attack_subcategory", "unknown")
            record.labels.automation_label = entry.get("automation_label", "unknown")
            record.labels.generator = entry.get("generator", "")
            record.labels.tool_version = entry.get("tool_version", "")
            record.labels.notes = entry.get("notes", "")
            if entry.get("round"):
                record.run.round = entry["round"]
            if entry.get("run_id"):
                record.run.run_id = entry["run_id"]

            report.labelled_records += 1
            report.by_ground_truth[record.labels.ground_truth] += 1
            report.by_automation[record.labels.automation_label] += 1
            report.by_round[record.run.round] += 1

        seen_sessions[key] = seen_sessions.get(key, False) or (entry is not None)
        out.append(record)

    report.total_sessions = len(seen_sessions)
    report.labelled_sessions = sum(1 for ok in seen_sessions.values() if ok)
    report.unlabelled_sessions = report.total_sessions - report.labelled_sessions
    report.labels_never_matched = len(set(labels) - matched_label_keys)
    return out, report


def build(
    log_paths: list[Path | str],
    label_paths: list[Path | str],
    *,
    min_coverage: float = MIN_COVERAGE,
    strict: bool = True,
) -> tuple[list[Record], CoverageReport]:
    labels: dict[str, dict] = {}
    for path in label_paths:
        labels.update(LabelSidecar(path).read())

    records: list[Record] = []
    for path in log_paths:
        store = LogStore(path)
        ok, detail = store.verify()
        if not ok and strict:
            raise JoinError(
                f"refusing to build a corpus from a log that fails integrity "
                f"verification: {path}: {detail}"
            )
        records.extend(store.read())

    corpus, report = join(records, labels)

    if strict and report.record_coverage < min_coverage:
        raise JoinError(
            f"join coverage {report.record_coverage:.1%} is below the required "
            f"{min_coverage:.0%}.\n\n{report.describe()}\n\n"
            "This usually means the generator's session marker is not reaching the log. "
            "A corpus that joins poorly is not a corpus with a few gaps -- it is one "
            "whose labels describe different sessions from its traffic."
        )

    return corpus, report


def assert_no_label_leakage(feature_names: Iterable[str]) -> None:
    """Guard for the Phase 3 feature extractor.

    Any feature derived from the label block or the provenance id would be
    training on the answer key. Accuracy would look excellent and mean
    nothing, and the failure is invisible in the results.
    """
    offenders = [
        name for name in feature_names
        if any(name == banned or name.startswith(banned + ".") for banned in NEVER_FEATURE_FIELDS)
    ]
    if offenders:
        raise ValueError(
            f"features derived from ground truth or provenance: {offenders}. "
            f"These fields are the answer key (adf.schema.NEVER_FEATURE_FIELDS)."
        )


def write_jsonl(records: Iterable[Record], path: Path | str) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(record.to_json_line() + "\n")
            count += 1
    return count


def iter_sessions(records: Iterable[Record]) -> Iterator[tuple[str, list[Record]]]:
    """Group a corpus into sessions, preserving request order.

    The session is the unit almost everything is measured over: scores
    accumulate across it (§6.4), decisions are made for it, and
    requests-to-decision is counted within it (§10.3).
    """
    grouped: dict[str, list[Record]] = defaultdict(list)
    for record in records:
        grouped[_label_key(record)].append(record)
    for key, group in grouped.items():
        yield key, sorted(group, key=lambda r: (r.session.request_index, r.seq))


if __name__ == "__main__":  # pragma: no cover - corpus CLI
    import argparse
    import glob as globmod

    from adf.config import system

    cfg = system()
    ap = argparse.ArgumentParser(description="Assemble and verify a labelled corpus.")
    ap.add_argument("--logs", default=str(cfg.log_dir / "*.jsonl"))
    ap.add_argument("--labels", default=str(cfg.label_dir / "*.jsonl"))
    ap.add_argument("--out", default=None, help="write the joined corpus here")
    ap.add_argument("--min-coverage", type=float, default=MIN_COVERAGE)
    ap.add_argument("--lenient", action="store_true", help="report instead of failing")
    args = ap.parse_args()

    log_paths = sorted(globmod.glob(args.logs))
    label_paths = sorted(globmod.glob(args.labels))
    print(f"logs   : {len(log_paths)} file(s)")
    print(f"labels : {len(label_paths)} file(s)\n")

    corpus, report = build(
        log_paths, label_paths,
        min_coverage=args.min_coverage,
        strict=not args.lenient,
    )
    print(report.describe())

    if args.out:
        n = write_jsonl(corpus, args.out)
        print(f"\nwrote {n} records -> {args.out}")
