"""
Tests for corpus assembly.

The join between traffic and labels is the least glamorous part of the
pipeline and one of the most dangerous, because when it fails it fails
silently: every downstream number still computes, and every one of them is
meaningless. The first implementation joined two namespaces that never met
and produced a corpus with zero labels while reporting no error at all.
"""

from __future__ import annotations

import pytest

from adf.dataset import (
    JoinError,
    assert_no_label_leakage,
    build,
    iter_sessions,
    join,
)
from adf.logstore import LabelSidecar, LogStore
from adf.schema import Record


def _record(provenance: str, session_id: str = "app-sid", index: int = 0, path: str = "/") -> Record:
    rec = Record()
    rec.session.provenance_id = provenance
    rec.session.session_id = session_id
    rec.session.request_index = index
    rec.request.path = path
    return rec


def test_labels_attach_via_the_provenance_marker():
    """The generator names the session before its first request; the app names
    it independently via a cookie. The marker is what bridges them."""
    records = [_record("gen-1", "cookie-abc", i) for i in range(3)]
    labels = {"gen-1": {
        "ground_truth": "attack", "attack_category": "sqli",
        "attack_subcategory": "sqli_union", "automation_label": "scripted",
        "generator": "sqlmap", "round": "eval",
    }}

    corpus, report = join(records, labels)

    assert report.record_coverage == 1.0
    assert all(r.labels.ground_truth == "attack" for r in corpus)
    assert all(r.labels.attack_category == "sqli" for r in corpus)
    assert all(r.run.round == "eval" for r in corpus)


def test_join_falls_back_to_session_id():
    """Attack tooling that cannot set a custom header is labelled by the
    application-side session id instead (docs/DECISIONS.md)."""
    records = [_record("", "app-sid-9", i) for i in range(2)]
    labels = {"app-sid-9": {"ground_truth": "attack", "automation_label": "scripted"}}

    _, report = join(records, labels)
    assert report.record_coverage == 1.0


def test_a_namespace_mismatch_is_reported_not_hidden():
    """The original bug: labels keyed one way, records another, zero overlap.

    Nothing raised, nothing looked wrong, and the corpus was unlabelled. The
    join must make this loud.
    """
    records = [_record("gen-1", "cookie-abc", i) for i in range(5)]
    labels = {"totally-different-key": {"ground_truth": "benign"}}

    corpus, report = join(records, labels)

    assert report.record_coverage == 0.0
    assert report.labels_never_matched == 1
    assert report.unlabelled_sessions == 1
    assert all(r.labels.ground_truth == "unknown" for r in corpus)


def test_build_refuses_a_corpus_that_barely_joins(tmp_path):
    log_path = tmp_path / "log.jsonl"
    store = LogStore(log_path)
    for i in range(10):
        store.append(_record("gen-unmatched", "sid", i))

    label_path = tmp_path / "labels.jsonl"
    LabelSidecar(label_path).write(session_id="something-else", ground_truth="benign")

    with pytest.raises(JoinError, match="coverage"):
        build([log_path], [label_path])


def test_build_refuses_a_log_that_fails_integrity(tmp_path):
    """A corpus assembled from a tampered or truncated log is not a corpus."""
    log_path = tmp_path / "log.jsonl"
    store = LogStore(log_path)
    for i in range(6):
        store.append(_record("gen-1", "sid", i))

    lines = log_path.read_text(encoding="utf-8").splitlines()
    del lines[2]
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    label_path = tmp_path / "labels.jsonl"
    LabelSidecar(label_path).write(session_id="gen-1", ground_truth="benign")

    with pytest.raises(JoinError, match="integrity"):
        build([log_path], [label_path])


def test_sessions_group_in_request_order():
    """Scores accumulate across a session in order (spec §6.4), so grouping
    must preserve it."""
    records = [_record("gen-1", "sid", i, f"/p{i}") for i in (3, 0, 2, 1)]
    grouped = dict(iter_sessions(records))

    assert list(grouped) == ["gen-1"]
    assert [r.request.path for r in grouped["gen-1"]] == ["/p0", "/p1", "/p2", "/p3"]


# ---------------------------------------------------------------------------
# Label leakage
# ---------------------------------------------------------------------------


def test_features_derived_from_labels_are_rejected():
    """Training on the answer key produces excellent accuracy and no
    knowledge. The failure is invisible in the results, so it has to be
    caught structurally."""
    with pytest.raises(ValueError, match="answer key"):
        assert_no_label_leakage(["payload_length", "labels.ground_truth"])

    with pytest.raises(ValueError, match="answer key"):
        assert_no_label_leakage(["session.provenance_id"])


def test_ordinary_features_pass_the_leakage_guard():
    assert_no_label_leakage([
        "payload_length", "special_char_ratio", "sql_keyword_count",
        "requests_per_minute", "static_assets_fetched", "session.request_index",
    ])


def test_the_provenance_marker_never_reaches_request_headers():
    """It is held on the session block precisely so that anything reading
    headers to build features cannot reach it by accident."""
    from adf.schema import PROVENANCE_HEADER
    from target_app.main import _LOGGED_HEADERS

    assert PROVENANCE_HEADER not in _LOGGED_HEADERS
