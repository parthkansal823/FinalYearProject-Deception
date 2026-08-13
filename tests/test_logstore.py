"""
Tests for the append-only, tamper-evident record store (NFR-13, FR-11).

The log is the training data, the evaluation data and the released dataset
all at once, so "the logging works" is a research claim here, not a
housekeeping detail.
"""

from __future__ import annotations

import json

from adf.logstore import GENESIS_HASH, LabelSidecar, LogStore
from adf.schema import Record


def _record(path: str) -> Record:
    rec = Record()
    rec.request.path = path
    return rec


def test_records_are_appended_in_order(tmp_path):
    store = LogStore(tmp_path / "log.jsonl")
    for i in range(5):
        store.append(_record(f"/p{i}"))

    seqs = [r.seq for r in store.read()]
    assert seqs == [0, 1, 2, 3, 4]


def test_chain_starts_at_genesis(tmp_path):
    store = LogStore(tmp_path / "log.jsonl")
    first = store.append(_record("/"))
    assert first.integrity.prev_hash == GENESIS_HASH
    assert first.integrity.hash


def test_intact_chain_verifies(tmp_path):
    store = LogStore(tmp_path / "log.jsonl")
    for i in range(20):
        store.append(_record(f"/p{i}"))

    ok, detail = store.verify()
    assert ok, detail
    assert "20 records" in detail


def test_edited_record_is_detected(tmp_path):
    path = tmp_path / "log.jsonl"
    store = LogStore(path)
    for i in range(10):
        store.append(_record(f"/p{i}"))

    lines = path.read_text(encoding="utf-8").splitlines()
    doc = json.loads(lines[4])
    doc["request"]["path"] = "/tampered"
    lines[4] = json.dumps(doc, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, detail = LogStore(path).verify()
    assert not ok
    assert "seq 4" in detail


def test_deleted_record_is_detected(tmp_path):
    """Quietly dropping an inconvenient session must not go unnoticed."""
    path = tmp_path / "log.jsonl"
    store = LogStore(path)
    for i in range(10):
        store.append(_record(f"/p{i}"))

    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[5]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, detail = LogStore(path).verify()
    assert not ok


def test_reopening_continues_the_chain(tmp_path):
    """A restarted proxy must not look like a truncated log."""
    path = tmp_path / "log.jsonl"
    first = LogStore(path)
    for i in range(3):
        first.append(_record(f"/a{i}"))
    last_hash = list(first.read())[-1].integrity.hash

    second = LogStore(path)
    resumed = second.append(_record("/b0"))

    assert resumed.seq == 3
    assert resumed.integrity.prev_hash == last_hash

    ok, detail = second.verify()
    assert ok, detail


def test_labels_are_written_separately_from_traffic(tmp_path):
    """Spec §7.3: labels are applied at generation time and must never be
    reachable from the detection path -- hence a separate sidecar file."""
    sidecar = LabelSidecar(tmp_path / "labels.jsonl")
    sidecar.write(
        session_id="s-1", ground_truth="attack", attack_category="sqli",
        attack_subcategory="sqli_union", automation_label="scripted",
        generator="sqlmap", round=2,
    )
    sidecar.write(session_id="s-2", ground_truth="benign", automation_label="human", round=1)

    labels = sidecar.read()
    assert labels["s-1"]["attack_category"] == "sqli"
    assert labels["s-1"]["round"] == 2
    assert labels["s-2"]["ground_truth"] == "benign"


def test_chain_recovers_when_the_file_is_removed_underneath(tmp_path):
    """Clearing data/logs while a server runs must not silently corrupt.

    Found during Phase 1 verification: the in-memory chain kept its sequence
    counter and previous hash after the file was deleted, so the new file
    began at seq 1755 referencing a record that no longer existed. That fails
    verification for a reason unrelated to tampering, which trains you to
    ignore the check — the worst outcome for an integrity mechanism.
    """
    path = tmp_path / "log.jsonl"
    store = LogStore(path)
    for i in range(5):
        store.append(_record(f"/a{i}"))

    path.unlink()

    for i in range(3):
        store.append(_record(f"/b{i}"))

    assert store.restarts == 1
    ok, detail = LogStore(path).verify()
    assert ok, detail
    assert [r.seq for r in store.read()] == [0, 1, 2]


def test_chain_recovers_when_the_file_is_truncated(tmp_path):
    path = tmp_path / "log.jsonl"
    store = LogStore(path)
    for i in range(5):
        store.append(_record(f"/a{i}"))

    path.write_text("", encoding="utf-8")
    store.append(_record("/after"))

    ok, detail = LogStore(path).verify()
    assert ok, detail
