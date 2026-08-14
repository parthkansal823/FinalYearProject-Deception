"""
Tests for the model freeze (spec §7.2, §13 Phase 6).

The freeze only matters if verify() actually FAILS when the system drifts, so
most of these deliberately move something after the freeze and assert the drift
is caught. A freeze that always says "OK" would silently let a retrained model
reach a reported result -- exactly what §7.2 forbids.
"""

from __future__ import annotations

import json

import pytest

import adf.freeze as fz


def _meter_file(tmp_path, payload="v1"):
    p = tmp_path / "meter.json"
    p.write_text(json.dumps({"meter_version": "meter-1", "weights": payload}), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Round trip on the real system state
# ---------------------------------------------------------------------------


def test_freeze_then_verify_passes_on_an_unchanged_system(tmp_path):
    manifest = tmp_path / "freeze.json"
    fz.freeze(path=manifest)
    ok, reasons = fz.verify(path=manifest)
    assert ok, reasons


def test_verify_fails_when_there_is_no_manifest(tmp_path):
    ok, reasons = fz.verify(path=tmp_path / "does_not_exist.json")
    assert not ok
    assert any("not been frozen" in r for r in reasons)


# ---------------------------------------------------------------------------
# Drift detection (the point of the whole mechanism)
# ---------------------------------------------------------------------------


def test_verify_detects_a_changed_meter(tmp_path):
    meter = _meter_file(tmp_path, "original")
    manifest = tmp_path / "freeze.json"
    fz.freeze(meter_path=meter, path=manifest)

    meter.write_text(json.dumps({"meter_version": "meter-1", "weights": "RETRAINED"}), encoding="utf-8")
    ok, reasons = fz.verify(meter_path=meter, path=manifest)
    assert not ok
    assert any("meter changed" in r for r in reasons)


def test_verify_detects_drift_in_any_component(tmp_path, monkeypatch):
    """Freeze a known state, then perturb each block in turn and confirm each is
    caught. Uses a controlled state so the test does not depend on editing the
    real cost table or library on disk."""
    base = {
        "schema": {"version": 3, "fingerprint": "S"},
        "cost_table": {"digest": "C", "frozen_on": "2026-08-13"},
        "features": {"version": 1, "count": 19, "hash": "F"},
        "meter": {"file": "m", "sha256": "M"},
        "bait_library": {"calibrated": True, "effects_hash": "B"},
        "bait_certificates": {"count": 6, "hash": "X", "certified": []},
    }
    manifest = tmp_path / "freeze.json"
    monkeypatch.setattr(fz, "_collect_state", lambda meter_path: dict(base, **{}))
    from adf.config import system  # freeze() needs a seed/mode
    fz.freeze(path=manifest, require_calibrated=False)

    perturbations = {
        ("schema", "fingerprint"): "the record schema changed",
        ("cost_table", "digest"): "the cost table changed",
        ("features", "hash"): "the feature set changed",
        ("meter", "sha256"): "the trained meter changed",
        ("bait_library", "effects_hash"): "the bait library (betas) changed",
        ("bait_certificates", "hash"): "the bait certificates changed",
    }
    for (block, key), expected in perturbations.items():
        drifted = {b: dict(v) for b, v in base.items()}
        drifted[block][key] = "MUTATED"
        monkeypatch.setattr(fz, "_collect_state", lambda meter_path, d=drifted: d)
        ok, reasons = fz.verify(path=manifest)
        assert not ok, f"drift in {block}.{key} was NOT detected"
        assert any(expected in r for r in reasons), f"wrong reason for {block}.{key}: {reasons}"


def test_require_frozen_raises_on_drift(tmp_path, monkeypatch):
    base = {
        "schema": {"version": 3, "fingerprint": "S"},
        "cost_table": {"digest": "C", "frozen_on": "x"},
        "features": {"version": 1, "count": 19, "hash": "F"},
        "meter": {"file": "m", "sha256": "M"},
        "bait_library": {"calibrated": True, "effects_hash": "B"},
        "bait_certificates": {"count": 6, "hash": "X", "certified": []},
    }
    manifest = tmp_path / "freeze.json"
    monkeypatch.setattr(fz, "_collect_state", lambda meter_path: base)
    monkeypatch.setattr(fz, "FREEZE_PATH", manifest)
    fz.freeze(path=manifest, require_calibrated=False)

    drifted = {b: dict(v) for b, v in base.items()}
    drifted["meter"]["sha256"] = "RETRAINED"
    monkeypatch.setattr(fz, "_collect_state", lambda meter_path: drifted)
    with pytest.raises(fz.FreezeError, match="no longer matches"):
        fz.require_frozen()


# ---------------------------------------------------------------------------
# Calibration guard
# ---------------------------------------------------------------------------


def test_freeze_refuses_an_uncalibrated_library(tmp_path, monkeypatch):
    base = {
        "schema": {"version": 3, "fingerprint": "S"},
        "cost_table": {"digest": "C", "frozen_on": "x"},
        "features": {"version": 1, "count": 19, "hash": "F"},
        "meter": {"file": "m", "sha256": "M"},
        "bait_library": {"calibrated": False, "effects_hash": "B"},   # NOT calibrated
        "bait_certificates": {"count": 6, "hash": "X", "certified": []},
    }
    monkeypatch.setattr(fz, "_collect_state", lambda meter_path: base)
    with pytest.raises(fz.FreezeError, match="not calibrated"):
        fz.freeze(path=tmp_path / "f.json", require_calibrated=True)
