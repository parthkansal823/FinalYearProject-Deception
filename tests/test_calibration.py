"""Tests for the calibration study and the sweep index it writes into.

Two things are guarded here, both of which failed silently rather than loudly
when they were wrong, which is the only reason they are worth a test:

  * `fixed_threshold_sweep` used to rewrite `arms.json` with whatever it had just
    run. Adding one arm with `--grid` therefore deleted every arm already
    measured from the index, while leaving their dumps on disk -- so the report
    still ran, and compared one arm against nothing.
  * `fit_calibration` used to read any directory containing a proxy log,
    including one still being written. A half-finished draw parses perfectly and
    is heavily weighted towards the opening requests of each session, which is
    exactly where the belief has not moved yet.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

import pytest

from tools import fit_calibration as fc


# --------------------------------------------------------------------------
# the calibration map itself
# --------------------------------------------------------------------------


def test_a_monotone_map_preserves_the_ordering_of_beliefs():
    """The whole equivalence the study rests on needs monotonicity.

    Measuring the calibrated policy through `b5_fixed` is only valid because
    'derived edges on a calibrated belief' and 'inverse-mapped edges on the raw
    belief' select the same action. That holds exactly when the map is monotone.
    """
    p = [0.01, 0.05, 0.1, 0.3, 0.5, 0.7, 0.9, 0.99]
    y = [0, 0, 0, 0, 1, 1, 1, 1]
    for fit in (fc.fit_platt, fc.fit_beta, fc.fit_isotonic):
        f = fit(p, y)
        vals = [float(np.atleast_1d(f(x))[0]) for x in p]
        assert all(b >= a - 1e-9 for a, b in zip(vals, vals[1:])), fit.__name__


def test_inverting_an_edge_lands_where_the_map_sends_it():
    p = [i / 100 for i in range(1, 100)]
    y = [1 if x > 0.5 else 0 for x in p]
    f = fc.fit_platt(p, y)
    for edge in (0.1, 0.5, 0.9):
        raw = fc.invert(f, edge)
        assert float(np.atleast_1d(f(raw))[0]) >= edge - 1e-6
        assert float(np.atleast_1d(f(max(raw - 1e-3, fc.EPS)))[0]) <= edge + 1e-6


def test_identity_map_scores_worse_than_a_fitted_one_on_a_skewed_belief():
    """A belief that is systematically over-confident must be measurably so."""
    # true P(attack) is half the stated belief: over-confident everywhere
    pairs = []
    for i in range(1, 100):
        p = i / 100
        n = 200
        k = int(round(n * p / 2))
        pairs += [(p, 1)] * k + [(p, 0)] * (n - k)
    P = [a for a, _ in pairs]
    Y = [b for _, b in pairs]
    e_id, _ = fc.ece_brier(P, Y, fc.fit_identity(P, Y))
    e_pl, _ = fc.ece_brier(P, Y, fc.fit_platt(P, Y))
    assert e_pl < e_id


def test_a_partial_draw_is_skipped_rather_than_fitted_on(tmp_path):
    run = tmp_path / "s1"
    (run / "logs").mkdir(parents=True)
    (run / "labels").mkdir(parents=True)
    (run / "labels" / "eval_labels.jsonl").write_text(
        json.dumps({"session_id": "a", "ground_truth": "attack"}) + "\n",
        encoding="utf-8")
    (run / "logs" / "proxy.1.jsonl").write_text(
        json.dumps({"source": "proxy", "scores": {"p_attack": 0.9},
                    "session": {"provenance_id": "a"}}) + "\n",
        encoding="utf-8")

    # no sessions.jsonl yet: the draw is still running
    assert fc.load_draw(run) == []

    (run / "sessions.jsonl").write_text("{}\n", encoding="utf-8")
    assert fc.load_draw(run) == [(0.9, 1)]


def test_selection_refuses_a_single_draw(tmp_path, monkeypatch):
    """One draw cannot separate a better map from a more expressive one."""
    run = tmp_path / "s1"
    (run / "logs").mkdir(parents=True)
    (run / "labels").mkdir(parents=True)
    (run / "labels" / "eval_labels.jsonl").write_text(
        json.dumps({"session_id": "a", "ground_truth": "attack"}) + "\n",
        encoding="utf-8")
    (run / "logs" / "proxy.1.jsonl").write_text(
        json.dumps({"source": "proxy", "scores": {"p_attack": 0.9},
                    "session": {"provenance_id": "a"}}) + "\n",
        encoding="utf-8")
    (run / "sessions.jsonl").write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(fc, "SPLIT", tmp_path)
    with pytest.raises(SystemExit, match="at least two"):
        fc.main()


# --------------------------------------------------------------------------
# the sweep index
# --------------------------------------------------------------------------


def test_adding_one_arm_keeps_the_arms_already_measured(tmp_path):
    """Reproduces the bug: --grid with one pair used to empty the index."""
    out = tmp_path / "fixed_threshold"
    out.mkdir()
    existing = []
    for lo, hi in [(0.05, 0.95), (0.2, 0.8)]:
        d = out / ("%.4f_%.4f" % (lo, hi))
        d.mkdir()
        dump = d / "sessions.jsonl"
        dump.write_text("{}\n", encoding="utf-8")
        existing.append({"lo": lo, "hi": hi, "dump": str(dump)})
    (out / "arms.json").write_text(json.dumps(existing), encoding="utf-8")

    new_dir = out / "0.4562_0.6423"
    new_dir.mkdir()
    (new_dir / "sessions.jsonl").write_text("{}\n", encoding="utf-8")
    done = [{"lo": 0.4562, "hi": 0.6423,
             "dump": str(new_dir / "sessions.jsonl")}]

    merged = _merge(out, done)
    pairs = {(a["lo"], a["hi"]) for a in merged}
    assert pairs == {(0.05, 0.95), (0.2, 0.8), (0.4562, 0.6423)}


def test_rerunning_the_same_pair_replaces_it_rather_than_duplicating(tmp_path):
    out = tmp_path / "fixed_threshold"
    out.mkdir()
    d = out / "0.2000_0.8000"
    d.mkdir()
    (d / "sessions.jsonl").write_text("{}\n", encoding="utf-8")
    (out / "arms.json").write_text(
        json.dumps([{"lo": 0.2, "hi": 0.8, "dump": "stale/path.jsonl"}]),
        encoding="utf-8")

    done = [{"lo": 0.2, "hi": 0.8, "dump": str(d / "sessions.jsonl")}]
    merged = _merge(out, done)
    assert len(merged) == 1
    assert merged[0]["dump"] == str(d / "sessions.jsonl")


def test_an_arm_whose_dump_was_deleted_is_dropped(tmp_path):
    out = tmp_path / "fixed_threshold"
    out.mkdir()
    (out / "arms.json").write_text(
        json.dumps([{"lo": 0.1, "hi": 0.9, "dump": str(out / "gone.jsonl")}]),
        encoding="utf-8")
    d = out / "0.3000_0.7000"
    d.mkdir()
    (d / "sessions.jsonl").write_text("{}\n", encoding="utf-8")
    done = [{"lo": 0.3, "hi": 0.7, "dump": str(d / "sessions.jsonl")}]

    merged = _merge(out, done)
    assert {(a["lo"], a["hi"]) for a in merged} == {(0.3, 0.7)}


def _merge(out: Path, done: list[dict]) -> list[dict]:
    """Call the shipped merge step, so these tests cannot pass against a copy."""
    from tools.fixed_threshold_sweep import merge_index
    merged, _ = merge_index(out / "arms.json", done)
    return merged
