"""
Tests for the read-only monitoring dashboard (spec §14).

Two things here are easy to get wrong and were: which belief a session is plotted
at, and what counts as a policy inconsistency. Both mislead a viewer rather than
crash, so they need tests rather than a glance at the page.
"""

from __future__ import annotations

import json

import pytest

from adf.dashboard import reader
from adf.dashboard.app import _fmt_p, _feature_count


def _rec(seq, p, action, *, injected=False, occurred=False, fail_open=False):
    return {
        "seq": seq,
        "session": {"session_id": "sid-test", "provenance_id": "prov-test", "in_decoy": False},
        "scores": {"p_attack": p, "before": {}, "after": {"automation": 0.1}},
        "decision": {"action": action, "fail_open_triggered": fail_open},
        "bait": {"injected": injected},
        "bite": {"occurred": occurred},
        "labels": {"ground_truth": "attack"},
    }


def _write_log(tmp_path, records):
    p = tmp_path / "proxy.test.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Which belief a session is plotted at
# ---------------------------------------------------------------------------


def test_session_is_reported_at_the_belief_it_was_decided_on(tmp_path):
    """Belief rises and falls within a session. Plotting the PEAK while colouring
    by the FINAL action puts dots in bands they were never decided in, which reads
    as a broken policy -- the decisive belief is the honest one."""
    log = _write_log(tmp_path, [
        _rec(1, 0.10, "pass"),
        _rec(2, 0.92, "bait"),     # belief peaks here
        _rec(3, 0.30, "pass"),     # ... then falls; this is the decisive record
    ])
    s = reader.load_sessions(log)[0]
    assert s.peak_malice == pytest.approx(0.92)
    assert s.decisive_malice == pytest.approx(0.30)
    assert s.action == "pass"


def test_a_diverted_session_is_reported_at_the_divert(tmp_path):
    """Divert is terminal -- everything after it is routed to the decoy -- so the
    decisive record is the first divert, not the last record in the log."""
    log = _write_log(tmp_path, [
        _rec(1, 0.20, "bait"),
        _rec(2, 0.95, "divert"),
        _rec(3, 0.99, "divert"),
    ])
    s = reader.load_sessions(log)[0]
    assert s.action == "divert"
    assert s.first_divert_req == 2
    assert s.decisive_malice == pytest.approx(0.95)


# ---------------------------------------------------------------------------
# What counts as a policy inconsistency
# ---------------------------------------------------------------------------


def test_a_no_bait_pass_in_the_middle_band_is_not_a_violation(tmp_path):
    """The regression this guards. A request with no applicable bait has EVSI = 0,
    so the policy collapses to the two-action rule and correctly PASSES at a
    belief that the bait-aware band would have baited. Flagging those marked 36 of
    54 legitimate sessions as violations."""
    log = _write_log(tmp_path, [_rec(1, 0.48, "pass")])
    assert reader.load_sessions(log)[0].band_violation is False


def test_passing_above_the_widest_divert_edge_is_a_violation(tmp_path):
    """Above the bait-aware divert edge there is no bait configuration that
    justifies passing, so this one is unambiguous."""
    log = _write_log(tmp_path, [_rec(1, 0.95, "pass")])
    assert reader.load_sessions(log)[0].band_violation is True


def test_diverting_below_the_cost_only_boundary_is_a_violation(tmp_path):
    """Below the two-action boundary, divert is never the cheapest action."""
    log = _write_log(tmp_path, [_rec(1, 0.40, "divert")])
    assert reader.load_sessions(log)[0].band_violation is True


def test_a_fail_open_record_is_never_a_violation(tmp_path):
    """Fail-open is a deliberate, logged degradation (NFR-04), not a policy bug."""
    log = _write_log(tmp_path, [_rec(1, 0.95, "pass", fail_open=True)])
    assert reader.load_sessions(log)[0].band_violation is False


def test_traffic_stats_counts_violations(tmp_path):
    log = _write_log(tmp_path, [_rec(1, 0.95, "pass")])
    assert reader.traffic_stats(log)["band_violations"] == 1


# ---------------------------------------------------------------------------
# Presentation that would mislead
# ---------------------------------------------------------------------------


def test_a_zero_p_value_is_rendered_as_a_bound_not_as_zero():
    """A rounded 'p = 0.0' reads as 'no effect' to anyone skimming, when it means
    the opposite."""
    out = _fmt_p(0.0)
    assert "0.0" not in out.replace("1e-5", "")
    assert "&lt;" in out          # escaped: a bare '<' is parsed as a tag
    assert "<" not in out


def test_small_and_ordinary_p_values_render():
    assert "1.0e-06" in _fmt_p(1e-6) or "1e-06" in _fmt_p(1e-6)
    assert _fmt_p(0.0342) == "Fisher p = 0.0342"
    assert _fmt_p(None) == ""


def test_a_missing_session_answers_404_not_200():
    """The proxy log rotates, so links to finished sessions go stale routinely.
    Anything watching this console has to tell 'gone' from 'here' without parsing
    the HTML."""
    from fastapi.testclient import TestClient
    from adf.dashboard.app import app
    with TestClient(app) as c:
        r = c.get("/session/definitely-not-a-real-session")
        assert r.status_code == 404
        assert "not found" in r.text.lower()


def test_the_index_and_health_endpoints_render():
    from fastapi.testclient import TestClient
    from adf.dashboard.app import app
    with TestClient(app) as c:
        assert c.get("/healthz").status_code == 200
        idx = c.get("/")
        assert idx.status_code == 200
        # a bare '<' from an unescaped p-value would truncate a tile
        assert "Fisher p=0.0<" not in idx.text


def test_feature_count_is_read_from_the_extractor_not_hard_coded():
    """The set is versioned and has already changed twice; a console stating a
    stale count is worse than one stating none."""
    from adf.features.extractor import AUTOMATION_FEATURES, MALICE_FEATURES
    assert _feature_count() == len(AUTOMATION_FEATURES) + len(MALICE_FEATURES)
