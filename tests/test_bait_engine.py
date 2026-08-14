"""
Tests for bite detection and the bait engine (spec §6.6, §16, §21).

Covers the three bite kinds, cross-session detection, the certificate guard
that stops an uncertified bait from ever being served, and the fail-safe that a
bait problem degrades to a clean response rather than a broken one.
"""

from __future__ import annotations

import pytest

from adf.bait import BaitedResponse, build_bait
from adf.bait.engine import BaitEngine


# ---------------------------------------------------------------------------
# Bite detection per kind
# ---------------------------------------------------------------------------


def test_value_bite_fires_when_the_token_string_reappears():
    bait = build_bait("B-SQL-1", session_id="s1", seed=1)   # value bite: fake table name
    token = bait.token
    assert bait.detect_bite(method="GET", path="/search", query=f"q={token}", body="")
    assert not bait.detect_bite(method="GET", path="/search", query="q=maintenance", body="")


def test_name_bite_fires_when_the_token_is_submitted_as_a_parameter():
    bait = build_bait("B-IDOR-1", session_id="s1", seed=1)   # name bite: ref_uid
    assert bait.detect_bite(method="GET", path="/api/profile/7", query="ref_uid=usr_x", body="")
    # merely echoing the value is not a bite; the NAME must be submitted
    assert not bait.detect_bite(method="GET", path="/api/profile/7", query="q=ref_uid", body="")


def test_path_bite_fires_on_the_deprecated_endpoint():
    bait = build_bait("B-AUTH-1", session_id="s1", seed=1)   # path bite: /auth/legacy/verify_x
    assert bait.detect_bite(method="GET", path=bait.token, query="", body="")
    assert not bait.detect_bite(method="GET", path="/login", query="", body="")


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _certified(monkeypatch):
    """Treat every bait as certified for these tests, so behaviour is tested
    independently of whether config/bait_certificates.json exists."""
    monkeypatch.setattr("adf.bait.engine.is_certified", lambda bait_id, path=None: True)


def _json():
    return BaitedResponse(body='{"profile": {"id": 7}}', content_type="application/json")


def _html():
    return BaitedResponse(body="<html><body><h1>x</h1></body></html>", content_type="text/html")


def test_engine_injects_and_then_detects_the_bite():
    eng = BaitEngine(seed=1)
    baited, issued = eng.serve(session_id="s1", bait_id="B-IDOR-1", response=_json(),
                               likelihood_ratio=800.0)
    assert issued is not None
    token = issued.bait.token
    assert token in baited.body

    bite = eng.check_bite(session_id="s1", method="GET", path="/api/profile/8",
                          query=f"{token}=usr_x", body="")
    assert bite is not None
    assert bite.bait_id == "B-IDOR-1"
    assert not bite.cross_session
    assert bite.logodds > 0        # a bite is positive evidence of hostility


def test_cross_session_bite_is_flagged():
    """A token issued to one session, seen in another, is a stronger signal --
    either a leaked bait or an attacker rotating identity (spec §16)."""
    eng = BaitEngine(seed=1)
    _, issued = eng.serve(session_id="victim", bait_id="B-SQL-1", response=_html(),
                          likelihood_ratio=1000.0)
    token = issued.bait.token

    bite = eng.check_bite(session_id="other", method="GET", path="/search",
                          query=f"q={token}", body="")
    assert bite is not None
    assert bite.cross_session
    assert bite.issued_to_session == "victim"
    assert bite.biting_session == "other"


def test_uncertified_bait_is_never_served(monkeypatch):
    """The run-time enforcement of §6.7: without a certificate, the bait must
    not reach the response, and the clean response is returned untouched."""
    monkeypatch.setattr("adf.bait.engine.is_certified", lambda bait_id, path=None: False)
    eng = BaitEngine(seed=1, require_certificate=True)
    clean = _json()
    baited, issued = eng.serve(session_id="s1", bait_id="B-IDOR-1", response=clean)
    assert issued is None
    assert baited.body == clean.body        # untouched


def test_serving_an_inapplicable_bait_degrades_to_clean_response():
    eng = BaitEngine(seed=1)
    clean = _html()
    # B-IDOR-1 is a json_field bait; it cannot apply to an HTML page
    baited, issued = eng.serve(session_id="s1", bait_id="B-IDOR-1", response=clean)
    assert issued is None
    assert baited.body == clean.body


def test_no_bite_on_ordinary_traffic():
    eng = BaitEngine(seed=1)
    eng.serve(session_id="s1", bait_id="B-SQL-1", response=_html(), likelihood_ratio=1000.0)
    assert eng.check_bite(session_id="s1", method="GET", path="/dashboard",
                          query="", body="") is None
