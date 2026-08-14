"""
Tests for the decoy application and the consistency fuzzer (spec §6.8, §6.9).

Two things are under test: that the decoy does not contradict itself under
probing (the Fact Notebook's job, surfaced over HTTP), and that it is
behaviourally INDISTINGUISHABLE from the target -- it gates auth, rejects
logins verbosely, leaks a consistent SQL error, has finite data, and never
signals a capture to the attacker. Those last ones are regression tests for the
tells a review found in the first, permissive version of the decoy.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from adf.decoy.fuzzer import ConsistencyFuzzer


@pytest.fixture(scope="module")
def decoy_module(tmp_path_factory):
    import importlib
    import os
    nb = tmp_path_factory.mktemp("decoy") / "notebook.sqlite3"
    os.environ["ADF_DATABASES__FACT_NOTEBOOK_DSN"] = f"sqlite:///{nb.as_posix()}"
    import decoy_app.main as decoy
    importlib.reload(decoy)
    return decoy


@pytest.fixture()
def authed(decoy_module):
    """A diverted, already-authenticated attacker: the proxy vouches via the
    trusted header, so gated pages are served."""
    with TestClient(decoy_module.app, headers={"X-ADF-Authenticated": "1"}) as tc:
        yield tc


@pytest.fixture()
def anon(decoy_module):
    """A client with no auth vouch -- must be gated exactly like the target."""
    with TestClient(decoy_module.app) as tc:
        yield tc


# ---------------------------------------------------------------------------
# Indistinguishability: the decoy must gate and reject like the target
# ---------------------------------------------------------------------------


def test_home_page_looks_like_the_real_site(authed):
    r = authed.get("/")
    assert r.status_code == 200 and "Northbridge" in r.text


def test_unauthenticated_dashboard_redirects_like_the_target(anon):
    r = anon.get("/dashboard", follow_redirects=False)
    assert r.status_code == 303          # target redirects to /login; decoy must too
    assert r.headers["location"] == "/login"


def test_login_with_bad_credentials_gives_the_targets_verbose_error(anon):
    r = anon.post("/login", data={"username": "nobody", "password": "x"}, follow_redirects=False)
    assert r.status_code == 401          # NOT a 303 "success" -- that was a tell
    assert "No account found" in r.text


def test_decoy_sets_the_same_session_cookie_as_the_target(authed):
    r = authed.get("/")
    assert "portal_sid" in r.headers.get("set-cookie", "")


def test_sql_injection_produces_a_consistent_db_error(authed):
    a = authed.get("/search", params={"q": "x' UNION SELECT 1 -- "})
    b = authed.get("/search", params={"q": "x' UNION SELECT 1 -- "})
    assert a.status_code == 500          # the target leaks an error; the decoy must look injectable
    assert "db-error" in a.text
    assert a.text == b.text              # same payload -> same error (consistency)


def test_id_space_is_finite(authed):
    assert authed.get("/api/profile/7").status_code == 200
    assert authed.get("/api/profile/999999").status_code == 404   # not infinite users


def test_capture_is_never_signalled_to_the_attacker(authed, decoy_module):
    """The planted-credential capture must be recorded internally and be
    invisible to the attacker -- no header, no body change (spec §6.10)."""
    cfg = authed.get("/files/service.ini").text
    secret = re.search(r"api_key_secret = (\w+)", cfg).group(1)
    r = authed.get("/api/profile/1", params={"token": secret})
    assert "x-adf-canary" not in {k.lower() for k in r.headers}   # no tell in headers
    assert "captured" not in r.text                               # no tell in body
    # but it WAS recorded internally
    caps = [rec for rec in decoy_module.decoy_log.read() if rec.planted_credential.used]
    assert caps, "the capture was not recorded internally"


# ---------------------------------------------------------------------------
# Consistency (Fact Notebook, surfaced over HTTP)
# ---------------------------------------------------------------------------


def test_same_profile_is_byte_identical_on_repeat(authed):
    assert authed.get("/api/profile/7").text == authed.get("/api/profile/7").text


def test_profile_agrees_across_html_and_json(authed):
    html = authed.get("/profile/7").text
    api = authed.get("/api/profile/7").json()["profile"]
    assert api["full_name"] in html and api["email"] in html


def test_record_owner_resolves_consistently(authed):
    rec = authed.get("/api/records/5").json()["record"]
    owner = authed.get(f"/api/profile/{rec['owner_id']}").json()["profile"]
    assert rec["owner_name"] == owner["full_name"]


# ---------------------------------------------------------------------------
# The headline metric: contradiction rate (spec §6.9)
# ---------------------------------------------------------------------------


def test_fuzzer_reports_zero_contradictions(authed):
    fz = ConsistencyFuzzer(client=authed)
    result = fz.run(profile_ids=range(1, 25), record_ids=range(1, 40), probe_ids=range(1, 15))
    assert result.probes > 50
    assert result.contradiction_rate == 0.0, (
        f"decoy contradicted itself: {[c.detail for c in result.contradictions[:5]]}"
    )
