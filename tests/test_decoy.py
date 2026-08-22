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
    """The fuzzer is adversarial: full-field cross-reference, multi-reference
    (records sharing an owner must agree), interleaving, error-surface and
    search consistency. A rate of zero over hundreds of such probes is a
    meaningful result, not a tautology."""
    fz = ConsistencyFuzzer(client=authed)
    result = fz.run(profile_ids=range(1, 25), record_ids=range(1, 60), probe_ids=range(1, 20))
    assert result.probes > 250, f"expected an aggressive probe count, got {result.probes}"
    assert result.contradiction_rate == 0.0, (
        f"decoy contradicted itself: {[c.detail for c in result.contradictions[:5]]}"
    )
    # multi-reference is the dimension a naive decoy fails; make sure it ran
    assert result.probed_by_dimension.get("multi-reference", 0) > 10
    # and the content is plausible, not just self-consistent (§10.4)
    assert result.plausibility_rate == 0.0, (
        f"implausible content: {[c.detail for c in result.plausibility[:5]]}"
    )


# ---------------------------------------------------------------------------
# Cross-boundary overlay: seen entities agree on every surface (LIMITATIONS §7)
# ---------------------------------------------------------------------------

def _observed_header(observed):
    from adf.decoy.observed import encode
    return encode(observed)


def test_overlay_makes_the_directory_agree_with_a_seen_profile(decoy_module):
    """The second-order tell: an attacker read /profile/3 on the target, then
    opens /directory (never seen) in the decoy. With the observed-facts overlay
    the listing must show the SAME name for id 3 as the profile page did, while
    an id the attacker never saw keeps the decoy's fabricated name."""
    from adf.decoy.observed import HEADER
    seen = {"user": {3: {"full_name": "Sofia Lindqvist", "department": "Operations",
                         "location": "Block C, Floor 4"}}}
    with TestClient(decoy_module.app,
                    headers={"X-ADF-Authenticated": "1", HEADER: _observed_header(seen)}) as tc:
        prof = tc.get("/profile/3").text
        directory = tc.get("/directory").text
        prof10 = tc.get("/profile/10").text

    assert "Sofia Lindqvist" in prof, "overlay not applied to the profile page"
    assert "Sofia Lindqvist" in directory, "the directory contradicts the seen profile (the tell)"
    # id 10 was never observed -> the fake world stands, nothing new is exposed
    fake10 = re.search(r"<h1>(.*?)</h1>", prof10).group(1)
    assert fake10 != "Sofia Lindqvist"
    assert fake10 in directory, "the decoy's own world must stay internally consistent"


def test_overlay_without_the_header_keeps_the_decoy_world(decoy_module):
    """No overlay header (an ordinary decoy request) -> the fabricated world,
    unchanged. Guards that the overlay is inert unless the proxy asks for it."""
    with TestClient(decoy_module.app, headers={"X-ADF-Authenticated": "1"}) as tc:
        a = tc.get("/profile/3").text
        b = tc.get("/profile/3").text
    assert a == b
    assert "Sofia Lindqvist" not in a  # the decoy uses different names by design


def test_overlaid_apostrophe_name_is_escaped_once_in_the_aggregate(decoy_module):
    """A name with an apostrophe must not double-escape when the decoy re-renders
    it in the directory. The proxy stores the DECODED value ("Maeve O'Connell"),
    so Jinja escapes it exactly once ("O&#39;Connell"), never "O&amp;#39;"."""
    from adf.decoy.observed import HEADER
    seen = {"user": {5: {"full_name": "Maeve O'Connell", "department": "People",
                         "location": "Block A, Floor 2"}}}
    with TestClient(decoy_module.app,
                    headers={"X-ADF-Authenticated": "1", HEADER: _observed_header(seen)}) as tc:
        directory = tc.get("/directory").text
    assert "O&#39;Connell" in directory
    assert "O&amp;#39;" not in directory, "name double-escaped in the aggregate (a fresh tell)"


def test_the_dashboard_only_lists_records_this_user_owns(decoy_module):
    """"Your records" must not claim a record the visitor knows is someone
    else's. The dashboard used to list a hardcoded 1..6 regardless of who was
    logged in, so an attacker who had read /records/6 on the target (owner
    profile #2) and was then shown it under "Your records" here had caught the
    swap. Found by re-pentesting after the login surface was added."""
    from fastapi.testclient import TestClient
    with TestClient(decoy_module.app, headers={"X-ADF-Authenticated": "1"}) as tc:
        body = tc.get("/dashboard").text
    shown = [int(n) for n in re.findall(r"#(\d+)", body)]
    # every id on the dashboard must resolve to a record this session owns
    uid = 1                      # the default identity for a vouched session
    for rid in shown:
        owner = decoy_module._record_view(rid)["owner_id"]
        assert owner == uid, (
            f"dashboard lists record #{rid} as the user's own, but its owner is #{owner}")


def test_the_decoy_accepts_the_targets_seeded_credentials(decoy_module):
    """A visitor handed a real credential must be able to log in here too. The
    decoy used to reject every login (unknown user, or always 'wrong password'),
    which broke the human study's decoy arm outright and is a glaring tell:
    valid credentials that never work."""
    from fastapi.testclient import TestClient
    from target_app.otp import otp_for
    with TestClient(decoy_module.app) as tc:
        r = tc.post("/login", data={"username": "a.mirza", "password": "Summer2024!"},
                    follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/otp"
        r = tc.post("/otp", data={"code": otp_for(1)}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/dashboard"
        body = tc.get("/dashboard").text
    assert "Ayesha Mirza" in body, "the decoy should greet them by the name they signed in as"


def test_a_wrong_password_still_fails_on_the_decoy(decoy_module):
    """Accepting the real credential must not mean accepting anything: a
    stuffing attacker who does not know the password fails exactly as on the
    real site (the same verbose, enumerable errors)."""
    from fastapi.testclient import TestClient
    with TestClient(decoy_module.app) as tc:
        bad = tc.post("/login", data={"username": "a.mirza", "password": "nope"})
        unknown = tc.post("/login", data={"username": "nobody", "password": "x"})
    assert bad.status_code == 401 and "Incorrect password" in bad.text
    assert unknown.status_code == 401 and "No account found" in unknown.text


def test_no_two_profiles_share_a_name(decoy_module):
    """Different ids must be different people.

    Names used to be drawn independently per user, so with 24 profiles over the
    20x20 name pool the birthday bound gave a ~50% chance of a collision --
    measured at 52% across 200 seeds. A study participant found one in ten
    minutes ("two people with the same name, Ravi Iqbal, but different profile
    numbers and different locations") and reported the site as a mock-up. The
    name is now a function of the id, so uniqueness holds by construction.
    """
    seen_name, seen_username = {}, {}
    for uid in range(1, decoy_module.MAX_USER_ID + 1):
        u = decoy_module._user(uid)
        assert u["full_name"] not in seen_name, (
            f"profiles #{seen_name.get(u['full_name'])} and #{uid} are both "
            f"{u['full_name']!r}")
        assert u["username"] not in seen_username, (
            f"profiles #{seen_username.get(u['username'])} and #{uid} share "
            f"username {u['username']!r}")
        seen_name[u["full_name"]] = uid
        seen_username[u["username"]] = uid


def test_the_fuzzer_would_catch_a_duplicated_name(decoy_module, authed):
    """The distinctness probe is the guard, so it has to actually fire. Feed the
    fuzzer a decoy that issues one person twice and check it complains -- a probe
    that cannot fail certifies nothing."""
    from adf.decoy.fuzzer import ConsistencyFuzzer, FuzzResult
    fz = ConsistencyFuzzer(client=authed)
    fz._profile = lambda pid: {"id": pid, "full_name": "Ravi Iqbal",
                               "username": "r.iqbal", "department": "Legal",
                               "role": "staff", "location": "Annexe",
                               "email": "r.iqbal@northbridge-internal.example"}
    result = FuzzResult()
    fz.probe_distinctness(result, range(1, 4))
    assert result.plausibility, "the probe passed a decoy that issues one person three times"
