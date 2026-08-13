"""
Tests that the target application is still WEAK in exactly the intended ways.

These read backwards compared with normal tests: a failure here usually means
somebody has fixed a vulnerability. That is a problem, not a win. Each
weakness is the attack surface for one of the three categories in scope
(spec §6.1), and removing one silently deletes a category from the study.

Equally, the tests pin the *boundaries* of the weakness. The app is meant to
be exploitable in four specific ways and ordinary everywhere else; an
accidental second injection point would widen the threat model and make the
attack-category labels wrong.
"""

from __future__ import annotations

import re

from target_app.otp import otp_for


def _sign_in(client, username="a.mirza", password="Summer2024!", user_id=1):
    client.post("/login", data={"username": username, "password": password})
    client.post("/otp", data={"code": otp_for(user_id)})


# ---------------------------------------------------------------------------
# WEAKNESS 1 -- login (spec §6.1: no rate limit, no lockout, verbose failures)
# ---------------------------------------------------------------------------


def test_login_distinguishes_unknown_user_from_wrong_password(client):
    """Username enumeration, on purpose. This is what makes a credential
    attack tractable and what B-AUTH-1 later exploits for plausibility."""
    unknown = client.post("/login", data={"username": "no.such.person", "password": "x"})
    wrong = client.post("/login", data={"username": "a.mirza", "password": "definitely-wrong"})

    assert unknown.status_code == 401
    assert wrong.status_code == 401
    assert "No account found" in unknown.text
    assert "Incorrect password" in wrong.text


def test_login_has_no_lockout_or_rate_limit(client):
    """Ten consecutive failures must still return a normal 401, never a 429
    and never a lockout -- otherwise the credential-attack category cannot
    generate the volume of traffic the meter needs to learn from."""
    for _ in range(10):
        response = client.post("/login", data={"username": "a.mirza", "password": "wrong"})
        assert response.status_code == 401, "login is being throttled; the auth surface has been fixed"

    assert client.post("/login", data={"username": "a.mirza", "password": "Summer2024!"}).status_code in (200, 303)


def test_login_reports_the_running_failure_count(client):
    """The counter tells an attacker nothing is throttling them, and gives
    B-AUTH-1 a natural place to fire (several failures in one session)."""
    fresh = client.__class__(client.app)
    fresh.post("/login", data={"username": "a.mirza", "password": "wrong"})
    second = fresh.post("/login", data={"username": "a.mirza", "password": "wrong"})
    assert re.search(r"\d+ failed attempt", second.text)


# ---------------------------------------------------------------------------
# WEAKNESS 2 -- OTP (predictable, uncapped, reusable)
# ---------------------------------------------------------------------------


def test_otp_is_predictable_from_user_id_alone(client):
    """No secret and no randomness: the code is a pure function of user id
    and the day. This is the OTP-bypass surface."""
    assert otp_for(1) == otp_for(1)
    assert otp_for(1) != otp_for(2)
    assert re.fullmatch(r"\d{6}", otp_for(1))


def test_otp_accepts_unlimited_attempts(client):
    fresh = client.__class__(client.app)
    fresh.post("/login", data={"username": "d.okafor", "password": "password1"})
    for _ in range(15):
        response = fresh.post("/otp", data={"code": "000000"})
        assert response.status_code == 401, "OTP attempts are being capped; the bypass surface has been fixed"

    assert fresh.post("/otp", data={"code": otp_for(2)}).status_code in (200, 303)


def test_otp_code_is_reusable(client):
    """A used code is never invalidated, so it can be replayed."""
    for _ in range(2):
        fresh = client.__class__(client.app)
        fresh.post("/login", data={"username": "d.okafor", "password": "password1"})
        assert fresh.post("/otp", data={"code": otp_for(2)}).status_code in (200, 303)


# ---------------------------------------------------------------------------
# WEAKNESS 3 -- SQL injection in search
# ---------------------------------------------------------------------------


def test_search_is_injectable_via_union(client):
    """The payload must actually exfiltrate from another table, not merely
    fail to crash -- otherwise the sqli label describes attempts, not attacks."""
    _sign_in(client)
    payload = "x' UNION SELECT id, username, password_hash, role FROM users -- "
    response = client.get("/search", params={"q": payload})

    assert response.status_code == 200
    assert "admin" in response.text, "UNION injection no longer reaches the users table"


def test_search_leaks_the_raw_driver_error(client):
    """Error-based injection, and the response B-SQL-1 impersonates. Without
    the verbose leak the SQL bait would look nothing like the real thing."""
    _sign_in(client)
    response = client.get("/search", params={"q": "x' UNION SELECT 1 -- "})

    assert response.status_code == 500
    assert 'class="db-error"' in response.text
    assert "UNION" in response.text


def test_ordinary_search_still_works(client):
    """The app has to be usable, or benign traffic cannot be generated."""
    _sign_in(client)
    response = client.get("/search", params={"q": "maintenance"})
    assert response.status_code == 200
    assert "maintenance" in response.text.lower()


def test_injection_is_confined_to_the_search_endpoint(client):
    """Exactly one `query_raw` call site in the application."""
    from pathlib import Path

    source = Path(__file__).resolve().parent.parent / "target_app" / "main.py"
    assert source.read_text(encoding="utf-8").count("query_raw(") == 1, (
        "a second raw-SQL call site has appeared; the injection surface must stay "
        "confined to /search or the attack-category labels become wrong"
    )


# ---------------------------------------------------------------------------
# WEAKNESS 4 -- IDOR (sequential ids, no ownership check)
# ---------------------------------------------------------------------------


def test_any_user_can_read_any_profile(client):
    _sign_in(client)  # signed in as user 1
    other = client.get("/profile/9")
    assert other.status_code == 200
    assert "Lucia Ferreira" in other.text, "profile access is now ownership-checked"


def test_json_api_exposes_profiles_by_sequential_id(client):
    """The endpoint B-IDOR-1 injects `ref_uid` into."""
    _sign_in(client)
    for pid in (2, 3, 4):
        response = client.get(f"/api/profile/{pid}")
        assert response.status_code == 200
        assert "profile" in response.json()


def test_records_are_readable_across_owners(client):
    _sign_in(client)
    response = client.get("/api/records/45")
    assert response.status_code == 200
    assert response.json()["record"]["owner_id"] != 1, "expected a record owned by another user"


def test_unauthenticated_access_is_still_refused(client):
    """The app is weak, not open. IDOR requires an authenticated session, so
    the category is 'authenticated user reads another's data', not 'no auth'."""
    anon = client.__class__(client.app)
    assert anon.get("/api/profile/3").status_code == 401
    assert anon.get("/profile/3").status_code in (303, 307, 200)  # redirected to login


# ---------------------------------------------------------------------------
# Static assets -- the automation signal (spec §6.1)
# ---------------------------------------------------------------------------


def test_a_session_is_created_once_per_client(client):
    """Regression guard (see docs/DECISIONS.md, 2026-08-13).

    The access-log middleware and the route handler both resolve the session.
    If they each create one, the first request of every session is logged
    against an orphaned id and split away from the rest — which would quietly
    corrupt `requests-to-decision` (spec §10.3), the project's headline
    efficiency metric, and every accumulated score (§6.4).
    """
    fresh = client.__class__(client.app)
    first = fresh.get("/")
    sid = first.cookies.get("portal_sid")
    assert sid, "no session cookie was issued"

    for _ in range(3):
        assert fresh.get("/").cookies.get("portal_sid", sid) == sid, \
            "session identity changed mid-session"

    # And the very first request must already carry the surviving id.
    import target_app.main as main
    assert sid in main._sessions
    assert main._sessions[sid].request_index >= 4, \
        "requests are not all being counted against the same session"


def test_static_assets_exist_and_are_referenced(client):
    """Browsers fetch these; scripted tools usually do not. The feature only
    exists if the pages actually reference real assets."""
    home = client.get("/")
    assert home.status_code == 200
    for asset in ("/static/app.css", "/static/app.js", "/static/logo.svg"):
        assert asset in home.text, f"{asset} is not referenced by the page"
        assert client.get(asset).status_code == 200
