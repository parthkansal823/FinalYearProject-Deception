"""
Indistinguishability regression: the decoy must match the target (spec §6.8).

Phase 5's review found that the decoy was distinguishable in seven ways (see
docs/DECISIONS.md). This test stands BOTH apps up in-process and compares them
directly, so any future drift in the route surface or in per-route behaviour
fails a test instead of silently betraying the decoy. The ONE intended
difference is the planted credential in service.ini (spec §6.10).
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from target_app.otp import otp_for


def _routes(app) -> set[str]:
    out = set()
    for r in app.routes:
        for m in getattr(r, "methods", set()) or set():
            if m not in ("HEAD", "OPTIONS"):
                out.add(f"{m} {r.path}")
    return out


@pytest.fixture(scope="module")
def both(tmp_path_factory):
    import importlib

    # target on a temp seeded DB
    tdb = tmp_path_factory.mktemp("t") / "target.sqlite3"
    os.environ["ADF_DATABASES__TARGET_DSN"] = f"sqlite:///{tdb.as_posix()}"
    # decoy on a temp notebook
    ndb = tmp_path_factory.mktemp("d") / "notebook.sqlite3"
    os.environ["ADF_DATABASES__FACT_NOTEBOOK_DSN"] = f"sqlite:///{ndb.as_posix()}"

    import target_app.main as target
    import decoy_app.main as decoy
    importlib.reload(target)
    importlib.reload(decoy)
    from target_app.seed import seed
    seed(target.db, seed_value=20260813)

    with TestClient(target.app) as tc, TestClient(decoy.app) as dc:
        # authenticate on the target for real ...
        tc.post("/login", data={"username": "a.mirza", "password": "Summer2024!"})
        tc.post("/otp", data={"code": otp_for(1)})
        # ... and give the decoy the proxy's auth vouch
        dc.headers["X-ADF-Authenticated"] = "1"
        yield target, decoy, tc, dc


def test_route_surfaces_are_identical(both):
    target, decoy, _, _ = both
    t, d = _routes(target.app), _routes(decoy.app)
    assert t - d == set(), f"routes only in target (decoy would 404): {t - d}"
    assert d - t == set(), f"routes only in decoy (a tell): {d - t}"


SHARED_PROBES = [
    "/", "/login", "/dashboard", "/directory",
    "/profile/7", "/api/profile/7", "/records/5", "/api/records/5",
    "/search?q=policy", "/files", "/files/readme.txt",
    "/profile/999999", "/nonexistent-xyz",
]


@pytest.mark.parametrize("path", SHARED_PROBES)
def test_status_and_content_type_match(both, path):
    _, _, tc, dc = both
    rt = tc.get(path, follow_redirects=False)
    rd = dc.get(path, follow_redirects=False)
    assert rt.status_code == rd.status_code, f"{path}: status {rt.status_code} vs {rd.status_code}"
    ct = lambda r: r.headers.get("content-type", "").split(";")[0]
    assert ct(rt) == ct(rd), f"{path}: content-type {ct(rt)} vs {ct(rd)}"


def test_unauthenticated_access_is_gated_identically(both):
    target, decoy, _, _ = both
    with TestClient(target.app) as ta, TestClient(decoy.app) as da:  # no auth
        for path in ("/dashboard", "/directory", "/files", "/search?q=x"):
            rt = ta.get(path, follow_redirects=False)
            rd = da.get(path, follow_redirects=False)
            assert rt.status_code == rd.status_code == 303, f"{path} not gated identically"


def test_bad_login_is_rejected_identically(both):
    target, decoy, _, _ = both
    with TestClient(target.app) as ta, TestClient(decoy.app) as da:
        rt = ta.post("/login", data={"username": "nobody", "password": "x"}, follow_redirects=False)
        rd = da.post("/login", data={"username": "nobody", "password": "x"}, follow_redirects=False)
        assert rt.status_code == rd.status_code == 401
        assert "No account found" in rt.text and "No account found" in rd.text


def test_sql_injection_surface_matches(both):
    _, _, tc, dc = both
    rt = tc.get("/search", params={"q": "x' UNION SELECT 1 -- "})
    rd = dc.get("/search", params={"q": "x' UNION SELECT 1 -- "})
    assert rt.status_code == rd.status_code == 500
    assert ("db-error" in rt.text) == ("db-error" in rd.text) is True


def test_mundane_files_are_identical_only_service_ini_differs(both):
    _, _, tc, dc = both
    for f in ("readme.txt", "changelog.txt", "maintenance.log"):
        assert tc.get(f"/files/{f}").text == dc.get(f"/files/{f}").text, f"{f} differs"
    # the ONE intended difference: the planted credential (spec §6.10)
    assert "api_key_secret" not in tc.get("/files/service.ini").text
    assert "api_key_secret" in dc.get("/files/service.ini").text


def test_logout_exists_in_both(both):
    target, decoy, _, _ = both
    with TestClient(target.app) as ta, TestClient(decoy.app) as da:
        ta.headers["X-ADF-Authenticated"] = "1"  # no-op on target, harmless
        da.headers["X-ADF-Authenticated"] = "1"
        rt = ta.get("/logout", follow_redirects=False)
        rd = da.get("/logout", follow_redirects=False)
        assert rt.status_code == rd.status_code == 303
