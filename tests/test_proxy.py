"""
Tests for the reverse proxy (spec §5, NFR-04).

The proxy is the single point of failure for the whole site, so the property
that matters most is the one spec NFR-04 names: it must FAIL OPEN. A crash in
any detection component must still serve the user from the real application.
Two tests here inject a detection fault and assert the response is unharmed.

The proxy needs a real upstream to forward to, so these tests stand a
TestClient-wrapped target app up in-process and point the proxy at it via a
transport shim, rather than binding real sockets.
"""

from __future__ import annotations

import os

import httpx
import pytest

from adf.proxy import Proxy, create_app
from adf.proxy.session import SessionRegistry


@pytest.fixture(scope="module")
def target_client(seeded_db):
    """The real target app as an ASGI TestClient."""
    os.environ["ADF_DATABASES__TARGET_DSN"] = "sqlite:///data/test_target.sqlite3"
    from fastapi.testclient import TestClient
    import target_app.main as main

    main.db = seeded_db
    with TestClient(main.app) as tc:
        yield tc


class _StubMeter:
    """A meter that returns fixed scores, so the proxy can be tested without a
    trained model."""

    def __init__(self, automation=0.1, malice=0.1, raises=False):
        self._a, self._m, self._raises = automation, malice, raises

    def score(self, vector):
        if self._raises:
            raise RuntimeError("injected detection fault")
        from adf.meter import MeterScores, AxisExplanation
        expl = AxisExplanation(score=self._m, logit=0.0, bias=0.0, contributions=[])
        aexpl = AxisExplanation(score=self._a, logit=0.0, bias=0.0, contributions=[])
        return MeterScores(automation=self._a, malice=self._m,
                           automation_expl=aexpl, malice_expl=expl)


def _make_proxy(target_client, tmp_path, *, meter=None, policy=None):
    """A Proxy whose httpx client is redirected into the in-process target."""
    from adf.logstore import LogStore

    proxy = Proxy(
        meter=meter,
        policy=policy,
        target_upstream="http://target.local",
        log=LogStore(tmp_path / "proxy.jsonl"),
    )
    # Redirect the proxy's async client onto the ASGI target app.
    import target_app.main as main
    proxy._client = httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app),
                                      base_url="http://target.local")
    return proxy


@pytest.fixture
def app_client(target_client, tmp_path):
    """A proxy wired to a stub meter, exposed as a TestClient."""
    from adf.policy.engine import DecisionPolicy

    proxy = _make_proxy(target_client, tmp_path, meter=_StubMeter(),
                        policy=DecisionPolicy.from_config())
    app = create_app(proxy=proxy)
    from fastapi.testclient import TestClient
    with TestClient(app) as tc:
        yield tc, proxy


# ---------------------------------------------------------------------------
# Forwarding
# ---------------------------------------------------------------------------


def test_proxy_forwards_get_to_the_target(app_client):
    tc, _ = app_client
    r = tc.get("/")
    assert r.status_code == 200
    assert "Northbridge" in r.text          # the real home page came back


def test_proxy_preserves_status_codes(app_client):
    tc, _ = app_client
    r = tc.get("/login")
    assert r.status_code == 200
    r404 = tc.get("/nonexistent-path-xyz")
    assert r404.status_code == 404


def test_proxy_forwards_post_and_the_login_flow_works(app_client):
    tc, _ = app_client
    from target_app.otp import otp_for

    tc.post("/login", data={"username": "a.mirza", "password": "Summer2024!"})
    r = tc.post("/otp", data={"code": otp_for(1)}, follow_redirects=True)
    # reached an authenticated page through the proxy
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Scoring and logging
# ---------------------------------------------------------------------------


def test_scored_requests_are_logged_with_a_decision(app_client):
    tc, proxy = app_client
    tc.get("/search?q=test")
    records = list(proxy.log.read())
    assert records, "the proxy logged nothing"
    scored = [r for r in records if r.decision.action]
    assert scored, "no request carried a decision"
    assert scored[-1].decision.action in {"pass", "bait", "divert"}


def test_scored_records_carry_features_and_both_score_pairs(app_client):
    """FR-11 / spec §6.11: each record captures the extracted features and BOTH
    scores, before and after the update.

    Regression: the proxy logged neither for a long time — `features` was {} and
    `scores.before` was 0.0 on every record. Nothing failed, because nothing
    read them yet; it would have surfaced as empty columns in the released
    dataset (§11), after collection, when it is expensive to fix.
    """
    from adf.features import ALL_FEATURES

    tc, proxy = app_client
    for _ in range(3):
        tc.post("/login", data={"username": "a.mirza", "password": "wrong"})

    scored = [r for r in proxy.log.read() if r.decision.action]
    assert scored, "no scored records to check"
    last = scored[-1]

    assert last.features, "FR-11: the feature vector was not recorded"
    assert set(last.features) == set(ALL_FEATURES), (
        "the logged feature vector does not match the declared feature set"
    )
    # the malice score must have moved across the session, so a later record's
    # `before` should carry a non-default value from the preceding update
    assert any(r.scores.before.malice > 0.0 for r in scored), (
        "FR-11: scores.before was never populated"
    )


def test_no_detection_marker_leaks_to_the_client(app_client):
    """Invisible transition / detection (spec FR-09, §6.7): the proxy must never
    reveal scoring, decisions or divert to the client. No response header may
    disclose the security layer -- the visitor sees a normal site whether they
    were passed, baited or diverted."""
    tc, _ = app_client
    for path in ("/", "/login", "/search?q=test", "/dashboard"):
        r = tc.get(path)
        leaked = [k for k in r.headers if k.lower().startswith(("x-adf", "x-detect", "x-score"))]
        assert not leaked, f"{path} leaked a detection marker: {leaked}"


def test_scores_accumulate_across_a_session(app_client):
    tc, proxy = app_client
    # hammer failed logins: malice features should climb within one session
    for _ in range(4):
        tc.post("/login", data={"username": "a.mirza", "password": "wrong"})
    # one session, so exactly one state entry
    states = list(proxy._state.values())
    assert len(states) == 1
    assert states[0].request_index >= 4


# ---------------------------------------------------------------------------
# THE FAIL-OPEN PROPERTY (spec NFR-04)
# ---------------------------------------------------------------------------


def test_proxy_fails_open_when_the_meter_raises(target_client, tmp_path):
    """A detection crash must not reach the user. The response must still be
    the real page, served from the target application."""
    from adf.policy.engine import DecisionPolicy

    proxy = _make_proxy(target_client, tmp_path, meter=_StubMeter(raises=True),
                        policy=DecisionPolicy.from_config())
    app = create_app(proxy=proxy)
    from fastapi.testclient import TestClient
    with TestClient(app) as tc:
        r = tc.get("/")
        assert r.status_code == 200, "fail-open violated: a detection fault broke the response"
        assert "Northbridge" in r.text

    # and the fault was recorded, so it is not silent
    faulted = [rec for rec in proxy.log.read() if rec.decision.fail_open_triggered]
    assert faulted, "fail-open event was not logged"


def test_forward_only_mode_serves_without_a_meter(target_client, tmp_path):
    """With no meter wired in, the proxy is a plain forwarder (mode b0). It
    must still serve every request."""
    proxy = _make_proxy(target_client, tmp_path, meter=None, policy=None)
    app = create_app(proxy=proxy)
    from fastapi.testclient import TestClient
    with TestClient(app) as tc:
        r = tc.get("/")
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Cross-divert-boundary decoy consistency (docs/LIMITATIONS.md §7)
# ---------------------------------------------------------------------------


class _SplitUpstream(httpx.AsyncBaseTransport):
    """Target and decoy return DIFFERENT content for the same path, so a
    re-read after a divert can be told apart: target host -> 'TARGET ...',
    decoy host -> 'DECOY ...'."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        who = "TARGET" if request.url.host == "target.local" else "DECOY"
        path = request.url.path
        return httpx.Response(200, headers={"content-type": "text/html; charset=utf-8"},
                              content=f"<p>{who} view of {path}</p>".encode())


def _split_proxy(tmp_path):
    from adf.logstore import LogStore
    from adf.policy.engine import DecisionPolicy
    p = Proxy(meter=_StubMeter(), policy=DecisionPolicy.from_config(),
              target_upstream="http://target.local", decoy_upstream="http://decoy.local",
              log=LogStore(tmp_path / "proxy.jsonl"))
    p._client = httpx.AsyncClient(transport=_SplitUpstream())
    return p


def test_a_re_read_after_divert_replays_the_target_view_not_the_decoy(tmp_path):
    """The tell an agentic attacker found: the same id returns different data
    after a divert. A path seen on the target before the divert must replay
    identically after it, while a genuinely new path still gets the decoy."""
    from fastapi.testclient import TestClient
    proxy = _split_proxy(tmp_path)
    app = create_app(proxy=proxy)
    with TestClient(app) as tc:
        before = tc.get("/records/6")
        assert "TARGET view of /records/6" in before.text

        # trip the divert by hand (the meter here is a stub)
        assert proxy._state, "no session state created"
        for st in proxy._state.values():
            st.diverted = True

        again = tc.get("/records/6")            # already seen -> must be consistent
        fresh = tc.get("/records/99")           # never seen  -> decoy fabricates

    assert again.text == before.text, "re-read after divert changed under the attacker (the tell)"
    assert "DECOY" not in again.text
    assert "DECOY view of /records/99" in fresh.text, "a new probe should still reach the decoy"

    notes = [r.run.notes for r in proxy.log.read()]
    assert any("replayed pre-divert view" in n for n in notes), "the replay was not logged"


def test_a_post_after_divert_still_reaches_the_decoy(tmp_path):
    """Only idempotent GET re-reads are replayed. A POST (a login attempt, the
    channel the planted credential is captured on) must always reach the decoy."""
    from fastapi.testclient import TestClient
    proxy = _split_proxy(tmp_path)
    app = create_app(proxy=proxy)
    with TestClient(app) as tc:
        tc.get("/login")
        for st in proxy._state.values():
            st.diverted = True
        posted = tc.post("/login", data={"username": "x", "password": "y"})
    assert "DECOY" in posted.text, "a POST after divert must reach the decoy, not a replay"


def test_disabling_the_replay_restores_the_tell(tmp_path):
    """The ablation flag `proxy.replay_pre_divert_views` really is what closes
    the tell: with it off, a re-read after the divert is answered by the decoy
    and the content changes under the attacker -- which is what
    tools/boundary_consistency.py measures as a ~91% contradiction rate."""
    from fastapi.testclient import TestClient
    proxy = _split_proxy(tmp_path)
    proxy._replay_enabled = False                 # pre-fix behaviour
    app = create_app(proxy=proxy)
    with TestClient(app) as tc:
        before = tc.get("/records/6")
        assert "TARGET view of /records/6" in before.text
        for st in proxy._state.values():
            st.diverted = True
        again = tc.get("/records/6")
    assert "DECOY view of /records/6" in again.text, \
        "with replay disabled the decoy should answer the re-read (the tell)"
    assert again.text != before.text
