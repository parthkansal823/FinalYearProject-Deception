"""
Per-component fail-open fault injection (spec NFR-04, §13 Phase 6).

NFR-04 is the property that lets the proxy sit in front of the real site
without being able to take it down: if ANY detection component fails, the
request is still forwarded to the real application. Phase 6 requires a fault
injection test on EACH component, not just one.

This injects an exception into every detection component in turn -- feature
extractor, meter, policy, bite detection, and bait injection -- and asserts the
benign user still gets the real page, and the failure is logged (loud, not
silent).
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from adf.proxy import Proxy, create_app


@pytest.fixture(scope="module")
def target_app(seeded_db):
    import os
    os.environ["ADF_DATABASES__TARGET_DSN"] = "sqlite:///data/test_target.sqlite3"
    import target_app.main as main
    main.db = seeded_db
    return main


def _stub_scores(a=0.1, m=0.1):
    from adf.meter import MeterScores, AxisExplanation
    e = AxisExplanation(score=m, logit=0.0, bias=0.0, contributions=[])
    ae = AxisExplanation(score=a, logit=0.0, bias=0.0, contributions=[])
    return MeterScores(automation=a, malice=m, automation_expl=ae, malice_expl=e)


class _OkMeter:
    def score(self, vector):
        return _stub_scores()


def _proxy(target_app, tmp_path, **kw):
    from adf.logstore import LogStore
    from adf.policy.engine import DecisionPolicy
    p = Proxy(meter=kw.get("meter", _OkMeter()),
              policy=kw.get("policy", DecisionPolicy.from_config()),
              target_upstream="http://target.local",
              log=LogStore(tmp_path / "proxy.jsonl"))
    p._client = httpx.AsyncClient(transport=httpx.ASGITransport(app=target_app.app),
                                  base_url="http://target.local")
    return p


def _assert_serves_and_logs_fault(proxy):
    app = create_app(proxy=proxy)
    with TestClient(app) as tc:
        r = tc.get("/")
        assert r.status_code == 200, "fail-open violated: detection fault broke the response"
        assert "Northbridge" in r.text, "the real page did not come back"
    faults = [rec for rec in proxy.log.read() if rec.decision.fail_open_triggered]
    assert faults, "the fault was not logged (silent failure)"


# ---------------------------------------------------------------------------
# One test per component
# ---------------------------------------------------------------------------


def test_fail_open_when_feature_extractor_raises(target_app, tmp_path, monkeypatch):
    import adf.proxy.proxy as pmod

    def boom(self, record):
        raise RuntimeError("feature extractor fault")
    monkeypatch.setattr(pmod.SessionFeatureExtractor, "observe", boom)

    proxy = _proxy(target_app, tmp_path)
    _assert_serves_and_logs_fault(proxy)


def test_fail_open_when_meter_raises(target_app, tmp_path):
    class BadMeter:
        def score(self, vector):
            raise RuntimeError("meter fault")
    proxy = _proxy(target_app, tmp_path, meter=BadMeter())
    _assert_serves_and_logs_fault(proxy)


def test_fail_open_when_policy_raises(target_app, tmp_path):
    class BadPolicy:
        fusion = {"epsilon": 1e-6}
        def decide(self, **kw):
            raise RuntimeError("policy fault")
    proxy = _proxy(target_app, tmp_path, policy=BadPolicy())
    _assert_serves_and_logs_fault(proxy)


def test_fail_open_when_bite_detection_raises(target_app, tmp_path):
    proxy = _proxy(target_app, tmp_path)

    class BadEngine:
        def check_bite(self, **kw):
            raise RuntimeError("bite detection fault")
        def serve(self, **kw):
            return None, None
    proxy.bait_engine = BadEngine()
    _assert_serves_and_logs_fault(proxy)


def test_fail_open_when_bait_injection_raises(target_app, tmp_path):
    """Bait injection runs on the OUTBOUND response, outside the scoring
    try/except. A fault there must still not break the benign response."""
    proxy = _proxy(target_app, tmp_path)

    class BadInjectEngine:
        def check_bite(self, **kw):
            return None
        def serve(self, **kw):
            raise RuntimeError("bait injection fault")
    proxy.bait_engine = BadInjectEngine()
    # force a bait decision so serve() is reached
    from adf.policy.engine import Decision
    proxy.policy = _ForceBaitPolicy()
    app = create_app(proxy=proxy)
    with TestClient(app) as tc:
        r = tc.get("/")
        assert r.status_code == 200, "bait-injection fault broke the benign response"
        assert "Northbridge" in r.text


class _ForceBaitPolicy:
    fusion = {"epsilon": 1e-6}
    def decide(self, **kw):
        from adf.policy.engine import Decision, POLICY_VERSION
        return Decision(action="bait", p_attack=0.5, evsi=1.0, bait_id="B-SQL-1",
                        bait_assignment="policy", immediate_costs={}, effective_costs={},
                        likelihood_ratio=1100.0, reason=[], policy_version=POLICY_VERSION)
