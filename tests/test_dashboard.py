"""The read-only dashboard renders from whatever log/eval data exists, and never
writes. These tests assert the routes work and the reader aggregation is sane;
they do not require a live proxy."""

from __future__ import annotations

from fastapi.testclient import TestClient

from adf.dashboard.app import app
from adf.dashboard import reader

client = TestClient(app)


def test_overview_renders():
    r = client.get("/")
    assert r.status_code == 200
    for fragment in ("ADF Monitor", "System topology", "Project health",
                     "Traffic distribution", "Decision bands"):
        assert fragment in r.text


def test_healthz_and_kpis():
    assert client.get("/healthz").json()["ok"] is True
    assert client.get("/api/kpis").status_code == 200


def test_missing_session_is_graceful():
    r = client.get("/session/definitely-not-a-real-session-id")
    assert r.status_code == 200
    assert "not found" in r.text.lower()


def test_health_reports_every_component():
    names = {h["component"] for h in reader.system_health()}
    for expected in ("cost table", "bait library"):
        assert expected in names
    for h in reader.system_health():
        assert h["status"] in ("ok", "warn", "idle")


def test_traffic_stats_are_consistent():
    t = reader.traffic_stats()
    a = t["action_sessions"]
    # every session took exactly one final action
    assert sum(a.values()) == t["total_sessions"]
    # flows never exceed the total request count
    assert t["flows"]["proxy_to_target"] + t["flows"]["proxy_to_decoy"] <= t["flows"]["client_to_proxy"]


def test_bands_are_ordered():
    b = reader.decision_bands()
    assert 0.0 < b["pass_to_bait"] < b["bait_to_divert"] < 1.0
