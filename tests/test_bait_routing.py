"""
Bait routing regressions (spec §6.6) — two bugs the Phase 7 evaluation exposed.

Both are correctness, not tuning, and both silently produced "decide to bait,
inject nothing", which is the worst kind of failure: the uncertain case the
whole system exists for was never resolved, and no test caught it because
nothing downstream read the result.
"""

from __future__ import annotations

from adf.proxy.proxy import Proxy, _applicable_baits


# ---------------------------------------------------------------------------
# Bug 1 — routing ignored the surface being probed
# ---------------------------------------------------------------------------


def test_object_reference_endpoints_route_to_idor():
    """A scattered IDOR attacker walking /profile/{id} leaves no malice signal,
    so a feature-only router gave them an SQL bait they would never take. The
    surface must route them to IDOR."""
    f = Proxy._suspected_categories
    assert f({}, "/profile/7") == ["idor"]
    assert f({}, "/records/33") == ["idor"]
    assert f({}, "/api/profile/9") == ["idor"]


def test_feature_signals_still_route():
    f = Proxy._suspected_categories
    assert "sqli" in f({"mal_db_keyword_hits": 2}, "/search")
    assert "auth" in f({"mal_failed_auth": 3}, "/login")


def test_no_signal_and_no_surface_leaves_selection_open():
    # empty -> the policy considers all baits and lets EVSI choose
    assert Proxy._suspected_categories({}, "/") == []


# ---------------------------------------------------------------------------
# Bug 2 — selection ignored the response type
# ---------------------------------------------------------------------------


def test_applicable_baits_respect_the_response_channel():
    """A json_field bait cannot be injected into an HTML page, and vice versa.
    Selecting one that cannot be injected is why the IDOR case silently failed
    (B-IDOR-1 is a JSON field; the profile PAGE is HTML)."""
    html = _applicable_baits("text/html; charset=utf-8")
    js = _applicable_baits("application/json")

    # html_comment baits belong to HTML, json_field baits to JSON
    assert "B-IDOR-2" in html and "B-IDOR-2" not in js          # html_comment
    assert "B-IDOR-1" in js and "B-IDOR-1" not in html          # json_field
    assert "B-SQL-1" in html and "B-SQL-1" not in js            # html_comment
    # nothing that is not applicable leaks in
    assert html.isdisjoint({"B-IDOR-1", "B-AUTH-2"})            # the JSON baits
    assert js.isdisjoint({"B-SQL-1", "B-SQL-2", "B-IDOR-2", "B-AUTH-1"})  # the HTML baits


def test_html_idor_attacker_would_receive_an_injectable_bait():
    """The intersection that was empty before the fix: IDOR category ∩ baits
    injectable into an HTML page must contain B-IDOR-2, or the scattered-UI-IDOR
    attacker can never be baited (and B2 already misses them)."""
    idor_baits = {"B-IDOR-1", "B-IDOR-2"}
    injectable_into_html = _applicable_baits("text/html")
    assert idor_baits & injectable_into_html == {"B-IDOR-2"}
