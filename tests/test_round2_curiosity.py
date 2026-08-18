"""Round-2 attackers must READ what comes back.

The obfuscated-SQLi profiles once fired payloads and never looked at the response.
Their bite rate was therefore 0.000 by construction while ~90% of their sessions
were being baited: the probe was unreachable rather than ineffective, and that
subcategory accounted for 65% of all remaining misses. These tests pin the fixed
behaviour so it cannot silently regress, and pin the mixed population so the
evaluation never quietly becomes a strawman that always bites.
"""
from __future__ import annotations

import random

import pytest

from tools import attack_traffic_round2 as r2

BAITED = "Table 'acct_shadow_a3f91c' doesn't exist near line 1"
CLEAN = "<html><body>no results for your search</body></html>"


class _FakeClient:
    """Records requests instead of making them."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.headers: dict[str, str] = {}

    def get(self, path, params=None, **kw):
        self.calls.append((path, params or {}))
        return _FakeResponse(CLEAN)

    def post(self, path, data=None, **kw):
        self.calls.append((path, data or {}))
        return _FakeResponse(CLEAN)

    def close(self) -> None:
        pass


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self.text = text


def _attack_calls(client) -> list[tuple[str, dict]]:
    """Calls excluding page sub-resources.

    Browser-driven attackers pull the stylesheet and script alongside every HTML
    page, so a raw call count now mixes two unrelated behaviours. These tests are
    about whether a leaked table name gets queried; asset fetches have their own
    tests below.
    """
    return [c for c in client.calls if not c[0].startswith("/static/")]


def _make(cls, curiosity: float):
    atk = cls("http://127.0.0.1:1", random.Random(7), dwell=False)
    atk.client.close()
    atk.client = _FakeClient()
    atk.curiosity = curiosity
    atk.bit = False
    return atk


SQL_PROFILES = [r2.ObfuscatedSQLi, r2.ManualObfuscated, r2.StealthProber]


@pytest.mark.parametrize("cls", SQL_PROFILES)
def test_a_curious_attacker_queries_the_leaked_table(cls):
    atk = _make(cls, 1.0)
    assert atk._follow_sql_bait(BAITED) is True
    assert atk.bit is True
    path, params = _attack_calls(atk.client)[-1]
    assert path == "/search"
    assert params["q"] == "acct_shadow_a3f91c", "must query the exact leaked table name"


@pytest.mark.parametrize("cls", SQL_PROFILES)
def test_a_bait_aware_attacker_does_not_bite(cls):
    atk = _make(cls, 0.0)
    assert atk._follow_sql_bait(BAITED) is False
    assert atk.bit is False
    assert _attack_calls(atk.client) == []


@pytest.mark.parametrize("cls", SQL_PROFILES)
def test_a_clean_response_is_never_bitten(cls):
    atk = _make(cls, 1.0)
    assert atk._follow_sql_bait(CLEAN) is False
    assert atk.bit is False


@pytest.mark.parametrize("cls", SQL_PROFILES)
def test_a_session_bites_at_most_once(cls):
    atk = _make(cls, 1.0)
    assert atk._follow_sql_bait(BAITED) is True
    assert atk._follow_sql_bait(BAITED) is False, "a bitten session must not bite again"
    assert len(_attack_calls(atk.client)) == 1


def test_population_is_mixed_by_default():
    """Some attackers must ignore the bait, or the evaluation is a strawman."""
    drawn = {r2.ObfuscatedSQLi("http://127.0.0.1:1", random.Random(s), dwell=False).curiosity
             for s in range(60)}
    assert 0.0 in drawn, "the population must contain bait-aware attackers"
    assert max(drawn) > 0.0, "the population must contain curious attackers"
    assert len(drawn) > 1, "curiosity must vary across sessions"


def test_curiosity_override_pins_the_population():
    """--curiosity 0.0 must reproduce the old blind model exactly, for the sweep."""
    r2.CURIOSITY_OVERRIDE = 0.0
    try:
        drawn = {r2.ObfuscatedSQLi("http://127.0.0.1:1", random.Random(s), dwell=False).curiosity
                 for s in range(20)}
        assert drawn == {0.0}
    finally:
        r2.CURIOSITY_OVERRIDE = None


def test_every_search_profile_reads_its_responses():
    """A profile that hits /search but never inspects the reply makes the probe
    unreachable. Guard the whole class, not just today's three."""
    import inspect
    for cls in (r2.ObfuscatedSQLi, r2.ManualObfuscated, r2.StealthProber):
        src = inspect.getsource(cls.run)
        assert "/search" in src
        assert "_follow_sql_bait" in src or "_maybe_bite" in src, (
            f"{cls.__name__} queries /search without ever reading the response")


# --------------------------------------------------------------------------
# Browser-driven attackers
# --------------------------------------------------------------------------
#
# No attack session in the corpus ever fetched a page sub-resource, while 96.5%
# of human-paced benign sessions did. A classifier fitted on those features
# separated the classes at AUC 0.9935 without learning anything about hostility.
# The shipped system is unaffected -- automation carries weight zero in the
# belief -- but the corpus was easier than reality, because a great deal of real
# tooling drives a browser and a browser fetches sub-resources regardless.


def test_the_population_contains_both_raw_http_and_browser_attackers():
    drawn = {r2.ObfuscatedSQLi("http://127.0.0.1:1", random.Random(s),
                               dwell=False).browser_driven
             for s in range(60)}
    assert drawn == {True, False}, (
        "if every attacker is one or the other, sub-resource fetching separates "
        "the classes perfectly again, in whichever direction")


def test_browser_driven_override_pins_the_population():
    r2.BROWSER_DRIVEN_OVERRIDE = 0.0
    try:
        assert not any(r2.ObfuscatedSQLi("http://127.0.0.1:1", random.Random(s),
                                         dwell=False).browser_driven
                       for s in range(30)), "0.0 must reproduce the raw-HTTP corpus"
    finally:
        r2.BROWSER_DRIVEN_OVERRIDE = None

    r2.BROWSER_DRIVEN_OVERRIDE = 1.0
    try:
        assert all(r2.ObfuscatedSQLi("http://127.0.0.1:1", random.Random(s),
                                     dwell=False).browser_driven
                   for s in range(30))
    finally:
        r2.BROWSER_DRIVEN_OVERRIDE = None


def test_a_browser_driven_attacker_fetches_page_assets():
    atk = _make(r2.ObfuscatedSQLi, 0.0)
    atk.browser_driven = True
    atk._load_page("/search", params={"q": "x"})
    fetched = {c[0] for c in atk.client.calls if c[0].startswith("/static/")}
    assert fetched, "a browser-driven session must pull sub-resources"
    assert fetched <= set(r2.PAGE_ASSETS)


def test_a_raw_http_attacker_fetches_no_assets():
    atk = _make(r2.ObfuscatedSQLi, 0.0)
    atk.browser_driven = False
    atk._load_page("/search", params={"q": "x"})
    assert not [c for c in atk.client.calls if c[0].startswith("/static/")]


def test_asset_list_matches_the_benign_generator():
    """If the two lists drift, the feature separates the generators again."""
    from tools import benign_traffic as bt
    assert r2.PAGE_ASSETS == bt.PAGE_ASSETS


def test_manual_browser_profiles_actually_behave_like_browsers():
    """They claimed a browser user-agent while never fetching a stylesheet."""
    for cls in (r2.ManualObfuscated, r2.ScatteredHtmlIDOR):
        atk = cls("http://127.0.0.1:1", random.Random(3), dwell=False)
        try:
            assert atk.browser_driven, cls.__name__
            assert "Accept-Language" in atk.client.headers, cls.__name__
            assert atk.client.headers["User-Agent"].startswith("Mozilla/"), cls.__name__
        finally:
            atk.client.close()
