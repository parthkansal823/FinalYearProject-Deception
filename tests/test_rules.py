"""
Tests for the rule-based WAF, baseline B1 (spec §10.1).

The point of B1 is a FAIR reference: it must catch textbook attacks (or it is a
straw man that flatters the learned system) and must not flag ordinary traffic
(or its precision is a lie). Its brittleness against obfuscation and its total
blindness to IDOR are properties to demonstrate, not defects to fix — a
signature WAF genuinely has them, and that is the comparison.
"""

from __future__ import annotations

import pytest

from adf.proxy.rules import RuleWAF


@pytest.fixture(scope="module")
def waf():
    return RuleWAF()


TEXTBOOK = [
    "x' UNION SELECT 1,2,3 -- ",
    "x' OR 1=1 -- ",
    "'; DROP TABLE users",
    "<script>alert(1)</script>",
    "../../etc/passwd",
]


@pytest.mark.parametrize("payload", TEXTBOOK)
def test_textbook_attacks_are_flagged(waf, payload):
    assert waf.flags(query=payload), f"a standard WAF must catch {payload!r}"


def test_scanner_user_agent_is_flagged(waf):
    assert waf.flags(user_agent="sqlmap/1.9-dev")
    assert not waf.flags(user_agent="Mozilla/5.0 (Windows NT 10.0)")


BENIGN = ["maintenance", "O'Connell", "terms and conditions",
          "policy for new starters", "where is the printer"]


@pytest.mark.parametrize("q", BENIGN)
def test_benign_traffic_is_not_flagged(waf, q):
    assert not waf.flags(query=q), f"WAF false-positived on benign {q!r}"


def test_double_url_encoding_evades_the_signature(waf):
    """A single normalisation pass leaves layered encoding intact — the
    brittleness the comparison exists to show."""
    # 'x%27%20OR%201=1  ->  double-encoded so one decode does not reveal it
    assert not waf.flags(query="x%2527%2520OR%25201%253D1")


def test_the_waf_is_blind_to_idor(waf):
    """There is no signature for accessing another user's object by id — it is
    valid syntax. This is why B1's recall on IDOR is zero and the learned system
    plus bait is the only arm that catches it."""
    assert not waf.flags(query="")   # GET /records/34 carries no flaggable payload
    assert not waf.flags(query="internal_view=1")   # even the bite looks benign to a WAF
