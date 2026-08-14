"""
Tests for the invisibility gate (spec §6.7, NFR-01).

The most important test in this file is the one that FAILS a bait on purpose.
A gate that passes everything is worthless; the spec's rule is that a bait
which changes the rendered page is deleted, so the gate must be shown to
reject a deliberately-visible bait. If that test ever goes green-by-passing,
the safety mechanism has quietly broken.
"""

from __future__ import annotations

import pytest

from adf.bait import (
    BaitedResponse,
    InvisibilityGate,
    build_bait,
    compare_rendered,
    BAIT_SPECS,
)
from adf.bait.baits import Bait, BaitSpec
from adf.bait.channels import inject_html_comment


# A small corpus of realistic benign responses, one per injection surface.
def _html_page(body_extra: str = "") -> BaitedResponse:
    return BaitedResponse(
        body=(
            "<!DOCTYPE html><html><head><title>Portal</title></head><body>"
            "<h1>Staff notices</h1><p>Scheduled maintenance this weekend.</p>"
            "<form action='/search' method='get'><input name='q' type='text'>"
            "<button type='submit'>Search</button></form>"
            "<a href='/directory'>Directory</a>"
            f"{body_extra}"
            "</body></html>"
        ),
        content_type="text/html; charset=utf-8",
    )


def _json_profile() -> BaitedResponse:
    return BaitedResponse(
        body='{"profile": {"id": 7, "full_name": "Klara Novak", "department": "Engineering"}}',
        content_type="application/json",
    )


def _search_error() -> BaitedResponse:
    return BaitedResponse(
        body=(
            "<!DOCTYPE html><html><body><h1>Search</h1>"
            "<div class='alert'><pre class='db-error'>syntax error at or near \"'\"</pre></div>"
            "</body></html>"
        ),
        content_type="text/html",
    )


@pytest.fixture
def corpus() -> list[BaitedResponse]:
    return [_html_page(), _json_profile(), _search_error(),
            _html_page("<p>Another notice.</p>"), _json_profile()]


# ---------------------------------------------------------------------------
# Every real bait must pass
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bait_id", list(BAIT_SPECS))
def test_every_real_bait_passes_the_gate(bait_id, corpus):
    gate = InvisibilityGate()
    bait = build_bait(bait_id, session_id="s1", seed=1)
    result = gate.test(bait, corpus)
    assert result.passed, f"{bait_id} failed invisibility: {result.failures}"
    assert result.injected_responses > 0, f"{bait_id} applied to no response"


def test_html_comment_bait_leaves_visible_text_untouched(corpus):
    bait = build_bait("B-SQL-1", session_id="s1", seed=1)
    page = _html_page()
    baited = bait.inject(page)
    # the token is present in the raw bytes ...
    assert bait.token in baited.body
    # ... but the rendered page is unchanged
    assert compare_rendered(page, baited).identical


def test_json_field_bait_is_additive_only(corpus):
    bait = build_bait("B-IDOR-1", session_id="s1", seed=1)
    clean = _json_profile()
    baited = bait.inject(clean)
    import json
    assert json.loads(baited.body)["ref_uid"]                      # the bait is there
    assert json.loads(baited.body)["profile"] == json.loads(clean.body)["profile"]  # real data intact
    assert compare_rendered(clean, baited).identical


# ---------------------------------------------------------------------------
# THE GATE MUST HAVE TEETH
# ---------------------------------------------------------------------------


def test_gate_rejects_a_bait_that_changes_visible_text(corpus):
    """A bait that writes into the rendered page must be rejected (spec §6.7).
    This proves the gate actually measures visibility rather than rubber-
    stamping."""

    class VisibleBait(Bait):
        def inject(self, response):
            out = response.clone()
            # write the token into the VISIBLE body, not a comment
            out.body = out.body.replace("</h1>", f" {self.token}</h1>")
            return out

        def applicable(self, response):
            return "</h1>" in response.body

    bad = VisibleBait(BaitSpec("B-BAD", "sqli", "html_comment", "value", "LEAK_{suffix}"), "LEAK_deadbe")
    result = InvisibilityGate().test(bad, corpus)
    assert not result.passed, "the gate passed a bait that changed the visible page!"
    assert any("visible" in f or "functional" in f for f in result.failures)


def test_gate_rejects_a_bait_that_breaks_a_form(corpus):
    """Changing a form's action is a functional change even if the text is the
    same -- the gate must catch it (spec §6.7 assertion 2)."""

    class FormBreaker(Bait):
        def inject(self, response):
            out = response.clone()
            out.body = out.body.replace("action='/search'", "action='/evil'")
            return out

        def applicable(self, response):
            return "action='/search'" in response.body

    bad = FormBreaker(BaitSpec("B-BAD2", "sqli", "html_comment", "value", "x"), "x")
    result = InvisibilityGate().test(bad, corpus)
    assert not result.passed
    assert any("functional" in f or "form" in f for f in result.failures)


def test_gate_rejects_a_bait_that_overwrites_a_real_json_field(corpus):
    """A json_field bait must be additive. Overwriting an existing key is a
    visible data change and injection itself must refuse it."""

    class Overwriter(Bait):
        def inject(self, response):
            out = response.clone()
            import json
            doc = json.loads(out.body)
            doc["profile"] = {"id": 999}     # clobbers real data
            out.body = json.dumps(doc)
            return out

        def applicable(self, response):
            return response.body.lstrip().startswith("{")

    bad = Overwriter(BaitSpec("B-BAD3", "idor", "json_field", "name", "x"), "x")
    result = InvisibilityGate().test(bad, corpus)
    assert not result.passed


def test_gate_rejects_a_bait_that_applies_to_nothing():
    """A bait the corpus can never exercise cannot be verified, so it must not
    pass (spec §6.7: verified before entering the library)."""
    gate = InvisibilityGate()
    bait = build_bait("B-IDOR-1", session_id="s1", seed=1)   # needs JSON
    html_only = [BaitedResponse(body="<html><body>hi</body></html>", content_type="text/html")]
    result = gate.test(bait, html_only)
    assert not result.passed
    assert any("none of the corpus" in f for f in result.failures)


# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------


def test_injection_overhead_is_below_the_ceiling(corpus):
    for bait_id in BAIT_SPECS:
        bait = build_bait(bait_id, session_id="s1", seed=1)
        result = InvisibilityGate().test(bait, corpus)
        assert result.median_overhead_ms <= InvisibilityGate().max_overhead_ms
