"""
Tests for the attack traffic generator (Attack Round 1, spec §7.2, Phase 2).

The corpus this produces is the meter's entire training signal, so the
properties worth testing are, again, about composition and correctness of
labelling rather than HTTP mechanics. Three failures would be silent and
fatal downstream:

  * an attack labelled as the wrong category, or not labelled before it acts,
    poisons the training labels (spec §7.3);
  * losing the attack/human cell collapses the 2x2 and makes the two-axis
    model indefensible (spec §6.3);
  * a payload that does not actually exploit means the label says "attack"
    while the traffic is indistinguishable from benign, which teaches the
    meter noise.

The last one is why several tests here drive real requests through the target
app (via the shared `client`) and assert the exploit LANDS, not merely that a
request was sent.
"""

from __future__ import annotations

import random

import pytest

from tools import attack_traffic
from tools.attack_traffic import PROFILES, DEFAULT_MIX, FOOTHOLD
from target_app.otp import otp_for


def _make(profile: str, seed: int = 1, **over):
    cls, kwargs = PROFILES[profile]
    return cls("http://localhost:1", random.Random(seed), dwell=False, **{**kwargs, **over})


# ---------------------------------------------------------------------------
# Labelling correctness (spec §7.3, §11)
# ---------------------------------------------------------------------------


def test_every_profile_is_labelled_attack_with_a_known_category():
    for profile in PROFILES:
        agent = _make(profile)
        try:
            label = agent.label
            assert label["ground_truth"] == "attack", profile
            assert label["attack_category"] in {"sqli", "idor", "auth"}, profile
            assert label["attack_subcategory"] not in {"unknown", "", "none"}, profile
            assert label["automation_label"] in {"human", "scripted"}, profile
        finally:
            agent.close()


def test_automation_label_matches_the_scripted_flag():
    """The label's automation class must reflect how the attacker actually
    behaves, or the corpus is mislabelled on the very axis it exists to test."""
    for profile in PROFILES:
        agent = _make(profile)
        try:
            expected = "scripted" if agent.scripted else "human"
            assert agent.label["automation_label"] == expected, profile
        finally:
            agent.close()


def test_the_mix_covers_all_three_categories_and_both_automation_classes():
    cats, autos = set(), set()
    for profile in DEFAULT_MIX:
        agent = _make(profile)
        try:
            cats.add(agent.label["attack_category"])
            autos.add(agent.label["automation_label"])
        finally:
            agent.close()
    assert {"sqli", "idor", "auth"} <= cats
    assert {"human", "scripted"} == autos, "the §6.3 attack/human cell must be in the mix"


def test_every_attacker_carries_the_provenance_marker():
    """Without it the attack traffic cannot be joined to its label and the
    corpus is effectively unlabelled (the Phase 1 join bug, on the attack
    side)."""
    from adf.schema import PROVENANCE_HEADER

    for profile in PROFILES:
        agent = _make(profile)
        try:
            assert agent.client.headers.get(PROVENANCE_HEADER) == agent.session_id
        finally:
            agent.close()


# ---------------------------------------------------------------------------
# Round hygiene (spec §7.2 — the rule the evaluation depends on)
# ---------------------------------------------------------------------------


def test_generator_refuses_to_emit_eval_round_data(monkeypatch, tmp_path):
    """Round 2 (eval) must use genuinely different techniques, so the straight
    round-1 generator must not be one flag away from producing eval data."""
    import argparse

    monkeypatch.setattr(
        "sys.argv",
        ["attack_traffic", "--round", "eval", "--sessions", "1", "--no-dwell"],
    )
    with pytest.raises(SystemExit):
        attack_traffic.main()


# ---------------------------------------------------------------------------
# The exploits actually LAND (drive the real app)
# ---------------------------------------------------------------------------


def _drive(profile: str, client, seed: int = 1, **over):
    """Rebind an attacker's HTTP methods onto the in-process TestClient and
    run it, capturing every response."""
    agent = _make(profile, seed=seed, **over)
    responses = []

    def get(path, **kw):
        r = client.get(path, **kw)
        responses.append(r)
        return r

    def post(path, **kw):
        r = client.post(path, **kw)
        responses.append(r)
        return r

    agent.client.get = get      # type: ignore[method-assign]
    agent.client.post = post    # type: ignore[method-assign]
    # otp_reuse spins up its own second client; keep this test to the ones
    # that stay on the injected client.
    agent.attack()
    return responses


def test_sqli_union_actually_dumps_credentials(client):
    import hashlib

    responses = _drive("sqli_union", client)
    bodies = " ".join(r.text for r in responses)
    admin_hash = hashlib.sha256("admin123".encode()).hexdigest()
    assert admin_hash in bodies or "svc_reports" in bodies, \
        "UNION injection did not exfiltrate the users table"


def test_sqli_error_leaks_a_verbose_driver_error(client):
    responses = _drive("sqli_error", client)
    assert any("db-error" in r.text for r in responses), \
        "error-based injection did not surface the verbose DB error"


def test_idor_sequential_reads_other_users_profiles(client):
    responses = _drive("idor_sequential", client)
    names = set()
    for r in responses:
        try:
            data = r.json()
        except Exception:
            continue
        if isinstance(data, dict) and "profile" in data:
            names.add(data["profile"].get("full_name"))
    assert len([n for n in names if n]) >= 3, \
        "IDOR sweep did not read multiple distinct profiles"


def test_bruteforce_eventually_finds_the_password(client):
    responses = _drive("bruteforce", client)
    assert any("/otp" in str(r.url) for r in responses), \
        "brute force never reached the OTP stage, so it never found the password"


def test_credential_stuffing_lands_one_valid_pair(client):
    # Seeded to include exactly one valid pair, so at least one success is
    # guaranteed regardless of RNG (see attack_traffic.AuthAttacker).
    responses = _drive("cred_stuffing", client, seed=7)
    assert any("/otp" in str(r.url) for r in responses), \
        "credential stuffing never landed the seeded valid pair"


def test_otp_bypass_reaches_the_dashboard(client):
    responses = _drive("otp_bypass", client)
    assert any("/dashboard" in str(r.url) for r in responses), \
        "OTP brute force never authenticated despite uncapped, non-expiring codes"
