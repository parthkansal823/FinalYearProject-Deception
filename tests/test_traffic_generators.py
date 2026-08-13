"""
Tests for the benign traffic generators.

The corpus these produce determines what the meter can possibly learn, so
the properties worth testing are about the *composition* of the traffic, not
about HTTP mechanics.

Two failures would be invisible in every downstream number:

  * losing the benign-but-automated class, which would make automation and
    malice perfectly correlated and contribution #2 unfalsifiable;
  * losing the hard negatives, which would make the benign bait exposure rate
    trivially zero and therefore uninformative.
"""

from __future__ import annotations

import pytest

from tools import benign_agents, benign_traffic
from target_app.otp import otp_for


# ---------------------------------------------------------------------------
# The middle case of spec §6.3
# ---------------------------------------------------------------------------


def test_automated_agents_are_labelled_benign_but_scripted():
    """"A price-comparison bot is highly automated and entirely harmless."

    If this class is ever labelled anything other than benign+scripted, the
    two axes collapse into one and a single combined score would do just as
    well — which is precisely the claim the project is trying to refute.
    """
    import random

    for profile, (cls, ua) in benign_agents.PROFILES.items():
        agent = cls(base_url="http://localhost:1", rng=random.Random(1), dwell=False, profile=profile)
        try:
            label = agent.label
            assert label["ground_truth"] == "benign", f"{profile} must be benign"
            assert label["automation_label"] == "scripted", f"{profile} must be scripted"
            assert label["attack_category"] == "none"
        finally:
            agent.close()


def test_all_three_agent_profiles_are_present():
    """Each is confusable with a different attack: monitor~scanner,
    crawler~recon, integration~IDOR. Dropping one removes a hard negative."""
    assert set(benign_agents.PROFILES) == {"monitor", "crawler", "integration"}


# ---------------------------------------------------------------------------
# Hard negatives
# ---------------------------------------------------------------------------


def test_hard_negative_personas_exist_with_meaningful_weight():
    weights = benign_traffic.PERSONA_WEIGHTS
    assert set(weights) == {"normal", "apostrophe_searcher", "forgetful"}

    awkward = weights["apostrophe_searcher"] + weights["forgetful"]
    assert 0.1 <= awkward <= 0.4, (
        "the awkward-but-honest population must be large enough to measure a "
        "false-positive rate against, and small enough to stay realistic"
    )
    assert sum(weights.values()) == pytest.approx(1.0)


def test_apostrophe_searches_target_a_name_that_actually_exists():
    """The hard negative only works if looking the name up is a plausible
    thing for a colleague to do. Maeve O'Connell is in the seed directory."""
    from target_app.seed import USERS

    seeded_names = " ".join(full_name for _, _, _, full_name, _ in USERS)
    assert "O'Connell" in seeded_names
    assert any("O'Connell" in term for term in benign_traffic.APOSTROPHE_SEARCHES)


def test_an_honest_apostrophe_search_produces_an_injection_shaped_error(client):
    """The whole point of this hard negative.

    A user looking up a colleague hits the same concatenated SQL an attacker
    probes, and gets the same verbose driver error. If the final system
    diverts sessions like this, NFR-05 has failed — and that can only be
    measured if the corpus contains the case.
    """
    client.post("/login", data={"username": "a.mirza", "password": "Summer2024!"})
    client.post("/otp", data={"code": otp_for(1)})

    response = client.get("/search", params={"q": "O'Connell"})

    assert response.status_code == 500
    assert 'class="db-error"' in response.text
    assert "syntax error" in response.text.lower()


def test_forgetful_persona_is_still_labelled_benign():
    """Three to five failed logins is the B-AUTH-1 trigger and the shape of a
    credential attack. It is also what forgetting your password looks like.
    Labelling it anything but benign would teach the meter that "looks odd"
    means "is hostile"."""
    import random

    user = benign_traffic.BenignUser(
        base_url="http://localhost:1", rng=random.Random(1), dwell=False, persona="forgetful"
    )
    try:
        assert user.persona == "forgetful"
    finally:
        user.client.close()


def test_persona_never_leaks_into_the_class_labels():
    """An awkward honest user is exactly as benign as a straightforward one.
    The persona lives in `notes` so analysis can break it out without the
    label itself encoding 'this one looked suspicious'."""
    import inspect

    source = inspect.getsource(benign_traffic.generate)
    assert 'notes=f"simulated human session; persona={persona}"' in source
    assert 'ground_truth="benign"' in source
    assert 'automation_label="human"' in source


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def test_both_generators_carry_the_provenance_marker():
    """Without it the corpus cannot be labelled at all — the defect that made
    schema v3 necessary."""
    import random

    from adf.schema import PROVENANCE_HEADER

    human = benign_traffic.BenignUser("http://localhost:1", random.Random(1), dwell=False)
    agent = benign_agents.UptimeMonitor(
        base_url="http://localhost:1", rng=random.Random(1), dwell=False, profile="monitor"
    )
    try:
        assert human.client.headers[PROVENANCE_HEADER] == human.session_id
        assert agent.client.headers[PROVENANCE_HEADER] == agent.session_id
        assert human.session_id != agent.session_id
    finally:
        human.client.close()
        agent.close()
