"""
Tests for the Fact Notebook (spec §6.9) -- the decoy's consistency guarantee.

The four dimensions §6.9 names are each tested directly, because the whole
second contribution of the project is that the decoy does not contradict
itself. A decoy that fails any of these betrays the trap to an attentive
attacker, so these are correctness tests, not nice-to-haves.
"""

from __future__ import annotations

from adf.decoy import FactNotebook, planted_credential, populate
from adf.decoy.world import gen_user, gen_record


def _nb(seed: int = 7) -> FactNotebook:
    return FactNotebook(":memory:", seed=seed)


# ---------------------------------------------------------------------------
# Dimension 1: repetition
# ---------------------------------------------------------------------------


def test_asking_the_same_fact_twice_returns_the_same_answer():
    nb = _nb()
    first = nb.get_or_generate("user", 7, gen_user)
    second = nb.get_or_generate("user", 7, gen_user)
    assert first == second


def test_generation_is_deterministic_across_notebooks_with_the_same_seed():
    """A fact generated on demand must match one produced in the offline batch,
    even in a different process -- same seed, same key, same value."""
    a = _nb(seed=42).get_or_generate("user", 99, gen_user)
    b = _nb(seed=42).get_or_generate("user", 99, gen_user)
    assert a == b


def test_different_seeds_produce_different_worlds():
    a = _nb(seed=1).get_or_generate("user", 5, gen_user)
    b = _nb(seed=2).get_or_generate("user", 5, gen_user)
    assert a != b


# ---------------------------------------------------------------------------
# Dimension 2: cross-reference
# ---------------------------------------------------------------------------


def test_a_user_has_the_same_details_through_every_route():
    """Whatever endpoint surfaces user 7, it reads the one stored fact."""
    nb = _nb()
    via_profile = nb.get_or_generate("user", 7, gen_user)
    via_directory = nb.get("user", 7)
    via_api = nb.get_or_generate("user", 7, gen_user)
    assert via_profile == via_directory == via_api


# ---------------------------------------------------------------------------
# Dimension 3: write-then-read
# ---------------------------------------------------------------------------


def test_attacker_write_is_read_back_unchanged():
    nb = _nb()
    nb.get_or_generate("user", 7, gen_user)          # exists as generated
    nb.record_write("user", 7, {"id": 7, "full_name": "Owned By Attacker", "role": "admin"})
    assert nb.get("user", 7)["full_name"] == "Owned By Attacker"


def test_a_generated_default_never_clobbers_an_attacker_write():
    """After an attacker modifies a fact, a later on-demand generation for the
    same key must NOT overwrite it -- precedence protects the mutation."""
    nb = _nb()
    nb.record_write("record", 3, {"id": 3, "title": "planted by attacker"})
    # a subsequent read-through generation attempt
    value = nb.get_or_generate("record", 3, gen_record)
    assert value["title"] == "planted by attacker"


# ---------------------------------------------------------------------------
# Dimension 4: referential integrity
# ---------------------------------------------------------------------------


def test_a_record_owner_resolves_to_a_consistent_user():
    nb = _nb()
    populate(nb, users=24, records=60, seed=7)
    for rec in nb.all("record"):
        owner_id = rec.value["owner_id"]
        owner = nb.get_or_generate("user", owner_id, gen_user)
        # the owner exists and is internally consistent
        assert owner["id"] == owner_id
        # asking again yields the identical owner (no drift)
        assert nb.get("user", owner_id) == owner


# ---------------------------------------------------------------------------
# Population + planted credential
# ---------------------------------------------------------------------------


def test_populate_creates_a_plausible_world():
    nb = _nb()
    counts = populate(nb, users=24, records=60, notices=8, seed=7)
    assert counts["user"] >= 24
    assert counts["record"] == 60
    assert "config" in counts


def test_planted_credential_is_present_and_watchable():
    nb = _nb()
    populate(nb, seed=7)
    cfg = nb.get("config", "service.ini")
    cred = planted_credential(7)
    assert cred.secret in cfg["content"]        # findable in the config file
    assert cred.appears_in(f"harvested {cred.secret} and reusing it")  # detectable when reused
    assert not cred.appears_in("nothing to see here")


def test_planted_credential_is_seed_stable_but_not_constant():
    assert planted_credential(7) == planted_credential(7)
    assert planted_credential(7) != planted_credential(8)


# ---------------------------------------------------------------------------
# Ablation (spec §10.2): Fact Notebook disabled
# ---------------------------------------------------------------------------


def test_notebook_ablation_shows_the_notebook_is_what_prevents_contradiction():
    """Isolates Contribution #4: with the notebook the decoy never contradicts
    itself; without it (persist=False, generate-fresh-each-time) it contradicts
    itself on essentially every repeat. This is the ablation that gives the
    contradiction-rate metric something to compare against."""
    with_nb = _nb(seed=7)
    contra_with = sum(1 for _ in range(30)
                      if with_nb.get_or_generate("user", 7, gen_user)
                      != with_nb.get_or_generate("user", 7, gen_user))

    without = FactNotebook(":memory:", seed=7, persist=False)
    contra_without = sum(1 for _ in range(30)
                         if without.get_or_generate("user", 7, gen_user)
                         != without.get_or_generate("user", 7, gen_user))

    assert contra_with == 0, "the notebook must guarantee repetition consistency"
    assert contra_without >= 25, "without the notebook the decoy must contradict itself"
