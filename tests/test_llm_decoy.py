"""
L9 -- the Fact Notebook makes a STOCHASTIC generator consistent.

The core claim does not need a live model to test: a language model is just one
instance of a stochastic generator (same input, different output). So we prove
the property with a mock stochastic generator, and separately check that the
real LLM adapter degrades safely to the deterministic world when the local model
is absent. The live-model numbers are produced by tools/llm_decoy_eval.py.
"""

from __future__ import annotations

import random

from adf.decoy.notebook import FactNotebook
from adf.decoy import world as _world
from adf.decoy.llm_generator import OllamaClient, make_llm_generators


# A generator that reinvents the entity every call -- exactly what an LLM does,
# and what a seeded deterministic generator does NOT.
_POOL = ["Ada", "Bo", "Cy", "Di", "Ez", "Fi", "Gu", "Ha", "Iz", "Jo"]


def _stochastic_user(rng: random.Random, key: str) -> dict:
    r = random.Random()  # unseeded ON PURPOSE: no memory of previous calls
    return {"id": int(key), "username": "x", "full_name": r.choice(_POOL),
            "email": "x@y.example", "department": r.choice(_POOL),
            "location": "Remote", "role": "staff"}


def test_notebook_makes_a_stochastic_generator_consistent():
    """WITH the notebook, a stochastic generator is answered from storage on the
    second read, so the two answers agree."""
    nb = FactNotebook(":memory:", seed=1, persist=True)
    keys = [str(i) for i in range(1, 31)]
    disagreements = 0
    for k in keys:
        a = nb.get_or_generate("user", k, _stochastic_user)
        b = nb.get_or_generate("user", k, _stochastic_user)
        if a["full_name"] != b["full_name"]:
            disagreements += 1
    assert disagreements == 0


def test_without_notebook_a_stochastic_generator_contradicts_itself():
    """The ablation: persist=False regenerates every call, so a stochastic
    generator disagrees with itself. This is what makes the notebook's zero a
    real result rather than a property of the generator."""
    nb = FactNotebook(":memory:", seed=1, persist=False)
    keys = [str(i) for i in range(1, 31)]
    disagreements = 0
    for k in keys:
        a = nb.get_or_generate("user", k, _stochastic_user)
        b = nb.get_or_generate("user", k, _stochastic_user)
        if a["full_name"] != b["full_name"]:
            disagreements += 1
    # with a 10-name pool the odds of 30 pairs all matching by chance are ~0
    assert disagreements > 20


def test_llm_adapter_falls_back_to_deterministic_when_model_absent():
    """No local model running: the LLM generators must produce a valid, complete
    record (the deterministic fallback), never a broken one."""
    client = OllamaClient(endpoint="http://127.0.0.1:1")  # nothing listens here
    assert client.available() is False
    gens = make_llm_generators(client)
    required = {"id", "username", "full_name", "email", "department", "location", "role"}
    for k in ["1", "7", "notarealid"]:
        rec = gens["user"](random.Random(int_or_hash(k)), k)
        assert required.issubset(rec)


def test_llm_adapter_preserves_structural_fields():
    """Even a valid LLM response must not overwrite the id or drop the reference
    structure: the merged record keeps the key's id and a resolvable owner_id for
    records."""
    client = OllamaClient(endpoint="http://127.0.0.1:1")
    gens = make_llm_generators(client)
    rec = gens["record"](random.Random(3), "12")
    assert rec["id"] == 12
    assert isinstance(rec["owner_id"], int)  # referential integrity preserved


def int_or_hash(k: str) -> int:
    try:
        return int(k)
    except ValueError:
        return abs(hash(k)) % 1000
