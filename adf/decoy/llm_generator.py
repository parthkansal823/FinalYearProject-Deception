"""
LLM-backed world generators for the decoy (spec §6.8, §12; contribution §4.3 #4).

The Fact Notebook is generator-agnostic: it does not care how a fact was first
produced, only that it never changes afterward. `adf/decoy/world.py` uses a
deterministic generator, which is already self-consistent (a seeded RNG returns
the same value every time). This module supplies the harder case -- a
*stochastic* generator, a local language model -- for two reasons:

  1. It produces a richer, more varied fake world than fixed content pools, which
     is what §6.8 anticipated ("any language model, run in batch") and what
     limitation §9 flagged as missing.
  2. It is the sharp test of the notebook's contribution. A language model asked
     the same question twice answers differently; on its own it CANNOT be
     consistent. So "the LLM decoy contradicts itself without the notebook and
     never with it" is a stronger demonstration than the deterministic ablation,
     because here the inconsistency is inherent to the generator, not injected by
     an unseeded RNG.

NO EXTERNAL API. The model runs locally, in an Ollama container on this host
(http://127.0.0.1:11434). Nothing leaves the machine; there is no cloud API key
and no network dependency beyond loopback. If Ollama is not running, importing
this module still succeeds -- only calling a generator raises, and the tests skip.

SAFETY OF SHAPE. The LLM supplies the *flavour* of a record (names, titles, prose)
but the record's *structure* is validated against the same schema the
deterministic generators produce, and any field the model omits or malforms falls
back to the deterministic value. So an LLM that returns nonsense degrades to the
deterministic world rather than breaking referential integrity or the decoy's
response schema. The id is never invented -- it is the key the notebook asked for.
"""

from __future__ import annotations

import json
import random
from typing import Any, Callable

import httpx

from adf.decoy import world as _world

GeneratorFn = Callable[[random.Random, str], dict[str, Any]]

DEFAULT_ENDPOINT = "http://127.0.0.1:11434"
# A small instruct model: fast enough for CPU-only batch generation, and the
# task (fill a few plausible fields) needs no more. Pinned so a run reproduces.
DEFAULT_MODEL = "llama3.2:1b"


class OllamaUnavailable(RuntimeError):
    """Raised when the local Ollama endpoint cannot be reached or has no model."""


class OllamaClient:
    """A minimal client for a LOCAL Ollama server. No external service."""

    def __init__(self, endpoint: str = DEFAULT_ENDPOINT, model: str = DEFAULT_MODEL,
                 *, timeout: float = 60.0) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout = timeout

    def available(self) -> bool:
        """Is *this exact* model pulled?

        The tag matters. Matching on the family prefix would report `llama3.2:3b`
        as available when only `llama3.2:1b` is pulled, so a capability sweep would
        silently attribute one model's behaviour to another -- the worst kind of
        wrong, because the run still succeeds. An untagged name is treated as
        `:latest`, which is what Ollama itself does.
        """
        try:
            r = httpx.get(f"{self.endpoint}/api/tags", timeout=3.0)
            if r.status_code != 200:
                return False
            wanted = self.model if ":" in self.model else f"{self.model}:latest"
            names = {m.get("name", "") for m in r.json().get("models", [])}
            return wanted in names
        except Exception:
            return False

    def generate_json(self, prompt: str, *, seed: int | None = None,
                      temperature: float = 0.8) -> dict[str, Any]:
        """Ask the local model for a JSON object. Ollama's `format: json` forces
        syntactically valid JSON; we still validate the contents ourselves."""
        options: dict[str, Any] = {"temperature": temperature}
        if seed is not None:
            options["seed"] = seed
        try:
            r = httpx.post(
                f"{self.endpoint}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False,
                      "format": "json", "options": options},
                timeout=self.timeout,
            )
            r.raise_for_status()
            return json.loads(r.json()["response"])
        except (httpx.HTTPError, KeyError, json.JSONDecodeError) as exc:
            raise OllamaUnavailable(str(exc)) from exc


# ---------------------------------------------------------------------------
# Per-namespace prompts. Each asks for exactly the fields the deterministic
# generator produces, so the two are interchangeable behind the notebook.
# ---------------------------------------------------------------------------

# Tiny instruct models wrap output in arrays or wrapper keys unless told very
# firmly to emit ONE FLAT object, and follow an example far better than a spec.
_ORG = "a UK back-office firm (Northbridge Internal)"

_PROMPTS = {
    "user": (
        "Output ONE flat JSON object (not an array, not nested, no wrapper key) "
        "describing a single staff member at " + _ORG + ". It MUST have exactly "
        "these keys: full_name, username, email, department, location, role. "
        'Example: {"full_name":"Aoife Byrne","username":"a.byrne",'
        '"email":"a.byrne@northbridge-internal.example","department":"Finance",'
        '"location":"Block A, Floor 2","role":"staff"}. Output a different one.'
    ),
    "record": (
        "Output ONE flat JSON object (not an array, not nested, no wrapper key) "
        "describing one internal business document at " + _ORG + ". It MUST have "
        "exactly these keys: title, classification, amount, created_at, body. "
        'Example: {"title":"Vendor onboarding","classification":"internal",'
        '"amount":"1284.50","created_at":"2026-03-14","body":"Awaiting sign-off '
        'from finance."}. Output a different one, classification one of '
        "internal/confidential/restricted, created_at a 2026 date."
    ),
    "notice": (
        "Output ONE flat JSON object (not an array, not nested, no wrapper key) "
        "for an internal staff notice at " + _ORG + ". It MUST have exactly these "
        "keys: title, body, posted_at. "
        'Example: {"title":"Maintenance window","body":"Systems briefly '
        'unavailable Saturday.","posted_at":"2026-08-10"}. Output a different one.'
    ),
}


def _validate(kind: str, obj: dict[str, Any]) -> bool:
    required = {
        "user": {"full_name", "username", "email", "department", "location", "role"},
        "record": {"title", "classification", "amount", "created_at", "body"},
        "notice": {"title", "body", "posted_at"},
    }[kind]
    return isinstance(obj, dict) and required.issubset(obj) and all(
        isinstance(obj[k], str) for k in required
    )


def _llm_generator(kind: str, client: OllamaClient, base: GeneratorFn) -> GeneratorFn:
    """Wrap a deterministic generator with an LLM front-end for the flavour
    fields, keeping structural fields (id, references) from the deterministic
    base and falling back to it entirely on any failure."""
    def generate(rng: random.Random, key: str) -> dict[str, Any]:
        fallback = base(rng, key)              # always correct, always available
        try:
            obj = client.generate_json(_PROMPTS[kind], temperature=0.9)
        except OllamaUnavailable:
            return fallback
        if not _validate(kind, obj):
            return fallback
        # Merge: LLM supplies flavour, the base supplies structure (id, owner_id,
        # and anything the model omitted), so referential integrity is preserved.
        merged = dict(fallback)
        for k, v in obj.items():
            if k in fallback and isinstance(v, str):
                merged[k] = v
        return merged
    return generate


def make_llm_generators(client: OllamaClient | None = None) -> dict[str, GeneratorFn]:
    """LLM-backed versions of `world.GENERATORS`. Namespaces without a prompt
    (schema_table, file -- structural, not prose) keep their deterministic
    generator unchanged."""
    client = client or OllamaClient()
    gens: dict[str, GeneratorFn] = dict(_world.GENERATORS)
    for kind in _PROMPTS:
        gens[kind] = _llm_generator(kind, client, _world.GENERATORS[kind])
    return gens
