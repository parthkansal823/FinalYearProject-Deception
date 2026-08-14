"""
The offline fake world (spec §6.8).

The decoy is populated in ADVANCE, not on demand: a batch process generates a
plausible fake world -- user records, filenames, database schema, config files,
log entries -- and writes it all into the Fact Notebook before the system ever
runs. Spec §6.8 gives three reasons this offline design beats live generation,
all of which this honours:

  * Latency: no generation ever sits in the request path, so the decoy answers
    as fast as the real site. A slow decoy is a detectable decoy.
  * Consistency: content generated once and stored cannot vary between requests.
  * Workload and cost: generation happens once, in a batch, reviewable by hand.

Spec §12 says the offline generator may be "any language model, run in batch".
Here it is a DETERMINISTIC synthetic generator instead. That is a deliberate,
honest substitution: it is seeded (NFR-08 reproducibility), reviewable, and --
crucially -- it is keyed per entity, so a fact first requested on demand months
later is byte-identical to one produced in the batch. A real deployment could
swap an LLM into `GENERATORS` without changing anything else; the notebook does
not care how a value was produced, only that it is fixed once produced.

REFERENTIAL INTEGRITY is a property of these generators (spec §6.9 dim 4): a
generator that emits a reference resolves it THROUGH the notebook, so the
referenced entity is generated consistently whether or not it existed yet.
"""

from __future__ import annotations

import random
from typing import Any

from adf.decoy.notebook import FactNotebook
from adf.decoy.credential import planted_credential

# Fake content pools. Deliberately DIFFERENT names from target_app/seed.py --
# the decoy contains no real (target) data (spec §6.6, §17) -- but the same
# register, so the decoy reads like the same kind of organisation.
_FIRST = ["Adaeze", "Bjorn", "Chandni", "Diego", "Elif", "Farah", "Gustavo",
          "Hyun", "Ines", "Jarrah", "Keiko", "Lorenzo", "Mira", "Noor",
          "Olamide", "Priya", "Quentin", "Ravi", "Sanne", "Tomas"]
_LAST = ["Achebe", "Berg", "Chaudhry", "Duarte", "Eren", "Faris", "Gomes",
         "Han", "Iqbal", "Jansen", "Kato", "Lombardi", "Mwangi", "Nasser",
         "Owens", "Patel", "Quinn", "Rao", "Svensson", "Toften"]
_DEPT = ["Finance", "Operations", "People", "Engineering", "Legal", "Facilities", "Data"]
_LOCATION = ["Block A, Floor 2", "Block B, Floor 1", "Block C, Floor 3", "Remote", "Annexe"]
_ROLE = ["staff", "staff", "staff", "manager", "service"]

_RECORD_TITLES = ["Quarterly reconciliation", "Vendor onboarding", "Access review",
                  "Budget variance report", "Incident post-mortem", "Procurement request",
                  "Capacity plan", "Contract renewal", "Audit response", "Migration runbook"]
_CLASSIFICATION = ["internal", "internal", "internal", "confidential", "restricted"]

_TABLES = {
    "users": ["id", "username", "password_hash", "role", "mfa_enabled", "last_login"],
    "accounts": ["id", "owner_id", "iban", "sort_code", "balance_minor", "status"],
    "documents": ["id", "owner_id", "title", "classification", "created_at"],
    "audit_log": ["id", "actor_id", "action", "target", "ts"],
    "api_tokens": ["id", "owner_id", "token_prefix", "scope", "revoked"],
}

_FILENAMES = ["backup.sql", "service.ini", "deploy.log", "users_export.csv",
              "readme.txt", ".env.bak", "schema.sql", "cron.d/reporting"]


# ---------------------------------------------------------------------------
# Per-entity generators. Each is a pure function of (rng, key); the rng is
# seeded from (seed, namespace, key) by the notebook, so output is stable.
# ---------------------------------------------------------------------------


def gen_user(rng: random.Random, key: str) -> dict[str, Any]:
    first = rng.choice(_FIRST)
    last = rng.choice(_LAST)
    username = f"{first[0].lower()}.{last.lower()}"
    return {
        "id": _as_int(key),
        "username": username,
        "full_name": f"{first} {last}",
        "email": f"{username}@northbridge-internal.example",
        "phone": f"+44 20 7946 {rng.randint(1000, 9999)}",
        "department": rng.choice(_DEPT),
        "location": rng.choice(_LOCATION),
        "role": rng.choice(_ROLE),
    }


def gen_record(rng: random.Random, key: str) -> dict[str, Any]:
    # owner_id is a REFERENCE. It is chosen here; the decoy resolves it through
    # the notebook, which generates that user consistently (referential
    # integrity, spec §6.9 dim 4).
    owner_id = rng.randint(1, 24)
    return {
        "id": _as_int(key),
        "owner_id": owner_id,
        "title": rng.choice(_RECORD_TITLES),
        "classification": rng.choice(_CLASSIFICATION),
        "amount": f"{rng.randint(40, 9800)}.{rng.randint(0, 99):02d}",
        "created_at": f"2026-{rng.randint(1, 8):02d}-{rng.randint(1, 28):02d}",
        "body": "Generated for internal review. Awaiting sign-off.",
    }


def gen_notice(rng: random.Random, key: str) -> dict[str, Any]:
    topics = ["maintenance window", "policy update", "office move", "training reminder",
              "access review", "system migration", "town hall"]
    return {
        "id": _as_int(key),
        "title": rng.choice(topics).capitalize(),
        "body": "Please review the details on the intranet. No action required unless contacted.",
        "posted_at": f"2026-08-{rng.randint(1, 28):02d}",
    }


def gen_schema_table(rng: random.Random, key: str) -> dict[str, Any]:
    cols = _TABLES.get(key)
    if cols is None:
        # an attacker guessing a table name gets a plausible one, once, forever
        cols = ["id"] + rng.sample(
            ["owner_id", "name", "value", "status", "created_at", "updated_at", "flags"],
            k=rng.randint(2, 4),
        )
    return {"table": key, "columns": cols, "row_estimate": rng.randint(120, 480000)}


def gen_file(rng: random.Random, key: str) -> dict[str, Any]:
    return {
        "name": key,
        "size_bytes": rng.randint(240, 900000),
        "modified": f"2026-0{rng.randint(1, 8)}-{rng.randint(10, 28)}",
        "mode": rng.choice(["-rw-r--r--", "-rw-rw----", "-rwxr-xr-x"]),
    }


GENERATORS = {
    "user": gen_user,
    "record": gen_record,
    "notice": gen_notice,
    "schema_table": gen_schema_table,
    "file": gen_file,
}


def _as_int(key: str) -> int:
    try:
        return int(key)
    except (TypeError, ValueError):
        return abs(hash(key)) % 100000


# ---------------------------------------------------------------------------
# Offline batch population
# ---------------------------------------------------------------------------


def populate(notebook: FactNotebook, *, users: int = 24, records: int = 60,
             notices: int = 8, seed: int = 0) -> dict[str, int]:
    """Generate the base fake world into the notebook, once, offline.

    On-demand generation (an attacker probing an id beyond this range) uses the
    same generators, so the world extends consistently without a batch rerun."""
    for uid in range(1, users + 1):
        notebook.get_or_generate("user", uid, gen_user)
    for rid in range(1, records + 1):
        rec = notebook.get_or_generate("record", rid, gen_record)
        # materialise the referenced owner so cross-reference holds immediately
        notebook.get_or_generate("user", rec["owner_id"], gen_user)
    for nid in range(1, notices + 1):
        notebook.get_or_generate("notice", nid, gen_notice)
    for table in _TABLES:
        notebook.get_or_generate("schema_table", table, gen_schema_table)
    for fname in _FILENAMES:
        notebook.get_or_generate("file", fname, gen_file)

    # The planted credential lives in a config file the attacker can find
    # (spec §6.10). Stored as a fact so the decoy serves it consistently.
    cred = planted_credential(seed)
    notebook.put("config", "service.ini", {
        "name": "service.ini",
        "content": cred.as_config_ini(),
        "key_id": cred.key_id,
    }, source="seeded")

    return notebook.namespaces()


def build_world(dsn=None, *, seed: int = 0, **counts) -> FactNotebook:
    """Convenience: make a notebook and populate it."""
    from adf.config import system
    dsn = dsn or system().get("databases.fact_notebook_dsn", "sqlite:///data/decoy/notebook.sqlite3")
    nb = FactNotebook(dsn, seed=seed)
    populate(nb, seed=seed, **counts)
    return nb
