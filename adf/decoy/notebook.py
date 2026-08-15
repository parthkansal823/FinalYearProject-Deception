"""
The Fact Notebook (spec §6.9) -- the second load-bearing contribution (§4.3 #4).

Decoys that generate their answers on the fly forget what they said: ask the
same question twice and you get two different answers, and that inconsistency
is exactly how an experienced attacker realises they are in a trap. The Fact
Notebook removes that failure mode by writing down every fact the decoy has
ever stated, so a repeated question is answered from the notebook rather than
generated afresh.

It must hold consistency across the four dimensions spec §6.9 names:

  1. Repetition       -- asking the same thing twice returns the same answer.
  2. Cross-reference  -- a user named in one place exists with the same details
                         wherever else they appear.
  3. Write-then-read  -- if the attacker modifies something, reading it back
                         returns what they wrote.
  4. Referential integrity -- an id mentioned in one record resolves to a
                         matching record elsewhere.

Design. A fact is `(namespace, key) -> value`. Two mechanisms together give all
four dimensions:

  * DETERMINISTIC generation. When a fact is first needed, it is produced by a
    generator seeded from `(seed, namespace, key)`. The same key therefore
    generates the same value even if it is first seen months apart or through a
    different endpoint -- repetition and cross-reference hold even before
    anything is persisted.
  * PERSISTENCE with attacker override. The generated value is stored on first
    use (INSERT OR IGNORE, so the first writer wins and concurrent reads agree).
    An attacker write is stored with higher precedence, so reading a mutated
    fact back returns the mutation -- write-then-read.

Referential integrity is a property of the generators: a generator that emits a
reference (record.owner_id = 7) resolves it by asking the notebook for that
entity, which generates it consistently if absent.

Storage is SQLite -- simple, persistent, no server -- as spec §12 allows.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator
import random

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Precedence: an attacker's write must win over the originally generated value
# so that write-then-read returns what they wrote (spec §6.9 dimension 3).
SOURCE_PRECEDENCE = {"generated": 0, "seeded": 0, "attacker": 10}

GeneratorFn = Callable[[random.Random, str], dict[str, Any]]


@dataclass
class Fact:
    namespace: str
    key: str
    value: dict[str, Any]
    source: str


class FactNotebook:
    def __init__(self, dsn: str | Path = "sqlite:///data/decoy/notebook.sqlite3",
                 *, seed: int = 0, persist: bool = True) -> None:
        self.seed = seed
        # persist=False is the ABLATION (spec §10.2 "Fact Notebook disabled"):
        # facts are generated fresh with an unseeded RNG on every request and
        # never stored, so the decoy forgets what it said and contradicts itself
        # -- exactly the failure mode the notebook exists to prevent. The
        # consistency fuzzer's contradiction rate then measures the notebook's
        # value directly (near-zero with it, high without it).
        self.persist = persist
        self._lock = threading.Lock()
        if isinstance(dsn, Path):
            self._path = dsn
        elif str(dsn).startswith("sqlite:///"):
            rel = str(dsn)[len("sqlite:///"):]
            self._path = REPO_ROOT / rel if not Path(rel).is_absolute() else Path(rel)
        elif str(dsn) == ":memory:":
            self._path = Path(":memory:")
        else:
            self._path = Path(str(dsn))

        if str(self._path) != ":memory:":
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._shared = None
        else:
            # an in-memory notebook must keep ONE connection alive or it
            # vanishes between calls
            self._shared = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared.row_factory = sqlite3.Row
        self._init_schema()

    # -- connection --------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if self._shared is not None:
            return self._shared
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS facts ("
                "  namespace TEXT NOT NULL,"
                "  key       TEXT NOT NULL,"
                "  value     TEXT NOT NULL,"
                "  source    TEXT NOT NULL DEFAULT 'generated',"
                "  precedence INTEGER NOT NULL DEFAULT 0,"
                "  created_at TEXT NOT NULL DEFAULT (datetime('now')),"
                "  PRIMARY KEY (namespace, key)"
                ")"
            )
            conn.commit()
        finally:
            if self._shared is None:
                conn.close()

    def _rng(self, namespace: str, key: str) -> random.Random:
        """Deterministic per-entity RNG: the same (seed, namespace, key) always
        produces the same stream, so a fact generated on demand is identical to
        one generated in the offline batch."""
        return random.Random(f"{self.seed}:{namespace}:{key}")

    # -- core operations ---------------------------------------------------

    def get(self, namespace: str, key: str) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM facts WHERE namespace = ? AND key = ?",
                (namespace, str(key)),
            ).fetchone()
            return json.loads(row["value"]) if row else None
        finally:
            if self._shared is None:
                conn.close()

    def put(self, namespace: str, key: str, value: dict[str, Any], *,
            source: str = "generated") -> None:
        """Store a fact. Higher-precedence sources (attacker writes) overwrite
        lower ones; equal or lower precedence never clobbers an existing higher
        one, so a generated default cannot erase an attacker's modification."""
        precedence = SOURCE_PRECEDENCE.get(source, 0)
        payload = json.dumps(value, sort_keys=True)
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO facts (namespace, key, value, source, precedence) "
                    "VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(namespace, key) DO UPDATE SET "
                    "  value = excluded.value, source = excluded.source, precedence = excluded.precedence "
                    "WHERE excluded.precedence >= facts.precedence",
                    (namespace, str(key), payload, source, precedence),
                )
                conn.commit()
            finally:
                if self._shared is None:
                    conn.close()

    def get_many_or_generate(self, namespace: str, keys: list, generator: GeneratorFn) -> list[dict[str, Any]]:
        """Fetch several facts of one namespace in a SINGLE connection, so a
        list page (e.g. the staff directory) does not open one connection per
        row. Missing keys are generated and persisted. This keeps the decoy's
        list-page latency inside the target's envelope (NFR-03) -- a decoy that
        is measurably slower on /directory is a detectable decoy (§6.8)."""
        keys = [str(k) for k in keys]
        if not self.persist:  # ablation: no memory (see get_or_generate)
            import random as _random
            return [generator(_random.Random(), k) for k in keys]
        conn = self._connect()
        try:
            placeholders = ",".join("?" * len(keys))
            rows = conn.execute(
                f"SELECT key, value FROM facts WHERE namespace = ? AND key IN ({placeholders})",
                (namespace, *keys),
            ).fetchall() if keys else []
            found = {r["key"]: json.loads(r["value"]) for r in rows}
        finally:
            if self._shared is None:
                conn.close()

        out = []
        for k in keys:
            if k in found:
                out.append(found[k])
            else:
                value = generator(self._rng(namespace, k), k)
                self.put(namespace, k, value, source="generated")
                out.append(self.get(namespace, k) or value)
        return out

    def get_or_generate(self, namespace: str, key: str, generator: GeneratorFn) -> dict[str, Any]:
        """Return the stored fact, or generate it deterministically, persist it,
        and return it. This is the repetition guarantee (spec §6.9): the first
        call fixes the value, every later call returns the same one."""
        if not self.persist:
            # ABLATION: no memory. Generate fresh, from an unseeded RNG, and do
            # not store -- so the same key yields a different value each time.
            import random as _random
            return generator(_random.Random(), str(key))
        existing = self.get(namespace, str(key))
        if existing is not None:
            return existing
        value = generator(self._rng(namespace, str(key)), str(key))
        # INSERT OR IGNORE semantics via precedence 0: if a concurrent caller
        # generated first, keep theirs so both callers agree.
        self.put(namespace, str(key), value, source="generated")
        return self.get(namespace, str(key)) or value

    def record_write(self, namespace: str, key: str, value: dict[str, Any]) -> None:
        """An attacker created or modified something. Stored with attacker
        precedence so reading it back returns exactly this (write-then-read)."""
        self.put(namespace, str(key), value, source="attacker")

    # -- introspection -----------------------------------------------------

    def all(self, namespace: str) -> Iterator[Fact]:
        conn = self._connect()
        try:
            for row in conn.execute(
                "SELECT namespace, key, value, source FROM facts WHERE namespace = ? ORDER BY key",
                (namespace,),
            ):
                yield Fact(row["namespace"], row["key"], json.loads(row["value"]), row["source"])
        finally:
            if self._shared is None:
                conn.close()

    def namespaces(self) -> dict[str, int]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT namespace, COUNT(*) AS n FROM facts GROUP BY namespace ORDER BY namespace"
            ).fetchall()
            return {r["namespace"]: r["n"] for r in rows}
        finally:
            if self._shared is None:
                conn.close()

    def count(self) -> int:
        conn = self._connect()
        try:
            return conn.execute("SELECT COUNT(*) AS n FROM facts").fetchone()["n"]
        finally:
            if self._shared is None:
                conn.close()
