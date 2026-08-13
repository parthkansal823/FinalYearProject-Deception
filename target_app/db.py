"""
Database access for the target application.

WARNING: this module intentionally builds SQL by string concatenation.
That is a defect everywhere else in the world and a requirement here: spec
§6.1 places an SQL injection surface in the search box on purpose, and spec
§12 prefers PostgreSQL specifically because its verbose error text is what
makes the SQL bait plausible.

Nothing in this file may be copied into production code. See SAFETY.md.

Two backends are supported behind one tiny interface:
  * PostgreSQL -- the intended backend, realistic error messages
  * SQLite     -- a no-Docker fallback for development
Both concatenate identically, so an injection payload behaves the same way
against either; only the error text differs.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent


class DatabaseError(Exception):
    """Carries the raw driver message, because the target app deliberately
    leaks it to the client (that verbosity is the vulnerability)."""

    def __init__(self, message: str, sqlstate: str = "", backend: str = "") -> None:
        super().__init__(message)
        self.raw = message
        self.sqlstate = sqlstate
        self.backend = backend


@dataclass
class Database:
    dsn: str

    def __post_init__(self) -> None:
        if self.dsn.startswith("sqlite:///"):
            self.backend = "sqlite"
            rel = self.dsn[len("sqlite:///"):]
            self._sqlite_path = REPO_ROOT / rel if not Path(rel).is_absolute() else Path(rel)
            self._sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        elif self.dsn.startswith(("postgresql://", "postgres://")):
            self.backend = "postgres"
        else:
            raise ValueError(f"unsupported DSN: {self.dsn!r}")

    # -- connection --------------------------------------------------------

    def _connect(self):
        if self.backend == "sqlite":
            conn = sqlite3.connect(self._sqlite_path)
            conn.row_factory = sqlite3.Row
            return conn
        import psycopg
        from psycopg.rows import dict_row

        return psycopg.connect(self.dsn, row_factory=dict_row)

    # -- queries -----------------------------------------------------------

    def query(self, sql: str, params: tuple | None = None) -> list[dict[str, Any]]:
        """Parameterised query -- used everywhere the app is NOT meant to be
        vulnerable, so that the injection surface stays confined to exactly
        the one place the research design puts it."""
        try:
            with self._connect() as conn:
                cur = conn.cursor()
                cur.execute(self._adapt(sql), params or ())
                rows = cur.fetchall()
                return [dict(r) for r in rows]
        except Exception as exc:  # noqa: BLE001 - the message is the point
            raise DatabaseError(str(exc), backend=self.backend) from exc

    def query_raw(self, sql: str) -> list[dict[str, Any]]:
        """DELIBERATELY UNSAFE. Executes a concatenated string verbatim.

        Only the search endpoint uses this. Kept as a separate, loudly named
        method so that every use site is greppable and auditable -- an
        accidental second injection point would quietly widen the threat
        model and make the attack-category labels wrong.
        """
        try:
            with self._connect() as conn:
                cur = conn.cursor()
                cur.execute(sql)
                rows = cur.fetchall()
                return [dict(r) for r in rows]
        except Exception as exc:  # noqa: BLE001
            sqlstate = getattr(exc, "sqlstate", "") or ""
            raise DatabaseError(str(exc), sqlstate=sqlstate, backend=self.backend) from exc

    def execute(self, sql: str, params: tuple | None = None) -> None:
        try:
            with self._connect() as conn:
                cur = conn.cursor()
                cur.execute(self._adapt(sql), params or ())
                conn.commit()
        except Exception as exc:  # noqa: BLE001
            raise DatabaseError(str(exc), backend=self.backend) from exc

    def executescript(self, sql: str) -> None:
        if self.backend == "sqlite":
            with self._connect() as conn:
                conn.executescript(sql)
                conn.commit()
            return
        import psycopg

        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
            conn.commit()

    def _adapt(self, sql: str) -> str:
        """SQLite uses ? placeholders, psycopg uses %s. The app writes %s."""
        return sql.replace("%s", "?") if self.backend == "sqlite" else sql
