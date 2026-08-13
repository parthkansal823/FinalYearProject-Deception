"""
Append-only, tamper-evident record store (spec §6.11, NFR-13, FR-11).

This log is simultaneously three things, which is why it is worth more care
than a print statement:

  1. the operational trace of what the system decided and why,
  2. the training and evaluation data for the whole project,
  3. after cleaning, the publicly released dataset (spec §11).

Records are written as JSON Lines and chained by hash: each record's
`integrity.hash` covers both its own content and the previous record's hash.
Removing, reordering or editing a line therefore breaks verification at a
determinate point, which is what "tamper-evident" has to mean in practice.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from adf.schema import Record, SCHEMA_VERSION

GENESIS_HASH = "0" * 64


class LogStore:
    """One append-only JSONL file, with a hash chain over its records."""

    def __init__(self, path: Path | str, *, hash_chain: bool = True) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.hash_chain = hash_chain
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = GENESIS_HASH
        self._last_size = 0
        self.restarts = 0
        self._resume()

    def _resume(self) -> None:
        """Continue an existing chain rather than restarting it.

        Restarting the sequence on every process start would make a restarted
        proxy look, in the logs, exactly like a truncated log.
        """
        if not self.path.exists() or self.path.stat().st_size == 0:
            return
        last = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last:
            doc = json.loads(last)
            self._seq = int(doc.get("seq", 0)) + 1
            self._prev_hash = str(doc.get("integrity", {}).get("hash", GENESIS_HASH))
        self._last_size = self.path.stat().st_size if self.path.exists() else 0

    def _file_was_replaced(self) -> bool:
        """Has the file been deleted, rotated or truncated underneath us?

        This is not hypothetical: clearing `data/logs/` while a server is
        running leaves the in-memory chain state pointing at records that no
        longer exist. Appending regardless produces a file that starts at
        sequence 1755 and references a vanished hash — a corpus that fails
        verification for a reason unrelated to tampering, which is the worst
        kind of integrity failure because it teaches you to ignore the check.
        """
        if self._last_size == 0:
            # Nothing has been written through this store yet, so a missing
            # file is simply a new one rather than a vanished one.
            return False
        try:
            return self.path.stat().st_size < self._last_size
        except FileNotFoundError:
            return True

    def append(self, record: Record) -> Record:
        with self._lock:
            if self._file_was_replaced():
                # Start a fresh, internally valid chain rather than continuing
                # a broken one. Counted so the condition is visible rather
                # than silent.
                self._seq = 0
                self._prev_hash = GENESIS_HASH
                self._last_size = 0
                self.restarts += 1
                self._resume()

            record.seq = self._seq
            if not record.ts:
                record.ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            record.schema_version = SCHEMA_VERSION

            if self.hash_chain:
                record.integrity.prev_hash = self._prev_hash
                record.integrity.hash = record.content_hash(self._prev_hash)

            line = record.to_json_line()
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                # Durability matters here: a crash mid-experiment must not
                # silently cost records that the evaluation later counts.
                os.fsync(fh.fileno())

            self._last_size = self.path.stat().st_size
            self._seq += 1
            if self.hash_chain:
                self._prev_hash = record.integrity.hash
            return record

    # -- reading -----------------------------------------------------------

    def read(self) -> Iterator[Record]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield Record.from_dict(json.loads(line))

    def verify(self) -> tuple[bool, str]:
        """Re-walk the chain. Returns (ok, human-readable detail)."""
        if not self.hash_chain:
            return True, "hash chain disabled for this store"

        prev = GENESIS_HASH
        count = 0
        expected_seq = 0
        for record in self.read():
            if record.seq != expected_seq:
                return False, f"sequence gap at record {count}: expected seq {expected_seq}, found {record.seq}"
            if record.integrity.prev_hash != prev:
                return False, f"chain break at seq {record.seq}: prev_hash does not match preceding record"
            recomputed = record.content_hash(prev)
            if recomputed != record.integrity.hash:
                return False, f"content modified at seq {record.seq}: hash mismatch"
            prev = record.integrity.hash
            expected_seq += 1
            count += 1
        return True, f"chain intact over {count} records"


class LabelSidecar:
    """Ground-truth labels written by whatever generated the traffic.

    Spec §7.3 requires labels to be applied at the point of generation, never
    inferred afterwards by inspecting the traffic. The generator knows what it
    did; the proxy does not and must never guess. So generators write session
    labels here, and `adf.dataset` joins them onto the request records by
    session id when the corpus is assembled.

    Keeping labels physically out of the live log also means the detection
    path can never accidentally read the answer key.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(
        self,
        *,
        session_id: str,
        ground_truth: str,
        attack_category: str = "none",
        attack_subcategory: str = "none",
        automation_label: str = "unknown",
        generator: str = "",
        tool_version: str = "",
        round: str = "dev",
        run_id: str = "",
        notes: str = "",
    ) -> None:
        entry = {
            "schema_version": SCHEMA_VERSION,
            "ts": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
            "session_id": session_id,
            "run_id": run_id,
            "round": round,
            "ground_truth": ground_truth,
            "attack_category": attack_category,
            "attack_subcategory": attack_subcategory,
            "automation_label": automation_label,
            "generator": generator,
            "tool_version": tool_version,
            "notes": notes,
        }
        line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()

    def read(self) -> dict[str, dict]:
        """session_id -> label entry."""
        out: dict[str, dict] = {}
        if not self.path.exists():
            return out
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    entry = json.loads(line)
                    out[entry["session_id"]] = entry
        return out


# --------------------------------------------------------------------------


def default_log_path(name: str, log_dir: Path | str = "data/logs") -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path(log_dir) / f"{name}.{stamp}.jsonl"


if __name__ == "__main__":  # pragma: no cover - verification CLI
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="Verify the integrity of a log file.")
    ap.add_argument("path", help="path to a .jsonl log")
    args = ap.parse_args()

    store = LogStore(args.path)
    ok, detail = store.verify()
    print(("OK   " if ok else "FAIL ") + detail)
    sys.exit(0 if ok else 1)
