"""
Synthetic seed data for the target application.

All content here is invented. No real personal data appears anywhere in this
project, in either the real or the decoy application (spec §17).

Realism matters more than volume (spec §6.1): if the target app is obviously
a toy, the decoy copy of it will be obviously a toy too, and the deception
metrics in §10.3 stop meaning anything. So the seed models a plausible small
internal portal -- staff directory, expense records, notices -- rather than
the usual foo/bar placeholder rows.
"""

from __future__ import annotations

import hashlib
import random

from target_app.db import Database

SCHEMA_SQL = """
DROP TABLE IF EXISTS records;
DROP TABLE IF EXISTS profiles;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS notices;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE profiles (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    full_name  TEXT NOT NULL,
    email      TEXT NOT NULL,
    phone      TEXT NOT NULL,
    department TEXT NOT NULL,
    location   TEXT NOT NULL,
    notes      TEXT
);

CREATE TABLE records (
    id             INTEGER PRIMARY KEY,
    owner_id       INTEGER NOT NULL,
    title          TEXT NOT NULL,
    body           TEXT NOT NULL,
    amount         TEXT,
    classification TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE TABLE notices (
    id         INTEGER PRIMARY KEY,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    posted_at  TEXT NOT NULL
);
"""

# Weak, guessable passwords are deliberate: spec §6.1 leaves the login form
# without rate limiting or lockout so that the credential-attack category has
# somewhere to land.
USERS = [
    # username,      password,        role,      full name,          department
    ("a.mirza",      "Summer2024!",   "staff",   "Ayesha Mirza",     "Finance"),
    ("d.okafor",     "password1",     "staff",   "Daniel Okafor",    "Finance"),
    ("s.lindqvist",  "hunter2",       "staff",   "Sofia Lindqvist",  "Operations"),
    ("r.banerjee",   "Welcome@123",   "manager", "Rohan Banerjee",   "Operations"),
    ("m.oconnell",   "letmein",       "staff",   "Maeve O'Connell",  "People"),
    ("t.yamamoto",   "Tokyo2019",     "staff",   "Taro Yamamoto",    "Engineering"),
    ("k.novak",      "qwerty123",     "staff",   "Klara Novak",      "Engineering"),
    ("j.mensah",     "Passw0rd",      "manager", "Joseph Mensah",    "Engineering"),
    ("l.ferreira",   "Brasil!2020",   "staff",   "Lucia Ferreira",   "Legal"),
    ("h.abbas",      "changeme",      "staff",   "Hana Abbas",       "Legal"),
    ("svc_reports",  "R3port!ng",     "service", "Reporting Service","Systems"),
    ("admin",        "admin123",      "admin",   "System Administrator", "Systems"),
]

LOCATIONS = ["Block A, Floor 2", "Block A, Floor 3", "Block B, Floor 1", "Remote", "Block C, Floor 4"]

RECORD_TITLES = [
    "Q3 travel reimbursement", "Vendor invoice INV-{n}", "Equipment purchase request",
    "Client site visit expenses", "Software licence renewal", "Conference registration",
    "Team offsite catering", "Contractor timesheet W{n}", "Courier and postage",
    "Monitor replacement", "Annual subscription renewal", "Training course fee",
]

RECORD_BODIES = [
    "Submitted via the portal. Awaiting line manager approval.",
    "Approved by department head; pending finance review.",
    "Rejected -- missing supporting receipt. Resubmission requested.",
    "Paid on the standard 30-day cycle.",
    "Held pending clarification of the cost centre code.",
    "Processed under the delegated authority threshold.",
]

CLASSIFICATIONS = ["internal", "internal", "internal", "confidential", "restricted"]

NOTICES = [
    ("Scheduled maintenance this weekend",
     "The portal will be unavailable on Saturday between 02:00 and 05:00 while storage is migrated. "
     "No action is required from staff."),
    ("Updated expense policy",
     "From the start of next quarter, receipts are required for all claims above the standard threshold. "
     "The claim form has been updated accordingly."),
    ("New starters this month",
     "Please welcome the colleagues joining Engineering and Legal. Introductions are on the team pages."),
    ("Reminder: annual security training",
     "Annual security awareness training must be completed before the end of the month. "
     "Access the module from the learning portal."),
    ("Office access cards",
     "Replacement access cards are issued from reception. Report lost cards immediately."),
    ("Parking allocation review",
     "The parking allocation for Block B is being reviewed. Comments to Operations by Friday."),
    ("Printer relocation",
     "The third-floor printer has moved next to the kitchen. Queue names are unchanged."),
    ("Quarterly all-hands",
     "The quarterly all-hands meeting is scheduled for the last Thursday of the month at 14:00."),
]


def password_hash(password: str) -> str:
    """Unsalted SHA-256. Weak on purpose and consistent with a small legacy
    internal app -- realistic for the threat model, never for production."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def seed(db: Database, *, seed_value: int = 20260813) -> dict[str, int]:
    """(Re)create the schema and fill it. Deterministic for a given seed so
    that every experiment run starts from an identical world (NFR-08)."""
    rng = random.Random(seed_value)
    db.executescript(SCHEMA_SQL)

    for uid, (username, password, role, full_name, department) in enumerate(USERS, start=1):
        db.execute(
            "INSERT INTO users (id, username, password_hash, role, active) VALUES (%s, %s, %s, %s, %s)",
            (uid, username, password_hash(password), role, 1),
        )
        db.execute(
            "INSERT INTO profiles (id, user_id, full_name, email, phone, department, location, notes) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                uid, uid, full_name,
                f"{username}@northbridge-internal.example",
                f"+44 20 7946 {rng.randint(1000, 9999)}",
                department,
                rng.choice(LOCATIONS),
                rng.choice([
                    "Primary contact for departmental queries.",
                    "Part-time, Tuesdays and Thursdays.",
                    "On secondment until the end of the year.",
                    "",
                ]),
            ),
        )

    record_id = 1
    for owner_id in range(1, len(USERS) + 1):
        for _ in range(rng.randint(3, 6)):
            title = rng.choice(RECORD_TITLES).format(n=rng.randint(100, 999))
            db.execute(
                "INSERT INTO records (id, owner_id, title, body, amount, classification, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    record_id, owner_id, title, rng.choice(RECORD_BODIES),
                    f"{rng.randint(15, 4200)}.{rng.randint(0, 99):02d}",
                    rng.choice(CLASSIFICATIONS),
                    f"2026-{rng.randint(1, 8):02d}-{rng.randint(1, 28):02d}",
                ),
            )
            record_id += 1

    for nid, (title, body) in enumerate(NOTICES, start=1):
        db.execute(
            "INSERT INTO notices (id, title, body, posted_at) VALUES (%s, %s, %s, %s)",
            (nid, title, body, f"2026-08-{nid:02d}"),
        )

    return {"users": len(USERS), "records": record_id - 1, "notices": len(NOTICES)}


if __name__ == "__main__":  # pragma: no cover
    import argparse

    from adf.config import system

    ap = argparse.ArgumentParser(description="Seed the target application database.")
    ap.add_argument("--dsn", default=None)
    args = ap.parse_args()

    cfg = system()
    dsn = args.dsn or cfg.get("databases.target_dsn")
    counts = seed(Database(dsn), seed_value=cfg.seed)
    print(f"seeded {dsn}: " + ", ".join(f"{v} {k}" for k, v in counts.items()))
