"""
Carrying what an attacker already saw on the target into the decoy.

WHY THIS EXISTS
---------------
The proxy replays a diverted session's pre-divert target *pages* so a re-read of
the same path is consistent (docs/LIMITATIONS.md §7). But an aggregate endpoint
re-lists the same entities under a *different* path: read `/profile/3` on the
target (Sofia Lindqvist), get diverted, open `/directory` (never seen, so the
decoy fabricates it) and it lists profile 3 as someone else. Same id, two names
across the boundary — a second-order tell the page-replay does not cover, found
by an agentic pentest.

The fix is entity-level, not page-level. The proxy extracts the *facts* it showed
the attacker (this profile's name/email/…, this record's title/amount/owner) as
it caches each pre-divert target page, and hands them to the decoy on every
diverted request. The decoy overlays those facts for exactly those ids at its one
generation chokepoint, so every surface — profile page, directory, dashboard,
JSON API — agrees with what the attacker already saw. Ids the attacker never saw
keep the decoy's fabricated world, so nothing new is exposed (NFR-06).

This module is the single place that knows the target/decoy template shapes, so
the coupling lives here rather than smeared across the proxy and the decoy app.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

HEADER = "x-adf-observed"

# Which rendered fields we lift for each entity. These are exactly the fields the
# shared templates display, so overlaying them makes every surface consistent.
_USER_FIELDS = ("full_name", "email", "phone", "department", "location")
_RECORD_FIELDS = ("title", "classification", "amount", "owner_id", "created_at", "body")

_PROFILE_PATH = re.compile(r"^/(?:api/)?profile/(\d+)$")
_RECORD_PATH = re.compile(r"^/(?:api/)?records/(\d+)$")


def _dd(html: str, label: str) -> str | None:
    m = re.search(rf"<dt>{label}</dt><dd>(.*?)</dd>", html, re.S)
    return m.group(1).strip() if m else None


def _h1(html: str) -> str | None:
    m = re.search(r"<h1>(.*?)</h1>", html, re.S)
    return m.group(1).strip() if m else None


def extract_entity(path: str, content_type: str, body: bytes) -> tuple[str, int, dict] | None:
    """From a served target response, recover (namespace, id, fields) if it is a
    profile or record view, else None. Handles both the HTML pages and the JSON
    twins, because an attacker may use either."""
    mp = _PROFILE_PATH.match(path)
    mr = _RECORD_PATH.match(path)
    if not (mp or mr):
        return None
    ns = "user" if mp else "record"
    ent_id = int((mp or mr).group(1))
    text = body.decode("utf-8", "replace")

    if "json" in content_type:
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return None
        payload = obj.get("profile") if mp else obj.get("record")
        if not isinstance(payload, dict):
            return None
        fields = _USER_FIELDS if mp else _RECORD_FIELDS
        picked = {k: payload[k] for k in fields if k in payload}
        return (ns, ent_id, picked) if picked else None

    # HTML
    if mp:
        name = _h1(text)
        if name is None:
            return None
        fields = {"full_name": name}
        for label, key in (("Email", "email"), ("Phone", "phone"),
                           ("Department", "department"), ("Location", "location")):
            v = _dd(text, label)
            if v is not None:
                fields[key] = v
        return ("user", ent_id, fields)

    # record HTML
    title = _h1(text)
    if title is None:
        return None
    fields: dict[str, Any] = {"title": title}
    cls = re.search(r'tag tag-\w+">(.*?)</span>', text, re.S)
    if cls:
        fields["classification"] = cls.group(1).strip()
    amt = _dd(text, "Amount")
    if amt is not None:
        fields["amount"] = amt
    owner = re.search(r"<dt>Owner</dt><dd>.*?Profile #(\d+)", text, re.S)
    if owner:
        fields["owner_id"] = int(owner.group(1))
    created = re.search(r"created ([0-9]{4}-[0-9]{2}-[0-9]{2})", text)
    if created:
        fields["created_at"] = created.group(1)
    return ("record", ent_id, fields)


def encode(observed: dict[str, dict[int, dict]]) -> str:
    """Compact, header-safe encoding of the observed-facts map."""
    # json keys must be strings; ids become strings and are restored on decode.
    slim = {ns: {str(i): f for i, f in ents.items()} for ns, ents in observed.items() if ents}
    raw = json.dumps(slim, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def decode(header_value: str) -> dict[str, dict[int, dict]]:
    """Inverse of `encode`; tolerant of a missing or malformed header."""
    if not header_value:
        return {}
    try:
        raw = base64.b64decode(header_value.encode("ascii"))
        obj = json.loads(raw)
    except Exception:
        return {}
    out: dict[str, dict[int, dict]] = {}
    for ns, ents in obj.items():
        if isinstance(ents, dict):
            out[ns] = {int(i): f for i, f in ents.items() if isinstance(f, dict)}
    return out


def apply_overlay(namespace: str, entity: dict, overlay: dict[str, dict[int, dict]]) -> dict:
    """Return `entity` with any observed fields for its id merged over it. The
    observed values win, because they are what the attacker already saw; every
    other field keeps the decoy's fabricated value."""
    ent_id = entity.get("id")
    seen = overlay.get(namespace, {}).get(ent_id)
    if not seen:
        return entity
    merged = dict(entity)
    merged.update(seen)
    return merged
