"""
The concrete bait catalogue (spec §6.6).

Each bait knows four things:

  * applicability -- which responses it can inject into (a json_field bait
    needs a JSON body; an html_comment bait needs HTML);
  * its per-session TOKEN -- the unique string that is planted and watched for.
    Value baits (a fake table name, a deprecated endpoint) get a random suffix
    so no fixed string can be published and burn the bait permanently
    (spec §16). Name baits (ref_uid, internal_view, mfa_debug_token) keep the
    plausible field name the spec names in §3.2/§6.6, and rely on per-session
    SELECTION rather than per-session content for freshness -- an honest
    trade-off recorded in docs/DECISIONS.md;
  * injection -- how the token enters the response, always through a
    non-rendered channel so the invisibility gate can pass it;
  * bite detection -- what a later request must contain to count as a bite:
    the token as a value, as a submitted parameter NAME, or as a requested PATH.

The research parameters (bite rates, category) live in config/bait_library.yaml.
The *phrasing* of each injected payload lives here, because it is behaviour to
be tested, not a number to be tuned.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import parse_qs

from adf.bait.channels import (
    BaitedResponse,
    inject_html_comment,
    inject_json_field,
    inject_response_header,
)

BiteKind = Literal["value", "name", "path"]
Channel = Literal["html_comment", "json_field", "response_header"]

# Characters that mean a parameter is malformed in an SQL sense -- the trigger
# for the SQL baits (spec §6.6 B-SQL-1 "a quote or comment character").
_SQL_TRIGGER = re.compile(r"['\"#;]|--|/\*")

# Plausible fake column names for B-SQL-2, so the leaked list reads like a real
# internal schema rather than an obvious plant.
_FAKE_COLUMNS = ["acct_no", "sort_code", "iban", "balance_minor", "status_flag"]


@dataclass
class BaitSpec:
    """Everything about one bait that is not a research parameter."""

    bait_id: str
    category: str
    channel: Channel
    bite_kind: BiteKind
    token_template: str          # from config; "{suffix}" -> per-session random


#: Structural definition of each bait. Channel and bite-kind are behaviour, so
#: they live in code; token_template and effects come from the config library.
BAIT_SPECS: dict[str, BaitSpec] = {
    "B-SQL-1":  BaitSpec("B-SQL-1",  "sqli", "html_comment", "value", "acct_shadow_{suffix}"),
    "B-SQL-2":  BaitSpec("B-SQL-2",  "sqli", "html_comment", "value", "col_{suffix}"),
    "B-IDOR-1": BaitSpec("B-IDOR-1", "idor", "json_field",   "name",  "ref_uid"),
    "B-IDOR-2": BaitSpec("B-IDOR-2", "idor", "html_comment", "name",  "internal_view"),
    "B-AUTH-1": BaitSpec("B-AUTH-1", "auth", "html_comment", "path",  "/auth/legacy/verify_{suffix}"),
    "B-AUTH-2": BaitSpec("B-AUTH-2", "auth", "json_field",   "name",  "mfa_debug_token"),
}


def make_token(spec: BaitSpec, rng: random.Random) -> str:
    """The session-unique bait content. Value baits get an unguessable suffix
    (spec §16); name baits keep their plausible fixed name."""
    if "{suffix}" in spec.token_template:
        suffix = "".join(rng.choice("abcdef0123456789") for _ in range(6))
        return spec.token_template.format(suffix=suffix)
    return spec.token_template


class Bait:
    """A bait bound to a session token, ready to inject and to watch for."""

    def __init__(self, spec: BaitSpec, token: str) -> None:
        self.spec = spec
        self.token = token

    @property
    def bait_id(self) -> str:
        return self.spec.bait_id

    @property
    def category(self) -> str:
        return self.spec.category

    # -- applicability -----------------------------------------------------

    def applicable(self, response: BaitedResponse) -> bool:
        ctype = (response.content_type or "").lower()
        is_json = "json" in ctype or response.body.lstrip()[:1] in ("{", "[")
        if self.spec.channel == "json_field":
            return is_json
        if self.spec.channel == "html_comment":
            return not is_json and "<" in response.body
        return True  # response_header applies to anything

    # -- injection ---------------------------------------------------------

    def inject(self, response: BaitedResponse) -> BaitedResponse:
        payload = self._payload()
        if self.spec.channel == "html_comment":
            return inject_html_comment(response, payload)
        if self.spec.channel == "json_field":
            return inject_json_field(response, self.token, self._json_value())
        if self.spec.channel == "response_header":
            return inject_response_header(response, "X-Debug-Ref", payload)
        raise ValueError(f"unknown channel {self.spec.channel}")

    def _payload(self) -> str:
        """The text an attacker reading raw traffic will find. Written to look
        like a genuine slip, per spec §6.6 (plausible, or it warns the attacker
        the site is defended)."""
        bid = self.spec.bait_id
        if bid == "B-SQL-1":
            return (f'psql error: relation "{self.token}" does not exist '
                    f'LINE 1: SELECT * FROM {self.token} WHERE ...')
        if bid == "B-SQL-2":
            cols = ", ".join(_FAKE_COLUMNS)
            return f"legacy view {self.token} columns: {cols}"
        if bid == "B-IDOR-2":
            return f"internal: append ?{self.token}=1 to expand the full record"
        if bid == "B-AUTH-1":
            return f"legacy auth endpoint {self.token} pending decommission (still active)"
        if bid == "B-AUTH-2":
            return f"debug: submit {self.token} to bypass second factor in staging"
        return self.token

    def _json_value(self) -> str:
        """A plausible value for name baits injected as JSON fields."""
        if self.spec.bait_id == "B-IDOR-1":
            return "usr_" + "".join(random.Random(self.token).choice("0123456789abcdef") for _ in range(10))
        if self.spec.bait_id == "B-AUTH-2":
            return "dbg_" + "".join(random.Random(self.token).choice("0123456789abcdef") for _ in range(12))
        return "1"

    # -- bite detection ----------------------------------------------------

    def detect_bite(self, *, method: str, path: str, query: str, body: str) -> bool:
        """Did this request act on the planted token (spec §21)?"""
        params = _param_names(query) | _param_names(body)
        haystack = f"{path}?{query} {body}"

        if self.spec.bite_kind == "value":
            # the token string appears anywhere the client controls
            return self.token.lower() in haystack.lower()
        if self.spec.bite_kind == "name":
            # the client submitted a parameter the site never emitted in a form
            return self.token.lower() in {p.lower() for p in params}
        if self.spec.bite_kind == "path":
            # the client requested the deprecated path
            return path.rstrip("/").lower() == self.token.rstrip("/").lower()
        return False


def _param_names(qs: str) -> set[str]:
    if not qs:
        return set()
    try:
        return set(parse_qs(qs, keep_blank_values=True).keys())
    except (ValueError, UnicodeDecodeError):
        return set()


def build_bait(bait_id: str, session_id: str, seed: int = 0) -> Bait:
    """Construct the session-bound bait the policy selected."""
    spec = BAIT_SPECS[bait_id]
    rng = random.Random(f"{seed}:{session_id}:{bait_id}")
    return Bait(spec, make_token(spec, rng))
