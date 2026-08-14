"""
Adaptive, bait-AWARE attacker (spec §18, §19 — robustness against an adversary
who knows the defence exists).

The specification lists this as out of scope and states it as a limitation: "An
attacker who [knows this defence exists] could probe for bait deliberately, and
countering that is out of scope." This tool turns that caveat into a MEASURED
result, because a defence that reports how it degrades under adaptive pressure
is far stronger than one that simply assumes the attacker is naive.

The attacker runs a FIXED escalating probe sequence -- so the only variable
across the sweep is behaviour, not effort -- and inspects every response for
the tell-tale shape of a planted token (a table name that surfaced in an error,
an unused field, a conveniently-deprecated endpoint). Its `bait_awareness` in
[0, 1] is the probability it correctly recognises such a token as planted and
REFUSES to act on it:

    awareness = 0.0   naive follower: acts on every token it sees (bites early)
    awareness = 1.0   fully aware: never bites; detection must come from the
                      passive features alone -- the robustness floor.

Because bait is invisible and inert, an attacker at awareness 1.0 behaves,
from the meter's point of view, exactly like a passive-classifier (B2) session:
the injected bait changes nothing it does. So the sweep interpolates between
"bait buys an early divert" and "the system falls back to passive detection".
"""

from __future__ import annotations

import re
import uuid

import httpx

from target_app.otp import otp_for

# Tokens an attacker might spot, and the "planted-ness" tell an aware attacker
# uses: each of these surfaced somewhere a genuine leak rarely would (an error
# message, an HTML comment, an unused JSON field).
_TOKEN_RE = re.compile(r"acct_shadow_[a-f0-9]+|/auth/legacy/verify_[a-f0-9]+|col_[a-f0-9]+")


class AdaptiveAttacker:
    def __init__(self, base_url: str, bait_awareness: float, rng, *,
                 profile: str = "escalating", dwell: bool = False) -> None:
        self.base = base_url
        self.awareness = max(0.0, min(1.0, bait_awareness))
        self.profile = profile
        self.rng = rng
        self.session_id = f"adapt-{uuid.uuid4().hex[:10]}"
        self.client = httpx.Client(base_url=base_url, follow_redirects=True, timeout=10.0,
                                   headers={"User-Agent": "curl/8.6.0",
                                            "X-ADF-Session": self.session_id})
        self.bit = False

    def _inspect_and_maybe_bite(self, text: str) -> None:
        if self.bit:
            return
        m = _TOKEN_RE.search(text)
        if not m:
            return
        token = m.group(0)
        # An aware attacker recognises the planted token and refuses; a naive
        # one acts on it. The draw is per encounter.
        if self.rng.random() < self.awareness:
            return  # recognised as bait, declined
        # act on it -> the bite
        if token.startswith("acct_shadow") or token.startswith("col_"):
            self.client.get("/search", params={"q": token})
        elif token.startswith("/auth/legacy"):
            self.client.get(token)
        self.bit = True

    #: Two attacker archetypes, to separate two findings:
    #  * `escalating` rises to aggressive injection that the passive malice
    #    features catch on their own -> tests the FLOOR (is the system still
    #    caught them without a bite?).
    #  * `low_slow` stays gentle, lingering in the bait band where passive
    #    detection is UNCERTAIN -> tests bait's VALUE and the cost of a
    #    bait-aware adversary who declines it.
    _SEQUENCES = {
        "escalating": [
            "a'", "b'", "policy'", "report'", "user'",
            "x' OR '1'='1",
            "x' UNION SELECT 1 -- ",
            "x' UNION SELECT username,password_hash,3,4 FROM users -- ",
        ],
        "low_slow": [
            "policy'", "report", "a'", "maintenance", "user'",
            "b'", "training", "c'", "review", "audit'",
        ],
    }

    def run(self) -> None:
        """A FIXED probe sequence (per profile), identical across awareness
        levels, so the only difference is whether the attacker acts on the bait
        it is shown."""
        try:
            self.client.post("/login", data={"username": "a.mirza", "password": "Summer2024!"})
            r = self.client.post("/otp", data={"code": otp_for(1)})
            self._inspect_and_maybe_bite(r.text)

            for q in self._SEQUENCES.get(self.profile, self._SEQUENCES["escalating"]):
                if self.bit:
                    break
                r = self.client.get("/search", params={"q": q})
                self._inspect_and_maybe_bite(r.text)
        finally:
            self.client.close()
