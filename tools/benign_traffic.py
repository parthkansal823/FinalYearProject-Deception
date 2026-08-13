"""
Benign traffic generator (spec §6.2).

This is not a side task. Without a substantial body of normal traffic the
suspicion meter has nothing to contrast attacks against, and -- more
importantly -- there is no way to measure the single most important safety
number in the project: how often a normal user ever sees bait (spec §6.2,
§10.3 benign bait exposure rate, NFR-05).

What "benign" means here, operationally:

  * signs in correctly, using a legitimately obtained OTP (computed, because
    a real user would have received it by another channel);
  * fetches the CSS, JS and logo alongside pages, the way a browser does --
    this is what makes benign traffic look non-automated (spec §6.1, §6.3);
  * pauses for human-like, irregular amounts of time between actions;
  * occasionally fat-fingers a password before getting it right;
  * browses only its own things, or the directory, which is a legitimate
    reason to view other people's profiles -- so that an honest user and an
    IDOR sweep are separated by *pattern*, not merely by which URLs appear.

Every session is labelled at the point of generation (spec §7.3): the
generator writes a benign label to the sidecar BEFORE it starts, so the label
can never be a post-hoc guess from the traffic.

Traffic is sent through whatever address is given as --base-url. In Phase 1
that is the target app directly (:8001); from Phase 3 it is the proxy (:8000)
so the detector sees it. The generator does not know or care which.
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
from target_app.otp import otp_for

GENERATOR_NAME = "benign_traffic.py"
GENERATOR_VERSION = "1.0"

# A realistic mix of desktop browser User-Agents. Real users are not all on
# one browser; a single UA across every "human" session would itself be an
# automation tell and would teach the meter the wrong thing.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
]

# The static assets a browser pulls with each fresh page load. Fetching these
# is the strongest single automation signal in the whole feature set (§6.1).
PAGE_ASSETS = ["/static/app.css", "/static/app.js", "/static/logo.svg"]

# (username, password) pairs a legitimate user knows. Mirror of the seed;
# duplicated deliberately so the generator does not read the answer key out
# of the database at runtime.
KNOWN_USERS = [
    (1, "a.mirza", "Summer2024!"),
    (2, "d.okafor", "password1"),
    (3, "s.lindqvist", "hunter2"),
    (4, "r.banerjee", "Welcome@123"),
    (5, "m.oconnell", "letmein"),
    (6, "t.yamamoto", "Tokyo2019"),
    (7, "k.novak", "qwerty123"),
    (8, "j.mensah", "Passw0rd"),
    (9, "l.ferreira", "Brasil!2020"),
    (10, "h.abbas", "changeme"),
]

SEARCH_TERMS = [
    "maintenance", "expense", "policy", "training", "parking",
    "security", "printer", "all-hands", "access card", "starters",
]


@dataclass
class HumanTiming:
    """Human pauses are irregular; scripts are metronomic (spec §6.3). This
    draws think-times from a lognormal so the gaps have realistic spread and
    the occasional long pause, rather than a constant tick."""

    rng: random.Random
    speed: float = 1.0            # <1 faster (skims), >1 slower (deliberate)

    def think(self) -> float:
        base = self.rng.lognormvariate(mu=0.2, sigma=0.6)  # ~0.8s median, long tail
        return max(0.15, base * self.speed)


class BenignUser:
    """One simulated human session."""

    def __init__(self, base_url: str, rng: random.Random, *, dwell: bool = True) -> None:
        self.rng = rng
        self.dwell = dwell
        self.timing = HumanTiming(rng, speed=rng.uniform(0.6, 1.8))
        self.ua = rng.choice(USER_AGENTS)
        self.session_id = f"benign-{uuid.uuid4().hex[:12]}"
        # A real browser keeps a cookie jar and sends a consistent, ordered
        # header set. Both are things the meter checks (§6.3).
        self.client = httpx.Client(
            base_url=base_url,
            follow_redirects=True,
            timeout=10.0,
            headers={
                "User-Agent": self.ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8",
                "Accept-Language": "en-GB,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                # Tag every request so the corpus can be joined to its label
                # even if cookies are lost; harmless, and mirrors how a real
                # study would mark synthetic traffic.
                "X-ADF-Session": self.session_id,
            },
        )
        self.user_id: int | None = None
        self.max_profile_id = len(KNOWN_USERS) + 2

    def _pause(self) -> None:
        if self.dwell:
            time.sleep(self.timing.think())

    def _load_page(self, path: str, **kwargs) -> httpx.Response:
        """Fetch a page and, like a browser, its assets."""
        resp = self.client.get(path, **kwargs)
        for asset in PAGE_ASSETS:
            # Browsers cache, so not every asset is refetched every time.
            if self.rng.random() < 0.7:
                self.client.get(asset)
        return resp

    def browse_public(self) -> None:
        self._load_page("/")
        self._pause()
        if self.rng.random() < 0.3:
            self._load_page("/search", params={"q": self.rng.choice(SEARCH_TERMS)})
            self._pause()

    def sign_in(self) -> bool:
        uid, username, password = self.rng.choice(KNOWN_USERS)
        self.user_id = uid
        self._load_page("/login")
        self._pause()

        # Humans mistype. Sometimes a wrong password first, then the right one
        # (spec §6.2). This must stay rare -- a benign user who fails six times
        # would, correctly, start to look like a credential attack.
        if self.rng.random() < 0.2:
            self.client.post("/login", data={"username": username, "password": password[:-1]})
            self._pause()

        self.client.post("/login", data={"username": username, "password": password})
        self._pause()

        # Second factor, using a legitimately held code.
        self.client.post("/otp", data={"code": otp_for(uid)})
        self._pause()
        return True

    def do_work(self) -> None:
        """A short, plausible working session."""
        self._load_page("/dashboard")
        self._pause()

        actions = self.rng.randint(2, 6)
        for _ in range(actions):
            choice = self.rng.random()
            if choice < 0.35:
                # look at own records
                rid = self.rng.randint(1, 40)
                self._load_page(f"/records/{rid}")
            elif choice < 0.6:
                # the directory is the *legitimate* reason to view others'
                # profiles -- a couple of colleagues, not a sweep
                self._load_page("/directory")
                self._pause()
                for _ in range(self.rng.randint(1, 2)):
                    pid = self.rng.randint(1, self.max_profile_id)
                    self._load_page(f"/profile/{pid}")
                    self._pause()
            elif choice < 0.85:
                self._load_page("/search", params={"q": self.rng.choice(SEARCH_TERMS)})
            else:
                self._load_page("/dashboard")
            self._pause()

    def run(self) -> None:
        try:
            self.browse_public()
            if self.rng.random() < 0.85:      # most visitors sign in; some just read notices
                if self.sign_in():
                    self.do_work()
            if self.rng.random() < 0.4:
                self.client.get("/logout")
        finally:
            self.client.close()


def generate(
    *,
    base_url: str,
    sessions: int,
    seed: int,
    round: int,
    run_id: str,
    label_path: str,
    dwell: bool,
) -> int:
    rng = random.Random(seed)
    sidecar = LabelSidecar(label_path)

    for i in range(sessions):
        user = BenignUser(base_url, random.Random(rng.random()), dwell=dwell)

        # Label BEFORE acting (spec §7.3): the truth is known by construction,
        # never inferred from what the traffic looked like afterwards.
        sidecar.write(
            session_id=user.session_id,
            ground_truth="benign",
            attack_category="none",
            attack_subcategory="none",
            automation_label="human",
            generator=GENERATOR_NAME,
            tool_version=GENERATOR_VERSION,
            round=round,
            run_id=run_id,
            notes="simulated human session",
        )
        user.run()
        if (i + 1) % 25 == 0:
            print(f"  ... {i + 1}/{sessions} benign sessions")

    return sessions


def main() -> None:
    cfg = system()
    ap = argparse.ArgumentParser(description="Generate labelled benign traffic (spec §6.2).")
    ap.add_argument("--base-url", default=f"http://{cfg.get('network.bind_host','127.0.0.1')}:{cfg.get('network.target_port',8001)}",
                    help="target app in Phase 1; the proxy from Phase 3")
    ap.add_argument("--sessions", type=int, default=100)
    ap.add_argument("--seed", type=int, default=cfg.seed)
    ap.add_argument("--round", type=int, choices=[0, 1, 2], default=1,
                    help="which experimental round this corpus belongs to (spec §7.2)")
    ap.add_argument("--run-id", default=f"benign-{uuid.uuid4().hex[:8]}")
    ap.add_argument("--label-path", default=str(cfg.label_dir / "benign_labels.jsonl"))
    ap.add_argument("--no-dwell", action="store_true",
                    help="skip human think-times for a fast smoke run (timing features will be unrealistic)")
    args = ap.parse_args()

    print(f"generating {args.sessions} benign sessions -> {args.base_url}")
    print(f"labels -> {args.label_path}  (round {args.round}, seed {args.seed})")
    n = generate(
        base_url=args.base_url,
        sessions=args.sessions,
        seed=args.seed,
        round=args.round,
        run_id=args.run_id,
        label_path=args.label_path,
        dwell=not args.no_dwell,
    )
    print(f"done: {n} benign sessions generated and labelled")


if __name__ == "__main__":
    main()
