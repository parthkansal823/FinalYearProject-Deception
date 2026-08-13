"""
Benign but AUTOMATED traffic (spec §6.3).

The specification justifies the two-axis suspicion model with a specific
example: "A vulnerability scanner is highly automated and highly hostile. A
price-comparison bot is highly automated and entirely harmless. A careful
human attacker is barely automated and extremely hostile. One combined score
cannot express those three situations; two scores can."

That argument only holds if the middle case actually exists in the data. A
corpus containing nothing but human-benign and scripted-hostile traffic makes
automation and malice perfectly correlated, and then:

  * a single combined score would do just as well, so contribution #2 of the
    project is unfalsifiable and indefensible in a viva;
  * the meter would learn "fast and scripted" as a proxy for "hostile", which
    is precisely the brittle heuristic this project exists to improve on;
  * the ablation "one combined score instead of two" (spec §10.2) would show
    no difference, and the correct conclusion would be that the second axis
    is unnecessary.

So this generator produces the missing class: sessions that are unambiguously
automated and unambiguously harmless.

Three profiles, chosen because each is confusable with a different attack:

  monitor      metronomic timing, no assets, no cookies    -- looks like a scanner
  crawler      broad sweep of public pages                 -- looks like recon
  integration  rapid SEQUENTIAL id access over the API     -- looks like IDOR

The third is the interesting one and the reason this file is worth writing.
A legitimate reporting integration pulling *its own* records in id order
produces almost exactly the request pattern of an IDOR sweep. It is a genuine
hard negative: any model that separates it from an attack has learned
something about ownership and intent rather than about request rate. If the
final system cannot tell these apart, that is a finding worth reporting
(spec §7.4) rather than something to quietly leave out of the corpus.
"""

from __future__ import annotations

import argparse
import random
import re
import time
import uuid
from dataclasses import dataclass

import httpx

from adf.config import system
from adf.logstore import LabelSidecar
from adf.schema import PROVENANCE_HEADER
from target_app.otp import otp_for
from tools.benign_traffic import KNOWN_USERS, PAGE_ASSETS

GENERATOR_NAME = "benign_agents.py"
GENERATOR_VERSION = "1.0"


@dataclass
class Agent:
    """Base for an automated but harmless client."""

    base_url: str
    rng: random.Random
    dwell: bool = True
    profile: str = "agent"
    user_agent: str = "python-httpx/0.28"

    def __post_init__(self) -> None:
        self.session_id = f"agent-{self.profile}-{uuid.uuid4().hex[:10]}"
        self.client = httpx.Client(
            base_url=self.base_url,
            follow_redirects=True,
            timeout=10.0,
            headers={
                "User-Agent": self.user_agent,
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
                PROVENANCE_HEADER: self.session_id,
            },
        )

    def _tick(self, seconds: float) -> None:
        """Machines wait on a clock, not on a thought. Jitter is small and
        symmetric, unlike the lognormal think-time of a human."""
        if self.dwell:
            time.sleep(max(0.02, seconds * self.rng.uniform(0.95, 1.05)))

    def close(self) -> None:
        self.client.close()

    # -- labelling --------------------------------------------------------

    @property
    def label(self) -> dict:
        return {
            "ground_truth": "benign",
            "attack_category": "none",
            "attack_subcategory": "none",
            # The whole point: automated, and harmless.
            "automation_label": "scripted",
            "generator": GENERATOR_NAME,
            "tool_version": GENERATOR_VERSION,
            "notes": f"benign automated agent: {self.profile}",
        }


class UptimeMonitor(Agent):
    """Availability check on a fixed interval.

    Metronomic timing, no cookies, no static assets, minimal headers — every
    automation feature in spec §6.3 fires at once, and it is completely
    harmless. If anything in the corpus is going to be wrongly diverted, it is
    this, which makes it a direct test of NFR-05.
    """

    def run(self) -> None:
        interval = self.rng.choice([1.0, 2.0, 5.0])
        for _ in range(self.rng.randint(6, 14)):
            self.client.get("/healthz")
            if self.rng.random() < 0.25:
                self.client.get("/")
            self._tick(interval)


class SearchCrawler(Agent):
    """Indexes the public pages.

    Fetches some assets (real crawlers render), follows only public links,
    and paces itself politely. Broad, shallow, and harmless.
    """

    def run(self) -> None:
        public = ["/", "/login", "/"]
        for path in public:
            self.client.get(path)
            # Crawlers do fetch CSS and JS, which is what stops "fetched
            # assets" from being a perfect human/machine separator.
            for asset in PAGE_ASSETS:
                if self.rng.random() < 0.5:
                    self.client.get(asset)
            self._tick(self.rng.choice([1.0, 2.0]))

        for missing in ("/robots.txt", "/sitemap.xml", "/favicon.ico"):
            self.client.get(missing)
            self._tick(0.5)


class ReportingIntegration(Agent):
    """A scheduled export job pulling its OWN records over the JSON API.

    This is the hard negative. It authenticates properly, then walks record
    ids in ascending order as fast as the server answers — the same surface
    shape as an IDOR sweep, differing only in that every id it touches
    belongs to it.

    Distinguishing this from an attack is the real test of the malice axis. A
    detector keying on "sequential ids + high rate + no assets" flags it; one
    that understands ownership does not.
    """

    def run(self) -> None:
        uid, username, password = self.rng.choice(KNOWN_USERS)
        self.client.post("/login", data={"username": username, "password": password})
        self.client.post("/otp", data={"code": otp_for(uid)})
        self._tick(0.3)

        dashboard = self.client.get("/dashboard")
        own_ids = sorted({int(m) for m in re.findall(r"/records/(\d+)", dashboard.text)})

        # Ascending order, no pauses to speak of: exactly what a batch export
        # looks like on the wire.
        for record_id in own_ids:
            self.client.get(f"/api/records/{record_id}")
            self._tick(0.05)

        if own_ids:
            self.client.get(f"/api/profile/{uid}")


PROFILES = {
    "monitor": (UptimeMonitor, "Northbridge-UptimeCheck/2.1 (+internal monitoring)"),
    "crawler": (SearchCrawler, "Mozilla/5.0 (compatible; NorthbridgeBot/1.0; +internal indexer)"),
    "integration": (ReportingIntegration, "northbridge-reporting/3.4 python-httpx/0.28"),
}


def generate(
    *,
    base_url: str,
    sessions: int,
    seed: int,
    round: str,
    run_id: str,
    label_path: str,
    dwell: bool,
    profiles: list[str],
) -> dict[str, int]:
    rng = random.Random(seed)
    sidecar = LabelSidecar(label_path)
    counts: dict[str, int] = {}

    for i in range(sessions):
        profile = profiles[i % len(profiles)]
        cls, user_agent = PROFILES[profile]
        agent = cls(
            base_url=base_url,
            rng=random.Random(rng.random()),
            dwell=dwell,
            profile=profile,
            user_agent=user_agent,
        )

        # Labelled before acting (spec §7.3).
        sidecar.write(session_id=agent.session_id, round=round, run_id=run_id, **agent.label)
        try:
            agent.run()
        finally:
            agent.close()

        counts[profile] = counts.get(profile, 0) + 1
        if (i + 1) % 15 == 0:
            print(f"  ... {i + 1}/{sessions} agent sessions")

    return counts


def main() -> None:
    cfg = system()
    ap = argparse.ArgumentParser(description="Generate benign automated traffic (spec §6.3).")
    ap.add_argument("--base-url",
                    default=f"http://{cfg.get('network.bind_host','127.0.0.1')}:{cfg.get('network.target_port',8001)}")
    ap.add_argument("--sessions", type=int, default=30)
    ap.add_argument("--seed", type=int, default=cfg.seed + 1)
    ap.add_argument("--round", choices=["dev", "train", "calibrate", "eval"], default="train")
    ap.add_argument("--run-id", default=f"agents-{uuid.uuid4().hex[:8]}")
    ap.add_argument("--label-path", default=str(cfg.label_dir / "benign_agent_labels.jsonl"))
    ap.add_argument("--profiles", default="monitor,crawler,integration")
    ap.add_argument("--no-dwell", action="store_true",
                    help="skip pacing for a fast smoke run (timing features will be unrealistic)")
    args = ap.parse_args()

    profiles = [p.strip() for p in args.profiles.split(",") if p.strip()]
    unknown = set(profiles) - set(PROFILES)
    if unknown:
        raise SystemExit(f"unknown profile(s): {sorted(unknown)}; choose from {sorted(PROFILES)}")

    print(f"generating {args.sessions} benign AUTOMATED sessions -> {args.base_url}")
    print(f"profiles: {', '.join(profiles)}")
    counts = generate(
        base_url=args.base_url,
        sessions=args.sessions,
        seed=args.seed,
        round=args.round,
        run_id=args.run_id,
        label_path=args.label_path,
        dwell=not args.no_dwell,
        profiles=profiles,
    )
    print("done: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))


if __name__ == "__main__":
    main()
