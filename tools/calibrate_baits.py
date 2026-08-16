"""
Bait calibration -- the `calibrate` round (spec §6.6, schema §Round, §13 Phase 6).

The bait library ships with PRIOR bite rates. Reporting a Phase 7 result computed
from priors would present a guess as a finding, so this round measures them.

Two rates per bait:
  * beta_benign = P(bite | benign). Measured directly and cheaply by running the
    benign traffic through the baited proxy and counting bites. It should come
    out at ~0 because bait is invisible (NFR-01); measuring it is the safety
    check, not an assumption.
  * beta_attack = P(bite | attacker). This is a property of the ATTACKER
    population, so it is measured by running bait-following attackers -- clients
    that inspect responses for planted tokens and act on them with a stated
    curiosity. beta_attack is therefore conditional on that attacker model,
    which is stated in the library provenance and is a limitation (spec §18):
    a single researcher's attacker model, not a physical constant.

Estimation uses the Jeffreys posterior mean (Beta(1/2,1/2)) so a rate of exactly
zero does not produce an infinite likelihood ratio, with a floor from the
library's `estimation` block.

Run against a LIVE b4 stack (target + decoy + proxy):
    python -m tools.calibrate_baits --sessions 60
"""

from __future__ import annotations

import argparse
import glob
import json
import random
import re
import time
import uuid
from collections import defaultdict

import httpx
import yaml

from adf.config import system, REPO_ROOT
from target_app.otp import otp_for

BAIT_LIBRARY_PATH = REPO_ROOT / "config" / "bait_library.yaml"

# Patterns the follower looks for in responses -- one per bait channel.
_TOKEN_PATTERNS = {
    "B-SQL-1": re.compile(r"acct_shadow_[a-f0-9]+"),
    "B-SQL-2": re.compile(r"col_[a-f0-9]+"),
    "B-IDOR-1": re.compile(r'"ref_uid"'),
    "B-IDOR-2": re.compile(r"internal_view"),
    "B-AUTH-1": re.compile(r"/auth/legacy/verify_[a-f0-9]+"),
    "B-AUTH-2": re.compile(r"mfa_debug_token"),
}


class BaitFollower:
    """An attacker that probes a category, then INSPECTS responses for planted
    slips and acts on them with probability `curiosity`."""

    def __init__(self, base_url: str, category: str, curiosity: float, rng: random.Random) -> None:
        self.category = category
        self.curiosity = curiosity
        self.rng = rng
        # the category is carried in the session id so the measurement step can
        # use the RIGHT denominator (see `session_category`)
        self.session_id = f"cal-atk-{category}-{uuid.uuid4().hex[:10]}"
        self.client = httpx.Client(base_url=base_url, follow_redirects=True, timeout=10.0,
                                   headers={"User-Agent": "curl/8.6.0",
                                            "X-ADF-Session": self.session_id})

    def _maybe_bite(self, text: str) -> None:
        """Scan a response for a planted token OF THIS FOLLOWER'S CATEGORY and
        act on it with `curiosity`.

        The category restriction is what makes the per-bait estimate mean
        anything, and its absence was a real defect. Every session warms up
        through `/login` -> `/otp` -> `/dashboard`, and those responses carry the
        auth and IDOR baits. An earlier version bit whichever token it saw first,
        so a *sqli* follower would take the IDOR bait on `/dashboard`, be diverted
        to the decoy during warm-up, and never reach its own `/search` probes at
        all. The SQL baits were therefore shown to **0 of 300** attack sessions
        and kept fabricated priors -- which is the entire content of the "half
        the baits keep their priors" limitation. Restricting the bite to the
        category under measurement lets each bait be measured on the traffic it
        is actually for.

        Cross-category biting is realistic *attacker* behaviour, and the round-2
        evaluation attackers do exactly that. It is wrong only here, where the
        job is to estimate one bait's rate rather than to imitate an adversary.
        """
        cat = self.category
        if cat == "sqli":
            for m in re.finditer(r"acct_shadow_[a-f0-9]+", text):
                if self.rng.random() < self.curiosity:
                    self.client.get("/search", params={"q": m.group(0)})
                return
            for m in re.finditer(r"col_[a-f0-9]+", text):
                if self.rng.random() < self.curiosity:
                    self.client.get("/search", params={"q": m.group(0)})
                return
        elif cat == "idor":
            if '"ref_uid"' in text or "ref_uid" in text:
                if self.rng.random() < self.curiosity:
                    self.client.get("/api/profile/3", params={"ref_uid": "1"})
                return
            if "internal_view" in text and self.rng.random() < self.curiosity:
                self.client.get("/records/4", params={"internal_view": "1"})
                return
        elif cat == "auth":
            for m in re.finditer(r"/auth/legacy/verify_[a-f0-9]+", text):
                if self.rng.random() < self.curiosity:
                    self.client.get(m.group(0))
                return
            if "mfa_debug_token" in text and self.rng.random() < self.curiosity:
                self.client.post("/otp", data={"code": "0", "mfa_debug_token": "x"})
                return

    def run(self) -> None:
        try:
            self.client.post("/login", data={"username": "a.mirza", "password": "Summer2024!"})
            r = self.client.post("/otp", data={"code": otp_for(1)})
            self._maybe_bite(r.text)

            if self.category == "sqli":
                probes = ["a'", "b'", "policy' "]
                for p in probes:
                    r = self.client.get("/search", params={"q": p}); self._maybe_bite(r.text)
            elif self.category == "idor":
                # Scattered access to the object-reference surfaces. This keeps
                # the session in the uncertain band where the IDOR baits are
                # actually deployed and can be measured, rather than escalating
                # out of it.
                #
                # BOTH surfaces are probed, and that matters for calibration
                # coverage: the HTML pages carry B-IDOR-2 (html_comment) while
                # the JSON twins carry B-IDOR-1 (json_field). An earlier version
                # browsed only /profile and /records, so no JSON response was
                # ever produced, B-IDOR-1 was never injectable, and it kept its
                # prior with n = 0 -- a fabricated parameter in a library that
                # claims to be measured. A real IDOR attacker uses both surfaces
                # (round 2's `idor_scattered` walks the API), so probing both is
                # the honest attacker model as well as the one that closes the
                # coverage gap.
                seen = set()
                for _ in range(8):
                    pid = self.rng.randint(1, 24)
                    while pid in seen:
                        pid = self.rng.randint(1, 24)
                    seen.add(pid)
                    surface = self.rng.choice(["/profile", "/records",
                                               "/api/profile", "/api/records"])
                    r = self.client.get(f"{surface}/{pid}")
                    self._maybe_bite(r.text)
            elif self.category == "auth":
                for _ in range(4):
                    r = self.client.post("/login", data={"username": "a.mirza", "password": "wrong"})
                    self._maybe_bite(r.text)
                r = self.client.post("/otp", data={"code": "000000"}); self._maybe_bite(r.text)
        finally:
            self.client.close()


def run_benign(base_url: str, rng: random.Random, *, agent: bool = False) -> str:
    """A benign session for beta_benign. It does NOT inspect responses for tokens
    -- a real user never would -- so it can only bite by accident.

    `agent=True` runs an automated-but-harmless client (uptime monitor, crawler,
    reporting integration) instead of a simulated human. That is not decoration:
    beta_benign has to be measured on the surfaces where each bait actually
    rides, and the human personas never touch `/api/*`. B-IDOR-1 is a json_field
    bait, so with a human-only benign corpus it was shown to **0 benign sessions**
    and fell back to the smoothing floor (0.0005) -- giving it a likelihood ratio
    of ~1200 on no evidence at all, which then drove the derived PASS/BAIT edge
    down. The reporting integration walks `/api/records/{id}`, which is exactly
    the surface that bait rides, so including agents is what makes its benign
    rate a measurement rather than a floor.
    """
    if agent:
        from tools.benign_agents import PROFILES
        name = rng.choice(list(PROFILES))
        cls, ua = PROFILES[name]
        a = cls(base_url=base_url, rng=rng, dwell=False, profile=name, user_agent=ua)
        a.run()
        a.close()
        return a.session_id
    from tools.benign_traffic import BenignUser
    user = BenignUser(base_url, rng, dwell=False, persona="normal")
    user.run()
    return user.session_id


#: which category of attacker a bait is written for. beta_attack is only
#: meaningful over sessions of that category, because that is the only kind of
#: session the policy ever deploys the bait to.
BAIT_CATEGORY = {"B-SQL-1": "sqli", "B-SQL-2": "sqli",
                 "B-IDOR-1": "idor", "B-IDOR-2": "idor",
                 "B-AUTH-1": "auth", "B-AUTH-2": "auth"}


def session_category(recs: list[dict]) -> str:
    """What kind of session this is: one of sqli / idor / auth / benign.

    Preferred source is the calibration session id, which now carries the
    category (`cal-atk-<category>-<hex>`). Older logs predate that, so the
    behaviour is inferred instead — which surface it probed — and both paths
    agree on the runs we have.
    """
    sid = recs[0]["session"].get("provenance_id") or recs[0]["session"].get("session_id", "")
    for cat in ("sqli", "idor", "auth"):
        if f"cal-atk-{cat}-" in sid:
            return cat
    if not any("curl" in (r["request"].get("user_agent", "")) for r in recs):
        return "benign"
    paths = [r["request"].get("path", "") for r in recs]
    query = " ".join(str(r["request"].get("query", "")) for r in recs)
    if any(p == "/search" for p in paths) and ("%27" in query or "'" in query):
        return "sqli"
    if sum(1 for p in paths if p.startswith(("/profile", "/records", "/api/"))) >= 3:
        return "idor"
    if sum(1 for p in paths if p == "/login") >= 3:
        return "auth"
    return "other"


def measure_from_logs(log_glob: str) -> tuple[dict, dict, dict, dict]:
    """Return per-bait (attack_shown, attack_bit, benign_shown, benign_bit).

    THE DENOMINATOR IS THE POINT. `beta_attack` is P(bite | bait shown, session
    hostile *and of this bait's category*): the policy only ever deploys an IDOR
    bait to a session it suspects of IDOR, so an estimate whose denominator also
    counts SQL and auth sessions measures something the policy never does.

    An earlier version counted every attack session the bait was shown to. Since
    every session warms up through `/login` -> `/otp` -> `/dashboard`, and those
    responses carry the auth and IDOR baits, all three categories entered those
    denominators while only one could ever bite — which pushed B-IDOR-2 to 0.21
    and B-AUTH-1 to 0.13 against corrected values of 0.65 and 0.93. The auth
    figure in particular was reported as a project limitation ("the auth bait is
    weakly taken") that turned out to be an artefact of this line.
    """
    records = []
    for f in glob.glob(log_glob):
        records += [json.loads(l) for l in open(f, encoding="utf-8") if l.strip()]
    by_session = defaultdict(list)
    for r in records:
        by_session[r["session"]["session_id"]].append(r)

    attack_shown, attack_bit = defaultdict(set), defaultdict(set)
    benign_shown, benign_bit = defaultdict(set), defaultdict(set)
    for sid, recs in by_session.items():
        cat = session_category(recs)
        for r in recs:
            b = r.get("bait", {})
            bt = r.get("bite", {})
            bid = b.get("bait_id")
            if b.get("injected") and bid:
                if cat == "benign":
                    benign_shown[bid].add(sid)
                elif BAIT_CATEGORY.get(bid) == cat:
                    attack_shown[bid].add(sid)
            tid = bt.get("bait_id")
            if bt.get("occurred") and tid:
                if cat == "benign":
                    benign_bit[tid].add(sid)
                elif BAIT_CATEGORY.get(tid) == cat:
                    attack_bit[tid].add(sid)
    return attack_shown, attack_bit, benign_shown, benign_bit


def jeffreys(bit: int, shown: int, floor: float) -> float:
    if shown <= 0:
        return floor
    return max((bit + 0.5) / (shown + 1.0), floor)


def main() -> None:
    cfg = system()
    ap = argparse.ArgumentParser(description="Calibrate bait effectiveness (spec §6.6).")
    ap.add_argument("--proxy", default=f"http://127.0.0.1:{cfg.get('network.proxy_port', 8000)}")
    ap.add_argument("--sessions", type=int, default=60, help="attack sessions per category")
    ap.add_argument("--benign", type=int, default=60)
    ap.add_argument("--seed", type=int, default=cfg.seed)
    ap.add_argument("--write", action="store_true", help="write calibrated betas back to the library")
    ap.add_argument("--from-logs", action="store_true",
                    help="skip traffic generation and re-measure the existing proxy log "
                         "(use after fixing the measurement, so an hour of traffic is not "
                         "re-run to recompute an estimator over the same sessions)")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    if args.from_logs:
        print("re-measuring the existing proxy log (no traffic generated) ...")
    else:
        # curiosity is drawn per session: a spread of attacker sophistication.
        print(f"running bait-following attackers + benign traffic through {args.proxy} ...")
        for category in ("sqli", "idor", "auth"):
            for _ in range(args.sessions):
                curiosity = rng.choice([0.3, 0.5, 0.7, 0.9])
                BaitFollower(args.proxy, category, curiosity, random.Random(rng.random())).run()
        # 60/40 humans to automated agents: beta_benign must be measured on the
        # surfaces each bait rides, and only the agents touch the JSON API.
        for i in range(args.benign):
            run_benign(args.proxy, random.Random(rng.random()), agent=(i % 5 >= 3))
        time.sleep(1.5)

    attack_shown, attack_bit, benign_shown, benign_bit = measure_from_logs(
        str(cfg.log_dir / "proxy.*.jsonl"))

    doc = yaml.safe_load(BAIT_LIBRARY_PATH.read_text(encoding="utf-8"))
    floor = float(doc.get("estimation", {}).get("beta_benign_floor", 0.0005))
    min_sessions = int(doc.get("estimation", {}).get("min_calibration_sessions", 30))

    print(f"\n{'bait':10} {'atk_shown':>9} {'atk_bit':>8} {'beta_attack':>12} "
          f"{'ben_shown':>9} {'ben_bit':>8} {'beta_benign':>12}")
    results = {}
    for entry in doc["baits"]:
        bid = entry["id"]
        a_shown, a_bit = len(attack_shown[bid]), len(attack_bit[bid])
        b_shown, b_bit = len(benign_shown[bid]), len(benign_bit[bid])
        ba = jeffreys(a_bit, a_shown, floor * 2)   # attack floor a bit above benign
        bb = jeffreys(b_bit, b_shown, floor)
        # never let the estimate assert benign >= attack (an uninformative bait)
        if bb >= ba:
            bb = min(bb, ba * 0.5)
        results[bid] = (ba, bb, a_shown, b_shown)
        flag = "" if a_shown >= min_sessions else "  (thin sample -> prior kept)"
        print(f"{bid:10} {a_shown:>9} {a_bit:>8} {ba:>12.4f} {b_shown:>9} {b_bit:>8} {bb:>12.4f}{flag}")

    # -- provenance report (always written on a real run) -----------------
    import datetime
    stamp = datetime.date.today().isoformat()
    report = {
        "calibrated_on": stamp,
        "calibration_seed": args.seed,
        "round": "calibrate",
        "attacker_model": {
            "curiosity_choices": [0.3, 0.5, 0.7, 0.9],
            "note": "beta_attack is a session-level bite rate conditional on this "
                    "attacker-curiosity model (a single researcher's model, spec §18), "
                    "not a physical constant. beta_benign IS measured on benign traffic.",
        },
        "min_calibration_sessions": min_sessions,
        "baits": {},
    }
    for entry in doc["baits"]:
        bid = entry["id"]
        ba, bb, a_shown, b_shown = results[bid]
        measured = a_shown >= min_sessions
        report["baits"][bid] = {
            "attack_sessions_shown": a_shown, "attack_bit": len(attack_bit[bid]),
            "benign_sessions_shown": b_shown, "benign_bit": len(benign_bit[bid]),
            "beta_attack": round(ba, 4) if measured else entry["effect"]["beta_attack"],
            "beta_benign": round(bb, 4) if measured else entry["effect"]["beta_benign"],
            "status": "measured" if measured else "prior (rarely deployed / thin sample)",
        }

    if not args.write:
        print("\n(dry run; pass --write to update the library and write the report)")
        return

    report_path = REPO_ROOT / "config" / "bait_calibration_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    text = BAIT_LIBRARY_PATH.read_text(encoding="utf-8")
    updated = 0
    for entry in doc["baits"]:
        bid = entry["id"]
        ba, bb, a_shown, _ = results[bid]
        if a_shown < min_sessions:
            continue  # keep the prior for thinly-sampled baits, honestly flagged
        eff = entry["effect"]
        text = _replace_beta(text, bid, "beta_attack", eff["beta_attack"], round(ba, 4))
        text = _replace_beta(text, bid, "beta_benign", eff["beta_benign"], round(bb, 4))
        updated += 1

    # Set the TOP-LEVEL calibrated flag (a YAML key at column 0), not the word
    # "calibrated" wherever it first appears in a comment.
    text = re.sub(r"(?m)^calibrated:\s*false\s*$",
                  f"calibrated: true\ncalibrated_on: \"{stamp}\"\ncalibration_seed: {args.seed}",
                  text, count=1)
    BAIT_LIBRARY_PATH.write_text(text, encoding="utf-8")
    print(f"\ncalibrated {updated}/{len(doc['baits'])} baits from measured data; "
          f"the rest keep priors (rarely deployed).")
    print(f"library marked calibrated (seed {args.seed}); provenance -> {report_path.name}")


def _replace_beta(text: str, bait_id: str, field: str, old, new) -> str:
    # replace the beta value within the block of this bait id, first occurrence
    idx = text.find(f"id: {bait_id}")
    if idx == -1:
        return text
    seg = text[idx:idx + 800]
    seg2 = re.sub(rf"({field}:\s*)[0-9.]+", rf"\g<1>{new}", seg, count=1)
    return text[:idx] + seg2 + text[idx + 800:]


if __name__ == "__main__":
    main()
