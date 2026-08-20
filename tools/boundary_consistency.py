"""
Cross-divert-boundary consistency measurement (docs/LIMITATIONS.md §7).

WHY THIS EXISTS
---------------
`adf/decoy/fuzzer.py` reports 0% contradiction, but it only ever talks to the
decoy: it measures the decoy disagreeing *with itself*. That number cannot see a
whole class of tell — the same object id returning different data on the real
target (before a session is diverted) versus the decoy (after). An agentic
attacker found exactly that: record #6 read one thing pre-divert and another
post-divert (`manual-testing/proxy.claude-agent.*.jsonl`).

The proxy was fixed to replay a session's pre-divert target views after it is
diverted, so already-seen ids stay consistent. This tool is the *measurement*
that certifies the fix and, more importantly, certifies the property the fuzzer's
0% never covered: it drives a real session through the live b4_full stack, reads
a sample of records and profiles on the target, gets diverted, re-reads the same
ids, and counts every field that changed across the boundary.

  * BEFORE the proxy fix it would report a high contradiction rate (the whole
    decoy world differs from the target).
  * AFTER the fix it reports 0% on already-seen ids, while a genuinely new id
    (never seen pre-divert) is still served by the decoy — the fake world is
    unchanged for anything the attacker had not already observed.

It touches nothing frozen: no retraining, no recalibration. It runs its own
isolated stack and reports a rate, the same shape as the fuzzer's headline.

    python -m tools.boundary_consistency --sessions 20
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import httpx

from adf.config import system
from adf.freeze import require_frozen
from target_app.otp import otp_for

# A staff user to log in as, to reach the post-auth surface (the same footing the
# human and agent sessions used). uid 1 in target_app/seed.py.
LOGIN_USER, LOGIN_PASS, LOGIN_UID = "a.mirza", "Summer2024!", 1

OUT = Path("data/eval/boundary_consistency.json")


# --- tiny HTML field extractors (target and decoy share the templates) --------

def _between(html: str, pattern: str) -> str | None:
    m = re.search(pattern, html, re.S)
    return m.group(1).strip() if m else None


def parse_record(html: str) -> dict | None:
    title = _between(html, r"<h1>(.*?)</h1>")
    if title is None:
        return None
    return {
        "title": title,
        "classification": _between(html, r'tag tag-\w+">(.*?)</span>'),
        "amount": _between(html, r"<dt>Amount</dt><dd>(.*?)</dd>"),
        "owner": _between(html, r"<dt>Owner</dt><dd>.*?Profile #(\d+)"),
    }


def parse_profile(html: str) -> dict | None:
    name = _between(html, r"<h1>(.*?)</h1>")
    if name is None:
        return None
    return {
        "name": name,
        "email": _between(html, r"<dt>Email</dt><dd>(.*?)</dd>"),
        "department": _between(html, r"<dt>Department</dt><dd>(.*?)</dd>"),
        "location": _between(html, r"<dt>Location</dt><dd>(.*?)</dd>"),
    }


def parse_directory(html: str) -> dict:
    """id -> (name, department, location) from the /directory listing."""
    rows = re.findall(r"<td>([^<]+)</td>\s*<td>([^<]+)</td>\s*<td>([^<]+)</td>"
                      r'\s*<td><a href="/profile/(\d+)"', html, re.S)
    return {int(pid): {"name": n.strip(), "department": d.strip(), "location": loc.strip()}
            for (n, d, loc, pid) in rows}


# --- stack management (mirrors tools/multiseed_eval.py) ------------------------

def _wait(url: str, name: str, tries: int = 200) -> bool:
    for _ in range(tries):
        try:
            httpx.get(url, timeout=1.0)
            return True
        except Exception:
            time.sleep(0.3)
    print(f"  !! {name} did not come up at {url}")
    return False


def _uvicorn(app_path: str, port: int, host: str, env: dict) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", app_path, "--host", host, "--port", str(port),
         "--log-level", "warning"], env=env)


# --- one attacker session -----------------------------------------------------

class Session:
    """A real cookie-carrying client, driven the way the manual attacker was."""

    def __init__(self, base: str) -> None:
        self.c = httpx.Client(base_url=base, timeout=20.0, follow_redirects=False,
                              headers={"User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                                                      "Chrome/120.0 Safari/537.36")})

    def get(self, path: str) -> httpx.Response:
        return self.c.get(path)

    def recon(self) -> None:
        """Fetch the landing page and its assets, the way a browser does. The
        automation axis keys on this (spec §6.1); without it the session looks
        scripted and diverts before the sample can be read on the target."""
        self.c.get("/")
        self.c.get("/static/app.css")
        self.c.get("/static/app.js")

    def login(self) -> bool:
        self.recon()
        self.c.get("/login")
        r = self.c.post("/login", data={"username": LOGIN_USER, "password": LOGIN_PASS})
        if r.status_code not in (302, 303):
            return False
        r = self.c.post("/otp", data={"code": otp_for(LOGIN_UID)})
        if r.status_code not in (302, 303):
            return False
        return self.c.get("/dashboard").status_code == 200


def run_session(base: str, record_ids: list[int], profile_ids: list[int],
                sentinel_id: int) -> dict:
    """Read a sample on the target, get diverted, re-read, compare. Returns
    per-session field counts and whether the divert actually happened."""
    s = Session(base)
    if not s.login():
        return {"ok": False, "reason": "login failed"}

    # ---- pre-divert: read on the real target, remember what we saw ----------
    pre_records, pre_profiles = {}, {}
    for rid in record_ids:
        r = s.get(f"/records/{rid}")
        if r.status_code == 200:
            v = parse_record(r.text)
            if v:
                pre_records[rid] = v
    for pid in profile_ids:
        r = s.get(f"/profile/{pid}")
        if r.status_code == 200:
            v = parse_profile(r.text)
            if v:
                pre_profiles[pid] = v
    # a sentinel id the target does not have: 404 now, but the decoy will
    # fabricate a 200 once we are diverted -- our proof the divert took effect.
    sentinel_pre = s.get(f"/records/{sentinel_id}").status_code

    # ---- trigger the divert (a single quote spikes the passive meter) -------
    s.get("/search?q=%27")

    sentinel_post = s.get(f"/records/{sentinel_id}").status_code
    diverted = (sentinel_pre == 404 and sentinel_post == 200)

    # ---- post-divert: re-read the SAME ids, compare field by field ----------
    compared = contradictions = 0
    examples: list[str] = []
    for rid, before in pre_records.items():
        after = parse_record(s.get(f"/records/{rid}").text) or {}
        for k, bv in before.items():
            compared += 1
            if after.get(k) != bv:
                contradictions += 1
                if len(examples) < 6:
                    examples.append(f"record {rid}.{k}: {bv!r} -> {after.get(k)!r}")
    for pid, before in pre_profiles.items():
        after = parse_profile(s.get(f"/profile/{pid}").text) or {}
        for k, bv in before.items():
            compared += 1
            if after.get(k) != bv:
                contradictions += 1
                if len(examples) < 6:
                    examples.append(f"profile {pid}.{k}: {bv!r} -> {after.get(k)!r}")

    # ---- aggregate cross-reference: /directory was NOT read pre-divert, so it
    # is served fresh by the decoy. Every profile the attacker saw individually
    # must still read the same in the listing (the second-order tell). ----------
    dmap = parse_directory(s.get("/directory").text)
    for pid, before in pre_profiles.items():
        row = dmap.get(pid)
        if not row:
            continue
        for dkey, pkey in (("name", "name"), ("department", "department"), ("location", "location")):
            compared += 1
            if row.get(dkey) != before.get(pkey):
                contradictions += 1
                if len(examples) < 6:
                    examples.append(f"directory[{pid}].{dkey}: "
                                    f"{before.get(pkey)!r} -> {row.get(dkey)!r}")

    return {"ok": True, "diverted": diverted,
            "records_seen": len(pre_records), "profiles_seen": len(pre_profiles),
            "fields_compared": compared, "contradictions": contradictions,
            "examples": examples}


def main() -> None:
    ap = argparse.ArgumentParser(description="Cross-divert-boundary consistency rate.")
    ap.add_argument("--sessions", type=int, default=20)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    require_frozen()
    cfg = system()
    tp = cfg.get("network.target_port", 8001)
    dp = cfg.get("network.decoy_port", 8002)
    pp = cfg.get("network.proxy_port", 8000)
    host = args.host
    base_env = dict(os.environ)

    print("seeding the target world ...")
    subprocess.run([sys.executable, "-m", "target_app.seed"], env=base_env, check=False)
    print("starting target + decoy + proxy (b4_full) ...")
    target = _uvicorn("target_app.main:app", tp, host, base_env)
    decoy = _uvicorn("decoy_app.main:app", dp, host, base_env)
    proxy = _uvicorn("adf.proxy:app", pp, host, dict(base_env, ADF_MODE="b4_full"))
    ok = (_wait(f"http://{host}:{tp}/healthz", "target")
          and _wait(f"http://{host}:{dp}/healthz", "decoy")
          and _wait(f"http://{host}:{pp}/", "proxy"))

    results = []
    try:
        if not ok:
            raise SystemExit("stack did not come up")
        base = f"http://{host}:{pp}"
        # ids chosen to span other users' records/profiles (IDOR reads); the
        # sentinel is well beyond the seeded record range.
        record_ids = list(range(1, 25))
        profile_ids = list(range(1, 13))
        for i in range(args.sessions):
            res = run_session(base, record_ids, profile_ids, sentinel_id=55)
            results.append(res)
            if res.get("ok"):
                print(f"  session {i+1}/{args.sessions}: diverted={res['diverted']} "
                      f"seen={res['records_seen']}rec/{res['profiles_seen']}prof "
                      f"fields={res['fields_compared']} contradictions={res['contradictions']}")
            else:
                print(f"  session {i+1}/{args.sessions}: SKIPPED ({res.get('reason')})")
    finally:
        for p in (proxy, decoy, target):
            p.terminate()
        for p in (proxy, decoy, target):
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()

    good = [r for r in results if r.get("ok")]
    diverted = [r for r in good if r["diverted"]]
    total_fields = sum(r["fields_compared"] for r in diverted)
    total_contra = sum(r["contradictions"] for r in diverted)
    rate = (total_contra / total_fields) if total_fields else 0.0
    report = {
        "sessions": args.sessions,
        "sessions_ok": len(good),
        "sessions_diverted": len(diverted),
        "fields_compared": total_fields,
        "contradictions": total_contra,
        "contradiction_rate": round(rate, 6),
        "examples": next((r["examples"] for r in diverted if r["examples"]), []),
    }
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n" + "=" * 66)
    print("CROSS-BOUNDARY CONSISTENCY  (target pre-divert vs decoy post-divert)")
    print("=" * 66)
    print(f"  sessions diverted        : {len(diverted)}/{len(good)}")
    print(f"  fields compared          : {total_fields}")
    print(f"  cross-boundary contradictions : {total_contra}")
    print(f"  CONTRADICTION RATE       : {rate*100:.2f}%  "
          f"{'(consistent across the divert)' if rate == 0 else '(TELL: data changed under the attacker)'}")
    if report["examples"]:
        print("  examples:")
        for e in report["examples"]:
            print("    -", e)
    print(f"\nwritten -> {args.out}")
    if not diverted:
        raise SystemExit("no session diverted -- cannot measure the boundary; check the stack")


if __name__ == "__main__":
    main()
