"""
Does a *response-reading* vertical brute-forcer take the auth bait?

LIMITATIONS §5 records a genuine open question, and is careful about it: the
simulated `auth_bruteforce` attacker only ever POSTs credentials and never reads
a response body, so a response-side probe cannot reach it *by construction* — the
measured β_attack = 0.12 for the auth bait is an artefact of that attacker model,
not a property of the probe. Real tools (hydra, patator, Burp Intruder) DO parse
the response to tell a success from a failure, which is the very channel the bait
rides.

This script measures that, against the CURRENT FROZEN MODEL, without touching the
training corpus, the freeze, or any reported number. It brings up target + proxy
in b4_full mode and runs three auth attacker variants through it:

  * blind        — POSTs passwords, never reads the body (today's model)
  * reading-0.5  — reads the failure body; with prob 0.5 follows the leaked
                   `/auth/legacy/verify_*` hint (a mixed, realistic population)
  * reading-1.0  — always follows the hint (the fully curious end of the range)

It reports, per variant, how often B4 diverts the session and how often the bait
is bitten. If the reading variants divert far above the blind one, the honest
conclusion is that the auth bait works against a realistic brute-forcer and the
0.12 was measuring the wrong attacker — which is exactly what LIMITATIONS §5
predicts but does not yet measure.

    python -m tools.auth_probe_experiment --n 60

Nothing here is wired into the corpus or the frozen model; it is a measurement,
reported as one.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import time
from pathlib import Path

import httpx

from adf.config import system
from adf.schema import PROVENANCE_HEADER
from target_app.otp import otp_for

# the passwords a vertical brute force walks against one account; the real one is
# NOT among them, so the session is all failures -- the shape that used to look
# like a forgetful user and now must be caught, if at all, by the bait
_PASSWORDS = ["123456", "password", "admin", "letmein", "qwerty", "welcome",
              "monkey", "dragon", "football", "iloveyou", "abc123", "111111"]
_LEGACY = re.compile(r"/auth/legacy/verify_[a-z0-9]+", re.I)


def _uvicorn(app, port, host, env):
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", app, "--host", host, "--port", str(port),
         "--log-level", "warning"], env=env)


def _wait(url, tries=80):
    for _ in range(tries):
        try:
            httpx.get(url, timeout=1.0); return True
        except Exception:
            time.sleep(0.3)
    return False


def _run_session(proxy: str, mode: str, rng: random.Random) -> dict:
    """One vertical brute force against a.mirza. `mode` controls whether the
    attacker reads the response and follows the leaked legacy-auth hint."""
    sid = f"authprobe-{mode}-{rng.getrandbits(40):010x}"
    c = httpx.Client(base_url=proxy, follow_redirects=True, timeout=10.0,
                     headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
                              PROVENANCE_HEADER: sid})
    follow = {"blind": 0.0, "reading-0.5": 0.5, "reading-1.0": 1.0}[mode]
    bit = False
    try:
        for pw in rng.sample(_PASSWORDS, k=len(_PASSWORDS)):
            r = c.post("/login", data={"username": "a.mirza", "password": pw})
            if mode != "blind":
                # a reading attacker inspects the failure body for anything useful
                m = _LEGACY.search(r.text)
                if m and not bit and rng.random() < follow:
                    c.get(m.group(0))     # follow the deprecated-endpoint hint = the bite
                    bit = True
    finally:
        c.close()
    return {"session_id": sid, "bit": bit}


def _sessionise(proxy_log_glob: str, prov_prefix: str) -> dict:
    import glob
    from collections import defaultdict
    recs = []
    for f in glob.glob(proxy_log_glob):
        recs += [json.loads(l) for l in open(f, encoding="utf-8") if l.strip()]
    by = defaultdict(list)
    for r in recs:
        p = r["session"].get("provenance_id", "")
        if p.startswith(prov_prefix):
            by[p].append(r)
    out = {}
    for p, rs in by.items():
        rs.sort(key=lambda r: r["seq"])
        out[p] = {
            "diverted": any(r["decision"].get("action") == "divert" for r in rs),
            "baited": any(r["bait"].get("injected") for r in rs),
            "bit": any(r["bite"].get("occurred") for r in rs),
            "peak_p": max((r["scores"].get("p_attack", 0.0) for r in rs), default=0.0),
        }
    return out


def main() -> None:
    cfg = system()
    ap = argparse.ArgumentParser(description="Measure the auth bait against a response-reading brute force.")
    ap.add_argument("--n", type=int, default=60, help="sessions per variant")
    ap.add_argument("--seed", type=int, default=cfg.seed + 555)
    ap.add_argument("--host", default=cfg.get("network.bind_host", "127.0.0.1"))
    args = ap.parse_args()

    host = args.host
    tp, pp = cfg.get("network.target_port", 8001), cfg.get("network.proxy_port", 8000)
    env = dict(os.environ, ADF_MODE="b4_full")

    print("seeding target ...")
    subprocess.run([sys.executable, "-m", "target_app.seed"], env=env, check=False)
    target = _uvicorn("target_app.main:app", tp, host, env)
    _wait(f"http://{host}:{tp}/healthz")

    results = {}
    try:
        proxy = _uvicorn("adf.proxy:app", pp, host, env)
        if not _wait(f"http://{host}:{pp}/"):
            print("proxy did not come up"); return
        # clear proxy log so we measure only this experiment
        import glob
        for f in glob.glob(str(cfg.log_dir / "proxy.*.jsonl")):
            os.remove(f)

        for mode in ("blind", "reading-0.5", "reading-1.0"):
            rng = random.Random(f"{args.seed}:{mode}")
            for _ in range(args.n):
                _run_session(f"http://{host}:{pp}", mode, rng)
            time.sleep(0.5)
            sess = _sessionise(str(cfg.log_dir / "proxy.*.jsonl"), f"authprobe-{mode}-")
            n = len(sess) or 1
            results[mode] = {
                "n": len(sess),
                "divert_rate": round(sum(s["diverted"] for s in sess.values()) / n, 4),
                "bite_rate": round(sum(s["bit"] for s in sess.values()) / n, 4),
                "mean_peak_p": round(sum(s["peak_p"] for s in sess.values()) / n, 4),
            }
            print(f"  {mode:12}  n={results[mode]['n']:>3}  "
                  f"divert={results[mode]['divert_rate']:.3f}  "
                  f"bite={results[mode]['bite_rate']:.3f}  "
                  f"mean_peak_p={results[mode]['mean_peak_p']:.3f}")
        proxy.terminate()
    finally:
        target.terminate()

    out = Path("data/eval/auth_probe.json")
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nwritten -> {out}")
    b = results.get("blind", {}).get("divert_rate", 0.0)
    r = results.get("reading-1.0", {}).get("divert_rate", 0.0)
    print(f"\nblind divert {b:.3f}  vs  reading divert {r:.3f}  "
          f"(+{r - b:.3f} from reading the response)")


if __name__ == "__main__":
    main()
