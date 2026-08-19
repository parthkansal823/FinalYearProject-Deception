"""Sweep OWASP CRS across every paranoia level, on the evaluation's own traffic.

The paper's B1 baseline is fifteen hand-written regexes. This measures the real
thing it stands in for, and measures it across the whole knob CRS actually
exposes, because quoting a WAF at one setting invites the obvious objection that
a different setting would have done better.

Two traps, both of which produce a confident and wrong answer:

  * The image has TWO paranoia variables. `PARANOIA` raises which rules are
    *evaluated*; `BLOCKING_PARANOIA` raises which are allowed to *block*, and it
    does not follow the first. Setting only `PARANOIA` leaves blocking pinned at
    level 1, so every level returns identical numbers and the sweep reports a
    flat curve that means nothing. Both are set here, and the guard below fails
    the run if the curve comes out flat anyway.
  * Replaying a defended arm's log would cut sessions short exactly where a
    defence acted, understating the WAF. Traffic comes from `b0_no_defence`
    draws on evaluation seeds, so it is byte-identical to what B1, B2 and B4
    saw and nothing truncates it.

Requests are replayed concurrently. A WAF reaches its verdict from one request
with no cross-request state, so order and concurrency cannot change a verdict it
actually returns. What concurrency does change is how many verdicts it returns at
all: pushed hard enough the container starts timing out, and a request that never
arrived is indistinguishable, in the accounting, from one the WAF allowed. A run
at 24 workers lost a quarter of its requests that way and reported a WAF far
weaker than it is. Hence the modest default, the retries, and the guard that
refuses to publish a level which still lost more than 1% of its requests.

    python -m tools.waf_sweep
"""
from __future__ import annotations

import argparse
import json
import math
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

from tools.waf_baseline import DROP, load_all, wilson

OUT = Path("data/eval/waf")
IMAGE = "owasp/modsecurity-crs:nginx"
NAME = "adf-crs"


def start(level: int, port: int, backend: int) -> None:
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)
    subprocess.run(
        ["docker", "run", "-d", "--name", NAME, "-p", f"{port}:8080",
         "-e", f"BACKEND=http://host.docker.internal:{backend}",
         "-e", "MODSEC_RULE_ENGINE=On",
         "-e", f"PARANOIA={level}",
         # Without this, rules above level 1 are evaluated but never block.
         "-e", f"BLOCKING_PARANOIA={level}",
         "--add-host=host.docker.internal:host-gateway", IMAGE],
        capture_output=True, check=True)


def wait_ready(url: str, tries: int = 40) -> None:
    for _ in range(tries):
        try:
            httpx.get(url + "/", timeout=3.0)
            return
        except httpx.HTTPError:
            time.sleep(2)
    raise SystemExit("the WAF never came up at " + url)


def replay(sessions: dict, url: str, workers: int) -> dict:
    """Which sessions does this WAF flag, and on which request?"""
    jobs = []
    for key, s in sessions.items():
        for k, q in enumerate(s["reqs"], 1):
            jobs.append((key, k, q))

    blocked: dict[tuple, int] = {}
    errors = 0

    with httpx.Client(timeout=25.0, follow_redirects=False,
                      limits=httpx.Limits(max_connections=workers * 2)) as client:
        def one(job):
            key, k, q = job
            target = url + q["path"] + (("?" + q["query"]) if q.get("query") else "")
            headers = {h: v for h, v in (q.get("headers") or {}).items()
                       if h.lower() not in DROP}
            body = q.get("body") or None
            # A request that never reached the WAF is not a request the WAF let
            # through, but the accounting below cannot tell the difference: both
            # end up as "no 403". Under load this quietly deflates the measured
            # recall -- a run at 24 workers lost a quarter of its requests to
            # timeouts and reported a WAF far weaker than it is. Retry before
            # giving up, and let the caller refuse to publish a run that still
            # lost a meaningful share.
            for attempt in range(3):
                try:
                    r = client.request(q["method"], target, headers=headers,
                                       content=body.encode() if body else None)
                    return (key, k, r.status_code)
                except httpx.HTTPError:
                    if attempt < 2:
                        time.sleep(0.2 * (attempt + 1))
            return (key, k, None)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for key, k, code in pool.map(one, jobs):
                if code is None:
                    errors += 1
                elif code == 403:
                    if key not in blocked or k < blocked[key]:
                        blocked[key] = k

    det = {"attack": 0, "benign": 0}
    tot = {"attack": 0, "benign": 0}
    first: list[int] = []
    for key, s in sessions.items():
        tot[s["label"]] += 1
        if key in blocked:
            det[s["label"]] += 1
            if s["label"] == "attack":
                first.append(blocked[key])
    first.sort()
    return {"attack_flagged": det["attack"], "attack_n": tot["attack"],
            "benign_flagged": det["benign"], "benign_n": tot["benign"],
            "requests": len(jobs), "requests_blocked": sum(
                1 for _ in blocked),  # sessions with >=1 block
            "median_req_to_block": first[len(first) // 2] if first else None,
            "errors": errors}


def main() -> None:
    ap = argparse.ArgumentParser(description="OWASP CRS paranoia sweep.")
    ap.add_argument("--levels", default="1,2,3,4",
                    help="CRS paranoia levels; 4 is the maximum the ruleset defines")
    ap.add_argument("--port", type=int, default=9761)
    ap.add_argument("--backend", type=int, default=9760)
    ap.add_argument("--runs", default="data/eval/waf/s*")
    ap.add_argument("--workers", type=int, default=6,
                    help="concurrent replay connections. A WAF is stateless per "
                         "request so concurrency cannot change a verdict, but it "
                         "can overwhelm the container and turn requests into "
                         "timeouts, which the accounting reads as 'not blocked'.")
    args = ap.parse_args()

    # Two sweeps share one container name and one port, restart it under each
    # other mid-level, and produce a curve that is not monotone in paranoia. That
    # happened; this is the guard.
    running = subprocess.run(["docker", "ps", "--filter", "name=" + NAME,
                              "--format", "{{.Names}}"],
                             capture_output=True, text=True).stdout.strip()
    if running:
        raise SystemExit(
            "a container named " + NAME + " is already running, which means "
            "another sweep is in progress. Two sweeps restart the WAF under each "
            "other between levels and neither result is usable. Wait for it, or "
            "`docker rm -f " + NAME + "` if it is a leftover.")

    sessions = load_all(args.runs)
    n_req = sum(len(s["reqs"]) for s in sessions.values())
    print("pooled %d sessions, %d requests" % (len(sessions), n_req))
    print()

    url = "http://127.0.0.1:%d" % args.port
    levels = [int(x) for x in args.levels.split(",")]
    results = {}

    for lv in levels:
        start(lv, args.port, args.backend)
        wait_ready(url)
        t0 = time.time()
        r = replay(sessions, url, args.workers)
        r["seconds"] = round(time.time() - t0, 1)
        loss = r["errors"] / r["requests"]
        if loss > 0.01:
            raise SystemExit(
                "PL%d lost %.1f%% of its requests to transport errors (%d of %d). "
                "Those are counted as 'the WAF did not block', so the recall this "
                "run would report is deflated by an unknown amount. Lower "
                "--workers and try again; a sequential run of this corpus loses "
                "about 0.1%%." % (lv, 100 * loss, r["errors"], r["requests"]))
        results[lv] = r
        print("PL%d  recall %.4f   benign FPR %.4f   (%.0fs)"
              % (lv, r["attack_flagged"] / r["attack_n"],
                 r["benign_flagged"] / r["benign_n"], r["seconds"]))

    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)

    # A flat curve is the signature of blocking still pinned at level 1. Fail
    # rather than publish four identical rows as though they were a measurement.
    if len(levels) > 1:
        flagged = {results[lv]["attack_flagged"] for lv in levels}
        if len(flagged) == 1:
            raise SystemExit(
                "every paranoia level flagged exactly %d attack sessions. That is "
                "the signature of BLOCKING_PARANOIA still pinned at 1, not of a "
                "ruleset that is indifferent to its own paranoia setting."
                % flagged.pop())

    print()
    print("OWASP ModSecurity CRS on the evaluation's own traffic")
    print("  PL   attack recall (95% CI)        benign FPR (95% CI)         median req")
    print("  " + "-" * 76)
    for lv in levels:
        r = results[lv]
        lo, hi = wilson(r["attack_flagged"], r["attack_n"])
        flo, fhi = wilson(r["benign_flagged"], r["benign_n"])
        print("  %d    %.4f [%.4f, %.4f]  %3d/%d     %.4f [%.4f, %.4f]  %3d/%d   %s"
              % (lv, r["attack_flagged"] / r["attack_n"], lo, hi,
                 r["attack_flagged"], r["attack_n"],
                 r["benign_flagged"] / r["benign_n"], flo, fhi,
                 r["benign_flagged"], r["benign_n"],
                 r["median_req_to_block"] if r["median_req_to_block"] else "-"))

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "crs_sweep.json").write_text(json.dumps(
        {"image": IMAGE, "sessions": len(sessions), "requests": n_req,
         "levels": {str(k): v for k, v in results.items()}}, indent=2),
        encoding="utf-8")
    print()
    print("wrote " + str(OUT / "crs_sweep.json"))


if __name__ == "__main__":
    main()
