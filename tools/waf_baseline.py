"""Replay the evaluation traffic through a real WAF, not one we wrote ourselves.

B1 in the paper is `adf/proxy/rules.py`: fifteen regexes "in the spirit of the
OWASP Core Rule Set", and the file says plainly that it is not a production WAF.
That is an honest thing to build and a weak thing to be measured against. A
reviewer is entitled to read a 0.408 baseline as a strawman we wrote and then
beat, and no amount of arguing in the text answers that.

So this measures the same traffic against **OWASP ModSecurity CRS**, which is the
thing the paper claims B1 stands in for -- the defence most sites actually run.

Two properties make the replay faithful rather than approximate:

  * A WAF is a stateless request matcher. It reaches its verdict from one
    request, so replaying a logged request produces the same verdict the WAF
    would have reached inline.
  * The traffic is read from a `b0_no_defence` draw, where nothing baits,
    scores or diverts. Every session runs to its natural end. Replaying a
    truncated log would cut short exactly the sessions a defence acted on and
    silently understate the WAF.

The draw uses an evaluation seed, so the traffic is byte-identical to what B1,
B2 and B4 saw.

Setup:

    docker run -d --name adf-crs -p 9761:8080 \\
        -e BACKEND=http://host.docker.internal:9760 \\
        -e MODSEC_RULE_ENGINE=On -e PARANOIA=1 \\
        --add-host=host.docker.internal:host-gateway \\
        owasp/modsecurity-crs:nginx

    python -m tools.waf_baseline
"""
from __future__ import annotations

import argparse
import glob
import json
import math
from pathlib import Path

import httpx

RUNS = "data/eval/waf/s*"
#: Hop-by-hop and length headers belong to the connection we are replaying over,
#: not to the request being judged. Forwarding them produces protocol errors that
#: look like WAF blocks.
DROP = {"connection", "content-length", "transfer-encoding", "keep-alive",
        "host", "upgrade", "proxy-connection", "te", "trailer"}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    ph = k / n
    d = 1 + z * z / n
    c = (ph + z * z / (2 * n)) / d
    h = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def load_all(pattern: str):
    """Pool every completed draw. One draw of 120 attack sessions gives an
    interval too wide to compare a WAF against anything."""
    sessions: dict[tuple[str, str], dict] = {}
    for d in sorted(glob.glob(pattern)):
        run = Path(d)
        if not (run / "sessions.jsonl").exists():
            print("  skipping " + run.name + ": draw did not complete")
            continue
        for key, val in load(run).items():
            sessions[(run.name, key)] = val
    if not sessions:
        raise SystemExit(
            "no completed b0 draw matching " + pattern + ". Generate one first "
            "-- see the module docstring. Replaying a defended arm's log would "
            "understate the WAF, because those sessions were cut short.")
    return sessions


def load(run: Path):
    logs = sorted(glob.glob(str(run / "logs" / "proxy.*.jsonl")))
    lab = run / "labels" / "eval_labels.jsonl"
    if not logs or not lab.exists():
        return {}
    truth = {}
    with lab.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            truth[r["session_id"]] = r["ground_truth"]

    sessions: dict[str, dict] = {}
    with open(logs[-1], encoding="utf-8") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("source") != "proxy":
                continue
            prov = r.get("session", {}).get("provenance_id", "")
            g = truth.get(prov)
            if g is None:
                continue
            sessions.setdefault(prov, {"label": g, "reqs": []})["reqs"].append(r["request"])
    return sessions


def main() -> None:
    ap = argparse.ArgumentParser(description="Replay traffic through OWASP CRS.")
    ap.add_argument("--waf", default="http://127.0.0.1:9761")
    ap.add_argument("--runs", default=RUNS)
    ap.add_argument("--tag", default="paranoia1",
                    help="names the result file, so a sweep does not "
                         "overwrite its own earlier levels")
    args = ap.parse_args()

    sessions = load_all(args.runs)
    n_req = sum(len(s["reqs"]) for s in sessions.values())
    print("sessions %d   requests %d" % (len(sessions), n_req))

    # Fail loudly if the WAF is not actually enforcing. A DetectionOnly engine
    # answers 200 to everything, which would report a recall of zero and look
    # exactly like a WAF that missed every attack.
    with httpx.Client(base_url=args.waf, timeout=15.0) as probe:
        canary = probe.get("/search", params={"q": "1' OR '1'='1"})
        if canary.status_code != 403:
            raise SystemExit(
                "the WAF answered %d to an unambiguous SQL injection. It is "
                "probably in DetectionOnly mode; a run against it would report "
                "zero recall and look like a WAF that simply missed everything."
                % canary.status_code)
    print("canary: unambiguous SQLi is blocked, the engine is enforcing")
    print()

    blocked_req = 0
    detected = {"attack": 0, "benign": 0}
    totals = {"attack": 0, "benign": 0}
    reqs_to_block: list[int] = []
    errors = 0

    with httpx.Client(timeout=20.0, follow_redirects=False) as client:
        for i, (key, s) in enumerate(sessions.items(), 1):
            totals[s["label"]] += 1
            hit = None
            for k, q in enumerate(s["reqs"], 1):
                url = args.waf + q["path"] + (("?" + q["query"]) if q.get("query") else "")
                headers = {h: v for h, v in (q.get("headers") or {}).items()
                           if h.lower() not in DROP}
                body = q.get("body") or None
                try:
                    resp = client.request(q["method"], url, headers=headers,
                                          content=body.encode() if body else None)
                except httpx.HTTPError:
                    errors += 1
                    continue
                if resp.status_code == 403:
                    blocked_req += 1
                    if hit is None:
                        hit = k
            if hit is not None:
                detected[s["label"]] += 1
                if s["label"] == "attack":
                    reqs_to_block.append(hit)
            if i % 50 == 0:
                print("  .. %d/%d sessions" % (i, len(sessions)))

    print()
    ar, br = detected["attack"], detected["benign"]
    at, bt = totals["attack"], totals["benign"]
    lo, hi = wilson(ar, at)
    flo, fhi = wilson(br, bt)
    print("OWASP ModSecurity CRS, replayed on identical traffic")
    print("  requests blocked        : %d / %d" % (blocked_req, n_req))
    print("  attack sessions flagged : %d / %d  recall %.4f [%.4f, %.4f]"
          % (ar, at, ar / at, lo, hi))
    print("  benign sessions flagged : %d / %d  FPR    %.4f [%.4f, %.4f]"
          % (br, bt, br / bt, flo, fhi))
    if reqs_to_block:
        reqs_to_block.sort()
        print("  requests until first block (attack): median %d, p90 %d"
              % (reqs_to_block[len(reqs_to_block) // 2],
                 reqs_to_block[int(0.9 * (len(reqs_to_block) - 1))]))
    if errors:
        print("  transport errors        : %d (excluded, not counted as passes)"
              % errors)

    out = Path("data/eval/waf") / ("crs_" + args.tag + ".json")
    out.write_text(json.dumps({
        "waf": "owasp/modsecurity-crs:nginx", "tag": args.tag,
        "sessions": len(sessions), "requests": n_req,
        "requests_blocked": blocked_req,
        "attack": {"flagged": ar, "n": at, "recall": ar / at,
                   "ci": [lo, hi]},
        "benign": {"flagged": br, "n": bt, "fpr": br / bt, "ci": [flo, fhi]},
        "errors": errors,
    }, indent=2), encoding="utf-8")
    print()
    print("wrote " + str(out))


if __name__ == "__main__":
    main()
