"""
Certify every bait against real benign responses from the target app
(spec §6.7, §13 Phase 4).

The invisibility gate is only as trustworthy as the responses it tests against.
A synthetic corpus could miss the case that matters most: the responses a
BENIGN user actually receives, including the awkward ones. The apostrophe
searcher (Maeve O'Connell) triggers a genuine SQL error, and B-SQL-1 fires on
exactly that error -- so if that page is not in the corpus, the gate never
proves the bait is invisible where it is most likely to meet an innocent user.

This tool drives the target app as a benign user, collects the real responses
across every surface, and runs the gate over them. Certificates are written to
config/bait_certificates.json; the bait engine refuses to serve any bait that
is not certified there (spec §6.6 require_invisibility_certificate).

Run against a live target app:  python -m tools.certify_baits
"""

from __future__ import annotations

import argparse

import httpx

from adf.bait import BaitedResponse
from adf.bait.gate import certify_all, CERTIFICATE_PATH
from adf.config import system
from target_app.otp import otp_for


def collect_benign_responses(base_url: str) -> list[BaitedResponse]:
    """Every distinct kind of response a benign user provokes -- including the
    hard negatives that look like attacks but are not."""
    responses: list[BaitedResponse] = []
    c = httpx.Client(base_url=base_url, follow_redirects=True, timeout=10.0,
                     headers={"User-Agent": "Mozilla/5.0 (certify)"})

    def grab(method: str, path: str, **kw) -> None:
        r = c.request(method, path, **kw)
        responses.append(BaitedResponse(
            body=r.text,
            headers={k: v for k, v in r.headers.items()},
            content_type=r.headers.get("content-type", ""),
            status=r.status_code,
        ))

    # public + auth surfaces
    grab("GET", "/")
    grab("GET", "/login")
    grab("POST", "/login", data={"username": "a.mirza", "password": "wrong"})   # login error page
    c.post("/login", data={"username": "a.mirza", "password": "Summer2024!"})
    grab("GET", "/otp")
    grab("POST", "/otp", data={"code": "000000"})                               # otp error page
    c.post("/otp", data={"code": otp_for(1)})

    # authenticated surfaces
    grab("GET", "/dashboard")
    grab("GET", "/directory")
    grab("GET", "/profile/7")
    grab("GET", "/records/10")
    grab("GET", "/search", params={"q": "maintenance"})                         # normal search
    # THE HARD NEGATIVE: a real name with an apostrophe -> genuine SQL error,
    # the same page B-SQL-1 fires on.
    grab("GET", "/search", params={"q": "O'Connell"})
    # JSON API surfaces (where json_field baits inject)
    grab("GET", "/api/profile/9")
    grab("GET", "/api/records/5")

    c.close()
    return responses


def collect_corpus_responses(base_url: str, *, limit: int = 4000) -> list[BaitedResponse]:
    """Replay the REAL benign corpus against the target and collect responses.

    Certifying against a dozen hand-picked responses is weaker than certifying
    against the traffic benign users actually produced. The corpus records every
    GET (path + query) benign sessions made -- every search term, every profile
    and record id, the apostrophe-search errors, the forgetful-login pages -- so
    replaying them gives the true distribution of benign responses the bait must
    stay invisible in. (POST bodies are not logged, so logins are re-done fresh;
    static assets carry no bait and are skipped.)
    """
    import glob as _glob
    from adf.dataset import build

    cfg = system()
    corpus, _ = build(sorted(_glob.glob(str(cfg.log_dir / "*.jsonl"))),
                      sorted(_glob.glob(str(cfg.label_dir / "*.jsonl"))), strict=False)
    benign = [r for r in corpus if r.labels.ground_truth == "benign"]

    # unique GETs a benign user made, excluding static assets and health
    seen: set[tuple[str, str]] = set()
    requests: list[tuple[str, dict]] = []
    for r in benign:
        if r.request.method != "GET":
            continue
        path = r.request.path
        if path.startswith("/static/") or path in ("/healthz",):
            continue
        key = (path, r.request.query)
        if key in seen:
            continue
        seen.add(key)
        requests.append((path, {k: v[0] for k, v in (r.request.query_params or {}).items() if v}))
        if len(requests) >= limit:
            break

    # an authenticated client, so gated pages return real content not a redirect
    c = httpx.Client(base_url=base_url, follow_redirects=True, timeout=10.0,
                     headers={"User-Agent": "Mozilla/5.0 (certify-corpus)"})
    c.post("/login", data={"username": "a.mirza", "password": "Summer2024!"})
    c.post("/otp", data={"code": otp_for(1)})

    responses: list[BaitedResponse] = []
    for path, params in requests:
        try:
            r = c.get(path, params=params)
        except httpx.HTTPError:
            continue
        responses.append(BaitedResponse(body=r.text, headers=dict(r.headers),
                                        content_type=r.headers.get("content-type", ""),
                                        status=r.status_code))
    c.close()
    return responses


def main() -> None:
    cfg = system()
    ap = argparse.ArgumentParser(description="Certify baits against real benign responses (spec §6.7).")
    ap.add_argument("--base-url",
                    default=f"http://{cfg.get('network.bind_host', '127.0.0.1')}:{cfg.get('network.target_port', 8001)}")
    ap.add_argument("--seed", type=int, default=cfg.seed)
    ap.add_argument("--curated-only", action="store_true",
                    help="certify only against the small curated set, not the full corpus")
    args = ap.parse_args()

    print(f"collecting benign responses from {args.base_url} ...")
    corpus = collect_benign_responses(args.base_url)          # curated hard-negatives
    if not args.curated_only:
        replayed = collect_corpus_responses(args.base_url)    # the FULL benign corpus
        corpus += replayed
        print(f"  + {len(replayed)} responses replayed from the benign corpus")
    print(f"  {len(corpus)} responses total "
          f"({sum(1 for r in corpus if 'json' in r.content_type.lower())} JSON, "
          f"{sum(1 for r in corpus if 'html' in r.content_type.lower())} HTML)")

    print("\nrunning the invisibility gate over every bait ...\n")
    results = certify_all(corpus, seed=args.seed)

    passed = 0
    for bait_id, result in results.items():
        mark = "PASS" if result.passed else "FAIL"
        print(f"  [{mark}] {bait_id:9} injected into {result.injected_responses}/{result.tested_responses} "
              f"responses, +{result.median_overhead_ms:.3f}ms median")
        if not result.passed:
            for f in result.failures:
                print(f"           - {f}")
        else:
            passed += 1

    print(f"\n{passed}/{len(results)} baits certified -> {CERTIFICATE_PATH}")
    if passed == len(results):
        print("Phase 4 invisibility requirement MET: every bait has a passing certificate.")
    else:
        print("Some baits FAILED the gate. Per spec §6.7 they are DELETED, not repaired.")


if __name__ == "__main__":
    main()
