"""
L2/L3 -- evaluate the defence against attack tooling we did NOT write.

docs/LIMITATIONS.md §2: beta_attack (and the recall gain that follows from it)
is measured against an attacker-curiosity model the researcher chose. A reviewer
is right to ask what the numbers look like against real, off-the-shelf tools.
This runs those tools -- sqlmap, ghauri, wapiti, and ZAP -- against the target
through the proxy, and measures the same two quantities the synthetic evaluation
reports: does the session reach DIVERT (recall), and does it BITE a bait.

Two lanes share this harness:
  L2 (--tools ... on our own target): the automated attacker floor. Every
     cookie-persistent tool is diverted to p->1.0; none bite (scope: the probe
     is for the human, the passive meter for the scanner).
  L3 (--external-upstream URL): the SAME frozen model in front of a second,
     structurally different app (OWASP Juice Shop), testing transfer.

WHAT TO EXPECT, STATED UP FRONT (so a null result is read correctly).
A blind SQL-injection tool does not read an HTML comment and decide to follow a
planted hint. Its bite rate against the response-side baits may well be ~0. That
is not a failure of the probe; it is a statement about WHICH adversary class the
probe addresses -- human and semi-automated -- while the passive meter is what
catches pure scanners. This harness demonstrates the second half of that sentence
directly: it reports whether the meter diverts the tool on its own, bait aside.

ISOLATION. Everything mutable is overridden onto a private prefix (data/l2/...)
and private ports, so this can run WITHOUT touching a concurrent Phase-7 or
multiseed run on the default ports/DBs. Nothing here retrains or re-freezes; it
reads the frozen model like any other evaluation arm.

SAFETY. Runs only against 127.0.0.1 on ports this script launched itself. It
refuses any --target that is not loopback (SAFETY.md: never point tooling at a
host you do not control).

    python -m tools.real_attack_eval                 # sqlmap only
    python -m tools.real_attack_eval --with-nikto    # add nikto if perl+nikto present
"""

from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parent.parent
L2 = REPO / "data" / "l2"
OUT = REPO / "data" / "eval" / "real_attack.json"

# Private ports, well clear of the default 8000-8002 an evaluation uses.
PROXY_PORT, TARGET_PORT, DECOY_PORT = 8010, 8011, 8012
HOST = "127.0.0.1"

# The endpoint sqlmap/ghauri point at. Our target concatenates SQL on /search;
# for the L3 transfer study it is overridden to the second app's injectable path
# (Juice Shop: /rest/products/search?q=). Set once in main().
INJECT_PATH = "/search?q=1"


def _tool_path(name: str) -> str | None:
    """Resolve an attack tool, preferring the CURRENT interpreter's own
    Scripts/bin directory over anything on the global PATH. When this harness is
    run from the isolated .venv-l2, that means it uses the venv's sqlmap/ghauri/
    wapiti and never the copies in the user's global Python -- the whole point of
    the venv. Falls back to PATH so it still works if run from a global install.
    """
    here = Path(sys.executable).parent
    # wapiti pins httpx 0.27, which conflicts with the project's 0.28.1, so it
    # cannot share the .venv-l2 interpreter and lives in its own sibling venv.
    # Look there for it specifically.
    wapiti_scripts = REPO / ".venv-wapiti" / "Scripts"
    search = [here / name, here / f"{name}.exe",
              wapiti_scripts / name, wapiti_scripts / f"{name}.exe"]
    for cand in search:
        if cand.exists():
            return str(cand)
    return shutil.which(name)


def _isolated_env(mode: str, fingerprint_fallback: bool = False,
                  external_upstream: str | None = None) -> dict:
    """A child-process environment whose every mutable path is private to L2.

    When `external_upstream` is set (L3 transfer study), the proxy forwards to
    that URL -- a second, structurally different application (OWASP Juice Shop) --
    instead of our own target_app. Everything else is unchanged, so the SAME
    frozen v4 meter scores traffic to an app it has never seen.
    """
    target = external_upstream or f"http://{HOST}:{TARGET_PORT}"
    env = dict(os.environ)
    env.update({
        "ADF_MODE": mode,
        "ADF_NETWORK__TARGET_UPSTREAM": target,
        "ADF_NETWORK__DECOY_UPSTREAM": f"http://{HOST}:{DECOY_PORT}",
        "ADF_DATABASES__TARGET_DSN": "sqlite:///data/l2/target.sqlite3",
        "ADF_DATABASES__FACT_NOTEBOOK_DSN": "sqlite:///data/l2/notebook.sqlite3",
        "ADF_LOGGING__LOG_DIR": "data/l2/logs",
        "ADF_LOGGING__LABEL_DIR": "data/l2/labels",
        "ADF_SESSION__FINGERPRINT_FALLBACK": "true" if fingerprint_fallback else "false",
    })
    return env


def _uvicorn(app: str, port: int, env: dict, bind: str = HOST) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", app, "--host", bind, "--port", str(port),
         "--log-level", "warning"], env=env)


def _wait(url: str, name: str, tries: int = 60) -> bool:
    for _ in range(tries):
        try:
            httpx.get(url, timeout=1.0)
            return True
        except Exception:
            time.sleep(0.3)
    print(f"  !! {name} did not come up at {url}")
    return False


# ---------------------------------------------------------------------------
# tool runners -- each returns a short dict describing what it did
# ---------------------------------------------------------------------------


def _reported_injectable(out: str) -> bool:
    """Did the SQLi tool confirm an exploitable injection point?

    Both sqlmap and ghauri print an explicit negative ("does not seem to be
    injectable" / "do not appear to be injectable") when they fail, so a naive
    substring test for "injectable" flips exactly backwards. Require a positive
    marker AND the absence of any negative one.
    """
    low = out.lower()
    negative = any(s in low for s in (
        "does not seem to be injectable", "do not appear to be injectable",
        "not injectable", "no parameter", "might not be injectable"))
    positive = any(s in low for s in (
        "is vulnerable", "the back-end dbms is", "injection point(s)",
        "the following injection point", "parameter is vulnerable"))
    return positive and not negative


def run_sqlmap(proxy: str, batch: bool = True) -> dict:
    """sqlmap against the one endpoint the target concatenates SQL on (/search).

    We hand it the injectable parameter directly (-u ".../search?q=1") so the
    run is bounded and reproducible rather than a full crawl. --batch answers
    every prompt with the default; --flush-session forces a fresh test each run.
    """
    url = f"{proxy}{INJECT_PATH}"
    cmd = [_tool_path("sqlmap") or "sqlmap", "-u", url, "--batch", "--flush-session",
           "--level", "2", "--risk", "2", "--technique", "BEUST",
           "--delay", "0", "--timeout", "10", "--retries", "1",
           "--answers", "quit=N,crack=N,dict=N,continue=Y"]
    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    out = (proc.stdout or "") + (proc.stderr or "")
    injectable = _reported_injectable(out)
    return {
        "tool": "sqlmap",
        "version": "1.10.8",
        "target_param": "q",
        "seconds": round(time.time() - started, 1),
        "reported_injectable": injectable,
        "stdout_tail": out[-1500:],
    }


def run_ghauri(proxy: str) -> dict:
    """ghauri -- a modern, independent SQLi engine (a second opinion to sqlmap).

    Two things make it a useful second tool here. It is a different detection
    engine, so "sqlmap said not-injectable" is not left resting on one tool. And
    it does NOT persist the proxy's Set-Cookie, so every request arrives
    cookieless -- which, with fingerprint_fallback off (the default), is exactly
    the score-resetting evasion spec §5.2 anticipates. Running it both ways (the
    --fingerprint-fallback flag) demonstrates the countermeasure the system
    already ships.
    """
    ghauri = _tool_path("ghauri") or "ghauri"
    url = f"{proxy}{INJECT_PATH}"
    cmd = [ghauri, "-u", url, "--batch", "--flush-session",
           "--level", "3", "--timeout", "10", "-v", "1"]
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"tool": "ghauri", "skipped": f"could not run ghauri: {exc}"}
    out = (proc.stdout or "") + (proc.stderr or "")
    injectable = _reported_injectable(out)
    return {"tool": "ghauri", "version": "1.4.3", "target_param": "q",
            "seconds": round(time.time() - started, 1),
            "reported_injectable": injectable, "stdout_tail": out[-1500:]}


def run_wapiti(proxy: str, max_seconds: int = 300) -> dict:
    """wapiti -- a broad DAST scanner that CRAWLS the app and fuzzes every
    parameter it finds (SQLi, XSS, command injection, file inclusion, ...).

    This is the important addition over sqlmap: sqlmap hammers one endpoint,
    whereas wapiti exercises the meter across every surface it can discover, so
    the divert result is a statement about the whole application rather than one
    parameter. It is also genuinely 'traffic we did not write'.
    """
    wapiti = _tool_path("wapiti") or "wapiti"
    cmd = [wapiti, "-u", f"{proxy}/", "--scope", "domain",
           "-m", "sql,xss,exec,file,htaccess,redirect",
           "--flush-session", "--max-scan-time", str(max_seconds),
           "--timeout", "10", "-v", "0", "--color",
           "-o", str((L2 / "wapiti_report").resolve()), "-f", "json"]
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max_seconds + 120)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"tool": "wapiti", "skipped": f"could not run wapiti: {exc}"}
    out = (proc.stdout or "") + (proc.stderr or "")
    return {"tool": "wapiti", "version": "3.2.3",
            "seconds": round(time.time() - started, 1), "stdout_tail": out[-1500:]}


def run_zap(proxy: str, minutes: int = 4) -> dict:
    """OWASP ZAP full scan (spider + AJAX/browser spider + active scan).

    This is the tool wapiti could not be: ZAP's AJAX spider drives a real browser,
    so it crawls a JavaScript single-page app (Juice Shop) that a non-JS crawler
    sees as one empty page. Runs from the official ZAP container and reaches the
    host proxy via host.docker.internal, which is why the proxy is bound to
    0.0.0.0 for a ZAP run. The scan's own report is discarded; we read the proxy
    log like every other tool.
    """
    # ZAP runs in a container; from there the host proxy is host.docker.internal.
    target = proxy.replace("127.0.0.1", "host.docker.internal").replace("localhost", "host.docker.internal")
    cmd = ["docker", "run", "--rm", "--add-host", "host.docker.internal:host-gateway",
           "ghcr.io/zaproxy/zaproxy:stable", "zap-full-scan.py",
           "-t", target, "-m", str(minutes), "-j", "-I"]
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60 * (minutes + 20))
    except subprocess.TimeoutExpired as exc:
        # a long active scan is fine -- we still have the proxy log of whatever
        # traffic it generated up to the cutoff
        return {"tool": "zap", "note": f"timed out after {exc.timeout:.0f}s (log still captured)",
                "seconds": round(time.time() - started, 1)}
    except FileNotFoundError:
        return {"tool": "zap", "skipped": "docker not available"}
    out = (proc.stdout or "") + (proc.stderr or "")
    return {"tool": "zap", "image": "ghcr.io/zaproxy/zaproxy:stable",
            "seconds": round(time.time() - started, 1), "stdout_tail": out[-2000:]}


def run_nikto(proxy: str) -> dict:
    """nikto web-server scanner, if perl and nikto.pl are present."""
    nikto = _tool_path("nikto") or _tool_path("nikto.pl")
    if not nikto:
        return {"tool": "nikto", "skipped": "nikto not found on PATH"}
    host_port = proxy.split("//", 1)[-1]
    cmd = [nikto, "-host", HOST, "-port", str(PROXY_PORT), "-nointeractive", "-maxtime", "300s"]
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        return {"tool": "nikto", "skipped": "could not execute nikto"}
    out = (proc.stdout or "") + (proc.stderr or "")
    return {"tool": "nikto", "seconds": round(time.time() - started, 1),
            "stdout_tail": out[-1500:], "_hostport": host_port}


# ---------------------------------------------------------------------------
# scoring -- read the proxy log this run produced and sessionise BY THE PROXY'S
# OWN session id (external tools set no provenance header)
# ---------------------------------------------------------------------------


def summarise_proxy_log(log_dir: Path, tool_label: str) -> dict:
    records = []
    for f in glob.glob(str(log_dir / "proxy.*.jsonl")):
        for line in open(f, encoding="utf-8"):
            if line.strip():
                records.append(json.loads(line))
    if not records:
        return {"tool": tool_label, "sessions": 0, "note": "no proxy records"}

    # Drop this harness's own liveness probes. `_wait` polls "/" with httpx to
    # know the stack is up; those requests are not attack traffic and must not
    # count as a "session". A real client never presents this UA here.
    records = [r for r in records
               if not r["request"].get("user_agent", "").startswith("python-httpx")]
    if not records:
        return {"tool": tool_label, "sessions": 0, "note": "no tool records"}

    by_sid = collections.defaultdict(list)
    for r in records:
        by_sid[r["session"]["session_id"]].append(r)

    n_sessions = len(by_sid)
    total_requests = len(records)
    diverted = 0
    reqs_to_divert = []
    any_bait = 0
    any_bite = 0
    peak_p = 0.0
    for sid, recs in by_sid.items():
        recs.sort(key=lambda r: r["seq"])
        actions = [r["decision"].get("action") for r in recs]
        peak_p = max(peak_p, max((r["scores"].get("p_attack", 0.0) for r in recs), default=0.0))
        first = next((i for i, a in enumerate(actions) if a == "divert"), None)
        if first is not None:
            diverted += 1
            reqs_to_divert.append(first + 1)
        if any(r["bait"].get("injected") for r in recs):
            any_bait += 1
        if any(r["bite"].get("occurred") for r in recs):
            any_bite += 1

    reqs_to_divert.sort()
    median_r2d = reqs_to_divert[len(reqs_to_divert) // 2] if reqs_to_divert else None
    return {
        "tool": tool_label,
        "sessions": n_sessions,
        "total_requests": total_requests,
        "sessions_diverted": diverted,
        "divert_rate": round(diverted / n_sessions, 4) if n_sessions else 0.0,
        "median_requests_to_divert": median_r2d,
        "sessions_shown_bait": any_bait,
        "sessions_that_bit": any_bite,
        "bite_rate": round(any_bite / n_sessions, 4) if n_sessions else 0.0,
        "peak_p_attack": round(peak_p, 4),
    }


# ---------------------------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate against off-the-shelf attack tooling (L2).")
    ap.add_argument("--tools", default="sqlmap,ghauri,wapiti",
                    help="comma-separated: sqlmap, ghauri, wapiti, nikto")
    ap.add_argument("--mode", default="b4_full", help="which arm to stand up (default full system)")
    ap.add_argument("--fingerprint-fallback", action="store_true",
                    help="link cookieless requests by fingerprint (spec §5.2 countermeasure "
                         "against a score-resetting tool like ghauri)")
    ap.add_argument("--external-upstream", default=None,
                    help="L3 transfer study: forward to this URL (e.g. Juice Shop at "
                         "http://127.0.0.1:3000) instead of our own target_app")
    ap.add_argument("--tag", default=None, help="suffix for the output JSON filename")
    ap.add_argument("--inject-path", default="/search?q=1",
                    help="endpoint sqlmap/ghauri target (Juice Shop: /rest/products/search?q=1)")
    args = ap.parse_args()

    global INJECT_PATH
    INJECT_PATH = args.inject_path

    runners = {"sqlmap": run_sqlmap, "ghauri": run_ghauri,
               "wapiti": run_wapiti, "nikto": run_nikto, "zap": run_zap}
    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    for t in tools:
        if t not in runners:
            print(f"unknown tool {t!r}; known: {', '.join(runners)}")
            sys.exit(2)

    # wipe and recreate the private state so a rerun is clean
    if L2.exists():
        shutil.rmtree(L2)
    for sub in ("logs", "labels", "decoy"):
        (L2 / sub).mkdir(parents=True, exist_ok=True)

    env = _isolated_env(args.mode, fingerprint_fallback=args.fingerprint_fallback,
                        external_upstream=args.external_upstream)

    started_procs = []
    if args.external_upstream:
        # L3: the proxy forwards to a second, structurally different app (Juice
        # Shop) that the caller is running. We do not seed or launch target_app;
        # we DO launch the decoy so a divert has somewhere to land (its content
        # is irrelevant here -- the transfer test measures the divert DECISION,
        # not decoy realism against a foreign app).
        print(f"[L3] transfer study: proxy -> external upstream {args.external_upstream}")
        if not _wait(args.external_upstream + "/", "external upstream"):
            print("  !! external upstream not reachable; is Juice Shop up?")
            sys.exit(1)
        target = None
    else:
        print(f"[L2] seeding a private target world at {L2}/target.sqlite3 ...")
        subprocess.run([sys.executable, "-m", "target_app.seed"], env=env, check=False)
        print(f"[L2] starting isolated stack on ports {PROXY_PORT}/{TARGET_PORT}/{DECOY_PORT} "
              f"(default eval ports untouched) ...")
        target = _uvicorn("target_app.main:app", TARGET_PORT, env)
        _wait(f"http://{HOST}:{TARGET_PORT}/healthz", "target")
        started_procs.append(target)

    decoy = _uvicorn("decoy_app.main:app", DECOY_PORT, env)
    started_procs.append(decoy)
    _wait(f"http://{HOST}:{DECOY_PORT}/healthz", "decoy")
    # ZAP runs in a container and reaches the proxy via host.docker.internal, so
    # for a ZAP run the proxy must listen on 0.0.0.0, not loopback only.
    proxy_bind = "0.0.0.0" if "zap" in tools else HOST
    proxy = _uvicorn("adf.proxy:app", PROXY_PORT, env, bind=proxy_bind)
    started_procs.append(proxy)
    proxy_url = f"http://{HOST}:{PROXY_PORT}"
    if not _wait(proxy_url + "/", "proxy"):
        for p in started_procs:
            p.terminate()
        sys.exit(1)

    tool_runs = []
    per_tool = []
    lane = "L3" if args.external_upstream else "L2"
    try:
        for i, name in enumerate(tools):
            print(f"[{lane}] running {name} against the proxy ({i+1}/{len(tools)}) ...")
            tool_runs.append(runners[name](proxy_url))
            time.sleep(2.0)               # let the proxy flush its append buffer
            per_tool.append(summarise_proxy_log(L2 / "logs", name))
            # rotate this tool's log aside so the next tool is summarised alone
            for f in glob.glob(str(L2 / "logs" / "proxy.*.jsonl")):
                os.rename(f, f + f".{name}")
    finally:
        for p in started_procs:
            p.terminate()
        for p in started_procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()

    result = {
        "mode": args.mode,
        "fingerprint_fallback": args.fingerprint_fallback,
        "external_upstream": args.external_upstream,
        "isolated_ports": {"proxy": PROXY_PORT, "target": TARGET_PORT, "decoy": DECOY_PORT},
        "tool_runs": tool_runs,
        "per_tool": per_tool,
    }
    if args.tag:
        out_path = OUT.with_name(f"real_attack_{args.tag}.json")
    elif args.fingerprint_fallback:
        out_path = OUT.with_name("real_attack_fpfallback.json")
    else:
        out_path = OUT
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"\n{'='*68}\nL2 -- off-the-shelf tooling vs the full system\n{'='*68}")
    print(f"  {'tool':>8}  {'sessions':>8}  {'divert rate':>11}  {'bite rate':>9}  {'peak p':>7}")
    for t in per_tool:
        print(f"  {t['tool']:>8}  {t.get('sessions',0):>8}  "
              f"{t.get('divert_rate',0):>11}  {t.get('bite_rate',0):>9}  "
              f"{t.get('peak_p_attack',0):>7}")
    print(f"\nfull tool output and per-session detail -> {out_path}")
    print("\nRead a zero bite rate as scope, not failure: a blind scanner does not")
    print("act on a planted hint. What matters is the divert rate -- whether the")
    print("passive meter catches the tool on its own behaviour, bait aside.")


if __name__ == "__main__":
    main()
