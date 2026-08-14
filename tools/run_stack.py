"""
Bring up the whole system with one command (spec §13 Phase 6, NFR-12).

Starts the target application, the decoy, and the reverse proxy, wired together,
on localhost only (NFR-14). This is the integrated system a client talks to
through the proxy port; the target and decoy are never addressed directly in
normal use.

    python -m tools.run_stack                 # b4_full (the full system)
    python -m tools.run_stack --mode b2_passive   # a baseline
    python -m tools.run_stack --check         # verify the frozen model, then exit

Ctrl-C stops all three.
"""

from __future__ import annotations

import argparse
import signal
import subprocess
import sys
import time

import httpx

from adf.config import system


def _wait(url: str, name: str, tries: int = 60) -> bool:
    for _ in range(tries):
        try:
            httpx.get(url, timeout=1.0)
            return True
        except Exception:
            time.sleep(0.3)
    print(f"  !! {name} did not come up at {url}")
    return False


def main() -> None:
    cfg = system()
    ap = argparse.ArgumentParser(description="Run the full ADF stack (spec NFR-12).")
    ap.add_argument("--mode", default=cfg.mode,
                    help="b0_no_defence | b1_rules | b2_passive | b3_static | b4_full")
    ap.add_argument("--host", default=cfg.get("network.bind_host", "127.0.0.1"))
    ap.add_argument("--check", action="store_true", help="verify the frozen model and exit")
    args = ap.parse_args()

    if args.check:
        from adf.freeze import verify, load_manifest
        ok, reasons = verify()
        m = load_manifest()
        if ok and m:
            print(f"frozen model OK ({m['frozen_on']}, seed {m['seed']}).")
        else:
            print("frozen-model check FAILED:")
            for r in reasons:
                print(f"  - {r}")
        raise SystemExit(0 if ok else 1)

    host = args.host
    tp = cfg.get("network.target_port", 8001)
    dp = cfg.get("network.decoy_port", 8002)
    pp = cfg.get("network.proxy_port", 8000)

    import os
    env = dict(os.environ, ADF_MODE=args.mode)

    def uvicorn(app_path: str, port: int):
        return subprocess.Popen(
            [sys.executable, "-m", "uvicorn", app_path, "--host", host, "--port", str(port),
             "--log-level", "warning"], env=env)

    print(f"starting the ADF stack in mode {args.mode} (localhost only) ...")
    # seed the target world so a fresh run has data
    subprocess.run([sys.executable, "-m", "target_app.seed"], env=env, check=False)

    procs = []
    try:
        procs.append(uvicorn("target_app.main:app", tp))
        procs.append(uvicorn("decoy_app.main:app", dp))
        _wait(f"http://{host}:{tp}/healthz", "target")
        _wait(f"http://{host}:{dp}/healthz", "decoy")
        procs.append(uvicorn("adf.proxy:app", pp))
        _wait(f"http://{host}:{pp}/", "proxy")

        print(f"\n  proxy  : http://{host}:{pp}   <- send all client traffic here")
        print(f"  target : http://{host}:{tp}   (behind the proxy)")
        print(f"  decoy  : http://{host}:{dp}   (behind the proxy)")
        print("\nfull system is up. Ctrl-C to stop.")
        signal.pause() if hasattr(signal, "pause") else _idle()
    except KeyboardInterrupt:
        pass
    finally:
        print("\nstopping the stack ...")
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


def _idle():
    # Windows has no signal.pause()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
