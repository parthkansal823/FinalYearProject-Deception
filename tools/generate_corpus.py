"""
One-command, reproducible corpus generation (spec §20 "reproducible setup",
§7.3 "labelled at the point of generation").

Running the generators by hand against a long-lived server is how a corpus
gets contaminated: any stray request to the same port -- a health check, a
manual `curl`, a debugging poke -- lands in the same append-only log with no
label, and then the corpus no longer consists solely of intentional, labelled
traffic. This orchestrator removes that failure mode by owning the whole
lifecycle:

    wipe logs+labels  ->  seed a fresh DB  ->  start a private server
      ->  run every generator against it  ->  stop the server
      ->  assemble and verify the corpus

so the only traffic in the log is what the generators put there. Because the
server is torn down at the end, nothing can append to the corpus afterwards
either.

Everything is seeded (NFR-08): the same --seed reproduces the same corpus.

  *** Binds to localhost only. The target app is deliberately weak (SAFETY.md). ***
"""

from __future__ import annotations

import argparse
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

from adf.config import system

REPO_ROOT = Path(__file__).resolve().parent.parent


def _free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) != 0


def _wait_healthy(base_url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"{base_url}/healthz", timeout=1.0).status_code == 200:
                return
        except Exception:
            time.sleep(0.3)
    raise SystemExit(f"target app did not become healthy at {base_url}")


def _wipe(cfg) -> None:
    for directory in (cfg.log_dir, cfg.label_dir):
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True, exist_ok=True)


def main() -> None:
    cfg = system()
    host = cfg.get("network.bind_host", "127.0.0.1")
    port = int(cfg.get("network.target_port", 8001))
    base_url = f"http://{host}:{port}"

    ap = argparse.ArgumentParser(description="Generate a clean, labelled corpus end to end.")
    ap.add_argument("--benign", type=int, default=100, help="simulated human sessions")
    ap.add_argument("--agents", type=int, default=30, help="benign automated sessions")
    ap.add_argument("--attacks", type=int, default=48, help="attack round-1 sessions")
    ap.add_argument("--seed", type=int, default=cfg.seed)
    ap.add_argument("--no-dwell", action="store_true",
                    help="skip pacing -- FAST but destroys timing features; smoke tests only")
    ap.add_argument("--keep-server", action="store_true",
                    help="assume a server is already running; do not start or stop one")
    args = ap.parse_args()

    if args.no_dwell:
        print("!! --no-dwell: timing features will be unrealistic; do NOT train on this corpus\n")

    print(f"[1/5] wiping {cfg.log_dir} and {cfg.label_dir}", flush=True)
    _wipe(cfg)

    print("[2/5] seeding a fresh target database", flush=True)
    subprocess.run([sys.executable, "-m", "target_app.seed"], check=True, cwd=REPO_ROOT)

    server: subprocess.Popen | None = None
    if not args.keep_server:
        if not _free(host, port):
            raise SystemExit(
                f"port {port} is already in use. Stop the existing server, or pass "
                "--keep-server to reuse it (only safe if nothing else talks to it)."
            )
        print(f"[3/5] starting a private target app on {base_url}", flush=True)
        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "target_app.main:app",
             "--host", host, "--port", str(port), "--log-level", "warning"],
            cwd=REPO_ROOT,
        )
    else:
        print(f"[3/5] reusing the server already at {base_url}", flush=True)

    try:
        _wait_healthy(base_url)

        dwell = ["--no-dwell"] if args.no_dwell else []
        steps = [
            ("benign humans", ["-m", "tools.benign_traffic",
                               "--sessions", str(args.benign), "--seed", str(args.seed)]),
            ("benign agents", ["-m", "tools.benign_agents",
                               "--sessions", str(args.agents), "--seed", str(args.seed + 1)]),
            ("attack round 1", ["-m", "tools.attack_traffic",
                                "--sessions", str(args.attacks), "--seed", str(args.seed + 2)]),
        ]
        for i, (name, cmd) in enumerate(steps, start=1):
            print(f"[4/5] ({i}/{len(steps)}) generating {name}", flush=True)
            subprocess.run([sys.executable, *cmd, "--base-url", base_url, *dwell],
                           check=True, cwd=REPO_ROOT)
    finally:
        if server is not None:
            print("[5/5] stopping the private server", flush=True)
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()

    print("\nassembling and verifying the corpus ...")
    result = subprocess.run([sys.executable, "-m", "tools.corpus_report"], cwd=REPO_ROOT)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
