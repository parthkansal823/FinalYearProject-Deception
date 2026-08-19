"""Wait for the two long runs, then produce every report that depends on them.

Left to itself the machine would finish the evaluation at two in the morning and
then sit idle until someone came back to type four commands. This waits for the
sharded evaluation and the ablation to exit, then runs the reports in dependency
order.

Every stage is independent: a failure is recorded and the rest still run, because
a WAF replay that cannot reach its container is no reason to skip the paired
comparison. Nothing here edits a document -- the numbers land in logs for a human
to read against the prose in the morning.

    python -m tools.overnight_finish
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

OUT = Path("data/eval/overnight")


def still_running(pattern: str) -> bool:
    r = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "(Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | "
         "Where-Object { $_.CommandLine -match '" + pattern + "' }).Count"],
        capture_output=True, text=True)
    try:
        return int(r.stdout.strip() or 0) > 0
    except ValueError:
        return False


def wait_for(patterns: list[str], poll: int = 60) -> None:
    t0 = time.time()
    while True:
        alive = [p for p in patterns if still_running(p)]
        if not alive:
            print("  both runs finished after %.0f min" % ((time.time() - t0) / 60),
                  flush=True)
            return
        print("  [%5.0f min] still running: %s" % ((time.time() - t0) / 60,
                                                   ", ".join(alive)), flush=True)
        time.sleep(poll)


def stage(name: str, cmd: list[str], log: Path) -> bool:
    print("\n" + "=" * 66)
    print(name)
    print("=" * 66, flush=True)
    log.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    with log.open("w", encoding="utf-8") as fh:
        rc = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT).returncode
    print("  exit %d after %.0f min  -> %s" % (rc, (time.time() - t0) / 60, log),
          flush=True)
    return rc == 0


def main() -> None:
    ap = argparse.ArgumentParser(description="Post-run reporting chain.")
    ap.add_argument("--skip-wait", action="store_true")
    args = ap.parse_args()

    if not args.skip_wait:
        print("waiting for sharded_eval and parallel_ablation ...", flush=True)
        wait_for(["sharded_eval", "parallel_ablation"])

    OUT.mkdir(parents=True, exist_ok=True)
    py = sys.executable
    failed = []

    # The WAF replay refuses to start beside another sweep, so clear any
    # container left behind by an interrupted run before asking.
    subprocess.run(["docker", "rm", "-f", "adf-crs"], capture_output=True)

    stages = [
        ("1/5  OWASP CRS paranoia sweep",
         [py, "-m", "tools.waf_sweep", "--runs", "data/eval/waf_v2/s*"],
         OUT / "crs_sweep.log"),
        ("2/5  derived vs hand-set vs calibrated",
         [py, "-m", "tools.calibration_report",
          "--fixed", "data/eval/fixed_threshold_v2",
          "--derived", "data/eval/curious_v2/sessions.jsonl"],
         OUT / "calibration_report.log"),
        ("3/5  statistics over the new evaluation",
         [py, "-m", "tools.stats_report",
          "--in", "data/eval/curious_v2/sessions.jsonl"],
         OUT / "stats_report.log"),
        ("4/5  what the documentation now disagrees with",
         [py, "-m", "tools.check_doc_numbers",
          "--dump", "data/eval/curious_v2/sessions.jsonl"],
         OUT / "doc_check.log"),
        ("5/6  figures from the new report",
         [py, "-m", "tools.make_figures"],
         OUT / "figures.log"),
        # Section 9.6 calls this the paper's own unfinished measurement: "a
        # weak-agent lower bound ... the honest way to finish it is a sweep
        # across stronger models". All three models are now present locally, so
        # the gap can be closed rather than caveated. It runs last because
        # language-model inference on CPU would starve the evaluation.
        ("6/6  agentic attacker capability sweep (1b / 3b / 7b)",
         [py, "-m", "tools.llm_agent_sweep",
          "--models", "llama3.2:1b,llama3.2:3b,qwen2.5:7b",
          "--n", "20", "--max-steps", "12", "--port-base", "9800"],
         OUT / "llm_agent_sweep.log"),
    ]
    for name, cmd, log in stages:
        if not stage(name, cmd, log):
            failed.append(name)

    print("\n" + "=" * 66)
    if failed:
        print("%d stage(s) failed:" % len(failed))
        for f in failed:
            print("  " + f)
        print("\nRead the logs under " + str(OUT) + " before believing anything.")
        print("A failed stage leaves the PREVIOUS run's output in place, which")
        print("looks completely normal.")
    else:
        print("every stage completed. Logs under " + str(OUT))
    print()
    print("The documentation still quotes the pre-browser-driven numbers on")
    print("purpose -- docs/CALIBRATION.md carries a supersession banner and")
    print("09-ablations.md carries pending-refresh comments. Stage 4's log lists")
    print("exactly which figures now need changing.")


if __name__ == "__main__":
    main()
