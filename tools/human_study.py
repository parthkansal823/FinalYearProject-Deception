"""
Human deception study — facilitator tooling (spec §10.4, LIMITATIONS §7).

The project measures whether a decoy is convincing with a consistency fuzzer and
the researcher's own judgement. That is a self-assessment, and it is listed as a
limitation because it is one. This closes it with the only thing that can: other
people.

WHAT IS MEASURED, AND WHY IT NEEDS A CONTROL
--------------------------------------------
The question is "does a person exploring the decoy work out that it is fake?"
Asking only decoy participants cannot answer it: some people say "this feels
fake" about *any* unfamiliar test system, so a raw suspicion count has no
baseline. Each participant is therefore assigned **blind and at random** to

    REAL   -> the genuine target application
    DECOY  -> the state-consistent fake

and both are asked the same questions. The interesting number is the *difference*
in suspicion between the arms; if the decoy works, it is small.

The facilitator knows the arm (they start it); the participant never does.

USAGE — three commands, in order
--------------------------------
    python -m tools.human_study assign  P01      # draw the arm, print the brief
    python -m tools.human_study serve   P01      # start that arm on :8080
    python -m tools.human_study record  P01      # type in the answers

    python -m tools.human_study report          # results, once everyone is done

Assignment is deterministic from the participant id and the study seed, so it is
reproducible and cannot be quietly re-drawn if a facilitator dislikes the result.

Full step-by-step instructions, including exactly what to say: docs/HUMAN_STUDY.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

STUDY_SEED = "adf-human-study-2026"
RESULTS = Path("data/eval/human_study.jsonl")
PORT = 8080

BRIEF = """
================ READ THIS OUT TO THE PARTICIPANT ================

  You are helping test a company intranet used for a security study.

  You have a working staff login:

        username:  a.mirza
        password:  Summer2024!

  If it asks for a 6-digit code, the facilitator will read it to you.

  Explore for about 10 minutes. Look around, open pages, try things,
  poke at anything that looks interesting. There is no task to finish
  and nothing you can break.

  Afterwards I will ask you a few questions about the experience.

  Please do not discuss this with the other participants until we are
  all finished.

==================================================================
  Do NOT tell them the study is about fake environments.
  Do NOT tell them which system they are on. You know; they must not.
==================================================================
"""

QUESTIONS = [
    ("q1_real", "1. Do you believe this was a REAL company system, or a MOCK-UP "
                "made for testing?  [real / mock / unsure]"),
    ("q2_confidence", "2. How confident are you in that answer, 1 (guessing) to 5 (certain)?"),
    ("q3_minutes", "3. If you suspected anything at any point, how many MINUTES in was that? "
                   "(blank / 0 if never)"),
    ("q4_why", "4. What, specifically, made you think that? (their words, verbatim)"),
    ("q5_odd", "5. Did anything look inconsistent or wrong — a name, a number, a page "
               "that disagreed with another? (their words)"),
]


def arm_for(pid: str) -> str:
    """Blind, deterministic, BLOCK-randomised assignment from the participant id.

    Block randomisation, not independent coin flips. With eight participants a
    fair coin can easily deal 6/2, and a two-person control arm cannot establish
    the baseline the study exists to measure. Pairing consecutive participants
    and randomising the order *within* each pair keeps the arms equal to within
    one person at every point, while leaving which-arm-first unpredictable.

    Deterministic in the participant id, so an assignment cannot quietly be
    re-drawn because a facilitator dislikes it.
    """
    digits = "".join(c for c in pid if c.isdigit())
    if not digits:                     # non-numeric id: fall back to a plain draw
        h = hashlib.sha256(f"{STUDY_SEED}:{pid}".encode()).hexdigest()
        return "decoy" if int(h[:8], 16) % 2 else "real"
    n = int(digits)
    block, first_of_pair = (n - 1) // 2, (n - 1) % 2 == 0
    h = hashlib.sha256(f"{STUDY_SEED}:block{block}".encode()).hexdigest()
    decoy_first = int(h[:8], 16) % 2 == 0
    return "decoy" if (first_of_pair == decoy_first) else "real"


def _load() -> list[dict]:
    if not RESULTS.exists():
        return []
    return [json.loads(l) for l in open(RESULTS, encoding="utf-8") if l.strip()]


def cmd_assign(pid: str) -> None:
    arm = arm_for(pid)
    print(f"\nparticipant : {pid}")
    print(f"ARM         : {arm.upper()}   <-- facilitator only, never say this aloud")
    print(BRIEF)
    print(f"next:  python -m tools.human_study serve {pid}\n")


def cmd_serve(pid: str) -> None:
    arm = arm_for(pid)
    app = "decoy_app.main:app" if arm == "decoy" else "target_app.main:app"
    env = dict(os.environ)
    print(f"\nparticipant {pid}: serving the {arm.upper()} app on http://127.0.0.1:{PORT}")
    print("give the participant that URL. Ctrl+C here when their 10 minutes are up.\n")
    if arm == "real":
        subprocess.run([sys.executable, "-m", "target_app.seed"], env=env, check=False)
    try:
        subprocess.run([sys.executable, "-m", "uvicorn", app,
                        "--host", "127.0.0.1", "--port", str(PORT),
                        "--log-level", "warning"], env=env, check=False)
    except KeyboardInterrupt:
        pass
    print(f"\nstopped. next:  python -m tools.human_study record {pid}\n")


def cmd_record(pid: str) -> None:
    arm = arm_for(pid)
    print(f"\nrecording participant {pid}  (arm: {arm})")
    print("ask each question as written; type their answer and press Enter.\n")
    row = {"participant": pid, "arm": arm, "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}
    for key, prompt in QUESTIONS:
        row[key] = input(f"  {prompt}\n     > ").strip()
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    print(f"\nsaved -> {RESULTS}\n")


def cmd_report() -> None:
    rows = _load()
    if not rows:
        print(f"no results yet at {RESULTS}")
        return
    print("=" * 66)
    print(f"HUMAN DECEPTION STUDY — {len(rows)} participants")
    print("=" * 66)
    for arm in ("real", "decoy"):
        g = [r for r in rows if r["arm"] == arm]
        if not g:
            print(f"\n{arm.upper():6}: no participants yet")
            continue
        said_mock = sum(1 for r in g if r.get("q1_real", "").lower().startswith("mock"))
        unsure = sum(1 for r in g if r.get("q1_real", "").lower().startswith("unsure"))
        mins = [float(r["q3_minutes"]) for r in g
                if str(r.get("q3_minutes", "")).replace(".", "", 1).isdigit()
                and float(r["q3_minutes"]) > 0]
        print(f"\n{arm.upper():6}  n={len(g)}")
        print(f"   said 'mock-up'      : {said_mock}/{len(g)}")
        print(f"   said 'unsure'       : {unsure}/{len(g)}")
        print(f"   suspected at (min)  : {sorted(mins) if mins else 'nobody suspected'}")
    real = [r for r in rows if r["arm"] == "real"]
    decoy = [r for r in rows if r["arm"] == "decoy"]
    if real and decoy:
        rm = sum(1 for r in real if r.get("q1_real", "").lower().startswith("mock"))
        dm = sum(1 for r in decoy if r.get("q1_real", "").lower().startswith("mock"))
        print("\n" + "-" * 66)
        print(f"  DECOY minus REAL suspicion rate: "
              f"{dm}/{len(decoy)} - {rm}/{len(real)} = "
              f"{dm/len(decoy) - rm/len(real):+.2f}")
        print("  Near zero = the decoy is no more suspicious than the real system,")
        print("  which is the claim. A large positive number = it gives itself away.")
        try:
            from scipy import stats
            p = stats.fisher_exact([[dm, len(decoy) - dm], [rm, len(real) - rm]])[1]
            print(f"  Fisher exact p = {p:.4f}"
                  f"{'  (difference is significant)' if p < 0.05 else '  (no significant difference)'}")
        except Exception:
            pass
    print("\nverbatim answers:")
    for r in rows:
        why = (r.get("q4_why") or "").strip()
        odd = (r.get("q5_odd") or "").strip()
        print(f"  [{r['arm']:5}] {r['participant']}: {r.get('q1_real','?')} "
              f"(conf {r.get('q2_confidence','?')})")
        if why:
            print(f"           why : {why}")
        if odd:
            print(f"           odd : {odd}")
    print("\nReport the sample size plainly in the paper; n is small by design "
          "(spec §10.4) and that is a stated limitation, not a hidden one.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Human deception study facilitator tool.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("assign", "serve", "record"):
        s = sub.add_parser(name)
        s.add_argument("participant", help="participant id, e.g. P01")
    sub.add_parser("report")
    args = ap.parse_args()
    if args.cmd == "assign":
        cmd_assign(args.participant)
    elif args.cmd == "serve":
        cmd_serve(args.participant)
    elif args.cmd == "record":
        cmd_record(args.participant)
    else:
        cmd_report()


if __name__ == "__main__":
    main()
