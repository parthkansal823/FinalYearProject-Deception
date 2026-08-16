"""
Does a *response-reading* vertical brute force take the auth probe?

WHY THIS EXISTS
---------------
LIMITATIONS.md §5 records that vertical brute force (one username, many
passwords) is passively undetected after v4, and that the auth bait which could
in principle separate it is weakly taken (beta_attack = 0.12). That number is
measured against the calibration round's bait-following model — and the
simulated brute forcer is not in that model at all: it only POSTs credentials
and never reads a response body (`tools/attack_traffic.py`, the
`auth_bruteforce` branch). A response-side probe cannot reach it *by
construction*, whatever the bait says.

Real tooling is not blind in that way. Hydra, patator and Burp Intruder all read
the response to tell a success from a failure — which is the exact channel the
probe rides on. This tool measures, against the **current frozen model**, what
changes when the attacker reads what it is sent:

  arm A  blind      — POSTs only, never inspects the body (today's generator)
  arm B  reading    — inspects each response, and follows a hinted endpoint with
                      probability `--curiosity` (the Burp-Intruder operator)

It changes NOTHING that is frozen: no retraining, no recalibration, no edit to
the round-1 generator. It runs its own isolated stack on its own ports and
reports divert rate, bite rate and requests-to-divert per arm, so the case for
(or against) rebuilding the corpus is made on evidence rather than on a hunch.

    python -m tools.bruteforce_probe_eval --sessions 40 --curiosity 0.6
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
import uuid
from pathlib import Path

import httpx

from adf.config import system
from adf.freeze import require_frozen
from adf.logstore import LabelSidecar

OUT = Path("data/eval/bruteforce_probe.json")

# The planted auth endpoint renders into the failure page as
#   "legacy auth endpoint /auth/legacy/verify_<suffix> pending decommission"
# A reader looking for somewhere else to authenticate finds it exactly here.
_HINTED_PATH = re.compile(r"/auth/legacy/verify_[A-Za-z0-9_]+")

COMMON_PASSWORDS = [
    "123456", "password", "qwerty", "letmein", "welcome", "admin123",
    "iloveyou", "monkey", "dragon", "football", "sunshine", "master",
    "Summer2024!", "Passw0rd!