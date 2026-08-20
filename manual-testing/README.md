# Manual pentest logs

Human-driven attack traffic against the frozen system. One file per session,
in the proxy's own record format (`adf/schema.py`), so the same tooling that
reads an evaluation log reads these.

## `proxy.20260820T111350Z.jsonl` — 2026-08-20, Siddhant Mehta

56 requests, one session, real browser, `mode: b4_full`.

| phase | what happened | `p_attack` |
|---|---|---|
| seq 0–8 | browse → login → OTP → dashboard | 0.163 → 0.476 |
| seq 9–38 | **manual IDOR sweep** — `/records/1..15`, `/profile/2..4`, revisits | 0.476, flat |
| seq 39 | `/search` | 0.476 |
| seq 40 | **`/search?q='`** → verbose SQL error | **0.476 → 0.998 → DIVERT** |
| seq 41–55 | post-divert | — |

**What it confirms.** The single quote spikes the meter to 0.998 in one request
and the session diverts before the bait band is ever reached — the mechanism
`docs/DECISIONS.md` predicted, reproduced by a human who did not know it. This
is also the spec §6.3 "careful human attacker" case: automation ≈ 0 throughout
(a real browser fetching its own sub-resources), malice high. Exactly the cell
a single combined score could not represent.

**What it exposed.** Two things 99 seeds × 3 arms never did:

1. *The IDOR sweep moved the meter not at all.* Thirty requests walking object
   ids left `p_attack` at 0.476, and nine baits were injected with **zero**
   bites. The entire IDOR phase went undetected; only the SQL probe caught him.
   The simulated corpus catches UI-IDOR via bait bites — a human who ignores
   bait is not represented in it.
2. *The decoy was not running,* so every request after the divert returned
   **HTTP 502 for 30 seconds** — the loudest possible tell, at the exact request
   he was caught on. Root cause was the README, which started only the target
   and the proxy. Both are now fixed:
   - `README.md` quick start uses `python -m tools.run_stack` (all three).
   - The proxy falls back to the target when the decoy is unreachable, rather
     than surfacing an error, and logs `decoy unreachable` with
     `fail_open_triggered: true` (`tests/test_fail_open.py`).

   **This log predates both fixes.** Its 502s are the bug, not the behaviour.

## Running another session

```bash
python -m tools.run_stack          # target + decoy + proxy. Do not start these by hand.
```

Point the browser at **http://127.0.0.1:8000** only. Then, so the session can be
scored rather than merely read:

* note the start time and what you intended to try, in order;
* do not tell the tester which requests are expected to trip anything;
* afterwards, copy the newest `data/logs/proxy.*.jsonl` here.

The open question the next session should answer is the one this one could not,
because the decoy was down: **after the divert, does the tester notice?** They
should be asked afterwards when they think they were detected, and the answer
compared against the actual divert `seq`. That is the deception measurement the
project has never made — see `docs/HUMAN_STUDY.md`.

Records carry `ground_truth: "unknown"` and an empty `run_id`, so manual logs
cannot be scored automatically; they are read, not pooled into the evaluation.

## `proxy.claude-agent.*.jsonl` — 2026-08-20, Claude (Opus) as the attacker

The frontier-model counterpart to Siddhant's human session: the assistant drove
the frozen `b4_full` stack by hand, reading each response and choosing the next
request, told nothing about bait or decoy. Unlike the human test, the decoy was
up, so the post-divert half is real rather than 502s. One session, 29 requests.

| phase | what happened | outcome |
|---|---|---|
| recon + login | browsed, logged in as a seeded staff user (uid 1) | p → 0.476 |
| IDOR sweep | read records #6, #7, #12, #20 and profiles #3, #8 — other users' restricted/confidential data | **undetected**, meter flat at 0.476 |
| bait exposure | 9 baits shown (B-IDOR-2 ×6, B-AUTH-1 ×2, B-SQL-1 ×1) | **0 bites** |
| SQL probe | a single `?q='` | p → **0.908**, **diverted** (seq 24) |
| inside the decoy | re-read ids seen earlier on the target | **caught the swap** (see below) |

**Two results.** First, it confirms the mechanism at the frontier: a capable
agent walked the entire IDOR surface undetected and was caught only by the SQL
path, biting none of the nine baits it was shown — the same shape as the human
session and as §3 of `docs/LIMITATIONS.md`. Bait's job is against a *curious*
attacker; a capable one that ignores it is still caught by the passive meter
where the meter can see (SQL), and slips the surface where it cannot (IDOR).

Second, it found a **cross-boundary decoy tell** the consistency fuzzer cannot
see, because the fuzzer only ever talks to the decoy. Record #6 read
"Conference registration / 3938.99 / owner #2" on the target and
"Procurement request / 6958.79 / owner #1" in the decoy; profile #3 was Sofia
Lindqvist (Operations) on the target and Noor Kato (Legal) in the decoy. The
decoy is internally consistent (the same ids are byte-stable on repeat inside
it) — it simply generated its own world instead of mirroring what the attacker
already saw. **Fixed the same day** (`docs/LIMITATIONS.md` §7): the proxy now
replays the pre-divert target view for any id the session already read, so the
swap is gone; re-running this attack shows record #6 and profile #3 identical
before and after the divert.

Caveats, stated plainly: n = 1, and the agent had read the source, so it is not a
blind adversary and this is a case study, not a sweep point. The `seq 1–2`
records in the dump are throwaway noise from a path-mangling bug in the driver,
not part of the trajectory. What the finding does not depend on is the agent's
knowledge: the tell is mechanical, and any attacker who browses before being
diverted and remembers what they saw would hit it.
