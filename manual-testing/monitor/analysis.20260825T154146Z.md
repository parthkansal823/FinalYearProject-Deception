# Pentest monitor — analysis journal

- **started** 2026-08-25T15:41:46+00:00
- **following** proxy, target-access, decoy-access in `data\logs/`
- **mode** `b4_full`
- **derived bands** PASS < 0.0646 ≤ BAIT < 0.8793 ≤ DIVERT

Written for Claude to read back before the next session. Each finding cites the document that says why it matters, so it is actionable.

## Findings (chronological)

- `sid-3b56` seq 15 — **IDOR sweep undetected — 5 ids, meter flat** — read 5 distinct object ids ([('profile', '8'), ('records', '2'), ('records', '3'), ('records', '4'), ('records', '7')]); p_attack held ~0.476 across the sweep.
  - _Why:_ The passive meter cannot see UI-IDOR: walking object ids is the request shape of a benign reporting integration, so the meter stays put. The simulated corpus only catches this via bait bites — an attacker who ignores bait is not represented.
  - _Do:_ This is the gap manual pentesting exists to characterise. Note whether ANY bait was bitten in this sweep; if not, the only catch left is a later SQL/auth probe.
  - _Ref:_ docs/LIMITATIONS.md §3; manual-testing/README.md
- `sid-3b56` seq 25 — **SESSION DIVERTED** — on `GET /search?q=%27+UNION+SELECT+id%2C+username%2C+password_hash%2C+role+FROM+users+--` p 0.706→1.000. top feature mal_db_keyword_hits=3 (contrib +6.40). Prior to this: 11 object ids read, 10 baits shown, 0 bites.
  - _Why:_ The catch. Note what did the catching vs what slipped: if the IDOR sweep moved the meter 0 and 0 baits were bitten, then only this probe caught them — the SQL/auth path, not the IDOR surface.
  - _Do:_ After this point the attacker is in the decoy. The open question (manual-testing/README.md): do they notice? Ask them afterwards which request they think tripped it, compare to this seq.
  - _Ref:_ docs/DECISIONS.md; manual-testing/README.md
- `sid-3b56` seq 26 — **post-divert re-read of a pre-divert page** — /directory was read before the divert and is being read again inside the decoy.
  - _Why:_ Cross-boundary consistency check: if the decoy returns different data than the target showed for this path, that swap is a tell the consistency fuzzer cannot see (it only talks to the decoy).
  - _Do:_ Manually compare the pre- and post-divert response for this path. Replay should make them identical (proxy.replay_pre_divert_views).
  - _Ref:_ docs/LIMITATIONS.md §7; manual-testing/README.md (claude-agent)
- `sid-3b56` seq 29 — **post-divert re-read of a pre-divert page** — /search was read before the divert and is being read again inside the decoy.
  - _Why:_ Cross-boundary consistency check: if the decoy returns different data than the target showed for this path, that swap is a tell the consistency fuzzer cannot see (it only talks to the decoy).
  - _Do:_ Manually compare the pre- and post-divert response for this path. Replay should make them identical (proxy.replay_pre_divert_views).
  - _Ref:_ docs/LIMITATIONS.md §7; manual-testing/README.md (claude-agent)
- `sid-3b56` seq 31 — **post-divert re-read of a pre-divert page** — / was read before the divert and is being read again inside the decoy.
  - _Why:_ Cross-boundary consistency check: if the decoy returns different data than the target showed for this path, that swap is a tell the consistency fuzzer cannot see (it only talks to the decoy).
  - _Do:_ Manually compare the pre- and post-divert response for this path. Replay should make them identical (proxy.replay_pre_divert_views).
  - _Ref:_ docs/LIMITATIONS.md §7; manual-testing/README.md (claude-agent)
- `sid-3b56` seq 32 — **post-divert re-read of a pre-divert page** — /login was read before the divert and is being read again inside the decoy.
  - _Why:_ Cross-boundary consistency check: if the decoy returns different data than the target showed for this path, that swap is a tell the consistency fuzzer cannot see (it only talks to the decoy).
  - _Do:_ Manually compare the pre- and post-divert response for this path. Replay should make them identical (proxy.replay_pre_divert_views).
  - _Ref:_ docs/LIMITATIONS.md §7; manual-testing/README.md (claude-agent)
- `sid-3b56` seq 34 — **post-divert re-read of a pre-divert page** — /otp was read before the divert and is being read again inside the decoy.
  - _Why:_ Cross-boundary consistency check: if the decoy returns different data than the target showed for this path, that swap is a tell the consistency fuzzer cannot see (it only talks to the decoy).
  - _Do:_ Manually compare the pre- and post-divert response for this path. Replay should make them identical (proxy.replay_pre_divert_views).
  - _Ref:_ docs/LIMITATIONS.md §7; manual-testing/README.md (claude-agent)
- `sid-3b56` seq 36 — **post-divert re-read of a pre-divert page** — /dashboard was read before the divert and is being read again inside the decoy.
  - _Why:_ Cross-boundary consistency check: if the decoy returns different data than the target showed for this path, that swap is a tell the consistency fuzzer cannot see (it only talks to the decoy).
  - _Do:_ Manually compare the pre- and post-divert response for this path. Replay should make them identical (proxy.replay_pre_divert_views).
  - _Ref:_ docs/LIMITATIONS.md §7; manual-testing/README.md (claude-agent)
- `sid-3b56` seq 37 — **post-divert re-read of a pre-divert page** — /records/2 was read before the divert and is being read again inside the decoy.
  - _Why:_ Cross-boundary consistency check: if the decoy returns different data than the target showed for this path, that swap is a tell the consistency fuzzer cannot see (it only talks to the decoy).
  - _Do:_ Manually compare the pre- and post-divert response for this path. Replay should make them identical (proxy.replay_pre_divert_views).
  - _Ref:_ docs/LIMITATIONS.md §7; manual-testing/README.md (claude-agent)
- `sid-3b56` seq 79 — **post-divert re-read of a pre-divert page** — /profile/12 was read before the divert and is being read again inside the decoy.
  - _Why:_ Cross-boundary consistency check: if the decoy returns different data than the target showed for this path, that swap is a tell the consistency fuzzer cannot see (it only talks to the decoy).
  - _Do:_ Manually compare the pre- and post-divert response for this path. Replay should make them identical (proxy.replay_pre_divert_views).
  - _Ref:_ docs/LIMITATIONS.md §7; manual-testing/README.md (claude-agent)

## Session summaries

### proxy session `sid-3b56` (unknown)

| requests | peak p | object ids read | baits shown | bites | outcome | 502s (post-divert) | fail-open |
|---|---|---|---|---|---|---|---|
| 81 | 1.000 | 16 | 10 | 0 | diverted at seq 25 | 0 (0) | 0 |

Walked 16 object ids undetected and bit none of 10 baits; caught only at seq 25. Same shape as the human/agent sessions in manual-testing/ — the IDOR surface slips the meter, a later probe does the catching.

### target session `78708715` (unknown)

| requests | peak p | object ids read | baits shown | bites | outcome | 502s (post-divert) | fail-open |
|---|---|---|---|---|---|---|---|
| 25 | 0.000 | 0 | 0 | 0 | never diverted | 0 (0) | 0 |

### decoy session `?` (unknown)

| requests | peak p | object ids read | baits shown | bites | outcome | 502s (post-divert) | fail-open |
|---|---|---|---|---|---|---|---|
| 48 | 0.000 | 0 | 0 | 0 | never diverted | 0 (0) | 0 |

