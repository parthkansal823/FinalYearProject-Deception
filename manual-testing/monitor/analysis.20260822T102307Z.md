# Pentest monitor — analysis journal

- **started** 2026-08-22T10:23:07+00:00
- **following** `data\logs\proxy.20260822T102307Z.jsonl`
- **mode** `b4_full`
- **derived bands** PASS < 0.0646 ≤ BAIT < 0.8793 ≤ DIVERT

Written for Claude to read back before the next session. Each finding cites the document that says why it matters, so it is actionable.

## Findings (chronological)

- `sid-4149` seq 13 — **IDOR sweep undetected — 5 ids, meter flat** — read 5 distinct object ids ([('profile', '1'), ('profile', '2'), ('profile', '6'), ('records', '4'), ('records', '8')]); p_attack held ~0.163 across the sweep.
  - _Why:_ The passive meter cannot see UI-IDOR: walking object ids is the request shape of a benign reporting integration, so the meter stays put. The simulated corpus only catches this via bait bites — an attacker who ignores bait is not represented.
  - _Do:_ This is the gap manual pentesting exists to characterise. Note whether ANY bait was bitten in this sweep; if not, the only catch left is a later SQL/auth probe.
  - _Ref:_ docs/LIMITATIONS.md §3; manual-testing/README.md
- `sid-4149` seq 15 — **SESSION DIVERTED** — on `GET /search?q=%27+UNION+SELECT+id%2C+username%2C+password_hash%2C+role+FROM+users+--` p 0.163→1.000. top feature mal_db_keyword_hits=3 (contrib +6.40). Prior to this: 5 object ids read, 6 baits shown, 0 bites.
  - _Why:_ The catch. Note what did the catching vs what slipped: if the IDOR sweep moved the meter 0 and 0 baits were bitten, then only this probe caught them — the SQL/auth path, not the IDOR surface.
  - _Do:_ After this point the attacker is in the decoy. The open question (manual-testing/README.md): do they notice? Ask them afterwards which request they think tripped it, compare to this seq.
  - _Ref:_ docs/DECISIONS.md; manual-testing/README.md

## Session summaries

### session `sid-4149` (unknown)

| requests | peak p | object ids read | baits shown | bites | outcome | 502s (post-divert) | fail-open |
|---|---|---|---|---|---|---|---|
| 15 | 1.000 | 5 | 6 | 0 | diverted at seq 15 | 0 (0) | 0 |

Walked 5 object ids undetected and bit none of 6 baits; caught only at seq 15. Same shape as the human/agent sessions in manual-testing/ — the IDOR surface slips the meter, a later probe does the catching.

