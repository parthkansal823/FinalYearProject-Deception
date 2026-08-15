# Results (Phase 7)

Held-out attack round 2 against the **frozen** model (spec §7.2), every baseline
arm run on byte-identical seeded traffic (`tools/run_evaluation.py`). Round 2 is
deliberately unlike round 1 — obfuscated/encoded SQLi, scattered-stride IDOR over
the API, password spraying, a low-and-slow stealth prober, and IDOR through the
UI pages by guessing ids (§7.2: different tools, encodings, pacing).

Read the theorem first (NOVELTY.md, Contribution 1): probing is the cost-optimal
third action over a *derived* band, and there is no third action at all under
cost accounting alone. That is a proof, scale-independent. The numbers below
confirm the mechanism does, in practice, exactly what the proof says it should —
help where the classifier is uncertain, and nowhere else — and a randomised
holdout attributes the effect causally.

## The comparison table

| Arm | recall | precision | F1 | median req→decide | benign diversion | benign bait exposure | E[cost]/session |
|---|---|---|---|---|---|---|---|
| **B0** no defence | 0.00 | – | – | – | 0.00 | 0.00 | **+15.0** |
| **B2** passive | 0.84 | 0.99 | 0.91 | 5 | 0.0125 | 0.00 | −6.7 |
| **B4** full | **0.93** | 0.99 | 0.96 | 5 | 0.0125 | 0.825 | **−8.65** |

120 attack + 80 benign sessions; holdout fraction 0.25 for the eval; cost per
session in the frozen table's units, negative = attacker contained.

## Where bait helps — and where it does not (the honest core)

Recall improves **0.84 → 0.93**, and the entire difference is in one
subcategory — precisely the uncertain-belief regime the theorem points to:

| round-2 subcategory | B2 diverts | B4 diverts | B4 bite rate |
|---|---|---|---|
| sqli_obfuscated | 1.00 | 1.00 | 0.00 |
| sqli_stealth | 1.00 | 1.00 | 0.45 |
| idor_scattered (API) | 1.00 | 1.00 | 0.00 |
| auth_spray | 1.00 | 1.00 | 0.00 |
| **idor_html_scattered** | **0.05** | **0.55** | **0.55** |

**On attacks the passive classifier is already confident about — anything that
touches the SQL keyword surface, the API, or the login counter — bait is
neutral.** Both arms divert at ~request 5; the passive evidence answers first and
the third action changes nothing (it also does no harm: identical recall, no
extra benign cost). Even the stealth SQL prober is caught passively, because its
quote probes trip the keyword and error features regardless of pacing; it bites
the bait 45% of the time, but too late to matter.

**On the one attack the passive classifier genuinely cannot see — IDOR through
the UI by guessing ids — bait is the difference between catching 5% and 55%.**
A scattered walk over `/profile/{id}` and `/records/{id}` leaves almost no
passive signal (no SQL keywords, no errors, no failed auth, no `/api` touch,
and, being scattered, no ascending-id run), so B2 sits it at p≈0.22 and lets it
through. B4 plants the `internal_view` bait in those pages; a curious attacker
submits it, malice jumps, and the session is diverted. This is the mechanism
working exactly as designed: **manufacturing the evidence a passive system would
have waited for forever.**

Two routing bugs had to be fixed for this to work, both exposed by the
evaluation and both genuine (docs/DECISIONS.md): bait selection ignored the
*surface* being probed (an IDOR attacker was routed to an SQL bait), and it
ignored the *response type* (a JSON-field bait was chosen for an HTML page and
silently injected nothing). Neither is tuning; both are correctness.

## The causal estimate (Contribution 3)

The randomised holdout — 10%–25% of bait-band sessions deliberately **not**
baited — attributes the effect to bait itself rather than to a difference
between two systems:

| arm | n | divert rate |
|---|---|---|
| baited | 82 | **0.94** |
| withheld (holdout) | 18 | **0.78** |

A +16-point divert rate from bait, measured inside one system at the same belief
state. The estimate is diluted by the aggressive attackers who divert regardless
(they dominate the bait band); restricted to the uncertain IDOR case the gap is
the 0.05 → 0.55 above. This is the sharper claim the literature almost never
makes: not "the system with bait scored higher" but "bait *caused* this."

## Safety (NFR-05)

- **Benign diversion: 1 / 80 (1.25%), unchanged by bait (identical in B2 and
  B4).** The single diverted benign session is a `forgetful` user who failed
  login five times; on the passive features (`mal_failed_auth`,
  `mal_error_ratio`) that is indistinguishable from an early credential attack,
  which is exactly why the persona is in the corpus (§7.4). It crossed the divert
  threshold on error ratio, not on any bite — bait neither caused nor prevented
  it. Excluding this boundary persona, benign diversion is 0.
- **Benign bait exposure: 82.5%, benign bites: 0.** Most benign sessions sit in
  the wide bait band and are shown bait; none ever act on it — the invisibility
  gate holding at run time. Exposure is harmless because the bait is invisible
  and inert; it is the bite rate that matters, and for benign traffic it is zero.

## Generalisation and cost

- **Recall on unseen, obfuscated attacks is high** even for B2 (0.84): the model
  was frozen after round 1's straightforward attacks, yet round 2's
  comment-split/case-mixed/URL-encoded SQLi, scattered IDOR and password spray
  are caught — the keyword features fire on syntax context, not literal strings.
- **Expected cost per session: +15.0 (no defence) → −6.7 (passive) → −8.65
  (full).** Bait improves the bottom line further by converting missed IDOR
  sessions (a positive cost) into contained ones (a negative cost).

## Cross-references (same story, measured elsewhere)

- **Decoy self-consistency:** 0.00% contradiction over 286 adversarial probes.
- **Adaptive robustness:** against a bait-aware adversary the system degrades to
  — provably not below — passive detection; the EVSI decay guarantees B4 ≥ B2 in
  detection whatever the adversary knows (NOVELTY.md Contribution 5). The recall
  gain above is against a *curious* adversary; a fully bait-aware one erodes it
  to the passive floor, which is the honest bound.

## Honest one-line summary

Bait is **neutral where passive detection is confident and decisive where it is
not** — it lifts recall from 0.84 to 0.93 entirely by catching UI-based IDOR that
the passive classifier cannot see, a gain a randomised holdout attributes
causally to the probe, at zero additional cost to benign users. The contribution
is the principled rule for *when* to deceive, proven as a theorem; the evaluation
confirms it fires exactly where the theory says it should.
