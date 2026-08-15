# Results (Phase 7)

Held-out attack round 2 against the **frozen** model (spec §7.2), every baseline
arm run on byte-identical seeded traffic (`tools/run_evaluation.py`). Round 2 is
deliberately unlike round 1 — obfuscated/encoded SQLi, scattered-stride IDOR over
the API, password spraying, a low-and-slow stealth prober, and IDOR through the
UI pages by guessing ids (§7.2). The benign side includes automated-but-harmless
agents (uptime monitor, crawler, reporting integration), not only humans —
because a human-only benign set is what hid a serious false positive the first
time (see below).

Read the theorem first (NOVELTY.md, Contribution 1): probing is the cost-optimal
third action over a *derived* band, and there is no third action at all under
cost accounting alone. That is a proof. The numbers below confirm the mechanism
does in practice what the proof says — help where the classifier is uncertain,
nowhere else, and never harm — with a randomised holdout attributing the effect
causally.

Feature set **v3** (17 features): two id-access malice features
(`mal_touched_sensitive`, `mal_seq_id_run`) were removed after they were found to
divert 100% of benign API-integration clients; the audit that found and fixed
that is the main story of this phase.

## The comparison table

| Arm | recall | precision | F1 | median req→decide | benign diversion | benign bait exposure | E[cost]/session |
|---|---|---|---|---|---|---|---|
| **B0** no defence | 0.00 | – | – | – | 0.00 | 0.00 | **+15.0** |
| **B2** passive | 0.87 | 0.97 | 0.92 | 5 | 3/80 | 0.00 | −5.4 |
| **B4** full | **0.92** | 0.97 | 0.94 | 5 | 3/80 | 0.78 | **−6.45** |

120 attack + 80 benign sessions; holdout fraction 0.25; cost per session in the
frozen table's units, negative = attacker contained.

## Where bait helps

Recall improves **0.87 → 0.92**, and the gain is concentrated in the one
subcategory the passive classifier is genuinely unsure about:

| round-2 subcategory | B2 diverts | B4 diverts | B4 bite rate |
|---|---|---|---|
| sqli_obfuscated | 0.93 | 0.93 | 0.00 |
| sqli_stealth | 1.00 | 1.00 | 0.35 |
| idor_scattered (API) | 0.95 | 0.95 | 0.00 |
| auth_spray | 1.00 | 1.00 | 0.00 |
| **idor_html_scattered** | **0.40** | **0.70** | **0.50** |

On attacks the passive classifier is confident about, bait is neutral (both
divert, no harm). The scattered API-IDOR is caught passively by `mal_error_ratio`
— an attacker probing many object ids hits many 404s, whereas a benign
integration reads only ids that exist and gets 200s, so error ratio separates
them *without* the id-access features that used to false-positive. The UI-based
scattered IDOR is the hardest case (some of it 404s on out-of-range profile ids,
which is why B2 already gets 40%); bait lifts it to 70% via the `internal_view`
bite. **This is the mechanism working where the theory says it should:
manufacturing evidence the passive classifier could not derive.**

## The causal estimate (Contribution 3)

The randomised holdout — 25% of bait-band sessions deliberately **not** baited —
attributes the effect to bait itself:

| arm | n | divert rate |
|---|---|---|
| baited | 76 | **0.93** |
| withheld (holdout) | 24 | **0.79** |

A +14-point divert rate from bait, measured inside one system at the same belief
state. The estimate is diluted by the aggressive attackers who divert regardless
(they dominate the bait band); the clean effect is the 0.40 → 0.70 on the
uncertain IDOR subcategory. Not "the system with bait scored higher" but "bait
*caused* this."

## Safety (NFR-05) — and the false positive the audit fixed

Benign diversion by class, agents included:

| benign class | diverted |
|---|---|
| agent — integration (JSON API) | **0 / 6** |
| agent — crawler | **0 / 7** |
| agent — monitor | 0 / 7 |
| human — normal | 0 / 45 |
| human — apostrophe (SQL-error hard negative) | 0 / 10 |
| human — forgetful (5 failed logins) | **3 / 5** |

**The headline fix.** An earlier version diverted **100% of benign integration
clients**: `mal_touched_sensitive` treated any `/api` access as hostile, and when
that was removed `mal_seq_id_run` took over, because a benign integration walks
object ids exactly like an IDOR sweep (§6.3 names this ambiguity). The first
evaluation missed it entirely because its benign set was human-only. Both
features were removed (feature-set v3): no passive feature honestly separates a
benign integration from an IDOR sweep, so that detection is delegated to bait.
Result: **every automated benign client now passes**, and the crawler false
positive (from 404s on `/robots.txt`, `/sitemap.xml`, `/favicon.ico`) was fixed
by having both apps serve those standard files.

**The one remaining false positive is honest and inherent.** All three diverted
benign sessions are the `forgetful` persona — a user who fails login five times.
On the passive features (`mal_error_ratio`, `mal_failed_auth`) that is
indistinguishable from an early credential attack, which is exactly why the
persona is in the corpus. It diverts on error ratio, not on any bite; the auth
bait that could in principle separate it (a forgetful user will not take the
deprecated-endpoint bait, an attacker will) is too weak — its calibrated bite
rate is only 0.12 — for the policy to defer divert for it. This is the genuine
false-positive cost of a hard negative, reported not hidden (§7.4). For every
other benign class, including all automated ones, diversion is zero.

**Benign bait exposure 78%, benign bites 0.** Most benign sessions are shown bait
and none act on it — the invisibility gate holding at run time. Exposure is
harmless because bait is invisible; the bite rate is what matters, and it is
zero for benign traffic.

## Cost and generalisation

- Expected cost per session: **+15.0 → −5.4 (passive) → −6.45 (full)**.
- Recall on unseen, obfuscated round-2 attacks is high even for B2 (0.87): the
  frozen model generalises from round 1's straightforward attacks to round 2's
  comment-split/case-mixed/encoded evasions, because the keyword features fire on
  syntax context, not literal strings.

## Cross-references

- **Decoy self-consistency:** 0.00% contradiction over 286 adversarial probes.
- **Adaptive robustness:** the recall gain is against a *curious* adversary; a
  bait-aware one erodes it to the passive floor, and the EVSI decay guarantees B4
  is never worse than B2 in detection (NOVELTY.md Contribution 5).

## Honest one-line summary

After removing two features that made benign JSON-API clients look hostile, the
system diverts **no automated benign client and no ordinary user** (the only
false positives are a five-failure forgetful login, an acknowledged hard
negative), while bait lifts recall from 0.87 to 0.92 entirely by catching
UI-based IDOR the passive classifier cannot see — a gain a randomised holdout
attributes causally to the probe. The contribution is the principled rule for
*when* to deceive, proven; the evaluation confirms it fires exactly where the
theory predicts and is safe where it must be.
