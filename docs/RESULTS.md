# Results (Phase 7)

> **Final numbers are the 20-seed pooled estimates (2026-08-15).** Every arm was
> run over **20 independent seeded traffic draws** against the one frozen model
> (`tools/multiseed_eval.py`; 120 attack + 80 benign per draw → n = 2400 attack /
> 1600 benign per arm), and every proportion is reported with a **Wilson 95%
> confidence interval**. Arm comparisons use a **paired McNemar exact** test
> (legitimate because each seed gives every arm byte-identical traffic), the
> holdout a **Fisher exact** test (`tools/stats_report.py`). An earlier single
> draw (`tools/run_evaluation.py`) gave optimistic point estimates (B2 0.87 /
> B4 0.90); the honest pooled values are lower **and now statistically
> significant** — which is the point of doing 20 seeds.

Held-out attack round 2 against the **frozen** model (spec §7.2). Round 2 is
deliberately unlike round 1 — obfuscated/encoded SQLi, scattered-stride IDOR over
the API, password spraying, a low-and-slow stealth prober, and IDOR through the UI
pages by guessing ids (§7.2). The benign side includes automated-but-harmless
agents (uptime monitor, crawler, reporting integration), not only humans — because
a human-only benign set is what hid a serious false positive the first time (see
below).

Read the **derived-band result** first (NOVELTY.md, Contribution 1 — applied EVSI,
Howard 1966, *not* a new theorem): probing is the cost-optimal third action over a
*derived* band, and there is no third action at all under cost accounting alone.
That, and its β-invariance, is the structural spine that holds regardless of
sample size. The numbers below show the mechanism doing in practice what the
derivation says — help where the classifier is uncertain, nowhere else — with a
randomised holdout attributing the effect causally.

Feature set **v3** (17 features): two id-access malice features
(`mal_touched_sensitive`, `mal_seq_id_run`) were removed after they were found to
divert 100% of benign API-integration clients; the audit that found and fixed
that is the main story of this phase.

## Headline results at a glance

| Result | Value (95% CI) | Test | Significance |
|---|---|---|---|
| **Causal effect of bait** (randomised holdout) | **+0.110 [+0.069, +0.153]** | Fisher exact | **p < 10⁻⁵** |
| Attack recall, B4 vs B2 | 0.873 [0.859, 0.886] vs 0.801 [0.785, 0.817] | paired McNemar (b=197, c=25) | **p < 10⁻⁴** |
| Per-seed consistency | **B4 > B2 in 20/20 seeds** | — | — |
| UI-IDOR subcategory gain | 0.113 → 0.578 | paired McNemar | **p < 10⁻⁴** |
| Benign diversion (FP), **B2 = B4** | 0.027 [0.020, 0.036] | Wilson | bait adds **0** FP |
| Band non-empty + divert floor | invariant over β ∈ [0.05, 0.99] | β sweep | structural (proof) |
| Decoy contradiction rate | 0% (100% without the notebook) | fuzzer, 286 probes | — |

**Table (summary).** Everything the paper claims, with its test and significance;
each row is expanded in the sections below.

## 1. Structural result (independent of sample size)

Before any measured number: the derived band and its invariance are a proof plus a
sweep, so they hold regardless of how many sessions were run.

![Two-panel figure. Left: the PASS-to-BAIT and BAIT-to-DIVERT band edges plotted against beta_attack from 0.05 to 0.99 with the BAIT band shaded between them; the BAIT-to-DIVERT edge stays above a dashed horizontal line at the cost-only boundary 0.816 for every value, with a dotted marker at the calibrated beta of 0.59. Right: band width rising smoothly with beta_attack from about 0.4 to 0.85, never zero.](img/beta-invariance.svg)

**Figure 1.** Sensitivity of the derived bands to $\beta_{\mathrm{attack}}$ — the
one parameter estimated in the attacker model. Across $\beta_{\mathrm{attack}} \in
[0.05, 0.99]$ the BAIT band stays **non-empty** and the divert threshold stays
**above the cost-only boundary** (0.816); only the band width and the bite
likelihood ratio move. The existence of the third action and the safety-relevant
divert floor do not depend on the point estimate (`tools/beta_sweep.py`).

## 2. The causal estimate (Contribution 3) — *the headline*

The randomised holdout — 25% of bait-band sessions deliberately **not** baited —
attributes the effect to bait itself (not "the system with bait scored higher" but
"bait *caused* this"), because assignment is random at the same belief state.

![Bar chart with two bars and 95% confidence intervals: baited sessions divert at 0.874 (n=1522), withheld holdout sessions divert at 0.764 (n=478); a bracket marks the difference of +0.110 with interval +0.069 to +0.153.](img/holdout-effect.svg)

**Figure 2.** Randomised-holdout causal estimate, pooled over 20 seeds. Baited vs
withheld divert rate at the **same belief band**; the gap is the causal effect of
the probe. Effect **+0.110** (bootstrap 95% CI **[+0.069, +0.153]**), odds ratio
2.14, **Fisher exact p < 10⁻⁵**.

| arm | n | divert rate |
|---|---|---|
| baited | 1522 | **0.874** |
| withheld (holdout) | 478 | **0.764** |

**Table 1.** The same estimate in numbers. This is the paper's headline: a causal,
significant estimate of the probe's effect at a fixed belief state — the
contribution no prior work in this literature provides. (The earlier single draw
gave +0.23; the honest pooled effect is +0.11 and highly significant.)

## 3. Baseline comparison

![Forest plot of attack recall with 95% confidence intervals for three arms over 20 seeds: B1 signature WAF at 0.408 with interval 0.389 to 0.428, B2 passive at 0.801 with interval 0.785 to 0.817, and B4 full at 0.873 with interval 0.859 to 0.886. The B2 and B4 intervals do not overlap.](img/recall-forest.svg)

**Figure 3.** Per-arm attack recall, pooled over 20 seeds, with Wilson 95% CIs. The
B2 and B4 intervals **do not overlap** — the recall gain is significant at the
aggregate level, and the paired test below confirms it.

![Paired slope plot of attack recall per seed for B2 and B4, 20 thin grey lines connecting each seed's B2 point to its B4 point; almost every line rises. B2 points cluster near 0.80 (mean marked 0.801), B4 points near 0.87 (mean 0.873). Title states B4 beats B2 in 20 of 20 seeds.](img/seed-stability.svg)

**Figure 4.** The same recall, per seed, paired by draw. **B4 beats B2 in 20/20
seeds** — the gain is consistent, not a lucky seed. (This is the visual companion
to the paired McNemar test.)

| Arm | recall (95% CI) | precision | F1 | benign diversion | benign bait exp. | E[cost]/session |
|---|---|---|---|---|---|---|
| **B0** no defence | 0.00 | – | – | 0.000 | 0.00 | **+15.0** |
| **B1** signature WAF | 0.408 [0.389, 0.428] | 1.000 | 0.580 | 0.000 [0.000, 0.002] | 0.00 | **+3.98** |
| **B2** passive | 0.801 [0.785, 0.817] | 0.978 | 0.881 | 0.027 [0.020, 0.036] | 0.00 | −4.48 |
| **B4** full | **0.873 [0.859, 0.886]** | 0.980 | 0.923 | 0.027 [0.020, 0.036] | 0.75 | **−6.13** |

**Table 2.** Baseline comparison on byte-identical held-out round-2 traffic, pooled
over 20 seeds (n = 2400 attack / 1600 benign per arm). Cost per session in the
frozen table's units; negative = attacker contained. **B4's recall CI clears
B2's**, and benign diversion is **identical** for B2 and B4 — bait adds detection
without adding a single false positive.

**Why B1 matters.** B1 is a real signature WAF (`adf/proxy/rules.py`): regexes for
SQLi/XSS/traversal/command-injection plus scanner user-agents. It is a *fair*
reference — it catches textbook payloads and false-positives on **zero** benign
sessions (precision 1.00) — but its recall is only **0.41**, because round 2's
attacks are obfuscated (double-encoding evades one normalisation pass) and,
decisively, **IDOR is invisible to it** (accessing another user's object by id is
valid syntax, no signature). Its cost (+3.98) is far closer to no defence (+15.0)
than to the learned system. This is the gap the learned system plus bait closes.

### Recall by attack category — the whole gain is in IDOR

![Grouped bar chart of recall by attack category (SQLi, IDOR, auth) for three arms with 95% confidence intervals. SQLi: B1 0.65, B2 and B4 both about 0.94. IDOR: B1 0.12, B2 0.49, B4 0.71 — B4 clearly above B2. auth: B1 0.25, B2 and B4 both 1.0.](img/recall-by-category.svg)

**Figure 5.** Recall by category, pooled over 20 seeds, with Wilson 95% CIs. The
learned system lifts every category over the WAF; **bait's gain over passive lives
entirely in IDOR** (0.486 → 0.714) — the one category no signature can see.

| category | B1 (WAF) | B2 (passive) | B4 (full) |
|---|---|---|---|
| sqli | 0.65 | 0.945 | 0.937 |
| idor | **0.12** | 0.486 | **0.714** |
| auth | 0.25 | 1.000 | 1.000 |

**Table 3.** The same, in numbers. On SQLi, B4 is a hair *below* B2 (0.937 vs
0.945) — the finite-horizon deferral cost discussed next.

## 4. The paired test — where bait helps, and what it costs

Because each seed gives every arm byte-identical traffic, B2 vs B4 is a matched
comparison: each attack session is one pair, and only the **discordant** pairs
carry information.

- **B4 catches, B2 misses:** *b* = **197**
- **B2 catches, B4 misses:** *c* = **25**
- concordant: 2178 · **McNemar exact p < 10⁻⁴** (significant)

The gain is real and one-directional (b ≫ c). But *c* = 25 is not zero, and that is
honest and expected: bait *raises* the divert threshold over the narrow band
[0.816, 0.863], so a few sessions that B2 diverts immediately are instead **baited
(deferred)** by B4 and, within the finite evaluation horizon, not caught. This is
the empirical footprint of the limiting-rule (not per-session) guarantee in
Contribution 5 — we report it rather than hide it.

Per subcategory (pooled divert rates):

| round-2 subcategory | B2 diverts | B4 diverts | B4 bite rate |
|---|---|---|---|
| sqli_obfuscated | 0.917 | 0.905 | 0.00 |
| sqli_stealth | 1.000 | 1.000 | 0.46 |
| idor_scattered (API) | 0.860 | 0.850 | 0.00 |
| auth_spray | 1.000 | 1.000 | 0.00 |
| **idor_html_scattered** | **0.113** | **0.578** | **0.535** |

**Table 4.** The entire net gain is UI-based scattered IDOR: **0.113 → 0.578**
(+0.465) via the `internal_view` bite. On this subcategory the paired test is
*b* = 197, *c* = 11, **p < 10⁻⁴**. Elsewhere bait is neutral or a hair negative:
`sqli_stealth` bites 46% of the time yet the divert rate does not move (already
caught), and the small dips on `sqli_obfuscated`/`idor_scattered` are the
deferrals that make up *c*. The scattered API-IDOR is caught passively by
`mal_error_ratio` (an attacker probing many ids hits many 404s; a benign
integration reads only ids that exist), so it needs no bait. **This is the
mechanism working where the theory says it should: manufacturing evidence only
where the passive classifier could not derive it.**

## 5. Safety (NFR-05) — and the false positive the audit fixed

Pooled benign diversion (false-positive rate) is **0.027 [0.020, 0.036]** — and
**identical** for B2 and B4, so the probe adds detection with **no** cost in false
positives. By class, the single-run breakdown that isolates the mechanism:

| benign class | diverted (single-run breakdown) |
|---|---|
| agent — integration (JSON API) | **0 / 6** |
| agent — crawler | **0 / 7** |
| agent — monitor | 0 / 7 |
| human — normal | 0 / 45 |
| human — apostrophe (SQL-error hard negative) | 0 / 10 |
| human — forgetful (5 failed logins) | **3 / 5** |

**Table 5.** Every pooled benign diversion is the `forgetful` persona; every
automated client and every ordinary user passes.

**The headline fix.** An earlier version diverted **100% of benign integration
clients**: `mal_touched_sensitive` treated any `/api` access as hostile, and when
that was removed `mal_seq_id_run` took over, because a benign integration walks
object ids exactly like an IDOR sweep (§6.3 names this ambiguity). The first
evaluation missed it entirely because its benign set was human-only. Both features
were removed (feature-set v3): no passive feature honestly separates a benign
integration from an IDOR sweep, so that detection is delegated to bait. Result:
**every automated benign client now passes**, and the crawler false positive (from
404s on `/robots.txt`, `/sitemap.xml`, `/favicon.ico`) was fixed by having both
apps serve those standard files.

**The remaining false positives are honest and inherent.** They are the
`forgetful` persona — a user who fails login five times. On the passive features
(`mal_error_ratio`, `mal_failed_auth`) that is indistinguishable from an early
credential attack, which is exactly why the persona is in the corpus. It diverts on
error ratio, not on any bite; the auth bait that could in principle separate it is
too weakly taken (calibrated β = 0.12) for the policy to defer divert. This is the
genuine false-positive cost of a hard negative, reported not hidden (§7.4).

**Benign bait exposure 75%, benign bites 0.** Most benign sessions are shown bait
and none act on it — the invisibility gate holding at run time. Exposure is
harmless because bait is invisible; the bite rate is what matters, and it is zero
for benign traffic across all 1600 benign sessions.

## 6. Ablations (§10.2)

| ablation | what it removes | measured effect |
|---|---|---|
| **no bait** (= B2 vs B4) | the probe | recall 0.801 → 0.873 (paired McNemar p < 10⁻⁴); gain entirely UI-IDOR (0.113 → 0.578) |
| **no notebook** | the decoy's memory | contradiction rate **0% → 100%** (below) |
| **adaptive adversary** | attacker refuses every probe | EVSI decays to the passive floor; decision rule *converges to* B2's two-action rule in the limit (asymptotic, not per-session — Contribution 5, empirically the *c* = 25 above) |

**No-notebook (isolating Contribution #4).** With the Fact Notebook, the decoy's
contradiction rate over repeated probing is **0%**; with it disabled (generate-
fresh, no memory — the `persist=False` switch, which *is* the ablation), it is
**100%**. That single pair of numbers is the notebook's entire justification: a
decoy that forgets what it said betrays the trap on the second question. Locked as
a test (`tests/test_fact_notebook.py::test_notebook_ablation_...`).

The *fixed-threshold* and *single-score* ablations are **not** shipped as numbers,
honestly: the cost model's value is carried by the derived-band result (there is no
threshold to fix) and its β-invariance, and the two-axis meter's value by the
calibration finding (bait selected by category, divert malice-only). A faithful
fixed-threshold arm needs a policy variant scoring the bait action on realised
outcomes rather than immediate cost; the naive analytical version would understate
the derived policy. Future work ([PAPER_OUTLINE.md](PAPER_OUTLINE.md) §9), not
papered over.

## 7. Cost and generalisation

![Bar chart of expected cost per session by arm around a zero line: B0 no-defence +15.0 and B1 WAF +3.98 above zero (attacks getting through), B2 passive −4.48 and B4 full −6.13 below zero (contained).](img/cost-by-arm.svg)

**Figure 6.** Expected cost per session by arm (frozen-table units). Only the
learned arms drive the cost **negative** (attacker contained); a signature WAF
(+3.98) sits far closer to no defence (+15.0), and bait takes B2's −4.48 to
B4's −6.13.

- Expected cost per session: **+15.0 (B0) → +3.98 (B1) → −4.48 (B2) → −6.13 (B4)**.
- Recall on unseen, obfuscated round-2 attacks is high even for B2 (0.80): the
  frozen model generalises from round 1's straightforward attacks to round 2's
  comment-split/case-mixed/encoded evasions, because the keyword features fire on
  syntax context, not literal strings — exactly what B1's signatures cannot do
  (recall 0.41).

## Cross-references

- **Decoy self-consistency:** 0.00% contradiction over 286 adversarial probes (and
  100% without the notebook — the ablation above).
- **Adaptive robustness:** the recall gain is against a *curious* adversary; a
  bait-aware one erodes it to the passive floor, and the EVSI decay drives the
  decision rule to B2's two-action rule in the limit — an asymptotic guarantee
  about the rule, not a per-session one (the *c* = 25 deferrals are its
  finite-horizon footprint; NOVELTY.md Contribution 5).

## Honest summary — in the order the paper should claim it

1. **Structural (holds regardless of sample size).** Probing is the cost-optimal
   third action over a *derived* band; under cost accounting alone there is no
   third action at all. Its existence and the divert floor are **invariant across
   β_attack ∈ [0.05, 0.99]**. A proof plus a sweep — does not depend on power.
2. **Causal effect (significant).** The randomised holdout gives **+0.11
   [+0.069, +0.153], Fisher p < 10⁻⁵** — the probe *causes* more diversions at the
   same belief state.
3. **Recall gain (now significant).** Bait lifts pooled recall **0.801 → 0.873**;
   the B2/B4 CIs separate and the **paired McNemar is p < 10⁻⁴**. The gain is
   entirely UI-based IDOR (0.113 → 0.578) that neither the passive classifier nor
   any signature WAF can see. Honestly, *c* = 25 sessions go the other way
   (deferred in the narrow [0.816, 0.863] band) — reported, not hidden.
4. **Safety (measured, tight).** Benign diversion **0.027 [0.020, 0.036]**,
   **identical** for B2 and B4 (bait adds no false positive); every diversion is
   the acknowledged forgetful-login hard negative. Benign bites: zero.
5. **Methodological finding.** A human-only benign set hid a **100% false positive**
   on benign JSON-API integration clients; only adding automated-but-harmless
   agents exposed it. A metric tests only what its inputs contain.
