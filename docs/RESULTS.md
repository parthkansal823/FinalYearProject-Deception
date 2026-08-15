# Results (Phase 7)

> **⚠ Re-estimation in progress (2026-08-15).** The recall / holdout / subcategory
> numbers in the tables below are from a **single** seeded draw
> (`tools/run_evaluation.py`, 120 attack + 80 benign). A 20-seed re-estimation
> (`tools/multiseed_eval.py` → `tools/stats_report.py`) is running to attach
> **Wilson 95% CIs** and **paired significance tests** (McNemar for arm
> comparisons, Fisher for the holdout). Until it lands, read the point estimates
> as *directional, single-draw*, not as final significant claims. What is already
> final and does **not** depend on that run: the derived-band result and its
> **β-invariance** (§ below / `tools/beta_sweep.py`), and the safety result
> (0 benign diversions among automated clients / ordinary users). The honest
> reading of the recall gain is **directionally positive, and — at n=120 in a
> single draw — not yet shown significant**; the significant result is the
> randomised holdout, which the 20-seed run is powering.

Held-out attack round 2 against the **frozen** model (spec §7.2), every baseline
arm run on byte-identical seeded traffic (`tools/run_evaluation.py`, 120 attack +
80 benign sessions, holdout fraction 0.25). Round 2 is deliberately unlike round
1 — obfuscated/encoded SQLi, scattered-stride IDOR over the API, password
spraying, a low-and-slow stealth prober, and IDOR through the UI pages by
guessing ids (§7.2). The benign side includes automated-but-harmless agents
(uptime monitor, crawler, reporting integration), not only humans — because a
human-only benign set is what hid a serious false positive the first time (see
below).

Read the **derived-band result** first (NOVELTY.md, Contribution 1 — applied
EVSI, Howard 1966, *not* a new theorem): probing is the cost-optimal third action
over a *derived* band, and there is no third action at all under cost accounting
alone. That, and its β-invariance, is the structural spine that holds regardless
of sample size. The numbers below show the mechanism doing in practice what the
derivation says — help where the classifier is uncertain, nowhere else — with a
randomised holdout attributing the effect causally.

Feature set **v3** (17 features): two id-access malice features
(`mal_touched_sensitive`, `mal_seq_id_run`) were removed after they were found to
divert 100% of benign API-integration clients; the audit that found and fixed
that is the main story of this phase.

## The comparison table

| Arm | recall | precision | F1 | median req→decide | benign diversion | benign bait exposure | E[cost]/session |
|---|---|---|---|---|---|---|---|
| **B0** no defence | 0.00 | – | – | – | 0/80 | 0.00 | **+15.0** |
| **B1** signature WAF | 0.38 | 1.00 | 0.55 | 5 | 0/80 | 0.00 | **+4.65** |
| **B2** passive | 0.87 | 0.97 | 0.92 | 5 | 3/80 | 0.00 | −5.4 |
| **B4** full | **0.90** | 0.97 | 0.94 | 5 | 3/80 | 0.76 | **−6.01** |

Cost per session in the frozen table's units; negative = attacker contained. A
positive cost means attacks are getting through: B0 lets every attacker past
(+15.0), and **B1's +4.65 shows a signature WAF is far closer to no defence than
to the learned system** — it stops the textbook payloads and nothing else.

### What each baseline is, and why B1 matters

- **B0** — proxy forwards, no scoring. The ceiling on attacker success; the
  reference for "cost of doing nothing."
- **B1** — a real signature WAF (`adf/proxy/rules.py`): regexes for SQLi/XSS/
  traversal/command-injection plus scanner user-agents. It is a *fair* reference,
  not a straw man — it catches every textbook payload and false-positives on
  **zero** benign sessions (precision 1.00). But its recall is only **0.38**,
  because round 2's attacks are obfuscated (double-encoding evades one
  normalisation pass) and, decisively, **IDOR is invisible to it**: requesting
  another user's object by id is valid syntax with no signature. This is the gap
  the learned system plus bait exists to close.
- **B2** — full scoring, no bait, no decoy. The honest baseline to beat.
- **B4** — bait + dual meter + cost policy + decoy. The contribution.

### Recall by attack category — the whole gain is in IDOR

| category | B1 (WAF) | B2 (passive) | B4 (full) |
|---|---|---|---|
| sqli | 0.65 | 0.95 | 0.95 |
| idor | **0.10** | 0.68 | **0.78** |
| auth | 0.15 | 1.00 | 1.00 |

The WAF catches two-thirds of SQLi by signature but almost no IDOR (0.10) and
almost no spray (0.15). The learned system lifts every category; bait then adds
its gain **entirely within IDOR** (0.68 → 0.78), the one category no signature
can see and the passive classifier is genuinely unsure about.

## Where bait helps

Recall improves **0.87 → 0.90**, and the gain is concentrated in the one
subcategory the passive classifier is genuinely unsure about:

| round-2 subcategory | B2 diverts | B4 diverts | B4 bite rate |
|---|---|---|---|
| sqli_obfuscated | 0.93 | 0.93 | 0.00 |
| sqli_stealth | 1.00 | 1.00 | 0.40 |
| idor_scattered (API) | 0.95 | 0.95 | 0.00 |
| auth_spray | 1.00 | 1.00 | 0.00 |
| **idor_html_scattered** | **0.40** | **0.60** | **0.40** |

On attacks the passive classifier is confident about, bait is neutral (both
divert, no harm — note `sqli_stealth` bites 40% of the time yet the divert rate
does not move, because those sessions were already caught). The scattered
API-IDOR is caught passively by `mal_error_ratio` — an attacker probing many
object ids hits many 404s, whereas a benign integration reads only ids that exist
and gets 200s, so error ratio separates them *without* the id-access features that
used to false-positive. The UI-based scattered IDOR is the hardest case (some of
it 404s on out-of-range profile ids, which is why B2 already gets 40%); bait lifts
it to 60% via the `internal_view` bite. **This is the mechanism working where the
theory says it should: manufacturing evidence the passive classifier could not
derive.**

## The causal estimate (Contribution 3) — *the intended headline*

The randomised holdout — 25% of bait-band sessions deliberately **not** baited —
attributes the effect to bait itself (not "the system with bait scored higher"
but "bait *caused* this"), because assignment is random at the same belief state.

Single-draw estimate (being re-estimated with a Fisher exact *p* and bootstrap CI
over 20 seeds; the pooled holdout arm will be ~10× this n):

| arm | n | divert rate |
|---|---|---|
| baited | 72 | **0.94** |
| withheld (holdout) | 28 | **0.71** |

A **+23-point** divert rate from bait at the same belief state in this draw. On
the single run this was the one result reaching significance (Fisher p ≈ 0.0035);
the 20-seed pool is what makes it robust rather than a single draw. The estimate
is diluted by the aggressive attackers who divert regardless (they dominate the
bait band); the cleanest single-subcategory effect is the 0.40 → 0.60 on the
uncertain UI-IDOR above. **This — not the aggregate recall — is the paper's
headline, because it is the causal, significant, and structurally novel result.**

## Safety (NFR-05) — and the false positive the audit fixed

Benign diversion by class, agents included (measured on the b4 run):

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

**Benign bait exposure 76%, benign bites 0.** Most benign sessions are shown bait
and none act on it — the invisibility gate holding at run time. Exposure is
harmless because bait is invisible; the bite rate is what matters, and it is
zero for benign traffic.

## Ablations (§10.2)

| ablation | what it removes | measured effect |
|---|---|---|
| **no bait** (= B2 vs B4) | the probe | recall 0.87 → 0.90; the loss is entirely the UI-IDOR band (0.60 → 0.40) |
| **no notebook** | the decoy's memory | contradiction rate **0% → 100%** (below) |
| **adaptive adversary** | attacker refuses every probe | EVSI decays to the passive floor; decision rule *converges to* B2's two-action rule in the limit (asymptotic, not per-session — Contribution 5) |

**No-notebook (isolating Contribution #4).** With the Fact Notebook, the decoy's
contradiction rate over repeated probing is **0%**; with it disabled (generate-
fresh, no memory — the `persist=False` switch, which *is* the ablation), it is
**100%**. That single pair of numbers is the notebook's entire justification: a
decoy that forgets what it said betrays the trap on the second question. Locked
as a test (`tests/test_fact_notebook.py::test_notebook_ablation_...`).

Two ablations named in §10.2 are **not** shipped as numbers, honestly: a
*fixed-threshold* arm and a *single-score* arm. The cost model's value is already
carried by the derived-band result (the band is derived, not tuned — there is no
threshold to fix) and its β-invariance, and the two-axis meter's value by the
calibration finding (bait is selected by category and divert is malice-only). A
faithful fixed-threshold arm needs a
policy variant that scores the bait action on realised outcomes rather than
immediate cost; shipping the naive analytical version would *understate* the
derived policy and mislead. Flagged as future work in
[PAPER_OUTLINE.md](PAPER_OUTLINE.md) §9, not papered over.

## Cost and generalisation

- Expected cost per session: **+15.0 (B0) → +4.65 (B1) → −5.4 (B2) → −6.01 (B4)**.
- Recall on unseen, obfuscated round-2 attacks is high even for B2 (0.87): the
  frozen model generalises from round 1's straightforward attacks to round 2's
  comment-split/case-mixed/encoded evasions, because the keyword features fire on
  syntax context, not literal strings — which is exactly what B1's signatures
  cannot do (recall 0.38).

## Cross-references

- **Decoy self-consistency:** 0.00% contradiction over 286 adversarial probes
  (and 100% without the notebook — the ablation above).
- **Adaptive robustness:** the recall gain is against a *curious* adversary; a
  bait-aware one erodes it to the passive floor, and the EVSI decay drives the
  decision rule to B2's two-action rule in the limit — an asymptotic guarantee
  about the rule, not a per-session one (finite-horizon sessions in the narrow
  [0.816, 0.863] band can be deferred; NOVELTY.md Contribution 5).

## Honest summary — in the order the paper should claim it

1. **Structural (holds regardless of sample size).** Probing is the cost-optimal
   third action over a *derived* band; under cost accounting alone there is no
   third action at all. The band's existence and the divert threshold's floor are
   **invariant across β_attack ∈ [0.1, 0.9]** (`tools/beta_sweep.py`). This is a
   proof plus a sweep, not a measured average — it does not depend on power.
2. **Safety (measured, tight).** The system diverts **no automated benign client
   and no ordinary user**; the only false positives are the five-failure
   forgetful login (an acknowledged hard negative). Benign bait exposure is
   common and benign bites are zero — the invisibility gate at run time.
3. **Methodological finding.** A human-only benign set hid a **100% false positive**
   on benign JSON-API integration clients; only adding automated-but-harmless
   agents to the corpus exposed it. Reported, not buried.
4. **Causal effect (the significant result).** A randomised holdout attributes the
   divert-rate lift to the probe itself at the same belief state (single-draw
   Fisher p ≈ 0.0035; being re-estimated with a CI over 20 seeds).
5. **Recall (honest).** Bait lifts aggregate recall 0.87 → 0.90, concentrated in
   UI-based IDOR that neither the passive classifier nor any signature WAF can
   see. At n=120 in a single draw this is **directionally positive but not yet
   shown statistically significant** — the paired-McNemar test over 20 seeds is
   what will settle it. We test it and say so; that is a strength, not a hedge.
