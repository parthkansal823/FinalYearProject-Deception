# Paper outline — mapping the artifact to a submission

This maps every claim the paper will make onto the concrete thing in this
repository that backs it: a proof, a measured number, a table, a test, or a
figure. It is the bridge between the code and the write-up. Nothing appears in a
paper section here that is not already produced by an artifact listed against it.

**Working title.** *Pricing Deception: When a Web-Attack Detector Should Probe
Rather Than Decide.*

**One-sentence thesis.** A response-side probe is worth deploying exactly over
the belief band where the expected value of the information it buys exceeds its
cost — a band that is *derived* from the cost of errors and the *measured*
effectiveness of the probe, and that does not exist at all under cost accounting
alone.

**Venue fit.** A defensive-systems / applied-security venue (RAID, ACSAC,
DIMVA, or a WWW security track). The contribution is a decision rule with a
proof plus a reproducible measurement harness, not a new ML model — so it is a
systems-and-measurement paper, not a learning paper.

---

## Section-by-section, with the backing artifact

### Abstract
- The claim in three sentences: probe-as-information-purchase; derived band, not
  tuned threshold; safe on a hard benign corpus; and a decision rule that
  converges to passive in the limit against a bait-aware adversary.
- Backing: the whole paper. Draft last.

### 1. Introduction
- The gap: WAFs decide (allow/block) on the request; honeypots deceive *after* a
  decision. Nobody prices the middle move — probing — as a first-class action.
- Contributions list = NOVELTY.md's five claims, verbatim, with the honesty
  paragraph ("Not new") folded in so a reviewer sees the boundary early.
- Backing: [NOVELTY.md](NOVELTY.md) §"The short version" and §"Not new".

### 2. Threat model and scope
- In scope: an attacker who interacts over HTTP, whose intent is uncertain from
  any single request (SQLi/XSS/traversal that can be obfuscated; IDOR that is
  *valid syntax*). Out of scope: network-layer DoS, client-side, and — stated
  plainly — an attacker with prior knowledge of the exact decoy world.
- The uncertain-intent case is the whole reason the middle action exists; IDOR
  is the load-bearing example because no signature can catch it (it is a
  well-formed request for an object that happens not to be yours).
- Backing: [docs/METHODOLOGY.md](METHODOLOGY.md); the IDOR blindness is proven by
  a test, `tests/test_rules.py::test_the_waf_is_blind_to_idor`.

### 3. System design
- Proxy in front of a real target; a state-consistent decoy behind it; the dual
  suspicion meter; the cost table; the Fact Notebook.
- One figure: the request path (proxy → meter → policy → {pass | bait | divert};
  divert → decoy). Use the existing diagram assets in `docs/img/`.
- Backing: [OVERVIEW.md](OVERVIEW.md) (plain-language system description +
  diagrams); code entry points `adf/proxy/proxy.py`, `adf/policy/engine.py`.

### 4. The decision rule *(the spine — Contribution 1)*
- **Do not oversell the maths.** EVSI is textbook (Howard 1966, [R29]); V(p) ≥ 0
  is a Jensen lemma. Frame the contribution as the **application**, not a theorem —
  a decision theorist will otherwise read the "theorem" and downgrade the paper.
  State it as a *result*: under a fixed error-cost table, a probe with positive
  information value is the cost-optimal action exactly where its EVSI exceeds its
  residual immediate cost; under cost accounting alone that interval is empty.
- Set up the three-action expected-cost problem and give the two derived facts:
  1. **Bait is never optimal on immediate cost alone** — a single PASS/DIVERT
     boundary (p ≈ 0.816 in the frozen table); no third action exists.
  2. **The middle band exists only once EVSI is added**, V(p) ≥ 0, so probing
     never makes the decision worse in expectation.
- State that the band's edges are *outputs* of the cost table and the calibrated
  bite likelihood ratio, not inputs — "derived, not tuned."
- **Sensitivity (pre-empt the β objection).** β_attack is chosen in the attacker
  model and sets both the band width and the gain. The β sweep (`tools/beta_sweep.py`)
  shows the *qualitative* conclusions are invariant across β ∈ [0.1, 0.9]: the BAIT
  band stays non-empty and the divert threshold stays ≥ the cost-only boundary;
  only width and LR move. So the safety guarantee and the existence of the third
  action do not depend on the point estimate.
- Backing: [NOVELTY.md](NOVELTY.md) Contribution 1; `adf/policy/voi.py`
  (`choose_action`, `survival_discount`, `derive_bands`); `tests/test_policy.py`
  (V(p) ≥ 0, band non-empty only with the VoI term) and `tests/test_stats_sensitivity.py`
  (β-invariance); `data/eval/beta_sweep.json`.

### 5. Calibrating the probe *(Contribution 2)*
- The bite weight is a **likelihood ratio measured** in a dedicated calibration
  round, not a constant: β_attack vs β_benign per bait category. Report the
  IDOR bait as the worked example (β_attack = 0.59, β_benign = 0.0037, n = 244).
- Emphasise the two-sided calibration: benign bite rate is measured, not
  assumed zero — that is what lets the policy trust a bite.
- Backing: `tools/calibrate_baits.py`; the calibrated library
  `data/bait_library.json` (frozen); NOVELTY.md Contribution 2.

### 6. Consistency: the Fact Notebook *(Contribution 4 of the spec)*
- The decoy must not contradict itself across the four dimensions (repetition,
  cross-reference, write-then-read, referential integrity); a decoy that forgets
  what it said betrays the trap.
- **Ablation (the clean isolation):** with the notebook, contradiction rate over
  repeated probing is **0 %**; with it disabled (generate-fresh, no memory), it
  is **100 %**. This single number is the notebook's entire justification.
- Backing: `adf/decoy/notebook.py` (the `persist` flag *is* the ablation switch);
  `tests/test_fact_notebook.py` (all four dimensions + the ablation test); the
  consistency fuzzer's 0.00 % over 286 probes.

### 7. Implementation & reproducibility
- Model **freeze** before evaluation (hash manifest over meter/cost/schema/
  features/bait-library/certificates), enforced at eval time — the paper's
  reproducibility guarantee. Tamper-evident hash-chained log store; fail-open.
- Feature-set **versioning** with a load guard (v3, 17 features).
- Backing: `adf/freeze.py`, `tools/freeze_model.py --verify`; `adf/logstore.py`;
  `adf/features/extractor.py` (`FEATURE_SET_VERSION`).

### 8. Evaluation *(the measurement)*
- **Setup.** Held-out round-2 traffic against the frozen model, byte-identical
  across arms (seeded). Round 2 is deliberately unlike round 1 (obfuscated SQLi,
  scattered-stride IDOR, spray, stealth prober, UI-IDOR). Benign corpus includes
  *automated-but-harmless* agents, not only humans — the design choice that
  exposed the paper's most important finding.
- **Statistical protocol (lead with this — it is what a reviewer checks first).**
  Every arm is run over **20 independent seeded traffic draws** against the one
  frozen model (`tools/multiseed_eval.py`); we report **Wilson 95% CIs** on pooled
  proportions and the per-seed distribution. Because each seed gives every arm
  byte-identical traffic, B2 vs B4 is compared with a **paired McNemar exact
  test** — only the discordant pairs (one arm catches, the other misses) carry
  information, which is far more powerful than an unpaired comparison of two
  recall numbers. The holdout uses **Fisher exact**. Single-draw point estimates
  are never reported without an interval. (`tools/stats_report.py`.)
- **Lead result — the causal effect (Contribution 3), because it is the one that
  is significant and the one nobody else in this literature has.** Randomised
  holdout: a fraction of bait-band sessions are withheld from bait at the same
  belief state, so the treated/withheld gap is an unbiased causal estimate of the
  probe's effect. Pooled over 20 seeds (baited 1330/1522 = 0.874 vs withheld
  365/478 = 0.764) → effect **+0.110, bootstrap 95% CI [+0.069, +0.153]**, odds
  ratio 2.14, **Fisher exact p < 10⁻⁵**. This is the headline; the recall table is
  supporting context, not the reverse.
- **Baselines (supporting).** B0 (no defence, ceiling on attacker success),
  **B1 signature WAF** — a fair reference (catches textbook, 0 benign FP,
  precision 1.00) whose recall is bounded (~0.38) by its IDOR blindness and
  brittleness to double-encoding — B2 (passive, the honest baseline), B4 (full).
- **Recall table, with CIs and honest significance.** Pooled B4 0.873 [0.859,
  0.886] vs B2 0.801 [0.785, 0.817] — the CIs **separate** — plus the **paired
  McNemar p<10⁻⁴** (b=197, c=25) for the arm difference. Significant over 20 seeds;
  the single-run 0.87→0.90 was one optimistic draw.
- **Where bait helps.** The gain is *concentrated* in the one uncertain
  subcategory (UI-IDOR) via the `internal_view` bite; neutral everywhere the
  passive classifier is already confident — the mechanism firing where the theory
  predicts. Report the paired McNemar on that subcategory too.
- **Safety (Contribution 4).** Benign diversion by class with Wilson CIs: 0 for
  every automated client and every ordinary user; the only FP is the
  forgetful-login hard negative, reported not hidden. Benign bait exposure high,
  benign bites 0 — the invisibility gate at run time.
- Backing: [RESULTS.md](RESULTS.md) (every table); `tools/multiseed_eval.py` +
  `tools/stats_report.py` (CIs + paired tests); `tools/run_evaluation.py`,
  `tools/evaluate.py`, `tools/attack_traffic_round2.py`;
  `data/eval/multiseed/report.json`.

### 9. Ablations *(§10.2)*
- **No-bait** = B2 vs B4 in the headline table (recall 0.801 vs 0.873, paired
  McNemar p<10⁻⁴): isolates the probe's contribution to detection.
- **No-notebook** = §6 above (contradiction 0 % → 100 %): isolates consistency.
- **Adaptive adversary** (Contribution 5): against a bait-aware attacker who
  refuses every probe, EVSI decay drives the decision rule to the passive
  two-action rule in the limit, so it cannot be *asymptotically* worse than B2.
  State this as a limiting-rule property, **not** per-session: report the paired
  McNemar *c* (sessions B2 catches that B4 defers) rather than claiming
  per-session dominance.
- **β_attack sensitivity** (`tools/beta_sweep.py`): recomputes the derived bands
  across β ∈ [0.1, 0.9]; the BAIT band stays non-empty and the divert threshold
  stays ≥ the cost-only boundary throughout, so the existence of the third action
  and the safety guarantee are invariant to the one chosen parameter — only band
  width and LR move. This is the direct answer to "β sets both the band and the
  gain".
- Stated honestly as *secondary / not shipped as numbers*: the fixed-threshold
  and single-score ablations. The cost model's value is already carried by the
  derived-band result (there is no threshold to fix) and the β sweep (the band is
  invariant in shape); the two-axis meter's value by the calibration finding (bait
  selected by category, divert malice-only). A faithful fixed-threshold arm needs
  a policy variant scoring bait on realised outcomes, not immediate cost — future
  work, not a misleading analytical number.
- Backing: RESULTS.md; `tests/test_fact_notebook.py` (notebook ablation);
  `tests/test_stats_sensitivity.py` (β-invariance); NOVELTY.md Contribution 5;
  `adf/policy/voi.py::survival_discount`; `data/eval/beta_sweep.json`.

### 10. Limitations
- Lead with them (reviewer-friendly). Separate **eliminated** (the 100 %
  benign-API FP, the crawler 404 FP — fixed and shown fixed) from **irreducible**
  (the forgetful-login FP; no lab substitute for real production traffic or
  independent human deception testing).
- Backing: [LIMITATIONS.md](LIMITATIONS.md) (eliminated-vs-irreducible framing).

### 11. Related work
- WAFs (signature + learned), honeypots/deception, honeytokens, LLM-generated
  decoy content, value-of-information in security. Position: each ingredient
  exists; the decision rule that prices *when* to deceive, with derived
  parameters, does not.
- Backing: [LITERATURE_REVIEW.md](LITERATURE_REVIEW.md).

### 12. Conclusion
- The one thing to remember: without the VoI term there is no third action, so
  the probe cannot be a tuned threshold — it is priced. Everything measured
  confirms it fires where the proof predicts and is safe where it must be.

---

## Figures and tables to cut for the paper

All figures are generated by `tools/make_figures.py` as vector SVG (docs) + PDF
(LaTeX) in `docs/img/` and `docs/img/pdf/` — publication-quality matplotlib,
Okabe–Ito colour-blind-safe palette.

| # | Artifact | File / source |
|---|---|---|
| Fig 1 | Request path (proxy → meter → policy → 3 actions → log), with the bite loop | `img/architecture.svg` |
| Fig 2 | Two-axis (automation×malice) — why one score is not enough | `img/two-axis.svg` |
| Fig 3 | Expected-cost curves for pass/bait/divert vs p, band shaded (two-panel) | `img/cost-curves.svg` |
| Fig 4 | Decision bands: 3 derived vs the cost-only 2-action rule | `img/decision-bands.svg` |
| Fig 5 | **β-invariance** — band edges + width vs β_attack | `img/beta-invariance.svg` |
| Fig 6 | Invisibility gate — three tests, verified before use | `img/invisibility-gate.svg` |
| Fig 7 | EVSI decay vs bait exposures (→ passive limit) | `img/evsi-decay.svg` |
| Fig 8 | **Holdout causal effect** — baited vs withheld, with CI (the headline) | `img/holdout-effect.svg` |
| Fig 9 | **Recall forest** — per-arm recall, Wilson CIs (B2/B4 separate) | `img/recall-forest.svg` |
| Fig 10 | **Seed stability** — B4 > B2 in 20/20 seeds (paired slope) | `img/seed-stability.svg` |
| Fig 11 | Recall by category — the gain is all IDOR | `img/recall-by-category.svg` |
| Fig 12 | Cost per session by arm — attacker containment | `img/cost-by-arm.svg` |
| Tbl 1 | Headline results at a glance (value, CI, test, significance) | RESULTS.md |
| Tbl 2 | Baseline comparison (B0/B1/B2/B4), pooled + CIs | RESULTS.md |
| Tbl 3 | Randomised-holdout causal estimate + Fisher exact p | RESULTS.md |
| Tbl 4 | Recall by category / bait effect by subcategory + paired McNemar | RESULTS.md |
| Tbl 5 | Benign diversion by class (safety) | RESULTS.md |
| Tbl 6 | Ablations (no-bait, no-notebook 0%→100%, β-sweep invariance) | RESULTS.md |
| Tbl 7 | Notation | METHODOLOGY.md §1a |

## What is genuinely future work (do not claim)
- Real production traffic and independent human deception testing — cannot be
  substituted in a lab; the honest benign corpus is the best available proxy.
- A second, structurally different target application — the current second-target
  idea (blind-injection variant) did not change detection because the SQL
  keyword features fire on syntax regardless of the echo channel; a genuinely
  different app (different framework, different object model) is the real test.
- Full fixed-threshold and single-score ablation arms (see §9).
