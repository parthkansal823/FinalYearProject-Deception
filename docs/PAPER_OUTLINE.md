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
  tuned threshold; safe on a hard benign corpus and never worse than passive.
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
- Set up the three-action expected-cost problem. Prove the two results:
  1. **Bait is never optimal on immediate cost alone** — under cost accounting
     there is a single PASS/DIVERT boundary (derived at p ≈ 0.816 in the frozen
     table); no third action exists.
  2. **The middle band exists only once the value of sample information (EVSI)
     is added**, and V(p) ≥ 0 by Jensen, so probing can never make the decision
     worse in expectation.
- State that the band's edges are *outputs* of the cost table and the calibrated
  bite likelihood ratio, not inputs — this is what makes it "derived, not tuned."
- Backing: [NOVELTY.md](NOVELTY.md) Contribution 1; `adf/policy/voi.py`
  (`choose_action`, `survival_discount`); proof reproduced by
  `tests/test_voi.py` (boundary location, V(p) ≥ 0, band non-empty only with the
  VoI term).

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
- **Baselines.** B0 (no defence, the ceiling on attacker success), **B1 (signature
  WAF** — a fair reference that catches textbook attacks, no benign FPs, but is
  brittle to double-encoding and blind to IDOR), B2 (passive scoring, the honest
  baseline to beat), B4 (full: bait + dual meter + cost policy + decoy).
- **Headline table.** recall / precision / F1 / req-to-decide / benign diversion
  / benign bait exposure / E[cost]. B4 recall 0.92 vs B2 0.87; B1's recall is
  bounded by its IDOR blindness (fill from the 4-arm run).
- **Where bait helps.** The 0.87→0.92 gain is *concentrated* in the one uncertain
  subcategory (UI-IDOR, 0.40→0.70 via the `internal_view` bite); neutral
  everywhere the passive classifier is already confident. This is the mechanism
  firing exactly where the theory says it should.
- **Causal estimate (Contribution 3).** Randomised holdout: 25 % of bait-band
  sessions withheld → bait's effect on divert rate is a within-system causal
  estimate (+14 pts aggregate; the clean 0.40→0.70 on the uncertain subcategory).
- **Safety (Contribution 4).** Benign diversion by class: 0 for every automated
  client and every ordinary user; the only FP is the forgetful-login hard
  negative (3/5), reported not hidden. Benign bait exposure high, benign bites 0
  — the invisibility gate at run time.
- Backing: [RESULTS.md](RESULTS.md) (every table); `tools/run_evaluation.py`,
  `tools/evaluate.py`, `tools/attack_traffic_round2.py`; `data/eval/summary.json`.

### 9. Ablations *(§10.2)*
- **No-bait** = B2 vs B4 in the headline table (recall 0.87 vs 0.92): isolates
  the probe's contribution to detection.
- **No-notebook** = §6 above (contradiction 0 % → 100 %): isolates consistency.
- **Adaptive adversary** (Contribution 5): against a bait-aware attacker who
  refuses every probe, EVSI decay drives the system to the passive floor and
  *provably not below* it — never worse than B2 in detection.
- Stated honestly as *secondary / not fully run*: the fixed-threshold and
  single-score ablations. The cost model's value is already carried by the
  theorem (derived vs tuned band); the two-axis meter's value is carried by the
  calibration finding (bait is selected by category, and divert is malice-only).
  A full fixed-threshold arm would need a policy variant that scores the bait
  action on realised outcomes, not immediate cost — flagged as future work rather
  than shipped as a misleading analytical number.
- Backing: RESULTS.md; `tests/test_fact_notebook.py` (ablation); NOVELTY.md
  Contribution 5; `adf/policy/voi.py::survival_discount`.

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

| # | Artifact | Source |
|---|---|---|
| Fig 1 | Request path (proxy → meter → policy → decoy) | `docs/img/` |
| Fig 2 | Expected-cost curves for pass/bait/divert vs p, with the derived band shaded | regenerate from `adf/policy/voi.py` + cost table |
| Fig 3 | EVSI decay vs bait exposures (adaptive adversary → passive floor) | `adf/policy/voi.py::survival_discount` |
| Tbl 1 | Baseline comparison (B0/B1/B2/B4) | RESULTS.md / `data/eval/summary.json` |
| Tbl 2 | Bait effect by subcategory (0.40→0.70 on UI-IDOR) | RESULTS.md |
| Tbl 3 | Randomised-holdout causal estimate | RESULTS.md |
| Tbl 4 | Benign diversion by class (safety) | RESULTS.md |
| Tbl 5 | Ablations (no-bait, no-notebook 0%→100%) | RESULTS.md + notebook ablation |

## What is genuinely future work (do not claim)
- Real production traffic and independent human deception testing — cannot be
  substituted in a lab; the honest benign corpus is the best available proxy.
- A second, structurally different target application — the current second-target
  idea (blind-injection variant) did not change detection because the SQL
  keyword features fire on syntax regardless of the echo channel; a genuinely
  different app (different framework, different object model) is the real test.
- Full fixed-threshold and single-score ablation arms (see §9).
