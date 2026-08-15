# Title and abstract (for the abstract deadline)

Written to lead with what is defensible **without statistical power** — the
derived-band result and its β-invariance, the safety measurement, and the
methodological finding — and to state the recall gain honestly as directional.
This is deliberate: at a venue that values rigour, "we tested it and it is not yet
significant at this sample size" reads as integrity, not weakness.

---

## Title (primary)

**Pricing the Probe: When a Web-Attack Detector Should Deceive Rather Than Decide**

### Alternatives
- *Deception as an Information Purchase: A Priced Third Action for Web-Attack Detection*
- *When to Deceive: A Cost-Derived Probing Action Between Allowing and Blocking*

---

## Abstract (~230 words)

Web-attack detectors act in two moves — allow or block — and defer deception to
after a confident decision. We ask when a detector should take a *third* move:
plant an invisible, inert response-side probe to manufacture the evidence a
passive classifier would otherwise have to wait for. We show this middle action
is not a tuned heuristic but a **priced** one. Modelling the probe as an
Expected-Value-of-Sample-Information purchase (a standard object; the contribution
is its application), the belief interval over which probing is cost-optimal is a
*derived* consequence of the error-cost table and the probe's measured
effectiveness — and under cost accounting alone that interval is empty, so the
third action cannot be a tuned threshold. A parameter sweep shows the interval's
existence and the safety-relevant divert-threshold floor are **invariant** across
the full range of the one estimated parameter; only their magnitude moves.

We build a complete reproducible system (frozen, hash-verified model; an
invisibility gate certified before any probe; a state-consistent decoy whose
contradiction rate drops from 100% to 0% with its consistency layer) and evaluate
it against a hard benign corpus containing automated-but-harmless clients — whose
omission, we report, had hidden a 100% false-positive on benign API integrations.
The system diverts no automated client and no ordinary user. A randomised holdout
gives a causal estimate of the probe's effect; the aggregate recall gain is
directionally positive and we report its significance honestly.

---

## Contributions, in the order to claim them

1. **A priced third action.** Response-side probing is the cost-optimal action
   over a band *derived* from the cost table and the calibrated probe
   effectiveness; without the information term the band is empty (no tuned
   threshold to attack). *Applied EVSI (Howard 1966); V(p) ≥ 0 is a Jensen lemma
   — we claim the application, not the mathematics.*
2. **β-invariance of the conclusions.** Across β_attack ∈ [0.1, 0.9] the band
   stays non-empty and the divert threshold stays ≥ the cost-only boundary; the
   existence of the third action and the safety guarantee do not depend on the
   one chosen parameter (`tools/beta_sweep.py`).
3. **A measured safety result on a hard corpus.** Zero diversions among automated
   clients and ordinary users, against a benign set built to look like an attack;
   the only residual false positive is a deliberately-included hard-negative
   persona. Reported with confidence intervals.
4. **A methodological finding.** A human-only benign set concealed a 100%
   false-positive on benign JSON-API integration clients; only adding
   automated-but-harmless agents exposed it. A metric tests only what its inputs
   contain.
5. **A causal estimate via randomised holdout**, and a **limiting-rule robustness
   result**: against a bait-aware adversary the decision rule converges to the
   passive two-action rule (asymptotic, not per-session).

## What we explicitly do not claim
- No new decision theory; EVSI is textbook and we say so.
- The aggregate recall gain (0.87 → 0.90) is **directionally positive; at a single
  draw of n = 120 it is not yet statistically significant.** A multi-seed,
  paired-test re-estimation is what settles it. We test it and report the result
  either way.
- No per-session dominance over passive; only a limiting-rule guarantee.
- Synthetic traffic, single target, single machine — a controlled laboratory
  study, not an internet-scale one.
