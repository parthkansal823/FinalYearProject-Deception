# Why the hand-set edges beat the derived ones

> **Re-measured on the browser-driven corpus (2026-08-19).** This document was
> first written against the raw-HTTP round-2 attacker, which never fetched a page
> sub-resource while 96.5% of human-paced benign sessions did (Section 6). That
> attacker has been fixed and everything below re-measured.
>
> Every finding survived the change. The belief is still not calibrated — held-out
> ECE **0.157 as shipped against 0.018 calibrated**, against 0.176/0.019 before —
> the belief still has almost no resolution, and the two errors still point in
> opposite directions. The figures moved; the diagnosis did not.

The fixed-threshold ablation returned a negative result: two hand-set edge pairs
beat the derived edges on expected cost per session. This document is the
investigation of *why*, because a negative result whose cause is unknown is not
usable, and one whose cause is understood usually turns out to be about something
other than what it appeared to be.

The short version: the derived edges are not being outperformed by better
judgement. They are being applied to a belief that is not a probability, and read
at a precision the belief cannot support. Two separate modelling errors point in
opposite directions and very nearly cancel, which is why the shipped
configuration looks close to optimal despite both.

**Nothing in this document changed a frozen artefact.** `config/costs.yaml` — the
cost matrix and the fusion block — is byte-identical to the version every
reported number was produced under. See *What was deliberately not done*.

---

## 1. The belief is not calibrated

The policy consumes `p_attack` as a probability: every band edge is a probability
threshold derived from the frozen cost table. The meter that produces it is a
hand-weighted logistic model that was never fitted to labels, so nothing had ever
checked whether its output behaves like one.

Measuring that needs labelled scores from traffic the evaluation never sees.
`tools/calibration_split.py` generates four draws on seeds far below the
evaluation range (20250401+, against the evaluation's 20260913+), so nothing
fitted here can reach a reported result.

Reliability of the shipped belief, 12,954 scored requests:

| belief bin | n | mean belief | actual P(attack) | 95% CI | |
|---|---|---|---|---|---|
| [0.10, 0.20) | 2,223 | 0.1628 | **0.0027** | [0.001, 0.006] | over-confident |
| [0.40, 0.50) | 7,400 | 0.4711 | **0.2696** | [0.260, 0.280] | over-confident |
| [0.50, 0.60) | 155 | 0.5719 | 0.3677 | [0.296, 0.446] | over-confident |
| [0.60, 0.70) | 690 | 0.6504 | **0.8826** | [0.856, 0.905] | under-confident |
| [0.70, 0.80) | 646 | 0.7561 | 0.9954 | [0.986, 0.998] | under-confident |
| [0.80, 0.85) | 176 | 0.8278 | 0.9943 | [0.969, 0.999] | under-confident |
| [0.85, 0.90) | 149 | 0.8669 | 1.0000 | [0.975, 1.000] | under-confident |

The belief is over-confident below about 0.6 and under-confident above it, and
the crossover is a step rather than a slope: the truth moves from 0.37 to 0.88
while the belief moves from 0.57 to 0.65.

Three calibration maps were fitted and compared by **leave-one-draw-out held-out
ECE**, so the winner is the one that survives a withheld draw rather than the one
that fits best:

| method | held-out ECE | held-out Brier |
|---|---|---|
| shipped (identity) | 0.1568 ± 0.0077 | 0.1489 |
| Platt (2 params) | 0.0396 | 0.1200 |
| Beta (3 params) | 0.0445 | 0.1200 |
| **Isotonic** | **0.0181 ± 0.0038** | **0.1161** |

Isotonic wins, reducing held-out ECE by **88.4%**.

---

## 2. The belief has almost no resolution

The calibration table above hides something the raw distribution makes obvious.
Across 12,954 decisions the meter produces 227 distinct values, and:

| belief | requests | share |
|---|---|---|
| 0.4758 | 5,848 | 45.1% |
| 0.1633 | 2,154 | 16.6% |
| 0.4629 | 1,061 | 8.2% |
| 1.0000 | 536 | 4.1% |

**Two values account for 55.7% of every decision the policy makes.**

This makes the derived band's four decimal places illusory. Any PASS→BAIT edge in
(0.1633, 0.4629] produces identical behaviour; so does any edge below 0.1633. The
edge is not being tuned to a value — it is choosing between two options, "bait
both plateaus" or "bait only the upper one".

The measured benign-bait rates confirm this exactly:

| arm | lower edge | plateaus baited | benign-bait rate |
|---|---|---|---|
| [0.05, 0.95] | 0.05 | both | 0.896 |
| [0.05, 0.8163] | 0.05 | both | 0.896 |
| [0.10, 0.90] | 0.10 | both | 0.903 |
| [0.1867, 0.6186] | 0.19 | upper only | **0.632** |
| [0.20, 0.80] | 0.20 | upper only | **0.649** |
| [0.30, 0.70] | 0.30 | upper only | **0.639** |

The rate splits cleanly on whether the edge clears 0.1633 and is flat within each
group, though the edge varies by 2× in the first group and 1.5× in the second.

---

## 3. Per-request thresholds, per-session costs

The policy tests its edges once per request. The cost table charges once per
session. A benign session with fifty requests therefore gets fifty chances to trip
the DIVERT edge, so what governs the benign false-positive rate is the
distribution of the *maximum* belief a session reaches, not `P(attack | p)` at any
one request.

Benign belief ceilings: median 0.4758, p90 0.5436, p99 0.7344, **max 0.8287**.

The shipped DIVERT edge is **0.8793** — above the benign maximum. That, and not
the derivation's precision, is why the shipped configuration diverts zero benign
sessions.

Nothing in the EVSI derivation accounts for repeated application. It prices one
decision. Deployment makes it a first-crossing rule.

---

## 4. Two errors of opposite sign

- The belief is under-confident at the top, which pushes the derived edge
  **higher** in raw-meter terms than the cost model intends.
- The rule is derived per-decision but applied per-session, which means the
  cost-optimal edge is **higher** than the per-decision indifference point.

Correcting only the first moves the DIVERT edge from 0.8793 down to **0.6423** in
raw-meter terms — into the benign upper tail, between p90 and p99. The shipped
edge sits where it does because the two errors nearly cancel, not because the
derivation got the answer right.

---

## 5. The derived edges on a calibrated belief, measured

Because every calibration map is monotone, running the derived edges on a
calibrated belief is arithmetically the same policy as running the inverse-mapped
edges on the raw belief. The existing `b5_fixed` arm already implements exactly
that, so the calibrated policy is measurable **without re-freezing anything**.

Derived edges (0.0646, 0.8793) on a calibrated belief = raw edges
**(0.1867, 0.6186)**.

Measured over 19 seeds shared with every other arm, 3,800 sessions per arm:

| edges (raw belief) | | cost/session | recall | benign diverted |
|---|---|---|---|---|
| [0.2000, 0.8000] | fixed | **-10.393** [-10.545, -10.242] | 0.9524 | 3/3840 |
| [0.0500, 0.8163] | fixed | -10.168 [-10.322, -10.015] | 0.9477 | 3/3840 |
| [derived edges] | **DERIVED, as shipped** | -10.030 [-10.167, -9.892] | 0.9403 | **0/3840** |
| [0.3000, 0.7000] | fixed | -9.989 [-10.284, -9.694] | 0.9705 | 46/3840 |
| [0.1000, 0.9000] | fixed | -9.881 [-10.050, -9.712] | 0.9349 | **0/3840** |
| [0.1867, 0.6186] | **DERIVED, calibrated belief** | -9.497 [-9.875, -9.119] | **0.9792** | 81/3840 |
| [0.0500, 0.9500] | fixed | -9.246 [-9.395, -9.098] | 0.9113 | **0/3840** |

Calibrating the belief produces the **best recall of any configuration measured**,
and the improvement is not marginal. Paired McNemar on matched attack sessions:
245 sessions are caught by the calibrated policy alone against 21 by the shipped
one, **p = 1.34 x 10^-49**.

It also produces 31 benign diversions where the shipped configuration produces
none, and under the frozen cost table that decides the matter. Expected cost per
session is -9.497 against -10.030.

**Break-even: 136.9.** Calibrating wins whenever a benign diversion is priced
below that. The frozen table prices it at 200, which is **46.1% above** break-even
— so this is not a close call under the prices this system was built to respect.

Two things follow, and they point in opposite directions, which is why both belong
in the paper:

* As a **detector**, the calibrated belief is clearly better: +4.2 points of recall
  at p < 10^-22, from a map fitted on traffic the evaluation never saw.
* As a **policy under this cost table**, it is clearly worse, because the cost
  table prices one benign diversion at eight times a missed attack.

Which of those is "the improvement" is not a question the data answers. It is a
question the cost table answers, and the cost table was written down first.


---

## 6. What "better technology" would and would not buy

The suspicion meter's 18 features were given hand-set weights. Fitting them
instead is the obvious upgrade, and `tools/meter_headroom.py` measures what it
would be worth, leave-one-draw-out on the calibration split:

| model | AUC | ECE | Brier |
|---|---|---|---|
| meter (shipped, hand-set) | 0.8820 | 0.1760 | 0.1557 |
| logistic regression (fitted) | **0.9991** | 0.0080 | 0.0111 |
| gradient boosting (fitted) | 0.9988 | 0.0139 | 0.0157 |

An out-of-sample AUC of 0.999 on simulated traffic is a warning, not a result.
Splitting the features by family shows where it comes from:

| feature family | held-out AUC (before the fix) |
|---|---|
| automation features only | **0.9935** |
| malice features only | 0.8774 |
| shipped hand-set meter | 0.8820 |

Making half the attackers browser-driven takes the automation-only figure from
**0.9935 to 0.898**, while malice-only is unmoved at 0.892. The separation that
remains is a real property of the population — attack tooling genuinely skews
scripted — rather than the near-perfect one an all-raw-HTTP corpus manufactured.
The fraction was deliberately not raised further to drive the number down; that
would be fitting the corpus to a desired measurement.

The automation features separate the classes almost perfectly, for a reason that
has nothing to do with hostility:

| feature | attack (human-paced) | attack (scripted) | benign (human) |
|---|---|---|---|
| `auto_fetched_assets` | **100% zero** | **100% zero** | 3.5% zero |
| `auto_browser_header_ratio` | 0.667 always | 0.667 always | 1.000 always |

**No attack session in the corpus ever fetches a page sub-resource**, while 96.5%
of human-paced benign sessions do. That is a property of the attack generator, not
of attacks — real tooling driving a headless browser fetches sub-resources
automatically. It is the same class of flaw as the round-2 attacker that never
read responses.

Two conclusions follow.

**The reported results are not contaminated.** `w_automation = 0.0` in the fusion
block, so automation never enters the hostility belief; it is spent on bait
selection. Verified against the logs rather than against the config: across all
12,954 scored requests, `p_attack` equals the malice score exactly (within the
documented 1e-6 clamp) while the automation score ranges over [0.0000, 1.0000].

**Fitting the meter would make the paper worse.** The hand-set meter scores 0.8820
against a malice-only ceiling of 0.8774 — it is already extracting what the
non-leaky features carry. The entire apparent headroom is the generator artefact.
A fitted meter would report a far better number and a far weaker claim.

The honest upgrade is not a better model. It is a better attack generator: one
that fetches sub-resources and sends browser-shaped headers, which would remove
the artefact and make the automation features mean what they are supposed to mean.

---

## What was deliberately not done

- **The cost matrix was not touched.** Re-pricing after seeing results would
  invalidate every baseline comparison in the evaluation.
- **The fusion block was not re-fitted**, though `config/costs.yaml` explicitly
  permits it ("may be fitted in Phase 3 IF the calibration data supports it").
  Adopting the calibration would re-freeze an artefact every reported number
  depends on, and the monotone-equivalence above makes that unnecessary for
  measuring the effect.
- **The meter was not re-fitted**, for the reason in §6.
- **No evaluation seed was reused for fitting.** The calibration split runs on
  20250401+; the evaluation runs on 20260913+.

## Reproducing

```
python -m tools.calibration_split --draws 4      # held-out split
python -m tools.fit_calibration                  # fit + method selection
python -m tools.meter_headroom                   # what refitting would buy
python -m tools.fixed_threshold_sweep --seeds 20 --port-base 9700 \
    --grid "0.4562,0.6423"                       # the calibrated policy
python -m tools.calibration_report               # the comparison
```
