# What is actually new here

Written for the paper. The specification's §4 already states five
contributions; this document sharpens two of them into claims that are
mathematically defensible rather than merely plausible, and adds a third that
strengthens the evaluation. It also states plainly what is *not* new, because
a contributions section that overclaims is the fastest way to lose a reviewer.

> **New to the project?** [OVERVIEW.md](OVERVIEW.md) explains the whole system
> in plain language, with diagrams. This document assumes it and goes straight
> to the arguments.

---

## The short version

| The claim | In one sentence | How strong |
|---|---|---|
| 1 · Bait is **priced**, not guessed | Probing is the cost-optimal action over a band derived from the cost of errors and the measured effectiveness of the probe — a band that does not exist at all under cost accounting alone. | applied decision theory (EVSI, Howard 1966) + implementation |
| 2 · The bite weight is **derived** | The evidence value of a bite is a likelihood ratio estimated in a dedicated calibration round, not a constant chosen to make the system work. | measured |
| 3 · Bait is a **randomised treatment** | 10% of sessions that reach the bait band are deliberately not baited, so bait's effect on time-to-decision is a causal estimate rather than a comparison between two different systems. | experimental design |
| 4 · The benign corpus is **built to be hard** | The safety numbers are measured against honest traffic that genuinely looks like an attack, not against traffic that could never have been misclassified. | measured |
| 5 · **Limiting rule converges to its baseline** | Against an adversary who refuses every probe, the decision rule converges to the passive two-action rule as exposures accumulate, so it cannot be *asymptotically* worse than passive (a property of the rule, not a per-session guarantee). | argued from EVSI decay + measured |

If you remember one thing: **without the value-of-information term there is no
third action at all**, so it cannot be a tuned threshold.

---

## Not new (state this early in the paper)

- Using a language model to write realistic fake content. Studied since 2022.
- Machine-learned detection of web attacks. That is a WAF.
- Redirecting a detected attacker into a honeypot.
- Honeytokens: planting a fake credential or file as a tripwire. Widely
  deployed commercially.

The novelty is not any single ingredient. It is the decision rule that
decides *when to deceive*, and the fact that its parameters are derived
rather than chosen.

---

## Contribution 1 — Bait priced as an information purchase

**The claim.** Response-side probing is not a heuristic middle option between
allowing and blocking. It is the action that maximises the expected value of
sample information, and its operating band is a *derived consequence* of the
cost of errors and the measured effectiveness of the probe.

**What is and is not new here — state this plainly.** The decision-theoretic
object is the Expected Value of Sample Information (EVSI), which is textbook
(Howard, 1966 — [R29] in the literature review). We claim **no new mathematics**:
V(p) ≥ 0 is an immediate consequence of Jensen's inequality — a lemma, not a
theorem. The contribution is the **application**: recognising that a response-side
probe *is* a sample-information purchase, and that pricing it as one turns the
"middle option" from a tuned heuristic into a derived action whose band falls out
of the cost table. Framed as a result: *under a fixed error-cost table, a
probe with strictly positive information value is the cost-optimal action exactly
on the belief interval where its EVSI exceeds its residual immediate cost; under
cost accounting alone that interval is empty.* The novelty is that this has, as
far as we found, not been applied to the when-to-deceive question in web defence.

**Why this is stronger than the original framing.** The specification argues
that bait is worth deploying because it is cheap (§6.5): wasted bait costs
"near zero", so the middle band is wide. That argument works, but it hides the
mechanism in two hand-set numbers:

1. the cost of baiting an attacker is "discounted [...] to reflect that
   purchased information" — a discount nobody computed;
2. on a bite the malice score "jumps sharply" (§5.2) — a jump nobody derived.

Both are the same quantity, counted twice and measured never. A reviewer who
reads §6.5's insistence that thresholds are derived rather than tuned will go
looking for exactly these constants.

**What this implementation does instead.** Bait carries its *true* immediate
cost. The request still reaches the real application, so baiting an attacker
costs precisely what passing them costs (25.0 = 25.0 in the frozen table).
Bait therefore has **no immediate benefit at all** — it is strictly more
expensive than passing at every belief, by the residual invisibility risk
borne by the benign probability mass.

Its entire value is informational, and that value is computed:

```text
V(p) = min_a E[C(a) | p]  −  E_Z[ min_a E[C(a) | p after observing Z] ]
```

the expected reduction in optimal cost from observing the bait outcome
Z ∈ {bite, no bite}. The decision rule becomes

```text
effective_cost(pass)   = E[C(pass)   | p]
effective_cost(divert) = E[C(divert) | p]
effective_cost(bait)   = E[C(bait)   | p] − V(p)
```

and the cheapest wins.

**Three properties worth putting in the paper.**

1. **V(p) ≥ 0 always.** `min` over linear functions is concave, so Jensen's
   inequality gives it in two lines. Information never hurts. This is a standard
   lemma (we do not claim it as ours), but it is a much stronger and more
   verifiable statement than the spec's "bait is cheap", and we enforce it as an
   invariant. *(`tests/test_policy.py::test_information_is_never_harmful`)*

2. **V(0) = V(1) = 0.** When you are already certain, no observation can
   change the decision, so probing is worth exactly nothing. The bait band is
   therefore bounded on both sides *by construction* — it cannot swallow the
   whole probability range, and it cannot be widened by tuning.

3. **Without the information term there is no third action at all.** On
   immediate cost alone the policy collapses to an ordinary two-outcome rule,
   PASS below p = 0.816 and DIVERT above it, with no middle band anywhere.
   *(`tests/test_frozen_artefacts.py::test_cost_accounting_alone_does_not_justify_bait`)*

   This is the sharpest available answer to "isn't your third option just a
   tuned threshold?" — without the EVSI term there is no third option to tune.

With the frozen cost table and the **calibrated** bait effectiveness (the
paper-carrying bait B-IDOR-2: β_attack = 0.59, β_benign = 0.0037, measured over
n = 244 in the calibrate round), the derived bands are:

```text
PASS    p < 0.0516
BAIT    0.0516 ≤ p < 0.8626
DIVERT  p ≥ 0.8626
```

Contrast the single boundary under cost accounting alone — **PASS/DIVERT at
p = 0.816, no middle band** — which is the derived result stated above (property 3).

![Two-panel line chart of expected cost against hostility probability p. Panel A, full range: pass rises linearly from 0 to 25; immediate bait runs just above it; divert falls steeply from 200 off the top of the axis, crossing the frame near p=0.85; effective bait, immediate bait minus the value of information V(p), stays near 1 across the shaded derived band from 0.0516 to 0.8626 before rising sharply. Panel B zooms on p from 0 to 0.12, where pass crosses above effective bait at p=0.0516.](img/cost-curves.svg)

**Figure 1.** Expected cost of each action vs. the hostility probability $p$,
computed from the frozen cost table and the calibrated bait library. Bait carries
its *true* immediate cost (just above pass); only after subtracting the value of
the information it buys, $V(p)$, does *effective bait* become the cheapest action —
and only inside the **derived** band $[0.0516,\,0.8626]$. Reproduce every number
with `python -m adf.policy`.

![A two-row band diagram over the p axis from 0 to 1. Top row, with the EVSI term: three coloured regions — PASS below 0.0516, BAIT from 0.0516 to 0.8626, DIVERT above. Bottom row, cost accounting alone: two regions with a single PASS to DIVERT boundary at 0.816 and no middle band.](img/decision-bands.svg)

**Figure 2.** The derived decision bands. *Top:* with the value-of-information
term, three actions over $p\in[0,1]$. *Bottom:* under cost accounting alone, a
single PASS/DIVERT boundary at 0.816 and **no middle band at all** — the third
action is a consequence of pricing information, not a tuned threshold.

Nothing in those numbers was chosen. Change the cost of a wrongly diverted
user, or measure a different bite rate, and they move on their own — as the next
figure shows across the whole range of the one estimated parameter.

![Two-panel figure. Left: the PASS-to-BAIT and BAIT-to-DIVERT band edges plotted against beta_attack from 0.05 to 0.99, with the BAIT band shaded between them; the BAIT-to-DIVERT edge stays above a dashed horizontal line marking the cost-only boundary at 0.816 for every value, and a dotted marker shows the calibrated beta of 0.59. Right: the band width increases smoothly with beta_attack from about 0.4 to 0.85 but is never zero.](img/beta-invariance.svg)

**Figure 3.** Sensitivity of the derived bands to $\beta_{\mathrm{attack}}$, the
one parameter estimated in the attacker model. Across the whole range the BAIT
band stays **non-empty** and the divert threshold stays **above the cost-only
boundary** (0.816); only the band *width* and the bite likelihood ratio move. The
existence of the third action and the safety-relevant divert floor do not depend
on the point estimate (`tools/beta_sweep.py`).

**Bonus: bait selection stops being hand-waved.** Spec §6.6 asks for "a bait
appropriate to the suspected attack category" without defining appropriate.
EVSI defines it: deploy the bait with the highest V(p) for this session. And
this is where the two-axis suspicion model finally earns its keep — the
automation score indexes *which* bait's effectiveness applies (a scripted
scanner and a careful human take different bait at different rates), while
malice supplies the belief p. The two scores are doing genuinely different
jobs rather than being decorative.

---

## Contribution 2 — The bite weight is derived, and it has a calibration round

**The claim.** The evidence value of a bite is a likelihood ratio estimated
from data, not a constant chosen to make the system work.

```text
LR(bite)    = P(bite | attacker) / P(bite | benign)
LR(no bite) = P(no bite | attacker) / P(no bite | benign)
```

Reporting the second matters: a system that only ever updates suspicion upward
accumulates without bound and will eventually divert somebody for browsing
slowly. Declining a bait is weak evidence of innocence, and the model says so.

**The problem this exposed in the original plan.** These parameters had **no
legitimate source of data**. Spec §13 runs attack round 1 (Phase 2) *before*
the bait library is built (Phase 4), so the training corpus contains no bait
and therefore no bites. Round 2 is the held-out test set. Estimating bait
effectiveness on either would be indefensible, and there was no third option.

**The fix.** A dedicated `calibrate` round (attack round 1b), run after Phase 4
and frozen before Phase 7, whose *only* permitted use is estimating bait
effectiveness. The round vocabulary is now `dev | train | calibrate | eval`,
each with exactly one permitted use, enforced in the frozen schema.

`P(bite | benign)` is separately measurable, cheaply, on the benign corpus —
and it should come out at essentially zero, because bait is invisible to a
real browser. It is *not* assumed zero: a hard zero makes the likelihood ratio
infinite and would assume away precisely the safety property the project
exists to measure. Jeffreys smoothing with a stated floor is used instead.

---

## Contribution 3 — Bait as a randomised treatment, not a system comparison

**The claim.** The headline result — that provoking reduces the number of
requests needed to reach a confident decision — is established by a randomised
experiment inside one system, not by comparing two different systems.

**Why the original design is weaker.** Spec §10.1 compares the full system
against baseline B2 (passive classifier, no bait). But B2 and B4 differ in
every component, so any difference in time-to-decision is confounded with all
of them. It is a between-systems comparison presented as evidence about one
mechanism.

**What this implementation adds.** A configurable fraction (default 10%) of
sessions that reach the bait band are deliberately **not** baited. They are
recorded as `bait_assignment: holdout` — distinguishable in the log from
sessions that were not baited because the policy chose PASS.

Because assignment is random, conditional on having reached the same belief
state, the treated/untreated difference is an **unbiased causal estimate of
the effect of baiting**, free of the confounding that a system comparison
carries. Assignment is a hash of (seed, session id): deterministic, so runs
replay exactly (NFR-08), and unpredictable to anyone who cannot see the seed.

It costs a little detection performance by design, and that cost must be
reported. In exchange the paper can say *bait caused this*, which almost
nothing in this literature can.

Keep the B2 comparison as well — it answers a different and also useful
question ("is the whole system better?"). The holdout answers the sharper one.

---

## Contribution 4 (supporting) — A benign corpus built to be hard

**The claim.** The safety result is measured against benign traffic that
genuinely approaches the decision boundary, not against traffic that could
never have been misclassified in the first place.

**Why this needs saying.** "Benign bait exposure rate" and "benign diversion
rate" (spec §10.3, NFR-05) are the numbers that carry the safety half of the
paper. Both are trivially zero if the benign corpus consists only of users
who browse gently and never do anything unusual — and a reviewer will ask
exactly that. A near-zero false-positive rate is only interesting in
proportion to how hard the negatives were.

So the corpus deliberately contains benign sessions that look like attacks:

| Class | What it does | Which attack it mimics |
|---|---|---|
| `apostrophe_searcher` | looks up a colleague named *O'Connell* | SQL injection probe — verified to return the identical verbose driver error (`near "Connell": syntax error`, HTTP 500) |
| `forgetful` | fails login 3–5 times, then succeeds | credential attack; the exact trigger condition for B-AUTH-1 |
| `integration` (agent) | walks record ids in ascending order over the API | IDOR sweep — differing only in that every id belongs to it |
| `monitor` (agent) | metronomic polling, no cookies, no assets | scanner — every automation feature in §6.3 fires at once |

![A two-by-two grid of automation against malice, showing where each traffic class sits. The two shaded off-diagonal cells — a careful human attacker, and benign automated clients — are the ones a single combined score cannot express.](img/two-axis.svg)

The first is the one to put in the paper. A staff member looking up a
colleague in the directory produces a response byte-identical in kind to what
an attacker sees while probing for injection. Any system that separates them
has learned something about *intent and context* rather than about payload
shape — and if the final system cannot separate them, that is a genuine
finding about the limits of response-level detection, reportable under §7.4
rather than quietly excluded from the corpus.

**Important labelling discipline.** These personas are recorded in
`labels.notes`, never in the class labels. An awkward honest user is exactly
as benign as a straightforward one; encoding "this one looked suspicious" into
the label would teach the meter that unusual means hostile, which is the
brittle heuristic the whole project exists to replace. Keeping it in notes
still lets the analysis report *where* the false positives concentrate, which
is more informative than a single aggregate rate.

---

## Contribution 5 — Robustness against a bait-aware adversary

**The claim (stated carefully).** Against an attacker who knows the defence
exists and refuses every probe, the full system's **decision rule converges to
the passive two-action rule** as unrewarded exposures accumulate, and therefore
cannot be *asymptotically* worse than passive. This is a statement about the
limiting rule and the aggregate — **not** a per-session monotonicity guarantee.
Within a finite evaluation horizon the full system raises the divert threshold
(0.816 → 0.8626), so an individual session whose belief sits in that narrow band
and never bites can be *baited* (deferred) where passive would have *diverted*
immediately; such a session is resolved later, or — if the horizon ends first —
missed within the horizon. We report those discordant cases honestly (the
paired-McNemar *c* count), and they are exactly why the claim is scoped to the
limiting rule rather than to every session.

**Why this needs its own contribution.** Spec §18 lists the adaptive adversary
as out of scope: "An attacker who [knows this defence exists] could probe for
bait deliberately, and countering that is out of scope." Every deception paper
has some version of that sentence, and a reviewer will read it as the weak
point. Measuring it instead is cheap and turns the weakness into a result.

**How it is measured.** A bait-aware adversary with a tunable
`bait_awareness ∈ [0,1]` — the probability it recognises a planted token and
declines it — is swept across two archetypes: one that escalates into
aggressive injection (testing the floor), one that stays low-and-slow in the
band where passive detection is uncertain (testing bait's value, and the cost
of refusing it). The probe sequence is fixed, so the only variable is whether
the attacker acts on what it is shown.

**What the sweep found — and this is the honest part.** The first run exposed a
real defect. Offering a third action *raises* the divert threshold (0.816 →
0.8626 with the calibrated library), so an adversary who kept its belief inside
that gap and never bit was baited indefinitely rather than diverted: **0%**
diverted by the full system versus **100%** by its own passive baseline B2. The
full system was strictly worse than the baseline it exists to beat.

**The fix is a modelling correction, not a tuned parameter.** EVSI prices a
probe as fresh information. That holds the first time and fails the tenth: a
session that has declined the same bait repeatedly has already answered the
question. The value is now discounted by

```text
(1 − β_attack)^exposures
```

— the probability that a genuinely hostile session would decline this bait that
many times in a row by chance — using the bait's **own calibrated
effectiveness**, so no constant is chosen by hand. As the discount bites, V → 0
and the policy converges to exactly the two-action decision it would have made
had bait never existed.

![Line chart of the surviving EVSI fraction, one minus beta_attack raised to the power n, against the number of unrewarded bait exposures n from 0 to 12, for four beta_attack values 0.20, 0.40, 0.59 and 0.80 drawn as a light-to-dark green ramp. Every curve starts at 1 and decays to near zero; larger beta_attack decays faster.](img/evsi-decay.svg)

**Figure 4.** The EVSI survival discount $(1-\beta_{\mathrm{attack}})^{n}$ against
unrewarded exposures $n$. A bait that has been shown and refused repeatedly has
already answered its question, so its information value decays to zero and the
decision rule converges to the passive two-action limit — the mechanism behind
the robustness result below (`adf/policy/voi.py::survival_discount`).

**Table (awareness sweep).** Divert rate against a bait-aware adversary, before
and after the survival-discount fix:

| bait-awareness | divert rate, before fix | after fix |
|---|---|---|
| 0.00 (naive) | 88% | 92.5% |
| 0.75 | 83% (median requests 5 → 8) | 82.5% |
| 1.00 (fully aware) | **0%** | **92.5%** |

The escalating adversary diverts 100% at every awareness level, before and
after: bait never blinds the passive features, because it is invisible and inert
by construction.

**The property this buys.** *In the limit of repeated unrewarded exposure the
full system's decision rule is identical to its passive baseline, so it cannot be
asymptotically worse — whatever the adversary knows.* That is a weaker-sounding
claim than a headline win and a much stronger one to defend, because it holds
against an adversary specifically built to defeat the mechanism, and because it
does not depend on statistical power: it is a property of the rule, provable from
the EVSI decay, not an average over a sample.

**What it does *not* claim, said plainly.** It is not a per-session guarantee.
Because bait raises the divert threshold over the narrow band [0.816, 0.8626], a
finite-horizon evaluation can contain isolated sessions that passive diverts and
the full system, still deferring for information, does not — the discordant
"B2-catches-B4-misses" pairs a paired McNemar counts as *c*. Those are expected,
they are bounded to that thin band, and reporting the *c* count is how we keep the
claim honest rather than pretending per-session dominance we cannot prove.

**Two tests pin it** — one that the policy stops deferring after repeated
refusal (deriving the gap from the fixture, so it is calibration-independent),
one that first-contact behaviour, and therefore every derived band reported
above, is unchanged.

---

## What to claim, and how strongly

| Claim | Strength | Evidence |
|---|---|---|
| Bait is the EVSI-optimal action in a derived band | **Applied standard result** (EVSI/Howard 1966; Jensen lemma) **+ implementation** | `test_information_is_never_harmful`; band invariance in `test_stats_sensitivity` |
| No tuned constants anywhere in the decision path | **Verifiable** | frozen cost table + calibrated β; both hash-enforced |
| Provoking reduces requests-to-decision | **Randomised experiment, paired McNemar / Fisher over 100 paired seeds** | holdout arm, round 2; `tools/stats_report.py` |
| Bait is invisible to real users | **Measured, with a stated bound** | invisibility gate + TOST equivalence |
| Low false positives against *hard* negatives | **Measured** | apostrophe/forgetful/integration classes |
| The decoy stays self-consistent | **Measured** | contradiction rate, consistency fuzzer |
| Limiting decision rule converges to passive under a bait-aware adversary (asymptotic, *not* per-session) | **Argued + measured** | awareness sweep; EVSI decay → two-action limit; per-session discordance reported as McNemar *c* |
| A public labelled dataset | **Artefact** | schema v3, frozen before collection |

Two of these — the EVSI band and the randomised holdout — do not appear in the
deception literature as far as the related-work survey has found. They are
also the two cheapest to defend, because one is a proof and the other is an
experimental design rather than a result that could fail to replicate.

---

## Suggested abstract-level sentence

> Existing web defences wait passively for an attacker to reveal themselves,
> forcing a choice between acting early on weak evidence and acting late on
> strong evidence. We show that this trade-off is avoidable: a defender can
> *manufacture* evidence by planting invisible, inert probes in responses, and
> the decision of when to do so follows from the expected value of the
> information the probe buys. Probing is not a heuristic compromise but the
> cost-optimal action over a band derived from the cost of errors and the
> measured effectiveness of the probe — a band that does not exist at all under
> cost accounting alone. We evaluate with a randomised holdout that identifies
> the causal effect of probing on time-to-decision, and we measure what
> probing costs the users it was never aimed at.
