# 9  Ablations

Each component of the system is justified by removing it and measuring what breaks,
which is the discipline this kind of evaluation is repeatedly faulted for skipping
\cite{arp2022dos,sommer2010outside}.
Two of those removals are clean switches with a number on either side; one is a
property of the decision rule that shows up as a bound rather than a measurement;
and one is an ablation of our own attacker model, which turned out to relocate a
limitation we had been reporting in the wrong place.

## 9.1  Removing the probe

Turning the probe off is B2, and the comparison is the headline of Section 8.4:
recall 0.889 against 0.943, intervals separated, paired McNemar p = 1.9 × 10⁻⁹⁵
over 11,880 matched sessions, B4 ahead in 99 of 99 seeds. The randomised holdout
(Section 8.3) isolates the same effect inside a single arm and puts a causal
estimate on it, in the spirit of the one controlled study this literature has
produced \cite{fergusonwalter2021examining}, +0.070 [+0.052, +0.088].

The honest reading of that ablation includes its cost. Removing the probe also
removes the 197 sessions B2 catches and B4 does not, which are diversions the
probing arm defers while it waits for an answer. The next subsection is the reason
that number is bounded rather than open-ended.

## 9.2  Removing the decoy's memory

The Fact Notebook is ablated by a single flag: generate afresh every time, remember
nothing. With the notebook, the decoy's contradiction rate over several hundred
adversarial probes from the consistency fuzzer is **0%**. Without it, **100%** — a
generator with no memory answers the second identical question differently almost
every time, and a decoy that contradicts itself has announced the trap.

A sceptic can read that as an artefact of a weak deterministic generator, so we ran
the same ablation with a language model behind the same seam (a local
llama3.2:1b, loopback only, never in the request path) over 15 entities:
**0 contradictions with the notebook, 15 of 15 without it**. The consistency
property belongs to the notebook rather than to whatever produces the content,
which is the claim Section 6 makes and the reason the seam is where it is.

The trade in the other direction is worth reporting in the same breath. The
language model writes more varied free text — 12 distinct bodies against the
deterministic generator's 1 — while the deterministic generator produces more
distinct names, 15 against 13, drawing from a 400-name pool. Richer prose, no better
consistency; the two are independent, which is the point of separating them.

## 9.3  The adaptive adversary

An attacker who learns that probes exist can refuse them, and the interesting
question is what the decision rule does then rather than whether it can be evaded.
Each unrewarded exposure decays the surviving value of the same bait by a factor of
(1 − β_attack), so the information value of a probe an attacker keeps ignoring
falls geometrically toward zero (`adf/policy/voi.py::survival_discount`). Once
V(p) is negligible the effective cost of baiting is its immediate cost, which
Section 4.2 showed is strictly above passing, and the three-action rule collapses
back to the two-action rule that B2 already implements.

This is a statement about the limit, not about any single session, and we state it
that way deliberately. Against a fully bait-aware adversary the rule converges to
passive, so it cannot be *asymptotically* worse than the passive baseline; but on
the way there it defers some diversions, and those deferrals are exactly the 197
discordant sessions measured in Section 8.4. We report that count rather than
claiming per-session dominance, because per-session dominance is not what the
argument supports.

## 9.4  Removing the estimated inputs

The two quantities the derived band depends on — the frozen cost table and the
measured β_attack — are each swept across their full plausible range in
Section 4.4. Across β_attack ∈ [0.05, 0.99] and across a divert-to-miss cost ratio
swept from 0.5 to 128, the BAIT band stays non-empty and the divert threshold never
falls below the cost-only boundary. Only the width of the band and the level of
conservatism move. Neither the existence of the third action nor the direction of
the safety guarantee is an artefact of the two numbers we estimated
(`tests/test_stats_sensitivity.py`).

## 9.5  Ablating our own attacker

The attacker model is ours, so it deserves an ablation of its own. A vertical
credential brute force was run against the unchanged frozen model in two variants:
one that ignores response bodies, and one that reads them and follows the
deprecated-endpoint hint a probe plants in a failure page.

| attacker | n | bite rate | divert rate | mean peak belief |
|---|---:|---:|---:|---:|
| blind (round-1 model) | 40 | 0.000 | **0.000** | 0.463 |
| reads bodies, follows half the time | 40 | 0.925 | 0.925 | 0.958 |
| reads bodies, always follows | 40 | 0.950 | **0.950** | 0.973 |

We had been reporting the auth probe as ineffective. It is not: the round-1
attacker was unrealistically incurious, and a probe that nobody reads cannot work
by construction. This does not change any arm reported in Section 8 — round 1 still
trains on the blind attacker, and we are not going to relabel a result by swapping
in a more convenient adversary — but it moves the limitation to where it belongs,
from the defence to the attacker model.

## 9.6  Measurements deliberately left unfinished

Two follow-ups are running and are reported as unfinished rather than folded into
the numbers above.

The **response-reading population** for round-2 SQLi replaces the curiosity
assumption with a swept parameter, where 0.0 reproduces the blind model exactly, so
the Section 8 numbers become the conservative floor of a curve rather than a point
chosen by us. This is the run expected to move `sqli_obfuscated` off a bite rate of
zero.

An **agentic language-model attacker** goes further: it reads each response and
chooses its own next request, and nothing tells it that anything is bait, which
replaces a parameter we picked with an adversary we did not tune. Two runs with a
1-billion-parameter model bit nothing. The first was not a result at all — the
trajectory dump showed the agent never logged in, so it never reached a surface
carrying a probe, and the number measured our harness rather than the model. Given
a seeded credential it reached the surfaces: all five probes were shown, the bite
rate was still 0.000 across the three exposed sessions of eight, and it was diverted
half the time before it could log in at a mean peak belief of 0.647. That places it
with the off-the-shelf scanners of Section 8.7 — loud enough for the passive meter,
and not the human-shaped adversary a probe is designed for. It is a weak-agent lower
bound, not evidence about the probe, and the honest way to finish it is a sweep
across stronger models. The transferable lesson is that a harness limitation and an
incurious adversary produce the same number, so agent trajectories have to be read
before an agent result is believed.

## 9.7  Hand-set thresholds

The obvious challenge to a derived rule is that someone could have picked the two
edges by hand and done as well. Answering it needs a policy variant that scores
baiting on immediate cost alone, without subtracting the information value —
otherwise the derived rule is being compared against itself in a disguise. That
variant is `b5_fixed`, and it was run over the same frozen model, the same seeds
and the same traffic as every other arm.

**The derived edges do not win on expected cost.** We report that rather than
withhold it.

| edges (belief) | | cost/session | recall | benign diverted |
|---|---|---|---:|---:|
| [0.200, 0.800] | hand-set | **−10.518** [−10.785, −10.251] | 0.958 | 2/1600 |
| [0.050, 0.816] | hand-set | −10.127 [−10.406, −9.849] | 0.948 | 2/1600 |
| [0.300, 0.700] | hand-set | −10.025 [−10.485, −9.564] | 0.971 | 19/1600 |
| derived | **as shipped** | −9.955 [−10.190, −9.719] | 0.938 | **0/1600** |
| [0.100, 0.900] | hand-set | −9.860 [−10.164, −9.555] | 0.934 | **0/1600** |
| [0.050, 0.950] | hand-set | −9.092 [−9.349, −8.835] | 0.905 | **0/1600** |

Paired over 20 seeds, 4,000 sessions per arm. Three measurements explain the
result, and none of them is that a person guessed better.

**The gap is benign nuisance baiting, not detection.** The derived arm shows a
probe to 89% of benign sessions against 62-64% for the arms that beat it, at one
unit each. That difference, not any difference in what the arms catch, is most of
the cost gap.

**The edge is not choosing a value; it is choosing a side.** The belief takes only
a handful of distinct values: two of them account for **56% of every decision the
policy makes** (0.163 and 0.476). Every edge below 0.163 behaves identically, and
so does every edge between 0.163 and 0.463. The measured benign-bait rate confirms
it — 0.886, 0.888 and 0.907 for the three arms whose edge falls below 0.163,
against 0.616, 0.642 and 0.623 for the three above it, flat within each group
though the edge varies by 2× in the first and 1.6× in the second. The derived
band's four decimal places are not doing the work that their precision suggests.

**The derived DIVERT edge is what buys zero benign diversion.** Benign belief
ceilings top out at 0.829; the derived edge sits at 0.879, above all of them. That
is a consequence of the derivation rather than a coincidence: the edge is placed by
the cost table's 200:25 ratio, which prices a benign diversion at eight times a
missed attack, and the ratio pushes it clear of the benign distribution.

Three arms divert no benign session at all, and **among those the derived edges are
the best on both axes** — recall 0.938 against 0.934 and 0.905, expected cost
−9.955 against −9.860 and −9.092. Every arm that beats the derived edges on cost
does so by diverting benign users: two sessions for [0.200, 0.800], nineteen for
[0.300, 0.700].

So the honest claim is narrower than "derived beats hand-set on cost", and it is
the claim the cost table actually supports: within the configurations that never
divert a benign user, the derived edges are the best available, and they pay for it
in benign nuisance exposure that the invisibility gate makes cheap. A reader who
prices a benign diversion lower than we do should prefer [0.200, 0.800], and we
give the price at which that preference flips in Section 9.8.

Section 9.8 reports what happens when the belief the edges are applied to is
calibrated first, which is the natural next question this table raises.

## 9.8  Calibrating the belief the edges are applied to

Section 9.7 leaves an obvious question. Every band edge is a threshold on a
probability, and the meter that produces that probability was given its weights by
hand and never fitted to a label. If the belief is not calibrated, the edges do not
land where the derivation intends, and the comparison in 9.7 is being made on an
input neither policy was designed for.

We measured it on four draws held out by construction: the calibration split runs
on seeds far below the evaluation range, so nothing fitted on it can reach a
reported number. **The belief is not calibrated.** It is over-confident below about
0.6 — requests the meter calls 0.163 are attacks 0.3% of the time — and
under-confident above it, where requests it calls 0.650 are attacks 88% of the
time. Three standard maps were fitted and chosen between by leave-one-draw-out held-out
expected calibration error, so the winner is the one that survives a withheld draw
rather than the one that fits best: logistic (Platt) scaling
\cite{platt1999probabilistic}, the three-parameter beta map
\cite{kull2017beta}, and non-parametric isotonic regression
\cite{zadrozny2002transforming}.

| map | held-out ECE | held-out Brier |
|---|---:|---:|
| as shipped (identity) | 0.157 ± 0.008 | 0.149 |
| Platt | 0.040 | 0.120 |
| Beta | 0.045 | 0.120 |
| **isotonic** | **0.018 ± 0.004** | **0.116** |

Measuring the consequence needs no change to any frozen artefact. A calibration
map is monotone, so applying the derived edges to a calibrated belief is
arithmetically the same policy as applying inverse-mapped edges to the raw one —
which `b5_fixed` already implements. The derived pair (0.065, 0.879) becomes
(0.187, 0.619) on the raw belief, and that arm was run alongside the others in 9.7.

| | recall | benign diverted | cost/session |
|---|---:|---:|---:|
| derived, as shipped | 0.938 | **0/1600** | **−9.955** |
| derived, calibrated belief | **0.979** | 37/1600 | −9.341 |

Calibrating produces the best recall of any configuration we measured, and the
improvement is not marginal: on matched attack sessions, 108 are caught by the
calibrated policy alone against 8 by the shipped one, **p = 1.7 × 10⁻²³**. It also
diverts 37 benign sessions where the shipped configuration diverts none, and under
the frozen cost table that decides it. The break-even price of a benign diversion
is **134**; the table, written before any data existed, prices it at 200.

Two conclusions follow, and they point in opposite directions, which is why both
belong here. As a **detector**, the calibrated belief is clearly better. As a
**policy under this cost table**, it is clearly worse. Which of those is the
improvement is not a question the data answers — it is a question the cost table
answers, and the cost table was fixed in advance precisely so that it could.

There is a third reading we think is the most useful. Two modelling errors are
present and they point opposite ways: the belief is under-confident at the top,
which pushes the derived edge higher on the raw scale than the cost model intends,
while the rule is derived for one decision and deployed as a first-crossing test
over a whole session, which means the cost-optimal edge is higher than the
per-decision indifference point. The shipped configuration sits close to the
session-level optimum because those two errors very nearly cancel. Correcting
either alone moves it away. We report this because a rule that is right for
compensating reasons is a different object from a rule that is right, and a reader
deciding whether to adopt the method is entitled to know which one this is.

## 9.9  What we did not ablate, and why

One arm a reader might expect is absent, and inventing plausible numbers for it
would be worse than its absence. A **single-score** arm, collapsing automation and
malice into one number,
is partly answered by the shipped configuration rather than by an experiment: the
belief that drives diversion is the malice score alone, automation carrying weight
zero because a price-comparison bot is fully automated and entirely harmless, while
the split reaches the decision through which bait categories are eligible for the
response at hand. Measuring the collapse properly would need a meter retrained on a
single fused label — again a different system, not a flag. It is stated here as a
gap rather than filled with an analytical estimate dressed up as a measurement.
