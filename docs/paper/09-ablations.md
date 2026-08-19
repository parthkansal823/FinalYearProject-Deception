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

That is an argument, so we also measured it. We sweep an attacker's bait-*awareness*
from 0 (follows a planted hint) to 1 (never bites, on principle) in five steps, forty
sessions each, against two attacker profiles: an escalating one that raises its own
signal as it works, and a low-and-slow one that is precisely the case a passive
score finds hard.

| awareness | 0.00 | 0.25 | 0.50 | 0.75 | 1.00 |
|---|---:|---:|---:|---:|---:|
| low-and-slow — bite rate | 0.925 | 0.975 | 0.850 | 0.775 | **0.000** |
| low-and-slow — diverted | 1.000 | 1.000 | 1.000 | 1.000 | **1.000** |
| escalating — diverted | 0.952 | 1.000 | 1.000 | 1.000 | **1.000** |
| median requests to divert | 5 | 5 | 5 | 5 | **5** |

The bite rate falls to zero as awareness reaches one, which is the sweep working:
a fully aware attacker really does refuse every probe. The diversion rate does not
move. On this target the passive features carry the session on their own, and the
number of requests taken to reach the decision is unchanged at five throughout.

The honest reading is narrower than "the system always wins". What the sweep
establishes is that **bait never blinds the detector it is built on**: withdrawing
every bite leaves the passive floor intact rather than below it, which is the
property the survival discount exists to guarantee. It does *not* establish that
timing is unaffected in general — this target's error-ratio and username features
are strong enough that the probe has little to add against these two profiles, and a
target where the passive score is weaker is exactly where a deferred diversion would
show up as a slower decision. The 197 discordant sessions of Section 8.4 are where
that deferral is visible in the main evaluation, and we report them rather than
claiming per-session dominance, because per-session dominance is not what any of
this supports.

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

## 9.6  Adversaries we did not choose

Two results here test the system against adversaries whose behaviour we did not
set: one sweeps the assumption we had to make about attacker curiosity, the other
replaces it with an autonomous agent.

The **response-reading population** for round-2 SQLi replaces the curiosity
assumption with a swept parameter, where 0.0 reproduces the blind model exactly, so
the Section 8 numbers become the conservative floor of a curve rather than a point
chosen by us. This is the run expected to move `sqli_obfuscated` off a bite rate of
zero.

An **agentic language-model attacker** goes further: it reads each response and
chooses its own next request, and nothing tells it that anything is bait. This
replaces the curiosity parameter of Section 5 with an adversary we did not tune.
Three local models, twenty autonomous sessions each, twelve steps per session.

| model | shown a probe | **bite \| shown** (95% CI) | diverted | mean peak belief |
|---|---:|---:|---:|---:|
| Llama 3.2 1B | 13/20 | 0.077 [0.014, 0.333] | 0.55 | 0.687 |
| Llama 3.2 3B | 16/20 | 0.375 [0.185, 0.614] | 0.30 | 0.511 |
| Qwen 2.5 7B | 18/20 | **0.556** [0.337, 0.754] | 0.85 | 0.928 |

The conditional bite rate rises monotonically with model size, and the largest
model's **0.556 falls inside the [0.51, 0.79] range measured for the scripted
attacker model in Section 5**. That is the answer to the objection this evaluation
was built to face: the curiosity assumption we chose by hand brackets the bite rate
of an autonomous adversary we did not choose. It is a single overlapping interval
on twenty sessions, not a tight agreement, and we claim no more than that.

The trajectories say what the rates cannot. The 1B model is shown a probe thirteen
times and never once mentions it in its reasoning: it is not declining the probe,
it is not perceiving it, which is a statement about the model rather than about the
bait. The 3B model finds the hint by itself in thirteen sessions and reasons about
it in its own words — *"try appending ?internal\_view=1 to the search query to see
if it expands the record view"* — from a prompt that never mentions HTML comments,
parameters, or any token.

Two honest deductions from the same data. Engagement exceeds the bite rate: the 3B
model attempts the probe in thirteen sessions but constructs a well-formed request
in four, splicing the parameter into the search *value* rather than submitting it,
so its 0.375 understates how often the probe is reached and overstates how often it
is used. And capability does not order everything: the 3B model is by some distance
the stealthiest (peak belief 0.511, passively diverted in six sessions of twenty)
while the larger 7B is the loudest (0.928, seventeen of twenty), so the probe's
marginal value is highest against the middle of this range, not the top of it.

**How this number was nearly wrong, three times.** All three failures produced a
confident number and none raised an error. First, the agent's view of each response was
capped at 1,400 characters while `inject_html_comment` places the probe immediately
before `</body>`; on a median page the token sits at 96% of the body, and 88% of
baited responses exceeded the cap, so the agent was shown a body with the probe
removed and recorded as having declined it. Second, after that was fixed, the
system prompt still told the agent to "follow up on … table names in an error,
hints in HTML comments … parameters" — an enumeration of the planted channels — and
used a real bait token as its example parameter. That version reported bite rates
of 0.650 and 1.000, which measured the instruction rather than the adversary.
Third, and least obvious, the agent had no structured way to *submit* a query
parameter: it could name one in its reasoning but could only write it into the
search text, where the bait engine cannot see it. Under that interface all three
models bite at 0.000 while being shown *more* probes than in the corrected runs
(80%, 90% and 90% exposure against 65%, 80% and 90%), so the defect looked like a
strong negative result rather than a broken instrument.

| the same measurement, four ways (bite rate over all 20 sessions) | 1B | 3B |
|---|---:|---:|
| probe truncated out of the response | 0.000 | 0.000 |
| no structured way to submit a parameter | 0.000 | 0.000 |
| prompt naming the channels and a token | 0.650 | 1.000 |
| **none of the three** | **0.050** | **0.300** |

The 7B model was also run under the weak interface and also bit 0.000, against
0.500 once it could submit a parameter. These are unconditional rates over all
twenty sessions, which is why the corrected
column reads 0.050 and 0.300 against the 0.077 and 0.375 of the table above: those
are conditional on the agent having been shown a probe at all. The unconditional
form is the right one here, because two of the three variants change how often a
probe is *seen*, and a conditional rate would hide exactly the failure being
illustrated.

The table is in the paper because the lesson generalises beyond this system: an
agentic evaluation can be wrong in both directions while every number in it looks
plausible, and the only thing that distinguishes them is reading what the agent
actually did. We stopped adjusting the harness at the point where the remaining
failures were the model's rather than ours — the 3B model has a structured way to
submit a parameter, is told about it, and mostly still writes it into the query
text. Continuing past that point would have been coaching, not measurement.

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
| [0.200, 0.800] | hand-set | **−10.393** [−10.545, −10.242] | 0.952 | 3/3,840 |
| [0.050, 0.816] | hand-set | −10.168 [−10.322, −10.015] | 0.948 | 3/3,840 |
| derived | **as shipped** | −10.030 [−10.167, −9.892] | 0.940 | **0/3,840** |
| [0.300, 0.700] | hand-set | −9.989 [−10.284, −9.694] | 0.971 | 46/3,840 |
| [0.100, 0.900] | hand-set | −9.881 [−10.050, −9.712] | 0.935 | **0/3,840** |
| [0.050, 0.950] | hand-set | −9.246 [−9.395, −9.098] | 0.911 | **0/3,840** |

Paired over 48 seeds, 9,600 sessions per arm. Three measurements explain the
result, and none of them is that a person guessed better.

**The gap is benign nuisance baiting, not detection.** The derived arm shows a
probe to 89% of benign sessions (3,433 of 3,840) against 65% for the arms that beat
it, at one unit each. That difference, not any difference in what the arms catch, is most of
the cost gap.

**The edge is not choosing a value; it is choosing a side.** The belief takes only
a handful of distinct values: two of them account for **56% of every decision the
policy makes** (0.163 and 0.476). Every edge below 0.163 behaves identically, and
so does every edge between 0.163 and 0.463. The measured benign-bait rate confirms
it — 0.897, 0.896 and 0.903 for the three arms whose edge falls below 0.163,
against **0.650, 0.650 and 0.650** for the three above it. The second group is
identical to three decimal places even though its lower edge varies from 0.187 to
0.300, which is the plateau made visible: within a group the edge is not selecting
anything at all. The derived
band's four decimal places are not doing the work that their precision suggests.

**The derived DIVERT edge is what buys zero benign diversion.** Benign belief
ceilings top out at 0.829; the derived edge sits at 0.879, above all of them. That
is a consequence of the derivation rather than a coincidence: the edge is placed by
the cost table's 200:25 ratio, which prices a benign diversion at eight times a
missed attack, and the ratio pushes it clear of the benign distribution.

Three arms divert no benign session at all, and **among those the derived edges are
the best on both axes** — recall 0.940 against 0.935 and 0.911, expected cost
−10.030 against −9.881 and −9.246. Every arm that beats the derived edges on cost
does so by diverting benign users: three sessions for [0.200, 0.800], forty-six for
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
reported number. **The belief is not calibrated.** Binned as the calibration error itself
bins them, into fifteen equal-width intervals, it is over-confident below about 0.6
— the 2,225 requests it scores in [0.13, 0.20), mean belief 0.163, are attacks
**0.4%** of the time — and under-confident above it, where the 555 requests in
[0.60, 0.67), mean belief 0.633, are attacks **87%** of the time. The full
reliability table is in the artefact. Three standard maps were fitted and chosen between by leave-one-draw-out held-out
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
| derived, as shipped | 0.940 | **0/3,840** | **−10.030** |
| derived, calibrated belief | **0.979** | 81/3,840 | −9.497 |

Calibrating produces the best recall of any configuration we measured, and the
improvement is not marginal: on matched attack sessions, 245 are caught by the
calibrated policy alone against 21 by the shipped one, **p = 1.3 × 10⁻⁴⁹**. It also
diverts 81 benign sessions where the shipped configuration diverts none, and under
the frozen cost table that decides it. The break-even price of a benign diversion
is **137**; the table, written before any data existed, prices it at 200.

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

Two arms a reader might expect are handled here rather than in a table.

**B3**, the static arm of Section 7 — scoring and decoy, no probe — is implemented
and is not reported, because it would repeat a number rather than add one. Its
decision path is identical to B2's: the same features, the same meter, the same
two-action rule. The only difference is where a diverted session is sent
afterwards, which cannot change whether the policy decided to divert it. Its recall
would equal B2's by construction, and reporting it as a separate row would suggest
an independent measurement that does not exist. B3 is worth implementing anyway,
because it is the configuration a deployment would choose to contain attackers
without probing them, and Section 8.1's definition of *diverted* is what makes B2
and B3 interchangeable as detectors.

A **single-score** arm, collapsing automation and malice into one number,
is partly answered by the shipped configuration rather than by an experiment: the
belief that drives diversion is the malice score alone, automation carrying weight
zero because a price-comparison bot is fully automated and entirely harmless, while
the split reaches the decision through which bait categories are eligible for the
response at hand. Measuring the collapse properly would need a meter retrained on a
single fused label — again a different system, not a flag. It is stated here as a
gap rather than filled with an analytical estimate dressed up as a measurement.
