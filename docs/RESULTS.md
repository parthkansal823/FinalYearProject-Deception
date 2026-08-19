# Results

**Current as of 2026-08-19.** Every number here comes from the re-frozen v5 bait
library and a full 99-seed evaluation against the **response-reading adversary**,
which is the primary condition. The blind adversary is reported in §7 as the
conservative floor rather than as a competing result: a probe that rides on a
response nobody reads is unreachable by construction, so that model measured our
attacker simulation rather than the defence. The earlier v4 figures have been
removed rather than kept alongside: where the two differ, the v4 ones were
produced by a calibration bug, and §8 explains what happened.

## How these numbers were produced

Each arm ran over 99 independent seeded traffic draws against one frozen model,
with 120 attack and 80 benign sessions per draw. That comes to 11,880 attack and
7,920 benign sessions per arm. One further seed was discarded from every arm
because it lost sessions to a resource fault mid-draw; dropping it from all three
keeps the pairing matched. Within any one seed every arm sees byte-identical
traffic, so each attack session forms a matched pair and the arms can be compared
with a paired test rather than an unpaired one.

Proportions carry Wilson intervals, which behave sensibly near zero where a normal
approximation does not. B2 against B4 uses an exact paired McNemar test. The
randomised holdout uses Fisher's exact test with a bootstrap interval on the
difference. The primary comparison was fixed before the runs; everything else is
labelled exploratory.

```bash
python -m tools.stats_report --in data/eval/curious/sessions.jsonl
python -m tools.make_figures
```

`report.json` now records the digests of the cost table, the bait library and the
meter that produced it, and `make_figures` refuses to draw from a report whose
digests do not match what is currently in `config/`. That guard exists because a
stale report plots perfectly happily and is wrong in a way nobody notices.

## Headline results

| Result | Value | Test | Significance |
|---|---|---|---|
| **Causal effect of the probe** (randomised holdout) | **+0.070, 95% CI [+0.052, +0.088]** | Fisher exact | **p = 3.4 × 10⁻¹⁹** |
| Attack recall, B4 against B2 | 0.943 [0.939, 0.947] against 0.889 [0.883, 0.894] | paired McNemar, b=842, c=197 over 11,880 pairs | **p = 1.9 × 10⁻⁹⁵** |
| Per-seed consistency | B4 ahead in **99 of 99** paired seeds | — | — |
| Where the probe acts | confined to UI object-reference sessions | paired McNemar on that subcategory, b=639, c=80 | **p < 10⁻⁴** |
| Benign diversion | B2 4/7,920, **B4 0/7,920** | Wilson | the probe adds no false positives |
| Band non-empty, divert floor holds | invariant across β ∈ [0.05, 0.99] | parameter sweep | structural |
| Decoy contradiction rate | 0% with the fact store, 100% without | fuzzer, 286 probes | — |
| Same under a language-model generator | 0% with, 100% without | 15 entities, local model | generator-independent |

## 1. The structural result

Read this part first, because it holds regardless of how many sessions were run.
The probing band and the divert floor follow from the frozen cost table and the
calibrated bite rates, not from the sample.

With the v5 library the derived bands are:

```
PASS    p < 0.0647
BAIT    0.0647 ≤ p < 0.8793
DIVERT  p ≥ 0.8793
```

Under cost accounting alone there is no middle band anywhere. Probing costs
1 − p more than passing at every belief below certainty, so the rule collapses to
a single PASS/DIVERT boundary at 0.816. The third action exists only because a
probe buys information, and it closes again at both ends where the system is
already certain and an observation cannot change the decision.

Sweeping the one estimated parameter, the attacker base rate, across [0.05, 0.99]
leaves the band non-empty and the divert edge at or above 0.816 throughout. Only
the width moves. Check it with `python -m adf.policy`.

Notice which way that edge moved. Adding the probe raised the divert threshold
from 0.816 to 0.879, so a system that probes is *more* reluctant to divert an
honest user than the same system without one. That falls out of the arithmetic; it
was not a design goal.

## 2. The causal estimate

The randomised holdout withholds the probe from a fraction of the sessions that
reach the probing band. Both groups sit at the same belief state, so the gap
between them is attributable to the probe rather than to the many other things
that differ between two whole systems.

| arm | n | divert rate |
|---|---|---|
| baited | 10,643 | **0.950** |
| withheld (holdout) | 1,237 | **0.880** |

Effect **+0.070**, bootstrap 95% CI **[+0.052, +0.088]**, odds ratio 2.59,
Fisher exact **p = 3.4 × 10⁻¹⁹**.

This is smaller than earlier drafts claimed, and the history is worth stating. A
single draw once gave +0.23, a 20-seed v3 run gave +0.11, and the v4 library gave
+0.053. Two things shrank it. The v4 meter is strong enough on its own that there
is little headroom left for a probe, and the v5 recalibration raised the divert
threshold so the probe now defers more diversions than it used to. What survives
all of that is +0.070, and it is still significant.

## 3. Baselines

| Arm | recall (95% CI) | benign diversion |
|---|---|---|
| **B1** signature WAF | 0.366 [0.358, 0.375] | 0 / 7,920 |
| **B2** passive | 0.889 [0.883, 0.894] | 4 / 7,920 |
| **B4** full | **0.943 [0.939, 0.947]** | **0 / 7,920** |

The B2 and B4 intervals do not overlap, and the paired test below confirms it.

B1 is a real signature firewall: regexes for injection, scripting, traversal and
command injection, plus scanner user-agents. It is a fair reference rather than a
straw man, since it false-positives on zero benign sessions. Its recall is only
0.366 because round-2 attacks are obfuscated and, more decisively, because reading
another user's record by changing an id is perfectly valid syntax with nothing for
a signature to match.

### A real WAF, not only ours

B1 is fifteen regexes we wrote, and a reader is entitled to distrust a baseline its
authors built. So the same traffic was replayed through **OWASP ModSecurity CRS**
at every paranoia level the ruleset defines. A WAF decides from a single request
with no cross-request state, so a replayed request gets the verdict it would have
got inline; the traffic comes from an undefended arm, so nothing is cut short by a
defence acting on it (`tools/waf_sweep.py`).

| CRS paranoia | attack recall (95% CI) | benign sessions blocked |
|---|---|---|
| 1 (default) | 0.353 [0.305, 0.404] | **0 / 240** |
| 2 | 0.544 [0.493, 0.595] | **0 / 240** |
| 3 | 0.544 [0.493, 0.595] | **0 / 240** |
| 4 (maximum) | **1.000** [0.989, 1.000] | **72 / 240 (30%)** |

At its default setting the real ruleset scores 0.353 against B1's 0.366, intervals
overlapping — B1 is not a weakened stand-in. And the ceiling is not a tuning
question: CRS reaches perfect recall only by blocking **30% of legitimate
sessions**. Across every setting that leaves benign traffic alone it tops out near
0.54, against 0.943 at zero benign diversions here.

One asymmetry in CRS's favour, stated rather than hidden: it is judged on blocking
any request of a session, while our arms are judged on diverting the session.
Blocking is the easier task — it needs no decision about who the visitor is.

## 4. Where the gain lives

Splitting the matched pairs by subcategory shows the probe is not helping
everywhere. It helps in one place.

| subcategory | B2 recall | B4 recall | gain | B4 bite rate | n |
|---|---|---|---|---|---|
| sqli_obfuscated | 0.898 | 0.921 | +0.022 | 0.162 | 3,960 |
| sqli_stealth | 1.000 | 1.000 | +0.000 | 0.503 | 1,980 |
| idor_scattered (API) | 0.994 | 0.993 | -0.001 | 0.000 | 1,980 |
| auth_spray | 1.000 | 1.000 | +0.000 | 0.000 | 1,980 |
| **idor_html_scattered** | **0.540** | **0.823** | **+0.282** | **0.620** | 1,980 |

The entire net gain is UI-based scattered object access, which is exactly what the
derivation predicts: the one category a signature cannot see, and the one where
the passive meter is genuinely uncertain. Elsewhere the probe is neutral.
`sqli_stealth` bites 22% of the time and its divert rate does not move, because
those sessions were already caught. Scattered API access is caught passively by
the error-ratio feature, since an attacker walking ids hits many 404s while a
benign integration reads only ids that exist.

**One subcategory cannot reach the probe at all, and it is half of all remaining
misses.** `sqli_obfuscated` has a bite rate of exactly 0.000 while 90% of its
sessions are shown a probe, and it accounts for 405 of B4's 799 misses. The cause
is in the attacker model rather than the defence: those profiles fired payloads
and never read the response body, so a response-side probe could not reach them by
construction. Fixed in `tools/attack_traffic_round2.py`; the run that measures it
is separate from everything above. See §7.

## 5. Safety

| arm | benign diverted | rate (95% CI) |
|---|---|---|
| B1 signature WAF | 0 / 7,920 | 0.0000 [0.0000, 0.0005] |
| B2 passive | 4 / 7,920 | 0.0005 [0.0002, 0.0013] |
| **B4 full** | **0 / 7,920** | 0.0000 [0.0000, 0.0005] |

The probe costs nothing in false positives. Roughly nine in ten benign sessions
were shown a probe and not one acted on it, which is the invisibility gate holding
at run time and at scale rather than only on the bench. High exposure is fine
precisely because the probe is invisible; the bite rate is the number that matters
and it is zero.

Two false positives were removed earlier by auditing rather than by argument, and
both belong in the record. Benign JSON-API integration clients were once diverted
100% of the time, because a reporting integration walks record ids in ascending
order exactly as an attacker sweep does. No passive feature separates those two
honestly, so that detection was handed to the probe, which is what a probe is for.
And a user who forgets their password was diverted three times in five until a
feature counting distinct usernames separated them from credential spray, which
fails against many accounts rather than against one.

## 6. Ablations

| ablation | what it removes | measured effect |
|---|---|---|
| no probe (B2 against B4) | the probe | recall 0.889 → 0.943, paired McNemar p = 1.9 × 10⁻⁹⁵ |
| no fact store | the decoy's memory | contradiction rate 0% → 100% |
| no fact store, language-model generator | the memory, with a stochastic generator | contradiction rate 0% → 100% (15/15) |
| adaptive adversary | the attacker refuses every probe | information value decays; the rule converges to the passive two-action rule in the limit |
| hand-set edges | the derivation | two hand-set pairs beat the derived edges on cost, both by diverting benign users; among the arms that divert none, derived is best on recall and cost (§6.1 below) |
| calibrated belief | the meter's miscalibration | recall 0.938 → 0.979 at 37/1,600 benign diverted; loses on cost at the frozen price of 200, break-even 134 (§7) |

The fact-store ablation is the entire justification for that component: a decoy
that forgets what it said betrays the trap on the second question. Repeating it
with a stochastic generator matters because a sceptic can otherwise read the
deterministic result as an artefact of a weak generator. A local language model
contradicts itself on every entity without the store and on none with it, so the
guarantee belongs to the store rather than to whatever produces the content.

## 7. Is the belief a probability?

Every band edge is a threshold on a probability, and the meter that produces it was
given its weights by hand and never fitted to a label. Measured on four draws held
out by seed range (`tools/calibration_split.py`, `tools/fit_calibration.py`), **it
is not calibrated**: over-confident below about 0.6 — requests it calls 0.163 are
attacks under 1% of the time — and under-confident above it. Three maps were fitted
and chosen between by leave-one-draw-out held-out ECE:

| map | held-out ECE | held-out Brier |
|---|---|---|
| as shipped (identity) | 0.157 ± 0.008 | 0.149 |
| Platt | 0.040 | 0.120 |
| Beta | 0.045 | 0.120 |
| **isotonic** | **0.018 ± 0.004** | **0.116** |

Because a calibration map is monotone, the derived edges on a calibrated belief are
the same policy as inverse-mapped edges on the raw one — which `b5_fixed` already
implements — so this needed no change to a frozen artefact. The derived pair
(0.065, 0.879) becomes (0.187, 0.619) on the raw belief.

| | recall | benign diverted | cost/session |
|---|---|---|---|
| derived, as shipped | 0.940 | **0 / 3,840** | **−10.030** |
| derived, calibrated belief | **0.979** | 81 / 3,840 | −9.497 |

Calibrating gives the best recall we measured — on matched attack sessions 245 are
caught by it alone against 21 by the shipped policy, **p = 1.3 × 10⁻⁴⁹** — and costs
the zero-benign-diversion property. Under the frozen table that decides it: the
break-even price of a benign diversion is **137**, and the table, written before any
data existed, prices it at 200.

The fuller version, including why the shipped edges sit close to the session-level
optimum despite an uncalibrated belief, is in [CALIBRATION.md](CALIBRATION.md).

## 8. Measurements still in flight

Two results are deliberately not folded into the numbers above.

**The response-reading adversary — first measurement in.** The round-2
obfuscated-SQLi profiles now read what comes back, with a mixed population in which
some attackers ignore what they find. `--curiosity` pins that population and
`--curiosity 0.0` reproduces the blind model exactly, so the headline can
eventually be reported as a curve with the numbers above as its conservative floor.

A short run (4 seeds of B4, against the 100-seed blind baseline) settles the
diagnosis, and it is worth reporting before the full run lands:

| subcategory | bite blind | bite reading | recall blind | recall reading |
|---|---|---|---|---|
| sqli_obfuscated | **0.000** | **0.163** | 0.899 | 0.781 |
| sqli_stealth | 0.217 | 0.475 | 1.000 | 1.000 |
| idor_html_scattered | 0.306 | **0.700** | 0.807 | **0.925** |
| idor_scattered | 0.000 | 0.000 | 0.996 | 1.000 |
| auth_spray | 0.000 | 0.000 | 1.000 | 1.000 |

The bite rate moves off zero everywhere the probe rides on a response the attacker
now reads. So the 0.000 in §4 was a property of the attacker simulation, not of the
probe: it could not be reached, rather than being resisted.

Two honest caveats, both of which cost more than they look. Four seeds is not a
result, only a direction. And the first version of this change did two things at
once: it made the attacker read responses *and* stop the session after biting. The
early exit truncated exactly the requests the passive meter was already catching
those sessions on, which is why `sqli_obfuscated` recall fell while its bite rate
rose — the delta was measuring session length, not the probe. The early exit has
been removed, so a bite is now an extra action rather than the end of the session,
and the numbers above will be regenerated. An automated injector does not abandon
its payload list because one response looked interesting.

**An agentic language-model attacker.** `tools/llm_agent_attacker.py` drives a
local model as an autonomous attacker: it reads each response and chooses its next
request, and nothing tells it that anything is bait. The point is to replace a
curiosity parameter we chose with a measurement against an adversary we did not
tune.

Two runs so far with a 1-billion-parameter model, and both bit nothing. The first
was not a result at all: the trajectory dump showed the agent never logged in, so
it never reached a surface carrying a probe, and the number measured our harness
rather than the model. After giving it a seeded test credential and completing the
second factor, all five probes were shown at least once and the bite rate was
still 0.000 across three exposed sessions. It also gets diverted half the time
before it can log in, at a mean peak belief of 0.647, which puts it in the same
class as the off-the-shelf scanners: loud enough for the passive meter, and not
the human-shaped adversary the probe is designed for.

Treat that as a weak-agent lower bound rather than as evidence about the probe. A
1-billion-parameter model is a poor attacker, and the honest way to report this is
as a capability sweep across stronger local models. Always read the trajectories
before believing an agent number: a harness limitation looks exactly like an
incurious adversary.

## 9. What changed from v4, and why the numbers went down

The defect was in the calibration harness, not in the system under test. The
simulated bait-following attacker bit whichever planted token it saw first rather
than the one belonging to the category being measured. Every session warms up
through the login flow, and those responses carry the auth and object-reference
probes, so an auth follower was often diverted during warm-up before it reached
its own probes. The wrong sessions ended up in the denominator, and one probe's
effectiveness was understated by roughly a factor of seven.

Recalibration moved the bands from [0.0516, 0.8626] to [0.0647, 0.8793] and
withdrew one probe that had no surface on this target to ride on, leaving five.
The higher divert edge makes B4 defer more diversions, which is why the discordant
count in the other direction rose from 72 to 280 and why recall fell from 0.946
to 0.933.

So the headline numbers are lower than they were, and that is the correction doing
its job. The structural results are untouched, because the derived band and its
invariance are properties of the decision rule and its frozen inputs rather than
of these estimates.

## Honest summary

1. **Structural.** Probing is the cost-optimal third action over a derived band,
   and under cost accounting alone there is no third action at all. Its existence
   and the divert floor are invariant across the full range of the one estimated
   parameter. A proof plus a sweep, independent of sample size.
2. **Causal.** The randomised holdout gives +0.070 [+0.052, +0.088], Fisher
   p = 3.4 × 10⁻¹⁹: the probe causes more diversions at the same belief state.
3. **Recall, and where it comes from.** 0.889 → 0.943, intervals separated and the
   paired test significant, concentrated in UI object-reference sessions. The 197
   sessions that go the other way are deferrals inside the narrow band between
   0.816 and 0.879, and they are reported rather than hidden.
4. **Safety.** Zero of 7,920 benign sessions diverted, with nine in ten shown a
   probe and none biting.
5. **Methodological.** A human-only benign set hid a 100% false positive on benign
   API clients. A metric tests only what its inputs contain.
6. **The derivation does not win the ablation.** Hand-set edges beat the derived
   ones on expected cost, and we report that with its cause rather than burying
   it: the derived band pays more benign nuisance baiting, the belief has too
   little resolution for four decimal places to mean anything, and every arm that
   beats it on cost does so by diverting benign users. Within the arms that divert
   none, the derived edges are the best available.
7. **Known incomplete.** The deception assessment is still ours rather than
   independent human participants, and the agentic-adversary result is a
   capability sweep across local models rather than a study of a competent human
   attacker. Both are stated as gaps, not filled with estimates.
