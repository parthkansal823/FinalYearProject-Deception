# 1  Introduction

A web application firewall makes a binary choice on every request: let it through
or block it. It has to make that choice from what the request alone reveals, which
is the source of a familiar and unpleasant trade-off. Act early, on thin evidence,
and legitimate users get blocked. Wait for evidence strong enough to be safe, and
the attacker has already had several requests' worth of head start. Learned
detectors soften the edges of this trade-off but do not escape it; they still
watch and wait, and they still have to commit on a single accumulated score.

Deception is the usual answer to passivity. Honeypots, honeytokens and decoy
documents all give the defender something to do other than wait. But in almost
every deployment the deception happens *after* the decision has been made: a
request is judged hostile, and only then is the session moved into a honeypot or
shown a planted file. The deception is a consequence of detection, not an
instrument of it. Nobody, as far as we have found, treats the act of deceiving as
a *move the detector can make while it is still unsure* — a way to manufacture the
evidence it would otherwise have to wait for.

This paper is about that move. When the system is uncertain about a visitor, it
adds something to the response that a real browser never renders but anyone
reading the raw bytes will see: a fake database error naming a table that does not
exist, an unused field in a JSON body, a hint at a deprecated login endpoint. An
honest user never notices. Someone probing the application acts on it, and the
moment they do, they have told the defender what a passive score could not: that
their intent is hostile. We call these response-side probes *bait*, and the
question the paper answers is not how to build them — invisibility and
consistency are engineering, and we treat them as such — but *when a detector
should deploy one at all.*

Our answer is that the decision is not a heuristic. A probe has no immediate
benefit; the request it rides on still reaches the real application, so baiting an
attacker costs exactly what letting one through costs. Its entire value is the
information the bite reveals, and that value can be computed. Priced as the
expected value of the sample information it buys, a probe becomes the cost-optimal
action over a band of belief that is *derived* from the cost of the defender's
errors and the *measured* effectiveness of the probe — and, we show, a band that
does not exist at all when the same costs are accounted without the information
term. The middle action cannot be a tuned threshold, because without pricing the
information there is no middle action to tune.

## Contributions

We are careful about what is new here, because a contributions list that overclaims
is the fastest way to lose a reviewer. The ingredients are all old. Using a
language model to write convincing fake content has been studied since 2022
\cite{sladic2024shellm,bridges2025sok,vero2026honeyval}. Machine-learned detection
of web attacks is a WAF \cite{kruegel2003anomaly,tekerek2021novel}. Redirecting a
caught attacker into a honeypot \cite{provos2004honeyd}, and planting a credential
as a tripwire \cite{juels2013honeywords,bowen2009baiting}, are both deployed
commercially. What is new is the rule that decides *when* to deceive, and the fact
that its parameters are derived rather than chosen. Concretely:

1. **A priced third action (Section 4).** We show that response-side probing is the
   action that maximises the expected value of sample information, over a belief
   band whose edges are outputs of the frozen cost table and the calibrated probe
   effectiveness. Under cost accounting alone the band is empty and the policy is
   an ordinary two-way rule, so the middle action is priced, not tuned. Two
   properties — the value of information is non-negative, and it vanishes at
   certainty — bound the band on both sides by construction, and two parameter
   sweeps show the band's existence and the direction of its safety guarantee are
   invariant to both estimated inputs.

2. **A derived evidence weight (Section 5).** The weight a bite carries is a
   likelihood ratio estimated in a dedicated calibration round, not a constant set
   to make the system work. We report both sides of it — declining a probe is weak
   evidence of innocence, and the model says so — and we measure the benign bite
   rate rather than assuming it away.

3. **Bait as a randomised treatment (Section 8).** A fixed fraction of sessions
   that reach the bait band are deliberately not baited. Because assignment is
   random conditional on the same belief state, the difference between the baited
   and withheld arms is an unbiased estimate of the *causal* effect of baiting,
   not a comparison of two different systems.

4. **A benign corpus built to be hard, and a finding it forced (Section 8).** The
   safety numbers are measured against honest traffic that genuinely looks like an
   attack — a staff member searching for a colleague named *O'Connell*, a
   forgetful user, an automated reporting integration that walks record ids
   exactly like an IDOR sweep. Including automated-but-harmless clients exposed a
   false positive that a human-only benign set had hidden completely, which we
   report as a methodological result in its own right.

5. **A consistency layer that does not depend on the generator (Section 6).**
   A decoy that answers the same question two different ways has announced itself.
   We decompose consistency into four properties — repetition, cross-reference,
   write-then-read, referential integrity — and meet all four with a component that
   records every value the decoy has emitted and serves the recorded value
   thereafter. Because it sits between the generator and the response it is
   indifferent to what produces the content, which we show by repeating the
   ablation against a language model that cannot be self-consistent on its own.

6. **Never worse than its own baseline (Section 9).** Against an adversary that
   knows the defence exists and refuses every probe, the value of information
   decays and the rule converges to the passive two-action policy it would have
   used had bait never existed. The full system is therefore never worse, in the
   limit, than the passive detector it is built on.

7. **The attacker model, checked against an adversary we did not choose
   (Section 9.6).** The probe's measured effectiveness rests on a curiosity
   parameter we set by hand, which is the sharpest objection to the whole
   evaluation. We test it by driving local language models as autonomous
   attackers that are told nothing about the probes: the conditional bite rate
   rises with model size and the largest lands inside the range we had assumed.
   Getting that measurement right required two corrections to our own harness,
   both of which had produced a confident and wrong answer, and we report the
   failures alongside the result because the way an agentic evaluation goes wrong
   generalises beyond this system.

We validate the system not only on synthetic traffic but against off-the-shelf
attack tools we did not write (sqlmap, ghauri, OWASP ZAP), against the OWASP
ModSecurity Core Rule Set on identical traffic rather than only against a baseline
of our own, and by checking that the frozen model still fires in front of a second,
structurally different application. Section 8 reports all three.

We also report where the approach does not win. Hand-set band edges beat the
derived ones on expected cost, and Section 9.7 gives the measured reason rather
than an argument: the belief the edges are applied to takes essentially two
distinct values, so the derivation's precision is not doing the work its decimal
places suggest, and every configuration that beats it on cost does so by diverting
benign users. Section 9.8 shows what happens when that belief is calibrated first.
Neither result is comfortable and both are more useful than the claim they qualify.
The paper closes with the limitations we could not retire (Section 10) and where
the work sits relative to the deception and web-security literature (Section 11).
