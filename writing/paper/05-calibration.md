# 5  Calibrating the Probe

The decision rule of Section 4 needs one empirical input: how much a bite tells
you. If that number is set by hand to make the system work, the derived band is a
fiction dressed up as a derivation. So we measure it, and we measure both sides of
it.

The evidence a bite carries is a likelihood ratio: how much more likely a hostile
session is to take the probe than a benign one.

```
LR(bite)    = P(bite | hostile) / P(bite | benign)       =  beta_a / beta_b
LR(no bite) = P(no bite | hostile) / P(no bite | benign) = (1 - beta_a) / (1 - beta_b)
```

The session's belief carries these in log-odds, which is what makes the update a
single addition rather than a special case in the policy:

```
logit(m_after) = logit(m_before) + log LR(observed outcome)
```

so a bite moves the malice score sharply upward and a declined probe nudges it
gently down, both by amounts the calibration measured rather than by constants we
chose. With the rates below, a bite on the `internal_view` probe is worth
`log 112 ≈ +4.7` in log-odds and a refusal is worth `log 0.25 ≈ -1.4`.

Reporting the second ratio matters as much as the first. A system that only ever
revises suspicion upward accumulates without bound and will eventually divert
someone for browsing slowly. Declining a probe is weak evidence of innocence, and
the model should say so rather than ignore it. For the bait that carries most of
our results, a planted `internal_view` reference aimed at the object-reference
attacks a passive score cannot resolve, **138 of 183 hostile sessions shown the
probe took it, and 0 of 74 benign ones did**, giving `β_hostile = 0.753` and
`β_benign = 0.0067` after smoothing: a bite likelihood ratio of about 112, and a
no-bite ratio of 0.25.

**A problem the phase order created.** These rates have no legitimate source in
the obvious data. The training corpus is collected before the bait library is
built, so it contains no probes and therefore no bites; the held-out corpus is the
test set and must not be touched \cite{arp2022dos}. Estimating probe effectiveness on either would
be indefensible, and there is no third option in the original plan. We add one: a
dedicated *calibration* round, run after the baits exist and frozen before the
evaluation, whose only permitted use is estimating probe effectiveness. The round
vocabulary — train, calibrate, evaluate — is enforced in the record schema \cite{sommer2010outside}, so a
rerun of one round cannot quietly become another.

**The benign rate is measured, not assumed.** It is tempting to set `β_benign` to
zero: bait is invisible to a real browser, so a real user has nothing to act on. We
do not, for two reasons. A hard zero makes the likelihood ratio infinite and the
arithmetic degenerate. And it would assume away precisely the safety property the
whole project exists to measure, namely whether an honest but unusual user trips the
probe \cite{srinivasa2020honeytoken}. Every benign count above is in fact zero, so the reported rates are posterior means
under a Jeffreys prior with an explicit floor:

```
beta_hat(bit, shown) = max( (bit + ½) / (shown + 1),  floor ),   floor = 0.0005
```

A Beta(½, ½) prior is the standard non-informative choice for a rate, and the half
in the numerator is what stops an observed zero from becoming a certainty. Every
benign rate we report is that posterior mean over the round's own counts and none
falls back to the floor: zero bites in 74 benign sessions gives `β_benign = 0.0067`
for the probe that carries most of our results, and the other measured baits sit
between 0.0056 and 0.0192 on samples of 25 to 88. The floor exists for a case that
did not arise here, and it matters that it did not, because a ratio computed against
a floor is a bound rather than a measurement.

The estimate is deliberately unfavourable to the probe. With zero benign bites
observed, any smaller prior — or none — would push `β_benign` toward zero and the
likelihood ratio toward infinity. Holding it at the posterior mean caps the ratio
at about 112 for the `internal_view` probe rather than letting the arithmetic claim
a certainty seventy-four sessions cannot support. The one bait that carries a prior
on both sides rather than a measurement is the fake column list discussed below; it
is flagged as such in the calibration report and is almost never selected on this
application's response shapes.

**What is measured, and what is not.** The frozen library holds five baits. Four
are measured in the calibration round — the two above plus a fake table name in a
database error (`β_hostile = 0.563` over 181 sessions) and a deprecated-endpoint
hint in a login failure (0.580 over 181) — and their bite likelihood ratios run
from 41 to 112. One, a fake column list in an HTML comment, was shown to no
hostile session at all in the round and keeps a prior; it is almost never selected
on this application's response shapes, so it moves no reported number. Provenance
is recorded per bait, measured or prior, with the session counts behind each
(`config/bait_calibration_report.json`), because a library whose whole claim is
that its parameters are measured has to say which ones are not.

That principle cost us an entry. A sixth bait — a debug token in a JSON
authentication failure — was **withdrawn rather than kept**, because the target's
login and OTP endpoints return HTML, so it was shown to zero sessions of either
kind and its `β_hostile` was still the prior 0.45 we had invented before any data
existed. An unmeasured number in a measured library is exactly the thing this
section exists to rule out. Withdrawing it also moved the derived PASS→BAIT edge,
which had been computed partly from that prior; the specification of the bait
survives in the codebase because it is sound on any target that authenticates over
JSON, where it would be calibrated before use.

**A calibration harness can be wrong in a way that looks like a result.** Our first
calibration was, and the correction is worth recording because the failure mode
generalises. The simulated bait-following attacker bit whichever planted token it
encountered first rather than the one belonging to the category being measured, and
since every session warms up through the login flow, sessions intended to measure
one probe were often diverted during warm-up by another. The wrong sessions landed
in the denominator and one probe's effectiveness was understated by roughly a factor
of seven. Nothing raised an error; the library was internally consistent, the bands
derived from it were plausible, and the evaluation built on it produced a headline
number that was simply wrong. Section 8.3 reports what the recalibrated numbers did
to that headline, which was to shrink it.
