# 5  Calibrating the Probe

The decision rule of Section 4 needs one empirical input: how much a bite tells
you. If that number is set by hand to make the system work, the derived band is a
fiction dressed up as a derivation. So we measure it, and we measure both sides of
it.

The evidence a bite carries is a likelihood ratio — how much more likely a hostile
session is to take the probe than a benign one:

```
LR(bite)    = P(bite | hostile) / P(bite | benign)
LR(no bite) = P(no bite | hostile) / P(no bite | benign)
```

Reporting the second ratio matters as much as the first. A system that only ever
revises suspicion upward accumulates without bound and will eventually divert
someone for browsing slowly. Declining a probe is weak evidence of innocence, and
the model should say so rather than ignore it. For the bait that carries most of
our results — a planted internal-view reference aimed at the object-reference
attacks a passive score cannot resolve — the measured rates are `β_hostile =
0.590` and `β_benign = 0.0037` over 244 exposures, a bite likelihood ratio of
about 160 and a no-bite ratio of 0.41.

**A problem the phase order created.** These rates have no legitimate source in
the obvious data. The training corpus is collected before the bait library is
built, so it contains no probes and therefore no bites; the held-out corpus is the
test set and must not be touched. Estimating probe effectiveness on either would
be indefensible, and there is no third option in the original plan. We add one: a
dedicated *calibration* round, run after the baits exist and frozen before the
evaluation, whose only permitted use is estimating probe effectiveness. The round
vocabulary — train, calibrate, evaluate — is enforced in the record schema, so a
rerun of one round cannot quietly become another.

**The benign rate is measured, not assumed.** It is tempting to set `β_benign` to
zero: bait is invisible to a real browser, so a real user has nothing to act on. We
do not, for two reasons. A hard zero makes the likelihood ratio infinite and the
arithmetic degenerate. And it would assume away precisely the safety property the
whole project exists to measure — whether an honest but unusual user ever trips the
probe. We estimate it with a stated smoothing floor and let the data place it near,
but not at, zero.

Of the six baits, three are measured from enough data to stand on their own; the
other three keep prior estimates and, as it happens, are almost never selected on
this application's response shapes, so they move no reported number. The bait that
carries the evaluation is one of the measured three, and its provenance — measured
versus prior — is recorded per bait so a reviewer can see which is which.
