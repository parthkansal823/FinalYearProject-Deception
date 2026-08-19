# 12  Conclusion

Passive web defences force a choice between acting early on weak evidence and
acting late on strong evidence. We have shown the choice is avoidable: a defender
can manufacture evidence by planting an invisible, inert probe in a response, and
the decision of when to do so follows from the expected value of the information
the probe buys. Priced this way, probing is not a heuristic middle option but the
cost-optimal action over a belief band derived from the cost of errors and the
measured effectiveness of the probe. That band does not exist at all under cost
accounting alone. The one thing to carry away is that last point: without the
information term there is no third action, so the probe cannot be a tuned
threshold. It is priced.

The evaluation supports the mechanism rather than a headline number. The probe
helps where the theory says it should, in the one region of belief the passive
classifier is genuinely unsure about, and a randomised holdout attributes that
help causally to the probe rather than to the rest of the system. It is safe where
it must be, diverting no automated benign client and no ordinary user against a
corpus of hard negatives, and it is never worse, in the limit, than the passive
detector it is built on, even against an adversary that refuses every probe.

Deriving the edges did not, however, beat setting them by hand on expected cost,
and we report the measured reason rather than the claim: the belief those edges are
applied to takes essentially two distinct values, so four decimal places of derived
precision are not doing the work they appear to, and every configuration that beats
the derived pair on cost does so by diverting benign users. Within the
configurations that divert none, the derived edges are the best available. That is
a narrower claim than we set out to make and a more useful one, because it says
what the derivation buys — a placement that clears the benign belief distribution
by construction — rather than asserting a superiority the data does not support.

What the study cannot claim is bounded by its setting: synthetic traffic, a single
tuned application, one laboratory. The parts meant to outlast that setting are not
measurements but a derivation, a design and a structural property: the priced band,
which follows by arithmetic from a frozen cost table; the randomised treatment,
which identifies the probe's effect whatever its size; and the convergence to
passive detection under an adaptive adversary, which is a property of the survival
discount rather than a result about this target.

Two next steps follow from what we found rather than from what we planned. The
first is theoretical and is the one our own calibration analysis exposed: the rule
is derived for a single decision but deployed as a first-crossing test over a
session, and on this system that mismatch happens to cancel against the meter's
miscalibration. Deriving the band for the sequential decision it actually makes
would remove both errors instead of relying on them to offset, and would let a
calibrated belief be adopted rather than merely measured. The second is empirical
and is the one the laboratory cannot supply: whether a human attacker, not a tool
and not an agent, takes the bait. We have narrowed that gap from one side — an
autonomous language-model adversary told nothing about bait bites at a rate whose
interval overlaps the range we assumed — but an agent is still not a person, and
the question of whether a human *feels* something is off remains the single most
valuable thing left to measure.
