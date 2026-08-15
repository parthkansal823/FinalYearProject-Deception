# 12  Conclusion

Passive web defences force a choice between acting early on weak evidence and
acting late on strong evidence. We have shown the choice is avoidable: a defender
can manufacture evidence by planting an invisible, inert probe in a response, and
the decision of when to do so follows from the expected value of the information
the probe buys. Priced this way, probing is not a heuristic middle option but the
cost-optimal action over a belief band derived from the cost of errors and the
measured effectiveness of the probe — a band that does not exist at all under cost
accounting alone. The one thing to carry away is that last point: without the
information term there is no third action, so the probe cannot be a tuned
threshold. It is priced.

The evaluation supports the mechanism rather than a headline number. The probe
helps where the theory says it should — in the one region of belief the passive
classifier is genuinely unsure about — and a randomised holdout attributes that
help causally to the probe rather than to the rest of the system. It is safe where
it must be, diverting no automated benign client and no ordinary user against a
corpus of hard negatives, and it is never worse, in the limit, than the passive
detector it is built on, even against an adversary that refuses every probe.

What the study cannot claim is bounded by its setting: synthetic traffic, a single
tuned application, one laboratory. The parts meant to outlast that setting are not
measurements but a proof, a design, and a guarantee — the priced band, the
randomised treatment, and the convergence to passive detection under an adaptive
adversary. The most valuable next step is the one the laboratory cannot supply: a
study of whether a human attacker, not a tool, takes the bait.
