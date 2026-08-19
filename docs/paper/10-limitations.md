# 10  Limitations

We separate the limitations we retired by fixing the underlying problem from the
ones that are irreducible in a study of this shape, because how a project retired
its weaknesses is itself evidence about the ones it kept.

**Retired.** An earlier version diverted every benign reporting-integration client,
because two features treated any API access and any run of ascending object ids as
hostile — the exact shape of a harmless integration. A human-only benign set had
hidden this completely; adding automated-but-harmless clients exposed it, and
removing the two features fixed it, at the cost of delegating that detection to
bait. A benign crawler was diverted on 404s for standard files, fixed by serving
them. A false positive on a forgetful user, which an earlier draft reported as an
inherent cost of a hard negative, turned out not to be inherent at all: it was a
missing feature (distinct usernames tried) plus a double count (login rejections
counted in the error ratio as well), and once both were addressed the benign
diversion rate is zero across every benign class in the corpus.

A second retirement is worth reporting because of how it was found. Our attack
generator spoke raw HTTP and never fetched a page sub-resource; the benign one
fetched them like a browser. The corpus therefore contained no attack session that
fetched an asset and almost no human-paced benign session that did not, and a
logistic regression on the automation features alone separated the two at an
out-of-sample AUC of 0.9935 — on a property of our two scripts, not of hostility.
No reported number was affected, because automation carries weight zero in the
hostility belief and the logs confirm it: across 12,954 scored requests the belief
equals the malice score exactly while the automation score ranges over its whole
domain. But the corpus was easier than reality, so half the attackers now drive a
browser (Section 2). The automation-only figure falls to 0.898, the corpus gets
harder — B1 0.408 to 0.366, B2 0.917 to 0.889, B4 0.951 to 0.943 — and every
measure of the probe's contribution rises, because the passive automation signal
that used to catch these sessions is gone. All numbers in this paper are the harder
ones. We did not raise the browser-driven fraction further to drive the AUC down,
which would be fitting the corpus to a desired measurement; attack tooling
genuinely does skew scripted, and the separation that remains is real.

**Irreducible.** The traffic is synthetic \cite{sommer2010outside}. The benign mix, hard negatives included,
approximates office traffic; it is not a sample of it, and every rate is a
statement about this distribution. Replaying a public labelled corpus such as CSIC
2010 \cite{csic2010} and recruiting human browsers would bound the benign side, and
is the natural next step. The band's derivation and the randomised-holdout
design do not depend on the traffic being real, but the magnitudes do. We ran real attack
tools against the system to bound this from one side — every cookie-persistent tool
is diverted and none bite a bait — but that measures the automated floor, not the
human rate the recall gain depends on.

The probe's effectiveness is a property of an attacker model we chose. We address
this three ways rather than caveating it. The adaptive-adversary result shows the
gain decays to the passive floor as the attacker learns to refuse probes. The
parameter sweep shows the band's existence and the safety direction hold across the
whole plausible range of that effectiveness. And an autonomous language-model
attacker, told nothing about bait and free to choose its own requests, bites at a
rate whose interval overlaps the range we assumed by hand (Section 9.6) — an
adversary we did not tune, landing where our assumption put it. None of that
rescues the magnitude of the gain, which remains a property of this attacker
population; the overlap is on twenty sessions per model and is evidence that the
assumption is not absurd, not evidence that it is right.

The sharpest limitation is one our own measurement produced, and it sits under the
decision rule rather than beside it. Every band edge is a threshold on a
probability, but the meter that produces that probability was weighted by hand and
never fitted to a label, and on held-out draws it is **not calibrated** — expected
calibration error 0.157, over-confident low and under-confident high (Section 9.8).
The edges therefore do not land where the derivation intends them to land. What
makes this worth stating plainly rather than burying is where the analysis led:
two modelling errors are present and they point in opposite directions. The belief
is under-confident at the top, which pushes the operating edge higher on the raw
scale than the cost model intends; and the rule is derived for a single decision
but deployed as a first-crossing test over a whole session, which puts the
cost-optimal edge higher still. The shipped configuration sits near the
session-level optimum because those two errors very nearly cancel, and correcting
either one alone moves it away. A rule that is right for compensating reasons is a
different object from a rule that is right. We report the correction that removes
one error and we do not adopt it. In the threshold sweep of Section 9.7 — a
separate, smaller run than the ninety-nine-seed headline, so its levels are not
comparable to the recalls quoted above — the shipped derived pair scores 0.940 and
the same pair on a calibrated belief scores 0.979, at a price under the frozen
table of 81 benign diversions against zero. We leave it unadopted
because the table was fixed in advance precisely so that this decision would not be
ours to make after seeing the numbers. <!-- not-the-headline --> Deriving the rule for the session-level
decision it actually makes, rather than for a single request, is the piece of
theory this work leaves undone.

The system is tuned on one application. We check transfer by placing the frozen
model in front of a second, structurally different one and attacking it with real
tools: the app-agnostic features fire correctly, the app-specific ones would need
re-pointing, and a full evaluation with a matched decoy on a second application
remains future work. The cost table is a reasoned estimate rather than a real
organisation's incident data; it is frozen so it cannot be tuned to the results,
and the sweep shows the conclusions survive across two orders of magnitude of the
one ratio it encodes, but the particular level of conservatism it sets is a
judgement. The deception is assessed by the researcher and a consistency fuzzer,
not by independent human participants; whether a human attacker *feels* something
is off is not measured, and it is the single most valuable thing left to measure.
