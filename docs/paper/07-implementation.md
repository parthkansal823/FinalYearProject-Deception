# 7  Implementation and Reproducibility

The defence is about six and a half thousand lines of Python behind an asynchronous
reverse proxy, with the deliberately weak target application and the decoy as
separate services; the evaluation harness adds a further ten and a half thousand
and the test suite — 358 tests, which must all pass before a model can be frozen —
another forty-seven hundred. Three
mechanisms make the evaluation in Section 8 reproducible and hard to fudge, and
they are worth stating because a measurement that cannot be replayed is difficult
to trust.

**The model is frozen before evaluation** \cite{arp2022dos}. A manifest hashes
everything a decision depends on: the two logistic heads, the cost table, the
feature set and its version, the calibrated bait library, and the invisibility
certificates. The system verifies that manifest at start-up and refuses to run if
any of it has moved.
Freezing is not a convention we promise to honour; it is checked. The cost table in
particular is hashed separately and enforced on every load, because the entire
argument of Section 4 rests on those numbers being fixed before the results were
seen. Re-freezing is possible but deliberate, and leaves a dated entry in a
changelog.

**Traffic is seeded and replayed.** Every generator is deterministic given a seed,
so each baseline sees byte-identical traffic. This is what makes the comparison in
Section 8 a comparison of *systems* rather than of *samples*: the only thing that
differs between arms is the code path selected by a single mode flag. There are six
such modes, and because every ablation in this paper is one of them it is worth
setting out exactly what each switches on:

| arm | rules | scoring | probe | decoy | what it is for |
|---|:--:|:--:|:--:|:--:|---|
| B0 no defence | – | – | – | – | undefended traffic; the corpus other tools replay |
| B1 signature WAF | ✓ | – | – | – | the conventional baseline |
| B2 passive | – | ✓ | – | – | the detector without the probe |
| B3 static | – | ✓ | – | ✓ | diversion without the priced middle action |
| **B4 full** | – | ✓ | ✓ | ✓ | the system of this paper |
| B5 fixed edges | – | ✓ | ✓ | ✓ | B4 with hand-set band edges (Section 9.7) |

B4 and B5 differ in one function: B5 prices the probe at its immediate cost and
takes hand-set thresholds, where B4 subtracts the value of information and derives
them. Nothing else in the two paths differs, which is what makes the comparison in
Section 9.7 a test of the derivation rather than of two systems. An arm cannot leak
capability into another by accident, because the components are constructed only in
the modes that declare them: a mode without probing has no bait engine to call. The
multi-seed evaluation repeats this over many independent seeds and reports
confidence intervals; we are explicit in Section 10 that these intervals quantify
variability under a fixed generative model, not generalisation to real traffic.
Because a draw is serial — the generator sends one request and waits for it — the
seed range is split across processes with disjoint seeds and separate ports, logs
and databases, which is what makes a ninety-nine-seed run over three arms a
one-hour job rather than a seven-hour one. The merge refuses to combine overlapping
seed ranges, so a mistake in the split fails loudly instead of double-counting
sessions into every pooled proportion.

**The log is tamper-evident.** Decisions are written to an append-only store whose
records are chained by hash \cite{schneier1999secure}, so a later edit to any
record breaks the chain and is detectable. The feature extractor is versioned, and
a model trained on one feature version refuses to load against another. That turns
a subtle source of silent error, features drifting out of step with the weights
that consume them, into a loud one.

For the external validation in Section 8 we run real attack tools against the
system, and we keep them off the host Python entirely. The pip-installed tools live
in dedicated virtual environments, and the browser-driven scanner and the second
target application run in containers. The harness itself is the same one used for
the synthetic arms, pointed at a different upstream: it stands up an isolated proxy
stack, drives each tool through it, and reads the decisions back from the log.
