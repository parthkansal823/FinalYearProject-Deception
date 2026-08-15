# 7  Implementation and Reproducibility

The system is about ten thousand lines of Python behind an asynchronous reverse
proxy, with the deliberately weak target application and the decoy as separate
services. Three mechanisms make the evaluation in Section 8 reproducible and hard
to fudge, and they are worth stating because a measurement that cannot be replayed
is difficult to trust.

**The model is frozen before evaluation.** A manifest hashes everything a decision
depends on — the two logistic heads, the cost table, the feature set and its
version, the calibrated bait library, and the invisibility certificates — and the
system verifies the manifest at start-up, refusing to run if any of it has moved.
Freezing is not a convention we promise to honour; it is checked. The cost table in
particular is hashed separately and enforced on every load, because the entire
argument of Section 4 rests on those numbers being fixed before the results were
seen. Re-freezing is possible but deliberate, and leaves a dated entry in a
changelog.

**Traffic is seeded and replayed.** Every generator is deterministic given a seed,
so each baseline sees byte-identical traffic. This is what makes the comparison in
Section 8 a comparison of *systems* rather than of *samples*: the only thing that
differs between arms is the code path selected by a single mode flag. The
multi-seed evaluation repeats this over many independent seeds and reports
confidence intervals; we are explicit in Section 10 that these intervals quantify
variability under a fixed generative model, not generalisation to real traffic.

**The log is tamper-evident.** Decisions are written to an append-only store whose
records are chained by hash, so a later edit to any record breaks the chain and is
detectable \cite{schneier1999secure}. The feature extractor is versioned, and a model trained on one feature
version refuses to load against another, which turns a subtle source of silent
error — features drifting out of step with the weights that consume them — into a
loud one.

For the external validation in Section 8 we run real attack tools against the
system, and we keep them off the host Python entirely: the pip-installed tools
live in dedicated virtual environments, and the browser-driven scanner and the
second target application run in containers. The harness that stands up an isolated
proxy stack, drives each tool through it, and reads back the decisions from the log
is the same one used for the synthetic arms, pointed at a different upstream.
