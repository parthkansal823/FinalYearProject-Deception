# 6  Consistency: The Fact Notebook

A decoy that looks convincing on the first request and contradicts itself on the
third has not fooled anyone; it has announced that it is a trap. The hard part of a
decoy is not plausibility in the moment but consistency over an engagement, and
consistency has structure worth naming. A decoy has to answer the same query the
same way twice (repetition). It has to keep a value the same when it is reached by
a different route (cross-reference). It has to return what was written to it if the
attacker writes and then reads (write-then-read). And references between objects
have to resolve — an order that names a customer must name a customer that exists
(referential integrity).

We meet all four with a single component, the Fact Notebook, which sits between
the decoy's generators and its responses. The first time any value is needed, the
notebook records what was produced; on every later reference it serves the recorded
value rather than generating afresh. The generator can be anything — a
deterministic function here, a language model in principle
\cite{sladic2024shellm,vero2026honeyval} — because the notebook does not care how
a value was first produced, only that it never changes afterward. This is the gap
we fill: evaluation frameworks for LLM-generated honeypots measure stealth and
fidelity but not whether a decoy contradicts itself over an engagement
\cite{vero2026honeyval,bridges2025sok}. This is also what keeps the decoy
reproducible: the same session replays identically.

The notebook's value is easy to isolate, because disabling it is a single switch —
generate afresh each time, remember nothing — and that switch is exactly the
ablation. With the notebook, the decoy's contradiction rate over several hundred
adversarial probes from a consistency fuzzer is zero. With it disabled, it is one
hundred percent: a generator with no memory answers the second identical question
differently almost every time. That pair of numbers is the notebook's entire
justification, and it is pinned as a test so it cannot silently regress.
