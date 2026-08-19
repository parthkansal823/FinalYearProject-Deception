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

The component is small enough to state completely:

```
notebook.get(namespace, key, generator):
    if (namespace, key) in store:            # repetition, cross-reference
        return store[namespace, key]
    v <- generator(seed(run_seed, namespace, key))
    store[namespace, key] <- v               # first write wins
    return v

notebook.put(namespace, key, value):         # write-then-read
    store[namespace, key] <- value           # attacker writes outrank defaults
```

Two mechanisms give all four properties together. Values are produced by a
generator seeded from the run seed, the namespace and the key, so the same key
yields the same value even when it is first reached months later through a
different endpoint; and the first write wins, so two concurrent readers cannot
disagree. Anything the attacker writes is stored at a higher precedence than a
generated default, which is what makes write-then-read hold: a default can never
overwrite a modification the attacker made and then went back to check.

Measuring this needs an adversary, because a decoy that is asked one question twice
will pass almost by accident. We therefore drive the decoy with a fuzzer that
interrogates it for the same fact through different routes, in different orders,
with repetition and interleaving, and counts the disagreements. It probes seven
ways a decoy realistically betrays itself:

| probe | what it asks |
|---|---|
| repetition | the same endpoint again — byte-identical? |
| interleaving | the same fact after many intervening reads — any drift? |
| cross-reference | a user via HTML page, JSON API and directory listing — every field agreeing? |
| multi-reference | every record owned by one user naming the *same* owner, matching that user's own profile |
| referential | a record's owner id resolving to a profile whose name matches the record |
| SQL error | the same injected payload yielding the same error text every time |
| search | the same query returning identical results on repeat |

Multi-reference is the case a naive decoy fails: two records generated independently
disagree about who owns them, and no amount of per-response realism fixes it. The
fuzzer separately checks *plausibility* — that departments, roles and
classifications come from real sets, that an email matches its username, that
amounts parse as money — and reports it apart from consistency, because an
implausible decoy that never contradicts itself is a different failure from a
contradictory one.

The notebook's value is then easy to isolate, because disabling it is a single
switch: generate afresh each time, remember nothing. With the notebook, the
contradiction rate over **286 adversarial probes is zero**. With it disabled it is
**one hundred percent** — a generator with no memory answers the second identical
question differently almost every time. That pair of numbers is the notebook's
entire justification, and it is pinned as a test so it cannot silently regress.

A sceptic can read that result as an artefact of a weak generator: a deterministic
function is already self-consistent, so perhaps the notebook is doing nothing a
seeded RNG could not. We therefore repeated the ablation against a genuinely
stochastic generator, a local language model, which cannot be consistent on its
own by construction. Over fifteen entities it contradicted itself on every one
without the notebook and on none with it. The guarantee therefore belongs to the
notebook rather than to whatever produces the content, which is the property that
matters if a deployment swaps in a language model for richer prose.
