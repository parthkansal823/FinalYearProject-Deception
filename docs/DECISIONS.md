# Decision log

Spec §16 lists "working alone means no one catches mistakes" as a risk and
prescribes a written decision log as the mitigation. This is that log. Each
entry records what was decided, why, and what would have to change for the
decision to be revisited.

Entries are append-only and dated. Re-read this file before each evaluation
run (spec §16).

---

## 2026-08-13 — Cost table values

**Decision.** Frozen at: benign/pass 0, benign/bait 1, benign/divert 200,
attack/pass 25, attack/bait 8, attack/divert −20.

**Why.** Spec §6.5 fixes the *ordering* and the rough magnitudes but not the
numbers. Chosen so that: a wrongly diverted user costs 8× a missed attacker
(§6.5 "must almost never occur", NFR-05); wasted bait is ~4% of a missed
attacker rather than exactly zero, so the policy cannot treat baiting as
free; and baiting an attacker is cheaper than passing them because it buys
evidence, but not free, because they still reach the real application.

**Consequence.** Derived thresholds are p=0.0556 (pass→bait) and p=0.8767
(bait→divert). The wide, low bait band is a *result* of the table, not a
tuning choice.

**Revisit if.** Never, once traffic generation has begun — that is the whole
point of the freeze. A re-freeze before Phase 2 is legitimate; afterwards it
invalidates the baseline comparison and must be reported in the limitations.

---

## 2026-08-13 — Score fusion left explicit and near-trivial

**Decision.** `p(hostile) = sigmoid(bias + w_m·logit(malice) + w_a·logit(automation))`
with `w_m = 1, w_a = 0, bias = 0`, i.e. p = malice by default.

**Why.** Spec §6.5 says the policy prices actions "for any given pair of
scores", but the cost matrix is indexed by *true class*, not by score pair.
Something has to map two scores to one hostility probability, and the spec
does not say what. Making that mapping explicit and configurable keeps the
gap visible instead of burying an arbitrary combination inside the policy.

Defaulting `w_a = 0` follows §6.3's own example: a price-comparison bot is
fully automated and entirely harmless, so automation should not by itself
raise the probability of hostility. Automation is spent on *bait selection*
instead (§6.6, matching bait to attacker type).

**Revisit if.** Phase 3 calibration shows automation carries independent
signal about hostility. Any non-zero `w_a` must be reported, because it
weakens the "two independent scores" claim in §4.3.

---

## 2026-08-13 — SQLite permitted as a development fallback

**Decision.** `target_app/db.py` supports both PostgreSQL and SQLite; Postgres
remains the intended backend and the Docker default.

**Why.** Spec §12 chooses Postgres specifically because its error messages are
what make the SQL bait plausible. That reasoning applies to data collection,
not to running the test suite, and requiring Docker for every unit test run
would slow the build loop down for no research benefit.

**Consequence.** Injection payloads behave identically against both; only the
error text differs. **All corpus generation (Phases 2 and 7) must use
Postgres**, or the SQL bait will be calibrated against the wrong error text.

**Revisit if.** Error-text realism turns out to matter for a bait that fires
outside the search endpoint.

---

## 2026-08-13 — Access logging lives in the target app for Phase 1 only

**Decision.** `target_app` writes its own access log via middleware.

**Why.** Phase 1's exit condition requires a labelled benign corpus, but the
proxy that normally produces the corpus does not exist until Phase 3.

**Consequence.** This is ordinary web-server logging: it records what was
served and nothing about suspicion, so NFR-10 (the target app is unaware of
the security layer) still holds — deleting the whole `adf` package would
leave the app serving traffic. From Phase 3 the proxy log supersedes it, and
the access log becomes a cross-check that the proxy drops and duplicates
nothing.

---

## 2026-08-13 — Labels written to a sidecar, never into the traffic log

**Decision.** Generators write ground truth to `data/labels/*.jsonl` keyed by
session id; `adf.dataset` joins them at corpus-assembly time.

**Why.** Spec §7.3 requires labels applied at the point of generation. Keeping
them physically out of the live log means the detection path *cannot*
accidentally read the answer key, which is a stronger guarantee than
remembering not to.

**Consequence.** Sessions must be identifiable across the join. The generator
tags requests with `X-ADF-Session` as well as carrying cookies, so the join
survives a client that drops its cookie jar.

**Revisit if.** Attack tooling (sqlmap, Hydra) cannot set a custom header —
then the join must fall back to source port or timing windows, and that
fallback needs its own validation.

---

## 2026-08-13 — Schema fingerprint normalises module qualification

**Decision.** `_typename()` strips the defining module from nested dataclass
type names.

**Why.** The fingerprint initially differed between `import adf.schema`
(`list[adf.schema.ReasonItem]`) and `python -m adf.schema`
(`list[__main__.ReasonItem]`), so the freeze check failed or passed depending
on how it was invoked. A freeze that depends on invocation mode is not a
freeze.
