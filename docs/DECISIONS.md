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

---

## 2026-08-13 — Session identity cached on the request

**Decision.** `target_app.get_session()` caches the resolved session on
`request.state`.

**Why.** Found during Phase 1 verification, not by a test. The access-log
middleware and the route handler each called `get_session()`; for a client
arriving without a cookie, the middleware created one session and the handler
created another. The first was logged and then orphaned, while the cookie
carried the second — so the first request of every session was split away
from the rest of it.

**Consequence.** Symptom was 143 sessions for 60 generated, median 1 request
per session. After the fix: 84 sessions (60 generated + 24 post-logout
continuations, matching the 40% logout rate), median 25 requests per session,
contiguous `request_index` within every session.

**Why it mattered enough to log.** Suspicion scores accumulate across a
session (spec §6.4) and `requests-to-decision` (§10.3) is measured per
session. A corpus that silently splits sessions would have made the headline
efficiency metric wrong in a way that looks plausible.

**Watch for.** The proxy will resolve sessions independently in Phase 3
(cookie or fingerprint, spec §5.2). The same double-resolution hazard exists
there, and the cross-check against this access log is how it would be caught.

---

## 2026-08-13 — Bait repriced as an information purchase (schema v2, cost re-freeze)

**Decision.** Three linked changes, all made before any corpus collection:

1. `attack/bait` raised from 8.0 to 25.0, equal to `attack/pass`.
2. The decision rule subtracts an explicitly computed EVSI term
   (`adf/policy/voi.py`) rather than relying on a pre-discounted cost.
3. Schema bumped v1 → v2: named rounds with a new `calibrate` round, plus
   `decision.evsi`, `decision.bait_assignment`, `bite.cross_session` and
   `bite.likelihood_ratio`.

**Why.** Spec §6.5 discounts the cost of baiting an attacker "to reflect that
purchased information", and §5.2 makes the malice score "jump sharply" on a
bite. These are the same quantity — the value of the evidence a bait buys —
counted twice and derived neither time. Both are exactly the sort of tuned
constant that §6.5's own methodology rejects, and a reviewer will look for
them.

Computing the value once, properly, removes both. It also produces a stronger
result than the original framing: with bait at its true immediate cost, the
cost table alone yields **no bait band at all** (a single PASS/DIVERT boundary
at p = 0.816). The third action exists purely because of the information term,
which is a much better answer to "isn't that just a tuned threshold?" than the
spec's "bait is cheap".

**Consequence.** Derived bands moved from 0.0556/0.8767 to 0.0426/0.8595, and
they now depend on measured bait effectiveness rather than on the cost table
alone. `config/bait_library.yaml` ships β values as **priors**, marked
`calibrated: false`; the policy refuses to run in reporting mode against them.

**Legitimacy of the re-freeze.** The freeze mechanism worked as intended: it
forced this to be a deliberate, dated, documented change rather than a quiet
edit, and it happened before any corpus existed, which is the only time such a
change is free. `config/costs.CHANGELOG.md` carries both digests.

**Revisit if.** Never after the `calibrate` round runs.

---

## 2026-08-13 — Randomised bait holdout

**Decision.** 10% of sessions reaching the BAIT band are deliberately not
baited, recorded as `bait_assignment: holdout`.

**Why.** The spec establishes bait's value by comparing the full system
against baseline B2 — two systems differing in every component, so the
difference in time-to-decision is confounded with all of them. Withholding
bait at random from sessions that reached the same belief state makes bait an
assigned treatment within one system, and the difference becomes an unbiased
causal estimate.

**Consequence.** Costs a little detection performance by design; that cost is
reported, not hidden. Assignment hashes (seed, session id) so runs replay
exactly while staying unpredictable to an attacker who cannot see the seed.
The B2 comparison is kept as well — it answers a different question.

**Revisit if.** Attack round 2 produces too few bait-band sessions for the
holdout arm to be informative. Check the power before round 2, not after.

---

## 2026-08-13 — Schema v3: the label join was silently producing zero matches

**Decision.** Added `session.provenance_id`, a generator-assigned session
marker carried in the `X-ADF-Session` header and recorded outside
`request.headers`. Added `adf/dataset.py` to perform and *verify* the join.

**Why.** Found by checking rather than assuming. Labels were keyed by the
generator's session id (`benign-791d33...`), records by the application's
cookie (`b5fe2e9bd3...`). Two namespaces that never met: **zero overlap**.
Nothing raised, nothing looked wrong, and the corpus was entirely unlabelled
while appearing complete. Phase 1's exit condition requires a *labelled*
corpus, so this was blocking rather than untidy.

The marker has to be carried rather than derived, because the label must be
written *before* the session acts (spec §7.3) and only the generator knows the
session at that point.

**Consequence.** Coverage is now a first-class, reported result, and
`adf.dataset.build()` refuses to emit a corpus below 95%. Current run: 99.9%
records, 0 labels unmatched.

**Why `provenance_id` is not in `request.headers`.** It uniquely identifies
the generator's intent, so it is the answer key. Held on the session block, it
is structurally out of reach of anything building a feature vector from
headers. `adf.schema.NEVER_FEATURE_FIELDS` and
`adf.dataset.assert_no_label_leakage()` enforce this for Phase 3.

---

## 2026-08-13 — Benign traffic gained an automated class and two hard negatives

**Decision.** Added `tools/benign_agents.py` (uptime monitor, search crawler,
reporting integration) and two awkward-but-honest human personas
(`apostrophe_searcher`, `forgetful`).

**Why — the automated class.** Spec §6.3 justifies the two-axis model with
"a price-comparison bot is highly automated and entirely harmless". The corpus
contained no such traffic, so automation and malice were perfectly correlated.
That makes contribution #2 unfalsifiable: a single combined score would have
performed identically, the "one score instead of two" ablation (§10.2) would
have shown no difference, and the correct reading would have been that the
second axis is unnecessary. The meter would also have learned "scripted" as a
proxy for "hostile", which is the brittle heuristic this project exists to
replace.

**Why — the hard negatives.** "Benign bait exposure rate" (§10.3) and NFR-05
only mean something if benign traffic ever approaches the decision boundary.
A corpus in which no honest user ever trips a malice feature reports zero
exposure, and that zero describes the corpus rather than the system.

- `apostrophe_searcher` looks up a colleague whose surname contains an
  apostrophe. Verified: `?q=O'Connell` returns HTTP 500 with
  `near "Connell": syntax error` — the *same* verbose error an attacker gets
  while probing. Maeve O'Connell is in the seed directory for this reason.
- `forgetful` fails login 3–5 times before succeeding: the trigger condition
  for B-AUTH-1 and the shape of an early credential attack.
- `ReportingIntegration` walks record ids in ascending order over the API —
  the request shape of an IDOR sweep, differing only in that every id it
  touches belongs to it.

**Consequence.** Personas are recorded in `labels.notes`, never in the class
labels: an awkward honest user is exactly as benign as a straightforward one.
Blurring that would teach the meter that "looks odd" means "is hostile". The
analysis can still break them out to see where false positives concentrate,
and they are the natural population for reporting NFR-05 against.

**Watch for.** If the final system diverts `forgetful` or `apostrophe_searcher`
sessions, NFR-05 has failed and it must be reported, not tuned away.

---

## 2026-08-13 — Timing separation measured over navigations, not raw requests

**Decision.** The corpus report computes inter-request timing over navigation
requests only, excluding static sub-resources (`/static/*`).

**Why.** The Phase 1 exit gate initially failed the timing-separation check,
and it was right to: the *measurement* was wrong. A browser fetches a page's
CSS, JS and logo in a rapid burst regardless of how human the user is, so
those few-millisecond gaps dominate the raw inter-request stream and bury the
think-times entirely (human median raw gap: 22 ms). Measured over navigations
only, the think-times reappear: human median navigation gap 1.27 s vs 0.49 s
for scripts. This is also the timing feature the Phase 3 extractor will
compute, so the diagnostic now matches it.

**The deeper finding (worth the paper).** No single timing statistic separates
all classes, and that is the point of §6.3, not a flaw:

  profile       assets/page   nav-gap
  normal            1.30       1.29 s
  apostrophe        1.27       1.24 s
  forgetful         0.94       1.23 s
  crawler           0.67       1.01 s
  monitor           0.00       1.01 s   <- human-like GAP, but no assets, metronomic
  integration       0.00       0.06 s   <- no assets, blazing rate

A 2-second uptime monitor is temporally indistinguishable from a human; it is
caught by *not fetching assets* and by *regularity*. A fast integration job is
caught by rate. The crawler (fetches some assets, polls at human speed) is the
genuine "automated but harmless" case of §6.3 and is separable mainly by
regularity plus behavioural markers. This multi-feature structure is exactly
why the meter combines weighted evidence (§6.4) rather than thresholding one
number, and it is the empirical justification for the two-axis design.

**Consequence — the gate was corrected, not the goalposts moved.** The
original gate demanded one feature (timing CV) be a 1.5x separator, which
contradicts §6.3's own thesis. The corrected gate asserts what is actually
required for Phase 3 to work: the strong signal §6.1 names (asset-fetching)
cleanly separates humans from pure scripts, human think-times are present and
plausible, and humans are more irregular than scripts as a supporting signal.
All six checks now pass on merit.

---

## 2026-08-13 — Database connections were leaking (Windows file lock)

**Decision.** `target_app/db.py` now closes every connection via a `_session()`
context manager.

**Why.** `with sqlite3.connect(...) as conn` commits but does NOT close the
connection -- a standard-library gotcha. Every query leaked a connection until
garbage collection, which on Windows kept the database file locked. Harmless in
the long-running server, but it made the test database undeletable and failed
suite teardown with `WinError 32`. Found via that teardown failure, not by a
test of the DB layer directly.

**Consequence.** Connections are closed deterministically now. The test
fixture also swallows a `PermissionError` on cleanup of its disposable,
gitignored database, so a stray OS lock can never fail the suite again.

---

## 2026-08-13 — Attack round 1 completes the automation×malice 2×2

**Decision.** `tools/attack_traffic.py` emits both scripted and *manual*
attackers, not scripted only.

**Why.** The two benign generators cover benign/human and benign/scripted. If
the attack side were scripted-only, automation and malice would be perfectly
correlated in the corpus and the two-axis model (contribution #2) would be
unfalsifiable — a single combined score would fit just as well, and the "one
combined score" ablation (§10.2) would correctly show the second axis is
pointless. The `ManualAttacker` and the `manual_*` profiles populate the
attack/human cell: browser UA, fetches assets, slow irregular timing —
"barely automated, extremely hostile" (§6.3). On the automation axis it looks
benign, so only malice catches it. The corpus report's 2×2 table now shows all
four cells with genuine off-diagonal mass.

**Guard.** The generator refuses `--round eval`. Round 2 must use genuinely
different techniques (§7.2); making eval one flag away from a rerun of the
straight round-1 corpus was a mistake waiting to happen.

---

## 2026-08-13 — Attacks are verified to actually exploit, not merely fire

**Decision.** Every attack profile has a test that asserts the exploit LANDS
(UNION dumps the users table, IDOR reads other profiles, brute force reaches
OTP, OTP brute force reaches the dashboard), driven against the real app.

**Why.** A payload that is sent but does not exploit produces traffic labelled
"attack" that is indistinguishable from benign — it teaches the meter noise
under a hostile label. One case was caught this way: credential stuffing with a
purely random password list sometimes landed no valid pair, so a valid pair is
now seeded into every stuffing session (a ~7% hit rate) to guarantee the corpus
contains successful stuffing, not only failed.

---

## 2026-08-13 — Corpus generation is orchestrated, not run by hand

**Decision.** `tools/generate_corpus.py` owns the whole lifecycle: wipe →
seed → start a private server → run every generator → stop the server →
verify.

**Why.** The strict label join failed at 94.5% after manual development, and
it was right to. Running generators by hand against a long-lived server let
stray traffic — my own verification pokes — into the same append-only log with
no label, so the corpus no longer consisted solely of intentional, labelled
traffic (§7.3). The orchestrator makes that impossible: the server is private
to the run and torn down at the end, so nothing else can append. Same seed
reproduces the same corpus (NFR-08).

---

## 2026-08-13 — Feature extractor is the single source of truth; accumulation lives in the features

**Decision.** `adf/features/extractor.py` defines every feature once. The
corpus diagnostic imports the same primitives. Features are session-cumulative
and streamed one request at a time.

**Why (single source).** The numbers used to justify Phase 1/2 must be the
same numbers the meter trains on. Two copies would drift, and the evidence
would then describe a different feature than the system uses. `corpus_report`
now imports `special_char_ratio`, `db_keyword_hits` and `client_inputs` from
the extractor rather than keeping its own.

**Why (accumulation in features).** Spec §5.2/§6.4 require the score to
accumulate across a session rather than reset each request. Rather than a
hand-tuned decay constant on top of a per-request model, the accumulation is
put in the features themselves — failed-auth count, longest sequential-id run,
a latched db-keyword flag, rolling rate — so a plain logistic model over the
cumulative vector rises monotonically as evidence builds. No magic constant.

**The load-bearing safety property.** No feature may read the ground-truth
label or the `provenance_id` join key (spec NEVER_FEATURE_FIELDS). This is
enforced by a test that holds the observable request fixed, flips the label and
provenance, and asserts the feature vector is byte-identical. Without it, the
eventual accuracy would be a fiction.

---

## 2026-08-13 — Dual meter: two interpretable heads, frozen as inspectable JSON

**Decision.** Two independent logistic heads (`automation`, `malice`), each
over its own feature partition, trained offline with scikit-learn but scored at
inference from three stored numpy arrays serialised as JSON.

**Why logistic, why two.** Spec §6.4 names logistic regression first for
interpretability and small-data robustness, and requires two scores because
one cannot express automated-but-harmless and manual-but-hostile at once. Each
decision is explainable as `bias + Σ wᵢxᵢ`, and `explain()` returns the signed
per-feature contributions (NFR-07); a test checks they reconstruct the logit
exactly.

**Why JSON, not a pickled sklearn model.** The frozen model (spec §7.2) should
be diffable and inspectable in review, and the live proxy should not pay an
sklearn import per request. The standardiser is stored with the weights so
inference is a dot product. `load()` refuses a model whose feature-set version
does not match the code, so a feature change cannot silently misalign weights.

**Training driver.** `tools/train_meter.py` keeps only the `train` round by
default and refuses eval without an explicit, loud override — the model is B2,
and B2 must be frozen before it meets round-2 traffic.

---

## 2026-08-13 — Reverse proxy forwards first, scores around it, fails open

**Decision.** The proxy (`adf/proxy/`) forwards to the upstream BEFORE scoring,
and wraps all detection in a try/except that swallows on failure when
`proxy.fail_open` is set.

**Why.** NFR-04 makes fail-open non-negotiable: the proxy is a single point of
failure, so a detection bug must never take the site down. Forwarding first
means the user's response is already in hand before any feature extraction,
scoring or policy call runs; if any of those raise, the response is served
anyway and the event is logged with `fail_open_triggered=true` so it is loud,
not silent. Two tests inject a meter crash and assert the real page still comes
back.

**Consequences that fell out of the design.**
- Turning scoring off via `mode` (b0) makes the proxy a plain forwarder using
  the same code path — the baseline machinery of §5.3/FR-12 for free.
- Bait injection (Phase 4) and decoy routing (Phase 5) are explicit empty
  hooks (`_maybe_inject_bait`, `_route_upstream`), so those phases extend this
  file rather than rewrite it. The spec forbids bait before the invisibility
  gate (§6.7), so the hook is deliberately inert now.
- Per-session state (streaming extractor + running scores) lives in memory in
  one worker, which is why the app runs unreplicated — the same constraint the
  target app already documents, for the same reproducibility reason.
- A missing frozen meter is not fatal: the proxy loads the model if present and
  otherwise forwards. A model file is not allowed to be a prerequisite for
  serving traffic.

**Session identity.** Cookie first, then a coarse header+IP fingerprint
(`adf/proxy/session.py`), so a cookieless attack tool still accumulates a score
across requests instead of resetting every time — the accumulating meter would
be trivially evaded otherwise.
