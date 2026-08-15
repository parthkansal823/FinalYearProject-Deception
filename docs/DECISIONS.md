# Decision log

Spec §16 lists "working alone means no one catches mistakes" as a risk and
prescribes a written decision log as the mitigation. This is that log. Each
entry records what was decided, why, and what would have to change for the
decision to be revisited.

Entries are append-only and dated. Re-read this file before each evaluation
run (spec §16).

**How to use it.** Newest entries are at the bottom. Each one follows the same
shape — *Decision* (or *Finding*), *Why*, *Consequence*, and *Revisit if* —
so that a future reader can tell a deliberate trade-off from an accident, and
knows what evidence would overturn it. Add an entry whenever a choice is made
that the code alone would not explain, especially one that touches the frozen
artefacts, the corpus, or a reported metric.

For what the project *is*, read [OVERVIEW.md](OVERVIEW.md); this file is only
the record of how it got that way.

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

---

## 2026-08-14 — End-to-end smoke caught a benign login diverting (NFR-05)

**Finding.** The first full end-to-end run — proxy + trained B2 meter on live
traffic — diverted a *benign* login. Request #6 of an ordinary sign-in,
`POST /login` with body `username=a.mirza&password=Summer2024!` (35 chars),
scored malice 0.834, over the b2 divert threshold. A divert is per-session, so
one false request would have sent a real user into the decoy — the exact
outcome NFR-05 requires to be effectively zero, and the most expensive cell in
the cost table.

**Root cause.** `mal_input_length` (and, latently, `mal_special_char_ratio`)
measured the login body. The malice head learned "long, symbol-dense input =
hostile" from injection payloads — but a password is legitimately long and
symbol-dense. The login form is not even the injection surface (it uses
parameterised queries; only /search concatenates), and the credential-attack
signal is `mal_failed_auth`, not input content.

**Fix.** `client_inputs` now excludes authentication bodies (/login, /otp) from
the content features, while still inspecting query parameters on those paths so
`/login?x=' UNION` is not a blind spot. Retrained B2. Re-ran the smoke: **0/308
benign requests diverted across 12 sessions; 6/6 attacks still diverted**,
most within 1–6 requests. Locked with two regression tests.

**Why this belongs in the paper.** It is a concrete instance of the project's
own thesis about false positives, and it was caught by the safety instrument
(the benign corpus + the smoke) rather than shipped. The benign corpus with its
hard negatives is what made the failure observable at all — without a realistic
login in the traffic, the bug would have surfaced only in the eval.

---

## 2026-08-14 — Proxy session identity: fingerprint fallback defaulted off

**Finding.** The same smoke grouped 12 distinct benign clients into 5 sessions.
Cause: `attach()` never set a cookie for fingerprint ("fp-") sessions, so a
cookie-capable client that arrived cookieless once was fingerprinted forever,
and every client sharing a coarse fingerprint (same UA + localhost IP) merged.

**Fix.** The proxy now mints a real session and sets a cookie on first contact,
so cookie-capable clients diverge from request 2. The fingerprint is coarse by
nature and cannot separate distinct clients that share it, so
`session.fingerprint_fallback` now defaults **off**: with it off every client
is cleanly distinct via its own cookie, which is what per-session eval metrics
require. It remains available (documented limitation) for the specific threat
of a cookie-refusing tool resetting its score (spec §5.2). After the fix the
smoke grouped exactly 12 benign + 6 attack sessions.

**Consequence for the corpus.** None: the round-1 corpus was generated against
the target app directly, which always set cookies, so its sessions were already
clean. This bug only affected live traffic through the proxy — i.e. Phase 6/7.

---

## 2026-08-14 — Phase 4: bait as a value-of-information purchase, proven end to end

**Built, in the order §13.1 demands.** The invisibility gate first, then the
baits, then bite detection — never the other way round.

**All bait lives in non-rendered channels.** Spec §3.2's mechanism ("a real
user sees a generic message; someone hunting sees a name worth querying") only
holds if the bait sits where a browser does not paint. So the three channels
are HTML comments, additive JSON fields, and response headers — nothing that
reaches the rendered DOM. The gate's comparator strips comments, scripts and
hidden nodes and compares visible text + form/link structure, which is exactly
"the page a real browser displays" (§6.7). A bait that writes into the visible
page, breaks a form, or overwrites a real JSON field is rejected; four tests
prove the gate rejects each, so it is not a rubber stamp.

**Certified against REAL benign responses**, collected from the running target
app — including the apostrophe-search error page, the one place B-SQL-1 is most
likely to meet an innocent user (Maeve O'Connell). 6/6 baits certified,
0.008–0.131 ms median overhead, far below the 0.5 ms detectability ceiling. The
certificate store is enforced at RUN TIME: the engine refuses to serve any bait
without a passing certificate (spec §6.6), so invisibility is a property of the
live system, not just the build.

**The bite is priced, not asserted.** A bite adds the bait's calibrated
likelihood ratio — log P(bite|attacker)/P(bite|benign) — to the session's
malice in log-odds. This is the derived form of the spec's "the malice score
jumps sharply"; with B-SQL-1's priors (LR≈1100) a bite adds ~7.0 to the logit.
Nothing is a hand-set jump constant. (The betas are still priors; a reported
result needs the `calibrate` round, which the policy already guards.)

**End-to-end demonstration — the contribution, working.** A curious attacker
authenticated and browsed, sitting at malice 0.26–0.41 the whole time: the BAIT
band, below the 0.877 divert threshold, where **passive B2 keeps passing them**.
B-SQL-1 was injected invisibly into the page source (`acct_shadow_269c89`). The
attacker read the source, harvested the fake table, and queried it — the BITE —
and malice jumped **0.412 → 0.960 → DIVERT**. The bait manufactured the evidence
passive detection did not have, and resolved the uncertainty in one request.

**Bite detection covers three kinds and cross-session.** Value (token string
reappears), name (a field the site never emitted is submitted), and path (the
deprecated endpoint is requested). A token seen in a session other than the one
it was issued to is flagged `cross_session` — either a leaked/published bait or
an attacker rotating identity (spec §16), both stronger signals than an
ordinary bite.

**Honest limitation recorded.** Name baits (ref_uid, internal_view,
mfa_debug_token) keep the plausible fixed names the spec names, so they are
partially publishable; freshness there comes from per-session SELECTION, not
per-session content. Value baits (fake tables, endpoints) get random suffixes
and are fully unpublishable (spec §16).

---

## 2026-08-14 — Verification pass found a real tamper-evidence bug in from_dict

**Finding.** A Phase-0-to-4 re-check caught the dataset builder REFUSING to
assemble a corpus, reporting "content modified" on a proxy log. The data was
not tampered; the VERIFIER was wrong. `Record.from_dict` reconstructed the
`decision` block from a hand-maintained field list that had drifted: when
`evsi` and `bait_assignment` were added in schema v2, `from_dict` was not
updated, so it silently dropped them. `verify()` rebuilt each record through
that lossy path, re-serialised it, and got different bytes -- a false tampering
report on EVERY log containing a bait or divert decision.

**Why it mattered.** This is the tamper-evidence mechanism (NFR-13) and the
dataset-assembly path (spec §11) both failing on exactly the records the whole
project produces once bait is active. Left in, it would have blocked corpus
assembly in Phases 6-7 and made the "logs are tamper-evident" claim false.

**Two fixes.**
1. `from_dict` now reconstructs the `decision` block with the same `build()`
   helper used for every other block, so it copies all fields and cannot drift
   again. Confirmed a fully-populated record now round-trips to identity.
2. `verify()` no longer routes through `from_dict` at all. It hashes the RAW
   stored dict (`Record.hash_raw`), so verification depends only on the bytes
   on disk -- never on `from_dict` being a perfect inverse. This is the correct
   design regardless: a verifier that reconstructs before hashing cannot tell a
   deserialisation imperfection from real tampering.

**Guard.** A new test writes five records with every block set to non-default
values, then asserts both that the chain verifies AND that `from_dict` is a
faithful inverse. The old tests used minimal records, which is why they missed
it -- the round-trip was lossless only for the fields they happened to set.

**Process note.** This is exactly the kind of defect a "looks done" pass hides:
all 145 tests were green because none exercised a fully-populated record
through verify. Worth remembering that green tests bound what was checked, not
what is correct.

---

## 2026-08-14 — Phase 5: the decoy, backed by a Fact Notebook, contradicts itself 0%

**Built.** The Fact Notebook, the offline world generator, the planted
credential, the decoy application, and the consistency fuzzer — the project's
second load-bearing contribution (§4.3 #4).

**The Fact Notebook is the consistency guarantee (§6.9).** A fact is
`(namespace, key) -> value`, held in SQLite. Two mechanisms give all four
consistency dimensions at once:
- Deterministic generation keyed by `(seed, namespace, key)`, so a fact first
  requested on demand months later is byte-identical to one produced in the
  offline batch — repetition and cross-reference hold before anything is even
  persisted.
- Persistence with precedence, so an attacker's write outranks the generated
  default and reading a mutated fact back returns the mutation — write-then-read.
Referential integrity is a property of the generators: a generator that emits a
reference (record.owner_id) resolves it through the notebook, which generates
that entity consistently if absent. Each dimension has its own test.

**Offline generation, not a live model (§6.8, §15.1).** Spec §12 allows "any
language model, run in batch"; here it is a deterministic synthetic generator.
This is a deliberate, honest substitution — seeded (NFR-08), reviewable, and
keyed per entity so on-demand and batch generation agree. A real deployment
could drop an LLM into `GENERATORS` without changing anything else; the notebook
does not care how a value was produced, only that it is fixed once produced.
Consequently NO generation ever sits in the request path, so the decoy answers
at database speed and a slow-decoy timing tell cannot arise.

**The decoy is pixel-identical to the target by construction.** It reuses the
target's own templates and static assets and serves every fact from the
notebook, so layout, error text and headers match (§6.8). A diverted attacker
lands mid-session and the decoy is deliberately permissive — everything
"works" — to maximise engagement (§10.3) rather than guard anything, because
there is nothing real to guard (NFR-06).

**Contradiction rate: 0.0000% over 101 probes** on the live decoy (repetition,
cross-reference, referential integrity). This is the metric §6.9 says existing
work does not report, and it is the Phase 5 exit condition: the decoy survives
the fuzzer with a low, measured contradiction rate. Met.

**End-to-end, demonstrated live.** A SQLi attacker diverted at request #4; every
later request routed transparently to the decoy (`in_decoy=true`), with no
visible transition (FR-09) — `/api/profile/1` returned the fake "Chandni Berg",
not the real "Ayesha Mirza", so the attacker is isolated from real data. The
attacker then found `service.ini`, harvested the planted key and reused it; the
decoy flagged the capture — deep exploration, credential harvesting and intent
to reuse proven in a single event (§6.10).

---

## 2026-08-14 — Phase 5 review: the "indistinguishable" decoy was distinguishable

**Why the review happened.** The first decoy passed its own tests and the
fuzzer at 0% contradictions, but "looks done" is not "is correct" (the Phase 4
lesson). A deliberate audit diffed the live decoy against the live target on the
probes an attacker actually uses to spot a trap. It found FIVE tells -- the
§6.8 indistinguishability claim was false.

**The tells, and why each mattered.**
1. **Canary header leak (critical).** On planted-credential reuse the decoy
   returned `X-ADF-Canary: captured` -- literally telling the attacker they were
   caught, the exact opposite of the executive summary's promise. Detection is
   now recorded INTERNALLY only; no header, no body change.
2. **Permissive auth.** `/dashboard` served 200 without auth (target: 303 to
   /login); `/login` with bad creds advanced (target: 401 verbose). The decoy
   now mirrors the target's auth state machine and verbose errors. A diverted
   attacker stays authenticated because the proxy vouches via a trusted
   `X-ADF-Authenticated` header, set only on the localhost-only proxy→decoy
   path, so there is no "why am I logged out?" tell.
3. **No SQL-injection surface.** The decoy's search never errored; the target
   leaks a verbose DB error on injection. A SQLi honeypot that does not look
   injectable is a tell. The decoy now reproduces a fake but CONSISTENT DB error
   (stored in the notebook, keyed by the query) for injection-shaped input.
4. **Infinite id space.** `/api/profile/99999` generated a user forever; real
   data is finite. The id space is now bounded and 404s beyond it, like the
   target past its rows.
5. **Timing.** `/directory` ran 3.4x slower than the target because the notebook
   opened one SQLite connection per row. A batch fetch (`get_many_or_generate`)
   brought it to 1.3x -- inside the target's envelope (NFR-03).

**Result after fixes.** A re-audit shows all five probes now match the target
(same status codes, same verbose errors, same DB-error surface, finite ids, no
canary). Contradiction rate still 0% over 101 probes. End-to-end through the
proxy: an authenticated attacker diverts, STAYS authenticated in the decoy
(no re-login tell), sees fake data ("Chandni Berg", not the real "Ayesha
Mirza"), and the credential capture is logged internally with nothing leaked.

**Honest residual limitations (for the paper, §18, and §10.4 time-to-suspicion).**
- Trusting `X-ADF-Authenticated` relies on the decoy being unreachable except
  via the proxy (NFR-14). Sound in the lab; a real deployment would sign it.
- The decoy has no HTTP write surface, so the write-then-read consistency
  dimension is exercised at the notebook level, not over HTTP. Adding an
  upload/edit surface would make it fully fuzzable -- deferred, not pretended.
- Residual timing differences on list pages are small but nonzero; §10.4 exists
  precisely to measure which such tells betray a decoy first.

---

## 2026-08-14 — Full route-surface parity (the audit's second pass)

**Why a second pass.** The first Phase 5 review fixed five behavioural tells but
only checked five probes. A COMPLETE audit -- enumerating every route on both
apps and diffing status, content-type, headers and error bodies -- found two
more, both structural:

- **/logout existed only on the target.** A diverted attacker who clicked
  "Sign out" would get a 404 the real site never returns. Added /logout to the
  decoy, mirroring the target (clears the session, 303 to /).
- **/files existed only on the decoy.** The planted credential lived behind a
  route the real app did not have, so the route's mere existence gave the decoy
  away. Added an identical /files area to the TARGET, with inert content -- the
  real service.ini carries NO harvestable secret; only the decoy's does. That
  one file is the intended bait (§6.10); every other file is byte-identical
  across the two apps, and the route surface is now identical.

**Result.** 17 shared routes probed authenticated, plus the gated/unauth and
error cases: zero tells. Route surfaces are identical (no target-only or
decoy-only routes). The only difference anywhere is the credential in
service.ini. Locked by tests/test_indistinguishability.py, which stands both
apps up in-process and fails on any status, content-type, gating, error or
route-surface divergence -- so a future edit that reintroduces a tell breaks a
test rather than the deception.

**Full state after both audit passes:** 186 tests pass; contradiction rate
0.0000% over 101 probes; end-to-end via the new /files path still captures the
planted credential internally with nothing leaked to the attacker.

**Method note.** The audit script itself had a bug -- it probed /logout (which
logs out) before /files, so everything after looked unauthenticated. The app
was correct; the test was wrong. Worth recording because it is the same trap in
miniature: a red result has to be diagnosed, not assumed, before it is fixed.

---

## 2026-08-14 — Made the contradiction-rate evidence actually adversarial

**Why.** The decoy was strong but the fuzzer behind the headline metric was
weak: it fetched a row twice and found it unchanged. A store-backed decoy is
self-consistent almost by construction, so a 0% from that fuzzer proved little.
The second contribution (§4.3 #4, "a metric not currently reported in this
literature") is only as convincing as the fuzzer that produces it.

**What changed.** The fuzzer now runs 286 CONTRADICTION probes across seven
dimensions and 214 PLAUSIBILITY probes, up from 101 across three:

- **multi-reference** (the one a naive decoy fails): group records by owner and
  assert every record referencing one owner agrees on the owner's name AND
  matches that owner's own profile. Two independently generated records that
  disagree about their shared owner would be caught here.
- **full-field cross-reference**: every field of every profile (name, email,
  phone, department, location) must agree across the HTML page, the JSON API
  and the directory listing -- not just the name.
- **interleaving**: a fact re-fetched after many intervening reads must be
  unchanged (no drift from generation order or a bounded cache).
- **sql-error consistency**: the same injection payload must yield the SAME
  error page every time -- the error surface is itself a fact.
- **search consistency**, **referential integrity**, **repetition**.
- **plausibility** (§10.4, reported separately, not folded into the
  contradiction rate): department/role/location/classification drawn from the
  real domains, email matches username, amounts are money-shaped.

**Result.** 0 contradictions over 286 adversarial probes; 0 implausible values
over 214 checks. The 0% now means the decoy stays consistent under aggressive,
multi-route, interleaved probing AND its content is plausible -- a defensible
demonstration rather than a tautology. Locked by an updated test that requires
the probe count to stay high and the multi-reference dimension to run.

---

## 2026-08-14 — Phase 6: integration, per-component fail-open, calibration, model freeze

**Per-component fail-open (NFR-04), and a real gap it found.** A fault-injection
test exercises EACH detection component in turn -- feature extractor, meter,
policy, bite detection, bait injection -- and asserts the benign user still gets
the real page. It caught a genuine hole: bait injection runs on the OUTBOUND
response, outside the scoring try/except, so a fault there broke the response
(500). Now wrapped in its own fail-open guard. All five components verified.

**Bait calibration (the `calibrate` round) -- with honest findings.** Bait-
following attackers (which read responses for planted tokens and act on them
under a stated curiosity model) plus benign traffic run through the b4 proxy;
per-bait bite rates are measured. Findings, all recorded in
config/bait_calibration_report.json and worth the paper:
  - B-SQL-1 is measured thoroughly (171 shown, 125 bit): beta_attack 0.73,
    beta_benign 0.0038 (130 benign shown, 0 bit). Its likelihood ratio drops
    from the prior's 1100 to a MEASURED 192 -- weaker, but honest, and still
    strong enough to drive a divert on a bite.
  - The cost-optimal policy concentrates deployment on the highest-EVSI bait per
    category, so several siblings are rarely deployed and keep their priors,
    flagged per bait. This is a finding, not a gap: the library's breadth is
    insurance, not routine.
  - IDOR attackers hit `mal_touched_sensitive` and DIVERT before a bait can be
    shown -- passive detection is already confident there, so bait is redundant
    for IDOR. Consistent with the thesis: bait earns its keep in the uncertain
    middle, not where the meter is already sure.
  - beta_attack is conditional on the attacker-curiosity model (a single
    researcher's model, §18), not a physical constant; beta_benign IS measured.

**Model freeze (the Phase 6 exit deliverable, spec §7.2).** `adf/freeze.py`
records a manifest of every artefact that must be immutable for a valid
evaluation -- the trained meter, cost table, record schema, feature set,
calibrated bait library, invisibility certificates -- each by content hash.
`verify()` recomputes them and fails on any drift; the Phase 7 evaluator calls
`require_frozen()` before producing a number, so a retrained meter, an edited
cost table or a recalibrated library cannot silently reach a reported result.
Tests perturb each component and confirm the drift is caught. Freezing refuses
an uncalibrated library.

**Invisible transition (FR-09).** A test asserts the proxy leaks NO detection
marker to the client on any path -- no header discloses scoring, decision or
divert. The X-ADF-Authenticated vouch is added only to the upstream request to
the decoy, never to the client response.

**One-command stack (NFR-12).** `python -m tools.run_stack` brings up target +
decoy + proxy wired together, localhost only; `--check` verifies the frozen
model. End-to-end via the launcher: benign browse returns 200, an attacker
diverts to the decoy and is served fake data with no visible error. 198 tests.

**Phase 6 exit condition MET:** the full system runs end to end and the model is
frozen for testing.

---

## 2026-08-14 — Paper-readiness pass: honest LLM framing, full-corpus certification

Acting on external strategic review. Three integrity/strength fixes before the
evaluation, none of which touch the frozen research parameters.

**LLM framing corrected (an unmakeable claim, removed).** The docs implied the
decoy uses a language model; the code uses a deterministic synthetic generator.
The comparison table in the literature review even listed "This work | LLM,
offline" — a claim a reviewer opening the repo would immediately falsify. Fixed
in LITERATURE_REVIEW.md, OVERVIEW.md. The reframing is a STRENGTH, not a
retreat: the contribution vs R11/R12 is *offline generation + a persistent
consistency layer + a measured contradiction rate*, which is generator-agnostic
— it holds whether the offline generator is an LLM or (as evaluated) a
deterministic synthesiser, and the deterministic choice is more reproducible
(NFR-08). The spec's LLM intent (§6.8, §12) is preserved as a drop-in option.

**Baits re-certified against the FULL benign corpus.** The invisibility gate
previously ran against 13 hand-picked responses. It now also replays every
unique benign GET from the corpus (search terms, profile/record ids, the
apostrophe-search errors) against the target: 116 responses total (82 HTML, 34
JSON). 6/6 baits still certified, overhead 0.009–0.116 ms. Certifying against
the traffic benign users actually produced is materially stronger than a curated
sample.

**Model re-frozen; drift enforcement demonstrated.** Re-certification changed
the certificate hash, so `verify` correctly reported DRIFT ("the bait
certificates changed since the freeze") until a deliberate re-freeze — the §7.2
guard working exactly as intended. NOVELTY.md's derived bands updated to the
CALIBRATED values (PASS < 0.047, BAIT 0.047–0.875, DIVERT ≥ 0.875), contrasted
with the theorem's single boundary at 0.816.

**The paper's spine, confirmed as a test.** The scale-independent claim — bait
is never optimal on immediate cost, so there is no middle band without the
value-of-information term — is pinned by
`test_cost_accounting_alone_does_not_justify_bait` (single PASS/DIVERT boundary
at 0.816) and `test_information_is_never_harmful` (V(p) ≥ 0). These are a proof
and a design, not measurements, so a reviewer who dislikes the sample size
cannot attack them. That is the lead, per the review.

**Remaining before submission:** attack round 2 (once, against the frozen
model), baselines B0–B4 and ablations on identical traffic with holdout arm
sizes reported honestly, then write-up → preprint. 198 tests pass.

---

## 2026-08-14 — Adaptive-adversary robustness: a regression found, diagnosed and fixed

**What was added.** A bait-AWARE adversary (`tools/adaptive_attacker.py`) with a
tunable `bait_awareness` in [0,1] — the probability it recognises a planted
token and REFUSES it — and a sweep that measures detection at each level
(`tools/robustness_eval.py`). This turns spec §18's stated limitation ("an
attacker who knows this defence exists could probe for bait deliberately, and
countering that is out of scope") into a measured curve. Two archetypes, to
separate two questions:
  * `escalating` — rises to aggressive injection the passive features catch
    unaided → tests the FLOOR.
  * `low_slow` — stays gentle, lingering where passive detection is UNCERTAIN
    → tests bait's VALUE and the cost of an adversary who declines it.

**The regression it found (the important part).** Against a fully bait-aware
low-and-slow attacker, the full system diverted **0%** of sessions while the
passive baseline B2 diverted **100%**. The full system was strictly WORSE than
its own baseline — the single most damaging thing that can be true of this
project, and no existing test caught it.

**Diagnosis.** Not a feature bug. Offering a third action RAISES the divert
threshold: 0.816 (immediate-cost boundary) → 0.875 (VoI boundary). An attacker
who keeps p inside that gap and never bites is baited forever instead of
diverted. The policy was waiting for information that was never coming. The
evading sessions sat at p≈0.86, receiving bait on 13 of 14 requests, never
biting.

**Fix — a modelling correction, not a knob.** EVSI prices a bait as fresh
information; that is true the first time and false the tenth. The value is now
discounted by `(1 - beta_attack)^exposures` — the chance a genuinely hostile
session would decline this bait that many times in a row by chance — using the
bait's OWN calibrated effectiveness, so nothing is hand-set. After a refusal or
two the information is priced at what it is worth, V→0, and the policy converges
to the two-action decision it would have made without bait.

**Result.** low_slow at full awareness: **0% → 92.5%** divert, equal to the naive
case; escalating floor stays 100% across all awareness levels. Two tests pin it:
one asserts the policy stops deferring after repeated refusal (computing the gap
from the fixture, so it does not depend on a calibration), the other asserts
first-contact behaviour — and therefore every derived band the paper reports —
is unchanged.

**The guarantee this buys, which is worth stating in the paper:** *the full
system is never worse than its own passive baseline, whatever the adversary
knows about the defence.* That is a stronger and more honest claim than a raw
win, and it exists only because an adaptive adversary was actually built and
run rather than assumed away.

**Method note.** This is the third time an assumption failed under direct test
(after the label join, the schema round-trip, and the decoy tells). The pattern
is consistent: the system behaves correctly on the traffic it was designed
against, and reveals real defects the moment something adversarial is pointed at
it. Worth saying plainly in the evaluation section.

---

## 2026-08-14 — Pre-evaluation code audit: two real defects fixed

A deliberate audit before Phase 7, on the principle that a defect found after
the evaluation is expensive (results would have to be rerun) and one found in
the released dataset is worse.

**1. FR-11 violation: the proxy logged neither `features` nor `scores.before`.**
Spec §6.11 requires each record to capture "the extracted features [and] both
scores before and after the update". The proxy recorded neither: `features` was
`{}` and `scores.before` was `0.0` on every record. Nothing failed, because
nothing read them yet — it would have surfaced as empty columns in the released
dataset (§11), *after* collection. Now both are populated, and the per-request
scratch is reset so an unscored request (b0 mode, or a fail-open fault) cannot
log stale values from the previous one. A test asserts the logged vector matches
the declared feature set and that `scores.before` is genuinely populated.

**2. `cross_session` fired falsely for shared-name baits.** The field means "this
token was issued to a different session" — evidence of identity rotation or a
leaked bait (spec §16). But three baits (`ref_uid`, `internal_view`,
`mfa_debug_token`) keep the plausible FIXED field name the spec calls for, so
every session is shown the same string. Any session that merely guessed that
generic parameter name was reported as having presented someone else's token.
Cross-session detection is now restricted to baits whose token carries a
per-session random suffix, where the inference is actually valid; for shared-name
baits it is undetectable by construction and is no longer claimed. Two tests pin
both halves. This mattered because `cross_session` is a released-dataset column:
the bug would have published false evidence.

**Also:** removed dead code (an unimplemented stub whose rationale was folded
into the function that replaced it) and unused imports across the source tree;
source lint is clean. Benchmarked the cross-session scan at Phase 7 scale (600
tracked sessions): 0.35 ms/request, inside the proxy's latency budget.

203 tests pass; model re-frozen. Ready for the evaluation.

---

## 2026-08-14 — File-by-file debugging pass: the SQL-keyword false positive

A deliberate read-through of the source, module by module, before the
evaluation. The headline finding is in the feature extractor and it mattered.

**`mal_db_keyword_hits` matched bare English.** The pattern was a word-boundary
alternation over `union|select|from|where|and|or|drop|insert|update|delete|...`.
Those last several are ordinary English: "terms **and** conditions", "**where**
is the printer", "notes **from** the all-hands", "**select** a training course"
— six of nine sampled staff-search phrases matched. And `mal_db_keyword_any`
LATCHES for the remainder of the session while carrying the second-largest
malice weight (+1.21), so a single such search would have elevated an honest
user permanently.

**Why no test caught it.** The benign corpus uses single-word search terms
("maintenance", "policy", "parking"), none of which contain a SQL-ish English
word. The 0% benign-diversion result was therefore partly an artefact of a
lexically narrow corpus rather than a property of the detector — exactly the
criticism NOVELTY.md itself warns about ("a near-zero false-positive rate is
only interesting in proportion to how hard the negatives were").

**Fix.** The patterns now require SQL *syntax context* rather than vocabulary:
UNION SELECT, SELECT…FROM, INSERT INTO, DELETE FROM, DROP/TRUNCATE TABLE,
ORDER BY <n>, information_schema, time-delay calls, tautologies (`or 1=1`),
quote break-outs (`x' OR`, `') AND`), and comment terminators. Verified in both
directions and pinned by parametrised tests: **0 false positives across 18
benign phrases (including all five apostrophe hard negatives), 0 misses across
15 real payloads** taken from the attack generators themselves.

**Consequence handled properly.** The feature names are unchanged but their
meaning is not, so `FEATURE_SET_VERSION` was bumped 1 → 2. The meter's load
guard fired correctly on the stale model, the meter was retrained, and the
freeze was re-taken. Retrained weights are stable (`mal_db_keyword_any`
1.233 → 1.210), i.e. the feature kept its real signal and lost only the noise.

**Also fixed in the same pass.**
- *Non-finite features would have produced invalid JSON.* Python writes `inf`
  as `Infinity`, which Python reads back but jq, pandas and every non-Python
  parser reject — part of the released dataset (§11) would simply have been
  unreadable. The extractor's divisions are all guarded so it cannot fire
  today, but the log store now zeroes non-finite values and records the
  substitution in `run.notes`, so the artefact is strict-JSON by construction.
  Sanitising rather than raising preserves the rule that logging can never
  break request serving (NFR-04).
- *Corpus hygiene.* `data/logs/` had accumulated unlabelled target-access logs
  from certification, calibration and robustness runs, dropping a naive dataset
  build to 17.6% label coverage. The round-1 corpus (4086 records, 100%
  coverage, 178 sessions) is now archived under `data/corpus/round1/` and the
  working log directory is empty, so round 2 starts clean and cannot be
  contaminated by tooling traffic.

**Edge-case checks that passed** (recorded so they are not re-derived): EVSI is
exactly 0 at p∈{0,1} and never negative; posteriors are absorbing at 0 and 1;
uninformative and out-of-range bait parameters are rejected at construction;
the meter rejects a short feature vector and stays finite under ±1e12 inputs;
the hash chain survives unicode, NULs and a 100 KB body; the feature vector is
provably independent of the label and provenance id.

234 tests pass; model frozen and verified.

---

## 2026-08-14 — Phase 7: the evaluation, and the honest negative it produced

Held-out attack round 2 against the frozen model, all arms on identical seeded
traffic (tools/evaluate.py, tools/run_evaluation.py). Full write-up in
docs/RESULTS.md; the decisions that shaped it:

**A blocker fixed first.** The proxy did not record `provenance_id`, so its
decisions (keyed by the proxy's own cookie session) could not be joined to the
labels the generators wrote in advance. Added it (kept out of request.headers,
so it still cannot reach a feature vector). Without this the evaluation could
not be scored at all.

**Round 2 gained a stealth prober.** The first round-2 set was all AGGRESSIVE
(obfuscated UNION dumps, scattered IDOR, password spray). Every one trips the
passive features fast, so the evaluation only ever measured bait in the regime
where it cannot help. A low-and-slow prober with mixed curiosity was added — the
canonical careful-manual-SQLi workflow, a faithful adversary, not a strawman —
so the uncertain belief band is actually exercised.

**The result is an honest negative on the efficiency claim, and it is fine.**
Recall is 1.00 on the unseen obfuscated attacks (generalisation), and expected
cost per session moves +13.9 → −10.0. But **B4 ≈ B2 and the powered holdout
(n=60 vs 20) shows a NULL causal effect of bait on time-to-decision.** Not
because bait fails — 40% of stealth probers bit the planted table (bite rate
0.40 in B4 vs 0.00 in B2, so the mechanism is live) — but because the target's
verbose SQL errors drive `mal_error_ratio` up so fast that passive detection
crosses the divert threshold (~request 5) before the bite arrives. The
information the probe buys is real but redundant here.

This is consistent with the theorem, which says EVSI is largest where belief is
uncertain; a target that hands the classifier strong passive evidence leaves
little for a probe to resolve. Bait's positive value is expected on weak-passive
targets (blind injection, no error oracle) — a limitation of the evaluation
TARGET, not the mechanism, reported as future work (§7.4). Critically the system
never diverts later than passive would, and the holdout confirms no harm.

**Why this is the right thing to report, per the strategic review.** "Lead with
the theorem, not the performance numbers... a proof, not a measurement." The
theorem (Contribution 1) and the randomised holdout (Contribution 3) are what
carry the paper; both survive a small evaluation and a null performance delta. A
carefully executed negative result is publishable (§7.4). The alternative —
engineering a weak-passive target until bait "wins" — would be the dishonest
move the review warned against.

**Safety, measured not assumed.** Benign diversion 1/80 (1.25%): a forgetful
user who failed login five times, indistinguishable from a credential attack on
passive features, diverted on `mal_error_ratio` (not on any bite). Excluding
that boundary persona it is 0. Benign bait exposure 70% with ZERO benign bites —
exposure is harmless because the bait is invisible; the bite rate is what
matters.

**Baselines run and honestly scoped:** B0 (floor), B2 (passive), B4 (full). B1
(rule WAF) is not implemented and was NOT run as a fake arm. B3 (passive+static
decoy) has detection identical to B2 by construction; the decoy's quality is
measured by the contradiction rate instead. Stated as such.

234 tests pass; model frozen and verified throughout.

---

## 2026-08-15 — Improving the results: from an honest null to a measured positive

The first Phase 7 run reported bait as NEUTRAL (B4 ≈ B2). Rather than accept that
or engineer a target until bait "won", the neutral result was interrogated: WHY
was there no room for bait, and was the evaluation actually testing the regime
the theorem points to? It was not — and fixing that, honestly, turned the null
into a measured positive concentrated exactly where the theory predicts.

**What the null was hiding.** Measuring the belief each attack style reaches on
the frozen meter showed that every round-2 attacker sat in the CONFIDENT region:
SQL (even blind, even stealth) trips `mal_db_keyword_any` to p≈1.0; API-IDOR
trips `mal_touched_sensitive`; auth trips `mal_failed_auth`. The one style that
sits in the UNCERTAIN band (p≈0.22) — IDOR through the UI pages by guessing ids,
scattered so no ascending run fires — was simply not in the round-2 set. That is
the canonical case the whole project exists for, and it was omitted.

**Two real routing bugs the omission had masked** (both correctness, both now
fixed and regression-tested in tests/test_bait_routing.py):
1. Bait category routing keyed only on malice features, so a scattered-IDOR
   attacker (no malice signal) was routed to an SQL bait. Now routes on the
   SURFACE too: object-reference endpoints → IDOR baits.
2. Bait selection ignored the RESPONSE TYPE, so the policy could pick a
   json_field bait (B-IDOR-1) for an HTML page, "decide" to bait, and inject
   nothing. Now the proxy passes the set of channel-applicable baits and the
   policy chooses only among those.

**The bait it now relies on was calibrated, not left on a prior.** The
calibration IDOR follower was switched to scattered-UI-IDOR so B-IDOR-2 is
actually deployed and measurable; a larger run put it over the n≥30 bar at
beta_attack = 0.885 (34/38). So the positive result rests on a measurement, not
a guess — the standard this project holds itself to. Re-froze after.

**The measured result (docs/RESULTS.md).** Recall B2 0.84 → B4 0.93, the entire
gain in `idor_html_scattered`: B2 diverts 5%, B4 diverts 55% via the B-IDOR-2
bite; every other subcategory is 100% in both (bait neutral, no harm). The
powered holdout (n=82 vs 18) attributes it causally: baited divert 0.94 vs
withheld 0.78. Benign diversion unchanged at 1.25% (the forgetful hard negative,
driven by error-ratio not any bite). Expected cost +15.0 → −6.7 → −8.65.

**Honesty checks kept.** The gain is against a CURIOUS adversary; a bait-aware
one erodes it to the passive floor (robustness sweep), and the guarantee remains
"never worse than passive". The recall figure is target-specific; the claim that
transfers is that bait pays exactly where belief is uncertain, which the
per-subcategory table shows. The scattered-UI-IDOR attacker is a faithful,
canonical technique, not a strawman — adding it made the evaluation representative
rather than favourable.

**Limitations rewritten** (docs/LIMITATIONS.md): synthetic traffic first, then
the attacker-model dependence of beta_attack, single verbose target, scale, the
curious-vs-bait-aware distinction, the two never-deployed baits on priors, the
self-assessed deception, compressed eval timing, the inherent forgetful-user
false positive, the deterministic (not LLM) generator, and the estimated cost
table. None touches the theorem, the holdout design, or the never-worse-than-
passive guarantee.

239 tests pass; model calibrated (4/6), frozen and verified.
