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
