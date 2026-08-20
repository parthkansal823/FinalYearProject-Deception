# Limitations

Several limitations that earlier drafts carried have since been **eliminated** by
fixing the underlying issue rather than caveating it; those are recorded first,
because how a project retired its weaknesses is itself evidence of rigour. What
remains is the irreducible set — the things a synthetic, single-target, solo
laboratory study genuinely cannot claim — and none of it touches the load-bearing
contributions (the applied-EVSI derived-band result and its β-invariance, the
randomised-holdout design, the limiting-rule convergence to passive, the
contradiction-rate metric), which are a derivation and a design rather than
measurements over a sample.

## Eliminated (found and fixed, not caveated)

- **Benign API clients were diverted 100% of the time.** `mal_touched_sensitive`
  treated any `/api` access as hostile, so every benign reporting-integration
  client was diverted; a human-only evaluation set hid it. No passive feature
  honestly separates a benign integration from an IDOR sweep (both walk object
  ids — §6.3), so both id-access features were removed and that detection was
  delegated to bait. Now 0/6 integration, 0/7 monitor diverted.
- **A benign crawler was diverted** on 404s from `/robots.txt`, `/sitemap.xml`,
  `/favicon.ico`. Both apps now serve those standard files; 0/7 crawler diverted.
- **Ordinary English tripped the SQL detector.** "terms and conditions", "where
  is the printer" matched bare keyword patterns. Patterns now require SQL syntax
  context: 0 false positives on 18 benign phrases, 0 misses on 15 real payloads.
- **Bait was neutral because the evaluation omitted the case it is for.** Round 2
  was all aggressive attacks that passive detection saturates; adding the
  canonical UI-based scattered IDOR (uncertain band) turned a null into a
  significant recall gain (pooled over 99 paired seeds: 0.889 → 0.943, paired McNemar
  p<10⁻⁴, and 0.704 → 0.807 on that subcategory), after fixing two real
  bait-routing bugs (surface-blind and response-type-blind selection).
- **The bait behind that result was calibrated, not assumed.** B-IDOR-2 is
  measured (β_a = 0.753, β_b = 0.0067 over 183 attack and 74 benign sessions),
  not left on a prior.
- **The "inherent" forgetful-login false positive was not inherent.** It was
  reported as the irreducible cost of a hard negative. It was a *missing feature
  plus a double count*. A forgetful user fails repeatedly against **one** account
  and then succeeds; a spraying attacker walks **many** — an axis no v3 feature
  looked at. Adding `mal_distinct_usernames` (feature-set v4) cut it from 3/5 to
  2/11; the rest was `mal_error_ratio` also counting login rejections, charging
  the same user twice for one behaviour. With the double count removed, benign
  diversion is **0/130 across every benign class** on the round-1 corpus,
  forgetful included. The cost of the fix is stated below (§5).
- **The cost table's status was upgraded from "estimate" to "swept".** The frozen
  numbers were never edited — `tools/cost_sweep.py` recomputes the derived bands
  across a 256× range of the one judgement they encode (a wrongly diverted user
  priced at 0.5× to 128× a missed attacker). The bait band is non-empty and the
  divert threshold stays above the cost-only boundary at **every** point. The
  cost table is therefore a choice about *conservatism*, not a choice that
  manufactures the result. Locked by four tests.

## Remaining, irreducible

### 1. All traffic is synthetic (concede first)
Neither benign nor attack traffic is real. The benign mix — including the hard
negatives (apostrophe search, forgetful login, automated agents) — approximates
office traffic; it is not a sample of it. Every rate is a statement about this
synthetic distribution and would need re-measuring on real traffic. The
derived-band result and the holdout *design* do not depend on the traffic being
real.

**A measured instance of exactly this, found and fixed.** The round-2 attacker
spoke raw HTTP: no browser headers, and no page sub-resources. The benign
generator fetches them, and its own comment calls asset fetching "the strongest
single automation signal in the whole feature set". The result was a corpus in
which **no attack session ever fetched an asset and 96.5% of human-paced benign
sessions did**. A logistic regression on the automation features alone separated
the classes at **held-out AUC 0.9935** — without learning anything about
hostility.

Two things follow, and the second is the reason this belongs under limitations
rather than under results.

*The reported numbers were never contaminated.* `w_automation = 0.0` in the
fusion block, so automation cannot enter the hostility belief; it is spent on
bait selection. Checked against the logs rather than against the configuration:
across 12,954 scored requests `p_attack` equals the malice score exactly, within
the documented 1e-6 clamp, while the automation score ranges over [0.0000,
1.0000]. The hand-set meter scores **0.882** against a malice-only ceiling of
**0.877** — it is already extracting what the non-leaky features carry, and a
fitted meter's apparent headroom (AUC 0.999) is the artefact, not signal
(`tools/meter_headroom.py`).

*The corpus was still easier than reality.* A great deal of current tooling
drives a real browser, and a browser fetches sub-resources whatever the operator
intends. `attack_traffic_round2` now draws a browser-driven fraction per session
(`--browser-driven` pins it on both that tool and `multiseed_eval`; 0.0 reproduces
the old corpus exactly), which takes the automation-only AUC from 0.9935 to 0.898.

The corpus gets harder and the probe's contribution gets **larger**. This was first
seen on a five-seed check and is now measured on two full ninety-nine-seed runs of
all three arms against the same frozen model, differing only in the corpus
(`data/eval/curious` before, `data/eval/curious_v2` after):

| | B1 | B2 | B4 | B4 − B2 | benign diverted (B4) |
|---|---:|---:|---:|---:|---:|
| raw-HTTP corpus | 0.408 | 0.917 | 0.951 | +0.034 | 0/7,920 |
| browser-mixed corpus | 0.366 | 0.889 | 0.943 | **+0.054** | 0/7,920 |

Every arm loses recall on the harder corpus, and the gap the probe is responsible
for grows by more than half. The benign side does not move: zero diverted in both.
<!-- not-the-headline -->

This is the same class of flaw as the round-2 attacker that never read responses,
and it was found the same way: by asking what a classifier could separate the
corpus on, rather than by reading the generator.

### 2. `beta_attack` is a property of an attacker model, not a constant
The bite rates that drive the value-of-information calculation are measured
against attackers whose curiosity we chose. So the recall gain is conditional on
that model. `beta_benign` is a clean measurement (0 benign bites observed). Two
things bound this, one analytic and one empirical:

- The adaptive-robustness sweep is the sensitivity analysis over the assumption:
  against a fully bait-aware adversary the gain decays to the passive floor, and
  the decision rule converges to the passive two-action rule in the limit (so it
  cannot be *asymptotically* worse — a property of the rule, not a per-session
  guarantee; see [NOVELTY.md](NOVELTY.md) Contribution 5).
- **Real off-the-shelf tooling was run against the full system** (sqlmap, ghauri,
  wapiti — [REAL_ATTACK_EVAL.md](REAL_ATTACK_EVAL.md)). Every cookie-persistent
  tool is diverted to `p → 1.0` within a handful of requests, and **no tool bites
  a bait** (`beta_attack ≈ 0` for pure automation). That is not a failure: it
  confirms the *scope* — automation is caught by the passive meter, and the probe
  addresses the human/semi-automated attacker a scanner is not. So the recall
  gain is honestly conditional on a *human* attacker model; the tooling run
  establishes the automated floor (zero) but not the human rate, which still
  needs the participant study (§7). One tool (ghauri) evaded score accumulation
  by refusing cookies; the shipped `fingerprint_fallback` counter closes it
  fully (divert 1.00).

### 3. A single target application (with a measured transfer check)
The tuning target is one deliberately-weak portal. Its verbose SQL error makes
passive SQL detection strong, so bait's measured value is concentrated on the
low-passive-signal surface (UI IDOR). The 0.889 → 0.943 figure is target-specific;
what transfers is the *shape* — bait pays where belief is uncertain — shown by the
per-subcategory breakdown, not the aggregate.

This is now partly measured rather than only argued. The frozen v4 model was put
in front of a **second, structurally different application** — OWASP Juice Shop
(Node/Angular SPA + JSON REST API), the opposite of our server-rendered Python
portal — and attacked with real tools ([REAL_ATTACK_EVAL.md](REAL_ATTACK_EVAL.md),
L3). sqlmap's SQLi against Juice Shop is diverted on the **2nd request** (`p → 1.0`),
and a full browser-driven ZAP scan of **589 endpoints** shows the meter diverting
attack traffic (mean 0.91 SQL-keyword hits) while passing benign crawl (0.00) —
on an app it never saw. The *app-agnostic* features (lexical SQL, error ratio,
timing, headers) transfer; the *app-specific* auth features do not without
re-pointing (Juice Shop authenticates via JSON `/rest/user/login`, not our
form-POST `/login`). So the mechanism transfers; the magnitude, and a full B4
run with a matched decoy on a second app, remain future work.

### 4. Scale
One machine, seeded; a controlled laboratory measurement (spec §17), not an
internet-scale one. The sample is no longer "hundreds of sessions per arm": a
99-draw run (`tools/multiseed_eval.py --seeds 99`) puts 11,880 attack and
7,920 benign sessions behind each arm, which is what makes the rare-event
statements — in particular the upper bound on benign diversion — worth stating
at all. What remains irreducibly out of reach is the *tail of real traffic*:
more draws from the same generator tighten the intervals without widening the
distribution they are drawn from (see §1).

### 5. Vertical brute force is not passively separable (the cost of fixing the FP)
The forgetful-login false positive is **gone** (0/11, and 0/130 across all benign
classes — see *Eliminated* above). It was replaced by a narrower and more honest
limitation, which is the correct trade rather than a free win.

Once the meter can read *how many accounts* a session tried, repeated failure
against **one** account stops being evidence of malice — and that is precisely
the shape of a vertical brute force (one username, many passwords). It is now
passively undetected (`auth_bruteforce` 0/4 on round 1). This is the *same*
finding the project already reached for IDOR in v3: where no passive feature
honestly separates two classes, detection is delegated to bait rather than bought
with a false-positive rate.

**The IDOR case, with the numbers, because it invites the obvious objection.**
A reader is entitled to ask whether B2 is a straw man on object-reference
attacks: it holds no feature that looks at object-id access, so of course the
probe wins there. It held two — `mal_touched_sensitive` and `mal_seq_id_run` —
and they were removed in v3 after they diverted **10/10** and **3/10** benign
integration clients respectively. Re-measured on the round-1 corpus, the longest
ascending id-run per session is:

| session class | n | longest ascending id-run |
|---|---|---|
| `attack/idor_sequential` | 8 | **8.5** |
| benign reporting integration (`benign_agents.py`) | 10 | **4.3** |
| `attack/idor_tamper` | 4 | 1.5 |
| benign humans (`benign_traffic.py`) | 81 | 1.1 |

The two distributions overlap, and the attack class that a run-length feature
would *not* catch at all — `idor_tamper`, which rewrites ids rather than walking
them — is a third of the object-reference traffic. So the feature buys part of
one subcategory at the price of diverting legitimate integrations, which is the
trade the project declined. B2's blindness here is the paper's premise, not a
weakened baseline: spec §6.3 names the ambiguity, and delegating IDOR to a
response-side probe is the consequence, not a convenience. The auth bait *appeared* weak (β = 0.12) — and two
independent measurements below show that number was an artefact of how our own
harnesses were written, not a property of the probe. Corrected, **β = 0.931**.

**Why that β was not a fair test of the probe — two separate defects, both ours.**

*First, the calibration denominator.* B-AUTH-1's β = 0.1163 came from a round in
which the bait-following attacker bit whichever token it saw first, so *auth*
followers were diverted by the IDOR bait during warm-up before reaching their own
probes, and sessions of every category sat in the denominator. Measured on
matching-category sessions with the bite restricted to the category under test,
B-AUTH-1 is taken **87 times in 93 exposures — β = 0.931** (§6).

*Second, the attacker model.* The simulated vertical brute-forcer only ever POSTs
credentials and **never reads a response body** (`tools/attack_traffic.py`, the
`auth_bruteforce` branch — unlike `cred_stuffing`, it does not even GET `/login`).
A response-side probe cannot reach it *by construction*, whatever the bait says.
So the honest reading was never "the auth bait is weak" but "this attacker is, as
simulated, blind to every response-side channel."

That cuts against the system in the write-up, not for it, and it is worth naming
because a **real** brute-force tool is not blind in that way: hydra, patator and
Burp Intruder all parse the response to tell a success from a failure, which is
the very channel a probe rides.

**So we measured it, and the expectation held** (`tools/auth_probe_experiment.py`
→ `data/eval/auth_probe.json`). Three vertical brute-force variants were run
against the **unchanged frozen v4 model** — same passwords, same account, same
everything except whether the attacker reads the failure body and follows the
leaked `/auth/legacy/verify_*` hint:

| attacker | divert rate | bite rate | mean peak $p$ |
|---|---|---|---|
| **blind** — POSTs only, never reads the body (today's simulated model) | **0.000** | 0.000 | 0.463 |
| **reading, follows with p = 0.5** | **0.925** | 0.925 | 0.958 |
| **reading, always follows** | **0.950** | 0.950 | 0.973 |

n = 40 sessions per variant. The blind attacker sits at mean peak belief 0.463 —
squarely in the BAIT band, below the 0.8793 divert edge — which is exactly the
"passively undetected" claim above, confirmed. Reading the response moves it to
**0.95 diverted**. The +0.95 comes from the probe alone: no feature, threshold,
cost or model changed between the rows.

**One human, and he bit nothing.** The single manual pentest on record
(`manual-testing/`, 2026-08-20) is the only non-simulated attacker this system
has faced. Over a 56-request session he was shown **nine** baits across three
categories and took **zero** of them, and his thirty-request object-reference
sweep left the meter flat at p = 0.476 throughout. He was eventually caught, but
by the SQL path: a single `?q='` moved the belief to 0.998 in one request. So the
one real attacker observed here sat at the blind end of the curiosity model for
the very category the probe is supposed to own. n = 1 settles nothing, and he was
not trying to evade a probe he did not know existed — but it is the one piece of
non-simulated evidence available, and it points the same way as §2: the recall
gain is conditional on an attacker who reads and acts on what he is sent.

**What this does and does not license us to say.** It does **not** repair the
headline numbers: the round-1 corpus still trains on a blind brute-forcer, and
`auth_bruteforce` is still 0/4 there, so every reported figure stands unchanged.
What it does is relocate the limitation. The honest statement is no longer "the
auth bait is too weak to catch vertical brute force" — measured against an
attacker that reads responses, it catches 95% of them. It is: **our round-1
attacker model is unrealistically blind, and that understates the probe.** Making
the simulated brute-forcer realistic would change the training corpus and so
requires a re-freeze and a re-run of every arm; until that is done we report the
measurement above as a targeted experiment against the frozen model, not as a
headline result.

On the frozen cost table the trade is favourable by construction — a wrongly
diverted user is priced at 200 against 25 for a missed attacker, so avoiding one
false positive is worth eight missed attacks — but it is a trade, and it is
reported as one. Credential *stuffing* (many accounts) remains caught 4/4, and
`auth_otp_bypass` is unaffected: the error-ratio exclusion is scoped to `/login`
alone, which is where the ambiguity lives.

### 6. Two baits cannot be measured on this target — and the reason is a result
This limitation was largely **a defect in our own calibration harness**, found and
fixed rather than caveated. It is recorded in full because the earlier text
("half the baits keep their priors, because they are rarely deployed") was
describing a bug and calling it a property of the world.

**What was wrong.** The bait-following attacker bit whichever planted token it saw
first, whatever category it was assigned to measure. Every session warms up
through `/login` → `/otp` → `/dashboard`, and those responses carry the auth and
IDOR baits — so a *sqli* follower took the IDOR bait during warm-up, was diverted
to the decoy, and never reached its own `/search` probes. Two things followed:
the SQL baits were shown to **0 of 300** attack sessions, and the denominator for
every other bait counted sessions of categories that could never bite it.
Restricting the bite to the category under measurement, and taking the
denominator over matching-category sessions, corrects both.

**What the corrected round says** (`config/bait_calibration_report.json`):

| bait | before | corrected | status |
|---|---|---|---|
| `B-AUTH-1` | β = 0.132 | **β = 0.931** (87/93) | measured |
| `B-IDOR-2` | β = 0.584 | **β = 0.650** (58/89) | measured |
| `B-IDOR-1` | prior 0.40, n = 0 | 0.605 (11/18) | **measured but under our own 30-session rule — prior retained** |
| `B-SQL-1`, `B-SQL-2` | priors, n = 19/39 | still n = 0 | unmeasurable here — see below |
| `B-AUTH-2` | prior 0.45, n = 0 | — | **withdrawn** (this target has no JSON auth surface) |

**Why the SQL baits stay unmeasurable, and why that is a finding rather than a
gap.** With the harness fixed, a SQL prober still never has a bait deployed to
it: its first quote probe returns a verbose 500, the passive meter goes to
p ≈ 0.995 on that single request, and the session is diverted before it ever
enters the bait band. So on *this* target the SQL baits cannot be calibrated —
not because the round is too small, but because passive detection wins first.
That is the same property recorded in §3, and it is the mechanism behind the
paper's central result: bait's measured value concentrates on IDOR precisely
because that is the surface where the passive meter is uncertain. A target with
quieter SQL errors would move the SQL baits into the measurable band and, by the
same logic, give bait more to do there.

**What remains, stated narrowly.** Of the five deployed baits, three are measured
(`B-AUTH-1`, `B-IDOR-2`, and `B-IDOR-1` at n = 18, below our own threshold so its
conservative prior is kept), and two carry β_attack priors that this target cannot
exercise. Their β_benign *is* measured (0 bites over ~70 benign sessions each),
and neither drives the derived bands, since the global band takes the maximum EVSI
over the library and both sit below `B-AUTH-1`. We keep the 30-session rule rather
than bend it for `B-IDOR-1`: reporting a prior we chose is more honest than
promoting an estimate our own stated threshold rejects.

### 7. The deception assessment is a self-assessment
Time-to-suspicion is measured by the researcher against a checklist and by the
consistency fuzzer (0% contradiction over 286 probes), not by independent human
participants. Whether a human attacker *feels* something is off is not measured.

**A cross-boundary tell the fuzzer cannot see, found by an agentic attacker.**
The 0% figure is the decoy disagreeing *with itself*: `adf/decoy/fuzzer.py`
interrogates the decoy through many routes and orders and finds it internally
consistent. It never crosses the target→decoy boundary, because by construction
it only ever talks to the decoy. An adaptive attacker does cross it.

Driving the frozen `b4_full` stack by hand as an autonomous attacker
(`manual-testing/proxy.claude-agent.*.jsonl`), the session read six other users'
records and profiles by walking object ids — undetected, the passive meter flat
at p = 0.476 the whole way, exactly as §3 and the earlier human test predict —
then tripped the SQL path on a single `'` (p → 0.908, diverted). **Then, inside
the decoy but not knowing it, it re-requested ids it had already seen on the real
target:**

| id | on the target (pre-divert) | in the decoy (post-divert) |
|---|---|---|
| record #6 | "Conference registration", 3938.99, owner #2 | "Procurement request", 6958.79, owner #1 |
| profile #3 | Sofia Lindqvist, Operations | Noor Kato, Legal |

The decoy's own answers are stable on repeat (re-fetched twice, byte-identical),
so this is not a generation bug — the decoy is internally consistent, as claimed.
It is that the decoy generates its **own** world rather than mirroring the target
for ids the attacker already observed. An attacker who does reconnaissance
*before* the request that catches them, remembers what they saw, and re-reads the
same id after being diverted, sees it change under them. That is a divert tell,
in a channel the fuzzer's 0% does not cover, and neither the single human test
(its decoy was down) nor the incurious LLM-sweep agents (which did not
cross-reference) surfaced it.

**Fixed, 2026-08-20.** The proxy now remembers what a not-yet-diverted session
was shown on the real target (`SessionState.observed_target`), and after a divert
a re-read of one of those paths replays that exact view instead of the decoy's
independent world (`adf/proxy/proxy.py`; regression in
`tests/test_proxy.py::test_a_re_read_after_divert_replays_the_target_view_not_the_decoy`).
Re-running the agentic attack confirms it: record #6 and profile #3 now read
identically before and after the divert, while a genuinely new id (#99, never
seen on the target) still gets the decoy's fabricated content.

**And now measured, not just asserted.** The whole reason this slipped through
is that the fuzzer's 0% never crossed the boundary. `tools/boundary_consistency.py`
does: it drives real sessions through the live `b4_full` stack, reads a sample of
records and profiles on the target, gets diverted on a SQL probe, re-reads the
same ids, and counts every field that changed. It is the cross-boundary analogue
of the fuzzer's within-decoy rate, and it is non-vacuous by construction —
toggling the fix off (`proxy.replay_pre_divert_views: false`) reproduces the tell:

| | fields compared | cross-boundary contradictions | rate |
|---|---|---|---|
| off (pre-fix) | 1,440 | 1,304 | **90.56%** |
| on (as shipped) | 3,600 | 0 | **0.00%** |

**A second-order tell, found by re-pentesting the fix and then closed.** The
page-replay above fixes a re-read of the *same path*. But re-attacking the fixed
stack surfaced a subtler one: an aggregate endpoint re-lists an entity under a
*different* path. Read `/profile/3` on the target (Sofia Lindqvist), get
diverted, open `/directory` — never seen, so the decoy fabricates it — and it
listed profile 3 as someone else, contradicting the individual page that now
replays the target's Sofia. Page-level replay cannot see this because
`/directory` is a different path.

The fix is entity-level (`adf/decoy/observed.py`): the proxy lifts the *facts* it
showed the attacker (a profile's name/email/…, a record's title/amount/owner) as
it caches each pre-divert page, and hands them to the decoy on every diverted
request; the decoy overlays them at its one generation chokepoint, so every
surface — profile page, directory, dashboard, JSON API — agrees for seen ids,
while ids the attacker never saw keep the fabricated world (nothing new exposed,
NFR-06). The measurement above now spans both classes (direct re-reads *and* the
directory cross-reference, 3,600 fields) and still reports 0%. It also caught a
sub-tell along the way — a name with an apostrophe double-escaped when the decoy
re-rendered the overlaid value (`O&#39;` → `O&amp;#39;`) — fixed by storing the
decoded value so Jinja escapes it exactly once
(`tests/test_decoy.py::test_overlaid_apostrophe_name_is_escaped_once_in_the_aggregate`).

So the property the fuzzer's 0% could not certify is now certified by a
measurement that demonstrably fails when the fix is removed
(`tests/test_proxy.py::test_disabling_the_replay_restores_the_tell` guards the
same toggle in CI, and three `tests/test_decoy.py` overlay tests guard the
aggregate case). The replay only
ever echoes bytes this same session already received, so it exposes nothing new
(NFR-06); it is GET-only, so credential POSTs still reach the decoy and are
captured; and new probes still fall through to the decoy, so the fake world is
unchanged for anything the attacker had not already seen.

Two things about the severity are worth keeping on record even though it is
fixed. The divert usually fires on the first strong signal, often before much
real data has been read, so the window in which this tell was reachable was
narrower than it looks — an attacker who trips a bait or a SQL error on their
first probe had no pre-divert memory to contradict.

**One narrower tell is left, and left deliberately.** The decoy presents a
larger organisation than the target (240 users, 900 records vs ~12/49), a
deliberate choice so its exact size is not a fingerprint. Across the boundary
that has a cost: an id past the target's range 404s on the target but is
fabricated 200 by the decoy, so an attacker who probes `/records/60`, is
diverted, and probes it again sees a row appear where there was none. It is an
*existence* tell, not a content one, and it is only reachable by re-probing the
same out-of-range id across the divert. Closing it (per-session, 404 the ids the
target 404'd) trades directly against the anti-fingerprinting reason the decoy
is bigger, so it is a design call recorded here rather than silently patched.

And it is the clearest
example in the project of the thing this section concedes: the fuzzer's 0% is
consistency measured against oneself, and it took an adversary with a memory —
here an agent, n = 1, that had read the source — to find the gap between that
estimand and the threat. The fix closes the specific tell; the general point,
that a self-consistency metric does not certify consistency across the divert
boundary, is why this stays in the limitations rather than moving to the
*Eliminated* section as a solved problem.

### 8. The cost table's *magnitudes* remain an estimate — its *conclusions* do not
The costs are argued rather than taken from a real organisation's incident data,
and that has not changed. What has changed is that nothing load-bearing rests on
them. `tools/cost_sweep.py` sweeps the single judgement they encode — how much
worse a wrongly diverted user is than a missed attacker — across 0.5× to 128×,
holding the calibrated bait effectiveness fixed:

| divert/miss | cost-only boundary | BAIT band | band? | divert ≥ cost-only? |
|---|---|---|---|---|
| 0.5 | 0.2174 | [0.0311, 0.3045) | yes | yes |
| **8.0 (frozen)** | **0.8163** | **[0.0646, 0.8793)** | **yes** | **yes** |
| 128.0 | 0.9861 | [0.3634, 0.9916) | yes | yes |

The band is non-empty and the divert threshold stays above the two-action
boundary at every point. What moves is *where* the boundaries sit — how
conservative the system is — never whether the third action exists or whether
bait can make the system divert earlier than cost accounting alone. So the
residual limitation is that the frozen table encodes one particular level of
conservatism; it is no longer that the results might be an artefact of it.

### 9. The offline decoy generator is deterministic, not an LLM *(now optional)*
The default generator is deterministic by design (reproducible, reviewable). The
project now also ships an **LLM-backed generator** (`adf/decoy/llm_generator.py`)
that plugs into the same notebook seam and runs against a **local** model (Ollama
on loopback — no external API, nothing leaves the host). This is the sharper test
of the notebook: a language model reinvents an entity on every call, so any
consistency the decoy shows must come from the notebook, not the generator. That
property is both unit-tested (`tests/test_llm_decoy.py`: a stochastic generator
contradicts itself 0/30 with the notebook, > 20/30 without) and **measured live
against a real local model** (llama3.2:1b in an Ollama container, no external API;
`tools/llm_decoy_eval.py`): the LLM decoy contradicts itself **0% with the
notebook and 100% without it** — the inconsistency is inherent to the model, not
injected by an unseeded RNG, which is the sharpest form of the result. On
*richness* the picture is honestly mixed: the LLM produces far more varied
free-text (record bodies: 12 distinct vs the deterministic generator's 1
hardcoded sentence) but does not beat a well-sized name pool on enumerable fields
(names: 13 vs 15) — a tiny model mode-collapses on those. The deterministic world
stays the default for reported results (reproducible, and the decoy sits
downstream of the divert decision so it changes no recall or safety number); the
LLM path is available and demonstrates the notebook is genuinely
generator-agnostic.

---

**The through-line:** the measurements are bounded by a synthetic, single-target,
solo laboratory setup and are not oversold. The parts meant to outlast it are not
measurements — the proof that probing is the cost-optimal third action, the
holdout that identifies its causal effect, and the guarantee that it never
underperforms passive detection.
