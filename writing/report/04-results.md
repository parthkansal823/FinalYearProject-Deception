# CHAPTER 4

# RESULTS ANALYSIS AND VALIDATION

## 4.1 Implementation Using Modern Engineering Tools

The framework was implemented as an asynchronous reverse proxy in Python, with the
deliberately weak target application and the decoy running as separate services. The
defence is about **6,600 lines** of Python; the evaluation harness adds a further
**10,700** and the test suite **4,700**, for roughly 22,000 lines in total.

**Table 13: Technologies used**

| Category | Technology / Tool | Purpose |
|---|---|---|
| Language | Python 3.11 | Framework, harness, generators and tests |
| Web framework | FastAPI + Uvicorn | Asynchronous reverse proxy; target and decoy services |
| HTTP client | httpx | Upstream forwarding inside the proxy; all traffic generators |
| Machine learning | scikit-learn | Logistic heads of the dual meter; calibration maps |
| Numeric / data | NumPy, pandas | Feature handling and evaluation statistics |
| Database | SQLite | Target world, decoy world and the Fact Notebook |
| Hashing | hashlib (SHA-256) | Log chaining, freeze manifest, per-session bait suffixes |
| Visualisation | matplotlib | Publication-quality SVG/PDF figures (Okabe–Ito palette) |
| Local LLM runtime | Ollama (llama3.2:1b, llama3.2:3b, qwen2.5:7b) | Decoy generation behind the consistency seam; autonomous attacker in §4.4.9 |
| Containerisation | Docker | OWASP CRS, OWASP Juice Shop, browser-driven scanner |
| Third-party attack tools | sqlmap 1.10.8, ghauri 1.4.3, wapiti 3.2.3, OWASP ZAP | External validation |
| Signature baseline | OWASP ModSecurity CRS | Replayed at paranoia levels 1–4 on identical traffic |
| Testing | pytest | 358 automated tests across 26 files |
| Version control | Git | Source management and decision audit trail |

### 4.1.1 Modules implemented

1. **Reverse proxy and session manager** — the only request-path component; owns
   fail-open and routing.
2. **Feature extraction module** — 18 versioned features from request and session
   history.
3. **Dual suspicion meter** — two logistic heads plus explicit fusion.
4. **Priced policy engine** — expected costs, EVSI, survival discount, action
   selection.
5. **Bait engine and invisibility gate** — selection, certified injection, bite
   detection.
6. **Decoy service and Fact Notebook** — parity-matched fake world with a write-once
   entity store.
7. **Tamper-evident log store** — append-only, hash-chained.
8. **Freeze subsystem** — manifest generation and verification.
9. **Evaluation harness** — seeded multi-arm runs, sharded execution, statistical
   reporting.
10. **Consistency fuzzer** — adversarial prober for the decoy.

### 4.1.2 Reproducibility mechanisms

Three mechanisms make the evaluation reproducible and hard to fudge, and they are
worth stating because a measurement that cannot be replayed is difficult to trust.

**The model is frozen before evaluation** [4]. A manifest hashes the two logistic
heads, the cost table, the feature set and its version, the record schema, the
calibrated bait library and the invisibility certificates. Every tool that produces a
reported number recomputes the manifest first and raises rather than proceeding, so a
figure in this report cannot have come from a model that had drifted. The cost table
is additionally verified on **every load**, so altering it stops any component that
makes a decision.

**Traffic is seeded and replayed.** Every generator is deterministic given a seed, so
each arm sees byte-identical traffic. The only thing that differs between arms is the
code path selected by a single mode flag.

**The log is tamper-evident** [45]. Decisions are chained by hash, so a later edit to
any record breaks the chain and is detectable.

## 4.2 System Design and Architecture

### 4.2.1 Overall system workflow

The system operates as a sequential pipeline:

1. Client sends an HTTP request; the proxy resolves session identity.
2. Eighteen features are extracted from the request and the session's history.
3. If a probe was planted earlier, the request is checked for the planted token, and
   the belief is updated in log-odds space by Λ⁺ (bite) or Λ⁻ (ignored).
4. The dual meter produces the hostility belief *p*.
5. The policy computes the expected cost of each action and the value of information
   for each deployable bait, applies the survival discount, and selects the least
   effective cost.
6. The request is forwarded — to the real application unless the session is diverted.
7. If the action is BAIT and the session is not in the holdout, the probe is injected
   into the response after its certificate is re-verified.
8. The decision is appended to the hash-chained log.

### 4.2.2 Key architectural components

**Table 14: Key architectural components**

| Component | Description |
|---|---|
| **Reverse proxy** | Sole request-path component; routes to target or decoy; injects on the response path; enforces fail-open |
| **Session manager** | Cookie-based identity with an optional coarse fingerprint fallback (default off) |
| **Feature extractor** | 18 versioned features; strictly request-side; never reads labels |
| **Dual meter** | Automation and malice logistic heads with explicit fusion weights (w_auto = 0.0) |
| **Cost table** | Frozen, hashed, verified on every load |
| **Policy engine** | Expected costs, EVSI per bait, survival discount, action selection with recorded reasons |
| **Bait library** | Five deployed baits with measured β_attack and β_benign |
| **Invisibility gate** | Issues certificates offline; the engine re-checks them at run time |
| **Bait engine** | Selects by max V, injects with a per-session suffix, detects bites |
| **Decoy application** | Route-surface parity with the target, asserted in both directions |
| **Fact Notebook** | Write-once entity store; source of the consistency guarantee |
| **Log store** | Append-only, hash-chained decision records |
| **Freeze manifest** | Hashes every decision-relevant artefact; verified before reporting |

### 4.2.3 Functional description of modules

**Reverse proxy.** Terminates the client connection and is the fail-open boundary.
Any exception raised by feature extraction, the meter or the policy results in the
request being forwarded normally with the decision marked failed-open. Across the
875,703 decisions recorded in the reported runs, this path was taken **zero** times.

**Feature extraction module.** Produces the eighteen features of Tables 4 and 5. Two
features present in an earlier version — `mal_seq_id_run` and
`mal_touched_sensitive` — were **removed** after they were found to divert 100 % of
benign JSON-API integration clients, and the detection they provided was delegated to
the probe.

**Dual meter.** Two logistic heads trained on round-1 traffic only. The fusion places
zero weight on automation, verified against the logs rather than the configuration:
across 12,954 scored requests in an audit, the belief equalled the malice score
exactly within the 10⁻⁶ clamp while the automation score ranged over its whole domain.

**Policy engine.** Implements Algorithms 4 and 5a. It refuses to operate against an
uncalibrated bait library, and asserts V ≥ 0 as a runtime invariant.

**Bait engine and gate.** Selects the applicable, certified bait with the largest
survival-discounted V. Injection re-verifies the certificate; an uncertified bait is
silently not served rather than served with a warning.

**Decoy and Fact Notebook.** Serves diverted sessions from a world whose facts are
pinned on first assertion. Route surfaces, status codes, content types, gating
behaviour and mundane file contents are asserted identical to the target's, with the
single deliberate exception of a planted credential in the decoy's `service.ini`.

**Log store and freeze subsystem.** Append-only with hash chaining; no update path
exists in the API.

### 4.2.4 Design features and advantages

- **Modular architecture** — each component is separately switchable, which is what
  makes the six-arm ablation of Table 11 possible from one binary.
- **Real-time evaluation** — the certified worst-case median injection overhead is
  0.11 ms against a 0.5 ms ceiling.
- **Adaptive but bounded** — the three-action rule provably converges to the
  two-action rule against an adversary who refuses every probe.
- **Tamper-evident by construction** — hash chaining makes post-hoc log edits
  detectable.
- **Fails open** — a defect in the detector degrades to plain forwarding rather than
  to an outage.

## 4.3 Testing and Validation

### 4.3.1 Test suite composition

**358 automated tests across 26 files.** All must pass before a model can be frozen.

**Table 15: Test suite composition**

| Area | Representative assertions |
|---|---|
| Policy and decision rule | V(p) ≥ 0 for all p; V(0) = V(1) = 0; band non-empty; divert edge ≥ cost-only boundary |
| Statistical sensitivity | Band invariance across β ∈ [0.05, 0.99] and cost ratio 0.5–128 |
| Cost table integrity | Load refuses on digest mismatch; refuses an unfrozen table |
| Feature extraction | Correct values on crafted requests; label isolation |
| Meter | Score ranges; blank-request behaviour; feature-version binding |
| Invisibility gate | Rendered-text equality; JSON parseability; latency ceiling; refusal of inapplicable baits |
| Bait routing and engine | Channel selection; per-session suffix uniqueness; cross-session validity by bite kind |
| Bite detection | Value/name/path matching; correct Λ applied |
| Fact Notebook | Write-once semantics; repeated queries return identical values |
| Decoy indistinguishability | 19 parity tests, both directions |
| Fail-open | Each of three components broken in turn; request still served |
| Freeze | Drift in any component raises; uncalibrated library refuses to freeze |
| Log store | Chain verification; tamper detection |
| Traffic generators | Population mixing; corpus knobs pinned correctly |
| Calibration | Monotonicity; edge inversion; map selection |

### 4.3.2 Unit testing

Individual components were verified in isolation: the policy's arithmetic against
hand-computed expected costs, the feature extractor against crafted requests with
known feature values, the gate against responses it should and should not accept, and
the notebook's write-once semantics under repeated queries.

### 4.3.3 Integration testing

Module interactions were verified end to end: features flow to the meter, the belief
flows to the policy, a BAIT decision reaches the bait engine, an injected token is
detected on a later request, the resulting belief update crosses the divert edge, and
the session is routed to the decoy and pinned there.

### 4.3.4 System testing

The complete workflow was exercised over seeded multi-arm runs:
**login → scoring → decision → probe → bite → divert → logging**, with every arm
receiving byte-identical traffic within a seed.

### 4.3.5 Guards added in response to observed failures

This subsection is included because the guards are part of the result. This project's
recurring bug class was **silent wrongness**: tooling that produced a plausible,
parseable, wrong artefact instead of failing.

| Failure observed | Consequence if unguarded | Guard added |
|---|---|---|
| Label join matched zero requests | Entire corpus unusable, silently | Provenance-id join with an asserted coverage floor |
| Evaluation driver wrote an empty dump when a proxy failed to boot | A "successful" run with no data | Driver exits non-zero on empty output |
| Calibration fitted on a still-running draw | Map biased toward early requests where the belief has not moved | Requires the end-of-draw marker file |
| Sweep index overwritten with only the arms just run | Report compared one arm against nothing | Merge function with tests |
| WAF replay counted a transport error as "not blocked" | Deflated the baseline's recall by 13–26 % | Retries plus refusal to publish a level that lost > 1 % of requests |
| Two sweeps sharing one container | Non-monotone, irreproducible results minutes apart | Refuses to start if the container is already running |
| CRS paranoia set without blocking paranoia | Flat, meaningless curve across all levels | Both variables set explicitly |
| Figures with hard-coded band values | Plots showed the pre-recalibration library | Figures read live configuration; refuse to draw on digest mismatch |
| Documentation numbers drifting from data | Reported figures no longer reproducible | Automated checker recomputes canonical facts and compares against every document |

## 4.4 Results and Observations

### 4.4.1 Evaluation setup

Three arms — **B1** (signature WAF), **B2** (passive) and **B4** (full system) — each
ran over **99 independent seeded traffic draws** of 120 attack and 80 benign sessions,
giving **11,880 attack** and **7,920 benign** sessions per arm. One further seed was
discarded from every arm because it lost sessions to a resource fault mid-draw;
dropping it from all three keeps the pairing matched.

**Table 16: Attack traffic composition per draw**

| Subcategory | Per draw | What the attacker does |
|---|--:|---|
| `sqli_obfuscated` | 40 | Injection split across inline comments, case-mixed, URL- and double-URL-encoded |
| `sqli_stealth` | 20 | The same intent at low volume and slow pacing |
| `idor_scattered` | 20 | Object ids walked with random strides over the **JSON API** |
| `idor_html_scattered` | 20 | The same walk through the **HTML UI**, where there is no API shape to key on |
| `auth_spray` | 20 | One password tried across many accounts |

The obfuscated-SQLi group is double-weighted deliberately, because it is the category
a signature firewall is supposed to be good at, and the headline comparison should not
rest on categories chosen to favour the proposed system.

### 4.4.2 Statistical protocol

The primary comparison — B2 against B4 on attack recall — was **fixed before the
runs**; everything else is labelled exploratory. Security-ML results are easy to
inflate by choosing the comparison after seeing the data [4] and easy to overstate by
reporting a single draw as a population [48], so the protocol is stated before the
numbers rather than after.

Proportions carry **Wilson intervals**, which behave sensibly near zero — and every
benign rate here is near zero. B2 against B4 uses an **exact paired McNemar test** on
matched sessions: only discordant pairs carry information about the difference, and
using them is far more powerful than comparing two pooled proportions as if they were
independent. The randomised holdout uses **Fisher's exact test** with a bootstrap
interval on the difference. Per-seed distributions are reported alongside pooled
intervals, because a narrow pooled interval can still hide an effect that appears in
only a few draws.

### 4.4.3 The causal estimate

The comparison that matters most is *not* B2 against B4, because those are two whole
systems that differ in more than the probe. The design that isolates the probe is a
**randomised holdout inside the treated arm**: whenever the policy decides to bait, a
deterministic pseudo-random draw over the session id withholds the probe from about
one session in ten. Withheld sessions sit at the same belief state, under the same
policy, in the same band — they are simply passed instead of probed.

**Table 17: Randomised holdout outcome**

| Group | n | Diverted | Divert rate |
|---|---:|---:|---:|
| Baited (policy) | 10,643 | 10,112 | **0.950** |
| Withheld (holdout) | 1,237 | 1,089 | **0.880** |

Effect **+0.070**, bootstrap 95 % CI **[+0.052, +0.088]**, odds ratio **2.59**,
Fisher exact **p = 3.4 × 10⁻¹⁹**.

![Two bars showing the divert rate for the baited group and the withheld holdout group, each with a 95 percent confidence interval, and the difference between them annotated with its bootstrap interval.](../figures/holdout-effect.svg)

**Figure 22: Randomised holdout: treated against withheld** Both groups sit at the
same belief state under the same policy; the only difference is whether the probe was
served. The gap is therefore attributable to the probe rather than to any other
difference between two configurations.

A randomised design is only worth the name if the draw actually balanced, so this was
checked rather than asserted. The withheld group is 10.4 % of the sessions that
reached the band, and its composition tracks the treated group closely.

**Table 18: Holdout balance check across subcategories**

| Subcategory | Baited | Withheld | Share difference |
|---|---:|---:|---:|
| `sqli_obfuscated` | 3,552 (0.334) | 408 (0.330) | −0.004 |
| `idor_scattered` | 1,786 (0.168) | 194 (0.157) | −0.011 |
| `sqli_stealth` | 1,779 (0.167) | 201 (0.162) | −0.005 |
| `auth_spray` | 1,765 (0.166) | 215 (0.174) | +0.008 |
| `idor_html_scattered` | 1,761 (0.165) | 219 (0.177) | +0.012 |

The largest share
difference is 1.2 percentage points, and a chi-square test of the withheld mix against
the treated mix gives **2.58 on four degrees of freedom**, well inside the 9.49 that
would matter at the 5 % level. This matters because the subcategories differ
enormously in how catchable they are (§4.4.5); had the draw put more of the easy
categories in one group, the effect above would be measuring composition rather than
the probe.

### 4.4.4 Baselines

**Table 19: Headline results by arm**

| Arm | Attack recall (95 % CI) | Per-seed sd | Benign diverted |
|---|---|---:|---:|
| **B1** signature WAF | 0.366 [0.358, 0.375] | 0.020 | 0 / 7,920 |
| **B2** passive | 0.889 [0.883, 0.894] | 0.024 | 4 / 7,920 |
| **B4** full system | **0.943 [0.939, 0.947]** | 0.018 | **0 / 7,920** |

![A forest plot of attack recall for arms B1, B2 and B4, each with a 95 percent Wilson confidence interval. The B2 and B4 intervals are visibly separated.](../figures/recall-forest.svg)

**Figure 23: Recall with 95 % confidence intervals by arm** The separation between
the B2 and B4 intervals is the fastest way to read the headline result.

The B2 and B4 intervals **do not overlap**. The paired test confirms it:

**Table 20: Paired McNemar contingency table**

| | **B4 diverts** | **B4 misses** | Total |
|---|---:|---:|---:|
| **B2 diverts** | 10,458 | **197** (c) | 10,655 |
| **B2 misses** | **842** (b) | 383 | 1,225 |
| Total | 11,300 | 580 | 11,880 |

Exact two-sided
**p = 1.9 × 10⁻⁹⁵**; concordant pairs 10,841. **B4 is ahead in 99 of 99 seeds.**

![A paired per-seed scatter of B2 recall against B4 recall across 99 seeds, with every point lying on the B4-ahead side of the diagonal.](../figures/seed-stability.svg)

**Figure 24: Per-seed paired comparison across 99 draws** Every point lies on the
same side of the diagonal, which is what rules out the possibility that the pooled
result rests on a handful of lucky draws.

The 197 discordant pairs in the other direction are reported rather than buried: these
are sessions the passive arm diverts and the probing arm defers, because the probing
arm's higher divert edge (0.8793 against the cost-only 0.8163) makes it wait. This is
the price of the safety property and it is visible in the data.

B1 is a real signature firewall — regular expressions for injection, scripting,
traversal and command injection, plus scanner user-agents — and it is a fair reference
rather than a straw man, since it false-positives on zero benign sessions. Its recall
is low because round-2 attacks are obfuscated and, more decisively, because reading
another user's record by changing an identifier is perfectly valid syntax with nothing
for a signature to match.

**A real ruleset, not only ours.** To confirm B1 is not a weak in-house baseline, the
**OWASP ModSecurity Core Rule Set** was replayed on identical traffic.

**Table 21: OWASP CRS paranoia sweep on identical traffic**

| CRS paranoia level | Attack recall (95 % CI) | Benign sessions blocked |
|---|---|---:|
| 1 (default) | 0.353 [0.305, 0.404] | **0 / 240** |
| 2 | 0.544 [0.493, 0.595] | **0 / 240** |
| 3 | 0.544 [0.493, 0.595] | **0 / 240** |
| 4 (maximum) | **1.000** [0.989, 1.000] | **72 / 240 (30 %)** |

At its default setting the real ruleset scores **0.353** against B1's 0.366, and the
intervals overlap — so the in-house baseline is, if anything, slightly generous to the
signature approach. The CRS reaches perfect recall only at paranoia 4, where it blocks
**thirty per cent of legitimate sessions**, which is not a deployable operating point.
The honest summary is that a signature ruleset tops out around **0.54** at settings
that leave benign users alone, against **0.943** at zero benign diversions here.

### 4.4.5 Where the gain lives

**Table 22: Recall by attack subcategory**

| Subcategory | n | B1 | B2 | B4 | B4 − B2 | Bite rate (B4) |
|---|---:|---:|---:|---:|---:|---:|
| **`idor_html_scattered`** | 1,980 | 0.000 | 0.540 | **0.823** | **+0.282** | 0.620 |
| `sqli_obfuscated` | 3,960 | 0.985 | 0.898 | 0.921 | +0.022 | 0.162 |
| `sqli_stealth` | 1,980 | 0.000 | 1.000 | 1.000 | +0.000 | 0.503 |
| `idor_scattered` (API) | 1,980 | 0.107 | 0.994 | 0.993 | −0.001 | 0.000 |
| `auth_spray` | 1,980 | 0.122 | 1.000 | 1.000 | +0.000 | 0.000 |

![Grouped bars of recall per attack subcategory for arms B1, B2 and B4, with Wilson intervals. The user-interface object-reference group shows a large B4-over-B2 gap while the other four groups show none.](../figures/recall-by-category.svg)

**Figure 25: Recall by attack subcategory**

This is the sharpest result in the project, and it is exactly what the theory
predicts. **Almost the entire gain is in user-interface object-reference attacks:
+0.282, against +0.022 or less everywhere else.** Three observations follow.

First, the probe helps *only where the passive detector is genuinely uncertain*. In
`sqli_stealth`, `idor_scattered` and `auth_spray` the passive meter is already at or
near 1.000, so there is no headroom and the probe correctly adds nothing. A probe that
raised recall everywhere would be a sign that the meter was weak, not that the pricing
was right.

Second, `idor_html_scattered` is precisely the category with no signature surface —
B1 scores **exactly zero** on it — and the one where a request is byte-identical to a
legitimate one. It is the case the entire design was built for, and it is where the
gain appears.

Third, note the `sqli_stealth` row: the bite rate is 0.503, so the probe *is* being
taken, yet recall does not move because the passive meter already catches every
session. This is the design behaving correctly rather than wastefully — the probe is
deployed where belief is uncertain, and uncertainty is not the same thing as
difficulty.

### 4.4.6 Safety on the benign side

**Table 23: Benign safety by client class**

| Benign client class | Sessions | Diverted | Shown a probe | Acted on a probe |
|---|---:|---:|---:|---:|
| Ordinary human users | ~4,455 | **0** | most | **0** |
| Hard negative: apostrophe search | ~594 | **0** | yes | **0** |
| Hard negative: forgetful login | ~594 | **0** | yes | **0** |
| Hard negative: URL mistyper | ~297 | **0** | yes | **0** |
| Automated: uptime monitor | ~660 | **0** | some | **0** |
| Automated: search crawler | ~660 | **0** | some | **0** |
| Automated: reporting integration | ~660 | **0** | yes | **0** |
| **Total** | **7,920** | **0** | **7,098 (89.6 %)** | **0** |

Two numbers carry this table. **Zero of 7,920 benign sessions were diverted.** And among the benign sessions
that were shown a probe — **7,098 of them, 89.6 %, effectively nine in ten** — not one
acted on it. The second number is the invisibility gate holding at scale
rather than only on the bench: the probes were served to real benign traffic
throughout, and produced no false evidence whatsoever.

The reporting-integration row deserves comment. Before the two offending features were
removed, this class was diverted **100 %** of the time, because a nightly integration
walks record identifiers in ascending order exactly as an attacker sweep does. No
passive feature separates those two honestly. The detection was delegated to the probe,
which distinguishes them by *asking* — and the integration, which does not read
response bodies looking for a way in, never bites.

### 4.4.7 Decoy consistency

| Configuration | Contradictions | Probes | Distinct bodies | Distinct names |
|---|---:|---:|---:|---:|
| Deterministic generator **with** Fact Notebook | **0 (0 %)** | 286 | 1 | 15 |
| Deterministic generator **without** notebook | **286 (100 %)** | 286 | 1 | 15 |
| Language model **with** notebook | **0 / 15 entities** | — | 12 | 13 |
| Language model **without** notebook | **15 / 15 entities** | — | 12 | 13 |

The consistency fuzzer asks the same question in different ways, revisits entities
after intervening requests, and cross-references answers across endpoints. With the
notebook the contradiction rate is **0 %**; without it, **100 %** — a generator with
no memory answers the second identical question differently almost every time, and a
decoy that contradicts itself has announced the trap.

A sceptic could read that as an artefact of a weak deterministic generator, so the
same ablation was run with a language model behind the same seam: **0 contradictions
with the notebook, 15 of 15 without it**, over 15 entities. The consistency property
therefore belongs to the notebook rather than to whatever produces the content, which
is exactly the claim §3.2.4 makes.

The trade in the other direction is worth reporting in the same breath. The language
model writes more varied free text — 12 distinct bodies against the deterministic
generator's 1 — while the deterministic generator produces more distinct names, 15
against 13. Richer prose, no better consistency; the two properties are independent.

### 4.4.8 Validation against third-party attack tools

Synthetic attackers are the project's own construction, so the sharpest objection is
that the attacker model was chosen to suit the defence. This was bounded from one side
by running real, third-party tools against the full system on an isolated local stack.

**Table 24: Third-party attack tools against the framework**

| Tool | Cookie behaviour | Requests | Outcome | Bit a probe? |
|---|---|---:|---|:--:|
| **sqlmap 1.10.8** | persists | — | Diverted on its **3rd** request, p → 1.0 | **No** |
| **wapiti 3.2.3** | persists | — | Diverted on its **13th** request, p → 1.0 | **No** |
| **ghauri 1.4.3** | **refuses** | 1,321 | Session-less; 46 % of individual requests diverted on their own lexical evidence | **No** |
| **sqlmap** vs OWASP Juice Shop | persists | — | Diverted on its **2nd** request | **No** |
| **OWASP ZAP** vs Juice Shop | browser-driven | 682 sessions, 589 endpoints crawled | Separated correctly rather than blanket-diverted | **No** |

Every cookie-persistent tool is diverted within a handful of requests, and **not one
tool bites a probe in any configuration**. That is not a failure of the probe; it is
the scope claim measured. A blind injection engine does not read a planted HTML
comment and decide to chase a deprecated-endpoint hint, and it does not need to be
caught that way, because its own behaviour is loud enough for the passive meter. The
probe exists for the adversary the scanner is not.

**One tool found a real evasion.** ghauri refuses the proxy's cookie, so every request
arrives session-less and the accumulating meter is reset before it can build a case —
the score-resetting attack the design anticipates. Even so, 46 % of its individual
requests are diverted on their own lexical evidence, and enabling the fingerprint
fallback the system already ships collapses its 1,321 requests into a single session
that is diverted outright. The evasion is real, it was anticipated, and the mitigation
is a configuration flag rather than a redesign.

**Transfer to a second application.** The same frozen model was placed in front of
OWASP Juice Shop — a Node/Express single-page application with a JSON API,
structurally unlike the target — in its passive configuration, since what transfer
tests is whether the features fire rather than whether the probe is taken. A
browser-driven ZAP scan that crawled 589 endpoints and mixed benign spidering with
payloads was **separated correctly rather than blanket-diverted**: diverted requests
carry a mean of 0.91 SQL-keyword hits, passed requests 0.00. What transfers is the
app-agnostic core — lexical context, error ratio, timing, header shape. What does not
is the app-specific authentication features, which key on the target's form-POST login
and stay silent against a JSON login endpoint; they would need re-pointing, and this is
stated rather than presented as a complete transfer.

These tool runs predate the bait recalibration and were made against the previous
freeze. Nothing in them depends on the bait weights, because no tool bit anything.

### 4.4.9 Validation against adversaries the project did not choose

Two further results test the system against adversaries whose behaviour the project
did not set.

**The adaptive adversary.** Attacker bait-*awareness* was swept from 0 (follows a
planted hint) to 1 (never bites, on principle) in five steps, forty sessions each,
against two profiles: an escalating attacker that raises its own signal as it works,
and a low-and-slow attacker that is precisely the case a passive score finds hard.

| Awareness | 0.00 | 0.25 | 0.50 | 0.75 | 1.00 |
|---|---:|---:|---:|---:|---:|
| Low-and-slow — bite rate | 0.925 | 0.975 | 0.850 | 0.775 | **0.000** |
| Low-and-slow — diverted | 1.000 | 1.000 | 1.000 | 1.000 | **1.000** |
| Escalating — diverted | 0.952 | 1.000 | 1.000 | 1.000 | **1.000** |
| Median requests to divert | 5 | 5 | 5 | 5 | **5** |

![Bite rate and diversion rate plotted against attacker bait-awareness from 0 to 1. The bite rate collapses from 0.925 to zero while both diversion curves stay flat at 1.000.](../figures/adaptive-adversary.svg)

**Figure 26: Adaptive adversary: bite rate against awareness** The two claims the
figure separates are that the bite rate genuinely reaches zero, and that the diversion
rate genuinely does not move.

The bite rate falls to zero as awareness reaches one, which is the sweep working: a
fully aware attacker really does refuse every probe. The diversion rate does not move,
and the number of requests taken to reach the decision is unchanged at five throughout.

The honest reading is narrower than "the system always wins". What the sweep
establishes is that **bait never blinds the detector it is built on**: withdrawing
every bite leaves the passive floor intact rather than below it, which is the property
the survival discount exists to guarantee. It does *not* establish that timing is
unaffected in general — this target's error-ratio and username features are strong
enough that the probe has little to add against these two profiles.

**An autonomous language-model attacker.** Three local models were given a tool
interface and twelve steps per session, reading each response and choosing their own
next request. Nothing in the prompt mentions bait, HTML comments, parameters or any
token.

**Table 25: Autonomous language-model attackers**

| Model | Shown a probe | Bite \| shown (95 % CI) | Diverted | Mean peak belief |
|---|---:|---:|---:|---:|
| Llama 3.2 1B | 13 / 20 | 0.077 [0.014, 0.333] | 0.55 | 0.687 |
| Llama 3.2 3B | 16 / 20 | 0.375 [0.185, 0.614] | 0.30 | 0.511 |
| Qwen 2.5 7B | 18 / 20 | **0.556** [0.337, 0.754] | 0.85 | 0.928 |

The conditional bite rate rises monotonically with model size, and the largest model's
**0.556 falls inside the [0.51, 0.79] range measured for the scripted attacker model**
in the calibration round. That is the answer to the objection this evaluation was
built to face: the curiosity assumption chosen by hand brackets the bite rate of an
autonomous adversary that was not chosen. It is a single overlapping interval on
twenty sessions per model, not a tight agreement, and no more than that is claimed.

The trajectories say what the rates cannot. The 1B model is shown a probe thirteen
times and never once mentions it in its reasoning — it is not declining the probe, it
is not perceiving it. The 3B model finds the hint by itself in thirteen sessions and
reasons about it in its own words, from a prompt that never mentions HTML comments,
parameters or any token. Capability does not order everything: the 3B model is by some
distance the stealthiest (peak belief 0.511, passively diverted in six sessions of
twenty) while the larger 7B is the loudest (0.928, seventeen of twenty), so the probe's
marginal value is highest against the *middle* of this range rather than the top.

**How this number was nearly wrong, three times.** All three failures produced a
confident number and none raised an error.

**Table 26: The same agent measurement under four harness conditions**

| The same measurement, four ways (bite rate over all 20 sessions) | 1B | 3B |
|---|---:|---:|
| Probe truncated out of the response | 0.000 | 0.000 |
| No structured way to submit a parameter | 0.000 | 0.000 |
| Prompt naming the channels and a token | 0.650 | 1.000 |
| **None of the three** | **0.050** | **0.300** |

First, the agent's view of each response was capped at 1,400 characters while the
probe sits at 96 % of a median page; 88 % of baited responses exceeded the cap, so the
agent was shown a body with the probe removed and recorded as having declined it.
Second, the agent had no structured way to *submit* a query parameter — it could name
one in its reasoning but could only write it into the search text, where the bait
engine cannot see it; under that interface all three models bit 0.000 while being
shown *more* probes than in the corrected runs (80 %, 90 % and 90 % exposure against
65 %, 80 % and 90 %). Third, after both were fixed, the system prompt still enumerated
the planted channels and used a real bait token as its example, which measured the
instruction rather than the adversary.

These are unconditional rates over all twenty sessions, which is why the corrected
column reads 0.050 and 0.300 against the 0.077 and 0.375 conditional rates above. The
table is in this report because the lesson generalises: an agentic evaluation can be
wrong in **both directions** while every number in it looks plausible, and the only
thing that distinguishes them is reading what the agent actually did. Harness
adjustment was stopped at the point where the remaining failures were the model's
rather than ours — the 3B model has a structured way to submit a parameter, is told
about it, and mostly still writes it into the query text. Continuing past that point
would have been coaching, not measurement.

## 4.5 Data Analysis and Interpretation

### 4.5.1 Why the gain is where it is

The subcategory table is not a curiosity; it is the mechanism made visible. The probe
is deployed when the belief lies in [0.0647, 0.8793), and belief lands in that band
exactly when the passive features are ambiguous. Three regimes appear in the data:

- **Belief already high** (`sqli_stealth`, `auth_spray`, `idor_scattered`): the
  passive meter reaches near-certainty on its own, the session diverts before or
  regardless of any probe, and the measured gain is zero. The probe is not wasted here
  so much as unnecessary.
- **Belief already low and staying low**: the session passes, correctly, and no probe
  is deployed.
- **Belief in the uncertain middle** (`idor_html_scattered`): the passive meter
  hovers, the probe is deployed, 62 % of these sessions bite, and the belief jumps
  across the divert edge in a single log-odds step. Recall moves **+0.282**.

This is the strongest available evidence that the pricing is doing what it claims. The
gain is not distributed; it is concentrated precisely where the theory says the
information purchase is worth making.

### 4.5.2 The cost view

**Table 27: Hand-set against derived band edges on expected cost**

| Configuration | Cost per session | Recall | Benign diverted |
|---|---:|---:|---:|
| Hand-set [0.200, 0.800] | **−10.393** [−10.545, −10.242] | 0.952 | 3 / 3,840 |
| Hand-set [0.050, 0.816] | −10.168 [−10.322, −10.015] | 0.948 | 3 / 3,840 |
| **Derived (as shipped)** | −10.030 [−10.167, −9.892] | 0.940 | **0 / 3,840** |
| Hand-set [0.300, 0.700] | −9.989 [−10.284, −9.694] | 0.971 | 46 / 3,840 |
| Hand-set [0.100, 0.900] | −9.881 [−10.050, −9.712] | 0.935 | **0 / 3,840** |
| Hand-set [0.050, 0.950] | −9.246 [−9.395, −9.098] | 0.911 | **0 / 3,840** |

Paired over 48
seeds, 9,600 sessions per arm. More negative is better; negative cost is a gain.

![Expected cost per session by arm, with confidence intervals, plotted so that more negative is better.](../figures/cost-by-arm.svg)

**Figure 27: Expected cost per session by arm** Reported separately from recall so
that neither figure is read as the other.

**The derived edges do not win on expected cost.** This is reported rather than
withheld, and the analysis of *why* is more useful than the headline would have been.

Three measurements explain the result, and none of them is that a person guessed
better.

**The gap is benign nuisance baiting, not detection.** The derived arm shows a probe
to 89 % of benign sessions (3,433 of 3,840) against 65 % for the arms that beat it, at
one unit each. That difference — not any difference in what the arms *catch* — is most
of the cost gap.

**The edge is not choosing a value; it is choosing a side.** The belief takes only a
handful of distinct values, and two of them account for **56 % of every decision the
policy makes** (0.163 and 0.476). Every edge below 0.163 behaves identically, and so
does every edge between 0.163 and 0.463. The measured benign-bait rates confirm it:
**0.897, 0.896 and 0.903** for the three arms whose edge falls below 0.163, against
**0.650, 0.650 and 0.650** for the three above it. The second group is identical to
three decimal places even though its lower edge runs from 0.187 to 0.300 — the plateau
made visible. The derived band's four decimal places are not doing the work their
precision suggests.

**The derived DIVERT edge is what buys zero benign diversion.** Benign belief ceilings
top out at **0.829**; the derived edge sits at **0.879**, above all of them. Every
configuration that beats the derived pair on cost does so by diverting benign users —
3, 3 and 46 sessions respectively. **Among the configurations that divert none, the
derived edges are the best available**, by a margin of 0.15 cost units over the next
best.

That is a narrower claim than the project set out to make and a more useful one,
because it says what the derivation *buys* — a placement that clears the benign belief
distribution by construction — rather than asserting a superiority the data does not
support.

### 4.5.3 Is the belief a probability?

Section 4.5.2 leaves an obvious question. Every band edge is a threshold on a
probability, and the meter that produces that probability was given its weights by
hand and never fitted to a label. If the belief is not calibrated, the edges do not
land where the derivation intends.

This was measured on four draws held out by construction — the calibration split runs
on seeds far below the evaluation range, so nothing fitted on it can reach a reported
number.

**Table 28: Probability calibration map selection**

| Map | Held-out ECE | Held-out Brier |
|---|---:|---:|
| As shipped (identity) | 0.157 ± 0.008 | 0.149 |
| Platt [39] | 0.040 | 0.120 |
| Beta [32] | 0.045 | 0.120 |
| **Isotonic** [59] | **0.018 ± 0.004** | **0.116** |

Selected by leave-one-draw-out
held-out expected calibration error over 14,270 scored requests, so the winner is the
one that survives a withheld draw rather than the one that fits best.

**The belief is not calibrated.** Binned as the calibration error itself bins them,
into fifteen equal-width intervals:

**Table 29: Reliability table of the shipped belief**

| Belief bin | Requests | Mean belief | Actual attack rate | Gap |
|---|---:|---:|---:|---:|
| [0.00, 0.07) | 107 | 0.0222 | 0.0654 | +0.0432 |
| [0.07, 0.13) | 4 | 0.0793 | 0.5000 | +0.4207 |
| **[0.13, 0.20)** | **2,225** | **0.1629** | **0.0036** | **−0.1593** |
| [0.20, 0.27) | 5 | 0.2493 | 0.0000 | −0.2493 |
| [0.33, 0.40) | 33 | 0.3603 | 0.9394 | +0.5791 |
| [0.40, 0.47) | 1,545 | 0.4521 | 0.0764 | −0.3757 |
| [0.47, 0.53) | 6,106 | 0.4761 | 0.3472 | −0.1289 |
| [0.53, 0.60) | 228 | 0.5772 | 0.6053 | +0.0281 |
| **[0.60, 0.67)** | **555** | **0.6332** | **0.8685** | **+0.2353** |
| [0.67, 0.73) | 441 | 0.6989 | 0.9773 | +0.2785 |
| [0.73, 0.80) | 509 | 0.7730 | 0.9980 | +0.2250 |
| [0.80, 0.87) | 340 | 0.8426 | 0.9971 | +0.1545 |
| [0.87, 0.93) | 228 | 0.9073 | 1.0000 | +0.0927 |
| [0.93, 1.00) | 1,944 | 0.9910 | 1.0000 | +0.0090 |

The meter is **over-confident
below about 0.6** — the 2,225 requests it scores in [0.13, 0.20), mean belief 0.163,
are attacks 0.4 % of the time — and **under-confident above it**, where the 555
requests in [0.60, 0.67), mean belief 0.633, are attacks 87 % of the time. The sign of
the gap flips around 0.6, which is the entire shape of the miscalibration.

![Reliability diagram: observed attack rate against mean predicted belief across fifteen equal-width bins, with a diagonal reference line, sparse bins faded, and bin populations shown beneath on a log scale.](../figures/reliability.svg)

**Figure 28: Reliability diagram of the shipped belief** Points below the diagonal
are over-confident, points above it under-confident, and the sign flips around 0.6.
The population strip beneath is there so the two bins holding four and five requests
are not read as evidence.

Measuring the consequence needs no change to any frozen artefact. A calibration map is
monotone, so applying the derived edges to a calibrated belief is arithmetically the
same policy as applying inverse-mapped edges to the raw one. The derived pair
(0.0647, 0.8793) becomes **(0.187, 0.619)** on the raw belief.

**Table 30: Effect of calibrating the belief under the frozen cost table**

| | Recall | Benign diverted | Cost / session |
|---|---:|---:|---:|
| Derived, as shipped | 0.940 | **0 / 3,840** | **−10.030** |
| Derived, calibrated belief | **0.979** | 81 / 3,840 | −9.497 |

Calibrating produces the **best recall of any configuration measured**, and the
improvement is not marginal: on matched attack sessions, 245 are caught by the
calibrated policy alone against 21 by the shipped one, **p = 1.3 × 10⁻⁴⁹**. It also
diverts 81 benign sessions where the shipped configuration diverts none, and under the
frozen cost table that decides it. The break-even price of a benign diversion is
**137**; the table, written before any data existed, prices it at 200.

Two conclusions follow and they point in opposite directions, which is why both belong
here. As a **detector**, the calibrated belief is clearly better. As a **policy under
this cost table**, it is clearly worse. Which of those is the improvement is not a
question the data answers — it is a question the cost table answers, and the cost table
was fixed in advance precisely so that it could.

There is a third reading, and it is the most useful. **Two modelling errors are
present and they point opposite ways.** The belief is under-confident at the top, which
pushes the operating edge higher on the raw scale than the cost model intends; and the
rule is derived for a *single decision* but deployed as a *first-crossing test over a
whole session*, which means the cost-optimal edge is higher still. The shipped
configuration sits close to the session-level optimum because those two errors very
nearly cancel. Correcting either alone moves it away. This is reported because a rule
that is right for compensating reasons is a different object from a rule that is right,
and a reader deciding whether to adopt the method is entitled to know which one this is.

## 4.6 Validation of the System

**Table 31: Validation criteria and outcomes**

| Criterion | Method | Result |
|---|---|---|
| Probe causes additional diversions | Randomised holdout, Fisher exact | **Confirmed** — +0.070 [+0.052, +0.088], p = 3.4 × 10⁻¹⁹ |
| Gain over passive detector is real | Exact paired McNemar, 11,880 pairs | **Confirmed** — 0.889 → 0.943, p = 1.9 × 10⁻⁹⁵ |
| Result is not a lucky draw | Per-seed paired comparison | **Confirmed** — B4 ahead in 99 / 99 seeds |
| Baseline is not a straw man | OWASP CRS replayed on identical traffic | **Confirmed** — CRS 0.353 at default vs B1 0.366 |
| No benign users diverted | Wilson interval on 7,920 sessions | **Confirmed** — 0 / 7,920 |
| Probes invisible to benign users | Bite count on 7,098 exposed benign sessions | **Confirmed** — 0 acted on a probe |
| Injection imperceptible | Certified median overhead vs 0.5 ms ceiling | **Confirmed** — worst 0.11 ms, p95 0.13 ms |
| Band exists only with information term | Algebra plus runtime invariant test | **Confirmed** — Property 0; band empty under cost alone |
| Band robust to estimated inputs | Sweep β ∈ [0.05, 0.99], cost ratio 0.5–128 | **Confirmed** — band non-empty, divert edge ≥ 0.8163 throughout |
| Degrades safely against bait-aware attacker | Awareness sweep, 5 levels × 40 sessions | **Confirmed** — divert rate unchanged at 1.000; bite → 0.000 |
| Decoy self-consistent | Consistency fuzzer, 286 probes | **Confirmed** — 0 % with notebook, 100 % without |
| Consistency independent of generator | Same ablation with a language model | **Confirmed** — 0 vs 15/15 over 15 entities |
| Robust to real attack tools | sqlmap, ghauri, wapiti, ZAP | **Confirmed** — every cookie-persistent tool diverted |
| Attacker model not self-serving | Autonomous LLM attacker, 3 models × 20 sessions | **Confirmed** — 0.556 falls inside the assumed [0.51, 0.79] |
| Fails open under component fault | Fault injection on three components | **Confirmed** — request served; 0 fail-opens in 875,703 decisions |
| Log tamper-evident | Chain verification with induced edits | **Confirmed** — any edit breaks the chain |
| Model cannot drift silently | Freeze manifest verification | **Confirmed** — reporting refuses on any digest mismatch |
| Derived edges beat hand-set ones on cost | 48-seed threshold sweep | **NOT confirmed** — see §4.5.2; derived best only among zero-diversion arms |
| Belief behaves as a probability | Held-out calibration, 14,270 requests | **NOT confirmed** — ECE 0.157; see §4.5.3 |

The final two rows are the reason this table is useful. Two pre-stated criteria were
**not** met, both are reported in full, and the analysis of why they failed produced
the most informative findings in the project.

## 4.7 Challenges and Limitations

### 4.7.1 Limitations retired by fixing the underlying problem

**Benign false positives on automated clients.** An early version diverted **every**
benign reporting-integration client, because two features treated any API access and
any run of ascending object identifiers as hostile — the exact shape of a harmless
integration. A human-only benign set had hidden this completely. Adding
automated-but-harmless clients exposed it; removing the two features fixed it, at the
cost of delegating that detection to bait.

**A benign crawler diverted on 404s** for standard files, fixed by serving
`robots.txt`, `sitemap.xml` and `favicon.ico` from both applications.

**A false positive on a forgetful user**, which an earlier draft reported as an
inherent cost of a hard negative, turned out not to be inherent at all: it was a
missing feature (`mal_distinct_usernames`) plus a double count (login rejections
counted in the error ratio as well). Once both were addressed, the benign diversion
rate is zero across every benign class.

**A corpus artefact that would have invalidated the automation axis.** This one is
reported at length because of how it was found. The attack generator spoke raw HTTP
and never fetched a page sub-resource; the benign generator fetched them like a
browser. The corpus therefore contained **no attack session that fetched an asset** and
almost no human-paced benign session that did not, and a logistic regression on the
automation features alone separated the two at an out-of-sample **AUC of 0.9935** — on
a property of the two scripts, not of hostility.

No reported number was affected, because automation carries weight zero in the
hostility belief and the logs confirm it. But the corpus was easier than reality, so
half the attackers now drive a browser. The automation-only figure falls to 0.898, and
every arm loses recall on the harder corpus:

| Corpus | B1 | B2 | B4 | B4 − B2 | Benign diverted (B4) |
|---|---:|---:|---:|---:|---:|
| Raw-HTTP attackers only | 0.408 | 0.917 | 0.951 | +0.034 | 0 / 7,920 |
| **Browser-mixed (reported)** | **0.366** | **0.889** | **0.943** | **+0.054** | **0 / 7,920** |

Every arm gets worse and the probe's contribution gets **larger** — from +0.034 to
+0.054, more than half again — because the passive automation signal that used to catch
these sessions is gone. **All numbers in this report are the harder ones.**

Because attributing a drop of that size to the corpus is easy to claim and hard to
check, the control was run: the browser-driven fraction is a pinned parameter, and
setting it to zero on the *current* frozen model reproduces the pre-browser numbers to
within 0.005 on every arm (B1 0.412, B2 0.918, B4 0.949 over twenty matched seeds,  <!-- not-the-headline -->
against 0.408, 0.917 and 0.951). The corpus is what changed, not the detector.

The browser-driven fraction was **not** raised further to drive the AUC down, which
would be fitting the corpus to a desired measurement; attack tooling genuinely does
skew scripted, and the separation that remains is real.

### 4.7.2 Irreducible limitations

**The traffic is synthetic** [48]. The benign mix, hard negatives included,
approximates office traffic; it is not a sample of it, and every rate in this report is
a statement about this distribution. Replaying a public labelled corpus such as CSIC
2010 [54] and recruiting human browsers would bound the benign side, and is the natural
next step. The band's derivation and the randomised-holdout design do not depend on the
traffic being real, but the magnitudes do.

**The probe's effectiveness is a property of an attacker model we chose.** This is
addressed three ways rather than caveated. The adaptive-adversary sweep shows the gain
decays to the passive floor as the attacker learns to refuse probes. The parameter
sweep shows the band's existence and the safety direction hold across the whole
plausible range. And an autonomous language-model attacker, told nothing about bait,
bites at a rate whose interval overlaps the range assumed by hand. None of that rescues
the *magnitude* of the gain, which remains a property of this attacker population.

**The belief is not calibrated, and the shipped rule is right for compensating
reasons.** This is the sharpest limitation and it sits under the decision rule rather
than beside it. Expected calibration error is 0.157 on held-out draws; the edges do not
land where the derivation intends; and the shipped configuration sits near the
session-level optimum only because two modelling errors of opposite sign nearly cancel.
Deriving the rule for the *sequential* decision it actually makes, rather than for a
single request, is the piece of theory this work leaves undone.

**The system is tuned on one application.** Transfer was checked by placing the frozen
model in front of OWASP Juice Shop: the app-agnostic features fire correctly, the
app-specific authentication features would need re-pointing, and a full evaluation with
a matched decoy on a second application remains future work.

**The cost table is a reasoned estimate**, not a real organisation's incident data. It
is frozen so it cannot be tuned to the results, and the sweep shows the conclusions
survive across two orders of magnitude of the one ratio it encodes, but the particular
level of conservatism it sets is a judgement.

**The human deception study is underpowered.** Four independent participants have now
been run, blind and block-randomised, two per arm (`human-study/`). One of the two
shown the decoy called it a mock-up; so did one of the two shown the *real*
application. The arm difference is 0.00 and Fisher gives p = 1.0 — but at two per arm
no p below 0.333 is reachable even under perfect separation, so no significant result
was *attainable*. The protocol's target of eight is the smallest n that could produce
one. What the study does establish is a baseline: a participant on the genuine system
called it fake after 15 minutes, over a directory-layout quirk. "Called it fake" is
not a zero-rate event on a real application, and any future claim has to be read
against that rather than against zero.

**Session identity can be reset.** ghauri demonstrated this in practice. The
fingerprint fallback mitigates it and ships disabled by default, which is the honest
configuration to evaluate.
