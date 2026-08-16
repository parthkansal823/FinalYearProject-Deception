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
  significant recall gain (pooled over 100 paired seeds: 0.915 → 0.946, paired McNemar
  p<10⁻⁴, and 0.704 → 0.890 on that subcategory), after fixing two real
  bait-routing bugs (surface-blind and response-type-blind selection).
- **The bait behind that result was calibrated, not assumed.** B-IDOR-2 is
  measured (β=0.59, n=244), not left on a prior.
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
low-passive-signal surface (UI IDOR). The 0.915 → 0.946 figure is target-specific;
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
100-draw run (`tools/multiseed_eval.py --seeds 100`) puts 12,000 attack and
8,000 benign sessions behind each arm, which is what makes the rare-event
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
with a false-positive rate. The relevant auth bait is weakly taken (β=0.12), so
this case is genuinely open.

**Why that β is not a fair test of the probe, stated precisely.** B-AUTH-1's
β_attack = 0.1163 is measured over 244 sessions against the calibration round's
*bait-following* attacker model. The simulated vertical brute-forcer is not in
that model at all: it only ever POSTs credentials and **never reads a response
body** (`tools/attack_traffic.py`, the `auth_bruteforce` branch — unlike
`cred_stuffing`, it does not even GET `/login`). A response-side probe therefore
cannot reach it *by construction*, whatever the bait says. So the honest reading
is not "the auth bait is weak" but "this attacker is, as simulated, blind to
every response-side channel."

That cuts against the system in the write-up, not for it, and it is worth naming
because a **real** brute-force tool is not blind in that way: hydra, patator and
Burp Intruder all parse the response to tell a success from a failure, which is
the very channel a probe rides. We therefore expect the measured β to understate
what a probe can do against a real vertical brute force — but we have **not**
measured that, so it is stated as an expectation and an experiment worth running,
never as a result. Closing it means making the simulated brute-forcer read
responses the way real tooling does, which changes the training corpus and so
requires a re-freeze and a re-run of every arm.

On the frozen cost table the trade is favourable by construction — a wrongly
diverted user is priced at 200 against 25 for a missed attacker, so avoiding one
false positive is worth eight missed attacks — but it is a trade, and it is
reported as one. Credential *stuffing* (many accounts) remains caught 4/4, and
`auth_otp_bypass` is unaffected: the error-ratio exclusion is scoped to `/login`
alone, which is where the ambiguity lives.

### 6. Half the baits keep their priors — because they are rarely deployed here
Of six baits, **three are measured** from data (`B-SQL-2` n=39, `B-IDOR-2` n=244,
`B-AUTH-1` n=244) and **three keep their priors** (`B-SQL-1` n=19 — a thin sample;
`B-IDOR-1` and `B-AUTH-2` n=0 — both JSON-field channel, essentially never
selected on this target's response shapes). The prior baits barely affect any
reported number precisely because they are rarely deployed, and the per-bait
provenance in `config/bait_calibration_report.json` marks each `measured` or
`prior` so a reviewer can see which is which. The one result that carries the
paper (UI-IDOR) rests on `B-IDOR-2`, which is measured over n=244.

### 7. The deception assessment is a self-assessment
Time-to-suspicion is measured by the researcher against a checklist and by the
consistency fuzzer (0% contradiction over 286 probes), not by independent human
participants. Whether a human attacker *feels* something is off is not measured.

### 8. The cost table's *magnitudes* remain an estimate — its *conclusions* do not
The costs are argued rather than taken from a real organisation's incident data,
and that has not changed. What has changed is that nothing load-bearing rests on
them. `tools/cost_sweep.py` sweeps the single judgement they encode — how much
worse a wrongly diverted user is than a missed attacker — across 0.5× to 128×,
holding the calibrated bait effectiveness fixed:

| divert/miss | cost-only boundary | BAIT band | band? | divert ≥ cost-only? |
|---|---|---|---|---|
| 0.5 | 0.2174 | [0.0379, 0.2741) | yes | yes |
| **8.0 (frozen)** | **0.8163** | **[0.0616, 0.8626)** | **yes** | **yes** |
| 128.0 | 0.9861 | [0.3260, 0.9902) | yes | yes |

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
