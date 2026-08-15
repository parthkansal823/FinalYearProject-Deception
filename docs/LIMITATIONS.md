# Limitations

Stated in the order a reviewer weights them, most disqualifying first. Naming a
weakness before it is found reads as rigour; the point of this document is that
none of the load-bearing claims (the EVSI theorem, the randomised-holdout design,
the contradiction-rate metric, the never-worse-than-passive guarantee) depends on
any of these, because those are a proof and a design rather than measurements.

## 1. All traffic is synthetic (the first thing to concede)

Neither the benign nor the attack traffic is real. Benign sessions are generated
to resemble a staff portal's users — including deliberately hard negatives (a
colleague named O'Connell whose apostrophe trips the SQL surface, a forgetful
user who fails login repeatedly) — but the *mix* is an approximation of real
office traffic, not a sample of it. Attack traffic is two rounds of generated
attacks. Every reported rate (recall, benign diversion, requests-to-decision) is
therefore a statement about this synthetic distribution, and would have to be
re-measured on real traffic before any operational claim.

What survives this: the theorem (Contribution 1) and the holdout *design*
(Contribution 3) are not measurements and do not depend on the traffic being
real; the contradiction rate is a property of the decoy, not the traffic.

## 2. `beta_attack` is a property of an attacker model, not a constant

The bite rates that drive the value-of-information calculation are measured, but
they are measured against **bait-following attackers whose curiosity is a
parameter we chose** (a mixed population, 0–100% likely to act on a planted
token). So `beta_attack` — and therefore the recall gain in the results — is
conditional on that attacker model, which reflects one researcher's assumptions,
not a physical fact about real adversaries. `beta_benign`, by contrast, IS a
clean measurement (benign users never inspect responses for tokens, and the
observed benign bite rate is zero). We report both, and the headline recall gain
should be read as "against a curious adversary"; the bait-aware case is measured
separately (§7 below).

## 3. A single, deliberately-verbose target application

Results come from one target. Its SQL weakness leaks a verbose database error on
every malformed query, which makes passive detection *strong* for the SQL and
auth categories — so bait is neutral there, and its measured value is
concentrated entirely in the one surface with weak passive signal (UI-based
IDOR). On a target with a different weakness profile the balance between "passive
suffices" and "bait is needed" would move. We do not claim the 0.84 → 0.93 recall
figure transfers; we claim the *mechanism* (bait pays exactly where the belief is
uncertain) transfers, and that is what the per-subcategory breakdown shows.

## 4. Scale

Everything runs on one machine, seeded, at the scale of hundreds of sessions per
arm — not the millions a deployed WAF sees, and not internet-exposed. The
evaluation is a controlled laboratory measurement (spec §17), adequate for the
comparative and causal claims but not for tail behaviour, rare-event rates, or
performance under real concurrency.

## 5. The recall gain requires a curious adversary; a bait-aware one erodes it

The 0.84 → 0.93 improvement is against attackers who act on what they find. An
adversary who knows the defence exists and declines the bait is not caught by it,
and the adaptive-robustness sweep measures exactly this: as bait-awareness rises
the gain decays to the passive floor. The guarantee we make is the conservative
one — **the full system is never worse than its own passive baseline, whatever
the adversary knows** (the EVSI decay makes this provable) — not that bait always
helps. A bait-aware adversary is a real, if presently uncommon, threat.

## 6. Two baits are never deployed and retain their priors

The cost-optimal policy concentrates deployment on the highest-value applicable
bait per surface, so of six baits four are calibrated from data and two
(`B-IDOR-1`, a JSON field; `B-AUTH-2`, an OTP-JSON field) are essentially never
selected on this target and keep their prior effectiveness. They barely affect
any reported number *because* they are rarely deployed, but the library is
"calibrated where sampled, prior otherwise", not fully calibrated, and the
per-bait provenance says so (`config/bait_calibration_report.json`).

## 7. The deception assessment is a self-assessment

Time-to-suspicion (spec §10.4) — how long before an attacker realises they are in
a decoy — is measured by the researcher against a fixed checklist, and by the
consistency fuzzer, not by independent human participants. The 0.00%
contradiction rate is an objective property of the decoy under automated probing;
whether a human attacker *feels* something is off is not measured. A blind study
with independent testers is future work.

## 8. Timing features are not exercised realistically in the evaluation

The evaluation traffic runs without human think-times (for speed and
determinism), so the automation-axis timing features (`interarrival_cv`,
`requests_per_min`) are compressed. Detection in the reported runs is
malice-driven (fusion weights malice only), so the divert results are unaffected,
but the automation axis — and any claim about separating a metronomic scanner
from a human on timing alone — is validated on the corpus (Phase 1), not in the
Phase 7 numbers.

## 9. The one benign diversion is an inherent passive-detection limit

A forgetful user who fails login five times is diverted (1/80), because on
passive features they are identical to an early credential attack. Bait is the
mechanism that *could* separate them — an attacker takes the deprecated-endpoint
bait, a forgetful user does not — but the passive malice from the failed logins
crosses the divert threshold before the bait resolves. Making the policy wait for
that evidence would trade this false positive for slower divert on real
credential attacks; we did not, and report the 1.25% as the honest cost.

## 10. The decoy's offline generator is deterministic, not a language model

The specification envisages a batched LLM to populate the fake world; the
implementation uses a deterministic synthetic generator instead. This is better
for reproducibility (NFR-08) and the contribution is generator-agnostic (the Fact
Notebook and its contradiction rate do not depend on how a value was produced),
but a deterministic generator produces a smaller and less varied fake world than
a capable LLM would, which may make the decoy easier for a human to exhaust or
find repetitive over a long engagement.

## 11. The cost table is a reasoned estimate

The costs that derive every threshold are argued from the relative severity of
each error, not taken from a real organisation's incident data (spec §18). The
derived bands are only as meaningful as those numbers; we freeze them before any
data is collected so they cannot be tuned to the results, but they remain an
estimate. Because they are frozen and hash-enforced, a reader can at least verify
they were not moved after the fact.

## 12. Adversary assumed unaware of the specific defence (headline only)

The headline detection numbers assume the attacker does not know this particular
bait scheme is in place. This is the standard honeytoken assumption, and the
adaptive-adversary sweep (§5 above) is precisely the relaxation of it; countering
an attacker who actively hunts for bait beyond "decline everything" — e.g. one
who fingerprints the decoy or the bait phrasing — is out of scope.

---

**The through-line:** the measurements here are bounded by a synthetic,
single-target, single-researcher laboratory setup, and we do not oversell them.
The parts meant to outlast this setup are the ones that are not measurements —
the proof that probing is the cost-optimal third action, the holdout design that
identifies its causal effect, and the guarantee that it never underperforms
passive detection — and those are stated as such.
