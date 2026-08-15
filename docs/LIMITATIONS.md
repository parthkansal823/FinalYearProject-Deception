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
  measured recall gain (0.87 → 0.90, and 0.40 → 0.60 on that subcategory), after
  fixing two real bait-routing bugs (surface-blind and response-type-blind
  selection).
- **The bait behind that result was calibrated, not assumed.** B-IDOR-2 is
  measured (β=0.59, n=244), not left on a prior.

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
that model. `beta_benign` is a clean measurement (0 benign bites observed). The
adaptive-robustness sweep IS the sensitivity analysis over this assumption:
against a fully bait-aware adversary the gain decays to the passive floor, and
the decision rule converges to the passive two-action rule in the limit (so it
cannot be *asymptotically* worse — this is a property of the rule, not a
per-session guarantee; see [NOVELTY.md](NOVELTY.md) Contribution 5).

### 3. A single target application
One deliberately-weak portal. Its verbose SQL error makes passive SQL detection
strong, so bait's measured value is concentrated on the low-passive-signal
surface (UI IDOR). The 0.87 → 0.90 figure is target-specific; what transfers is
the *shape* — bait pays where belief is uncertain — shown by the per-subcategory
breakdown, not the aggregate.

### 4. Scale
One machine, seeded, hundreds of sessions per arm; a controlled laboratory
measurement (spec §17), not internet-scale, and not a study of tail or
rare-event rates.

### 5. One residual false positive is inherent
A `forgetful` user who fails login five times is diverted (3/5 of that persona;
0 for every other benign class including all automated ones). On passive features
that is indistinguishable from credential stuffing, and the auth bait that could
separate it is too weakly taken (β=0.12) for the policy to defer divert. This is
the genuine cost of a hard negative, not a tuning failure.

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

### 8. The cost table is a reasoned estimate
The costs that derive every threshold are argued, not taken from a real
organisation's incident data. They are frozen and hash-enforced so they cannot be
tuned to the results, but they remain an estimate.

### 9. The offline decoy generator is deterministic, not an LLM
A design choice (reproducible, generator-agnostic — the Fact Notebook does not
care how a value was produced), but a deterministic generator produces a smaller,
less varied fake world than a capable LLM would, which may make the decoy easier
to exhaust over a long engagement.

---

**The through-line:** the measurements are bounded by a synthetic, single-target,
solo laboratory setup and are not oversold. The parts meant to outlast it are not
measurements — the proof that probing is the cost-optimal third action, the
holdout that identifies its causal effect, and the guarantee that it never
underperforms passive detection.
