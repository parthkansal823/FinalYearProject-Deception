# An Active Deception Framework for Web Attack Detection

**Response-side probes and state-consistent decoys.**

Existing defences wait until they are confident before acting. This system
*deceives a little in order to become sure* — it plants invisible bait in
responses to manufacture the evidence that passive systems can only wait for,
and it measures what that costs real users.

> ⚠️ **This repository contains deliberately vulnerable software.**
> Read [SAFETY.md](SAFETY.md) before running anything. Never expose any
> service here to a network you do not fully control.

The full specification is in [docs/PROJECT_SPEC.txt](docs/PROJECT_SPEC.txt);
section references throughout the code (`spec §6.5`) point into it.

---

## The idea in one paragraph

When the system is unsure about a visitor, it adds something to the response
that a real browser never displays but anyone reading raw traffic will see —
a fake database error naming a table that does not exist, an unused JSON
field, a hint at a deprecated login endpoint. An honest user never notices.
Someone probing the site acts on it, and the moment they do, they have
identified themselves. They are not blocked: they are moved silently into a
consistent fake copy of the site where everything they do is recorded.

## Status

| Phase | Name | State |
|---|---|---|
| 0 | Foundation — cost table, label schema, logging skeleton | ✅ complete |
| 1 | Target application + benign traffic generator | ✅ complete — corpus verified, all 6 exit checks pass |
| 2 | Attack round 1 (training corpus) | ✅ generator + verification + 2×2 coverage; clean corpus generating |
| 3 | Detection engine — features, dual meter, cost policy, proxy (baseline **B2**) | 🟨 features/meter/policy/proxy built + tested; meter awaits corpus to train |
| 4 | Bait library — **invisibility gate first** | ⬜ not started |
| 5 | Decoy environment + Fact Notebook + consistency fuzzer | ⬜ not started |
| 6 | Integration, fail-open verification, model freeze | ⬜ not started |
| 7 | Attack round 2, baselines, ablations, results | ⬜ not started |

Do not begin a phase until the previous one has met its exit condition
(spec §13) — that sequencing is what prevents discovering in the final week
that the data was collected in the wrong format.

## Quick start

```bash
pip install -r requirements.txt

# create the synthetic world (deterministic for a given seed)
python -m target_app.seed

# run the target application
python -m uvicorn target_app.main:app --host 127.0.0.1 --port 8001

# in another shell: generate labelled benign traffic
python -m tools.benign_traffic --sessions 100        # simulated humans
python -m tools.benign_agents  --sessions 30         # benign BUT automated

# assemble the corpus and verify the labels actually joined
python -m adf.dataset

# characterise it — this is the Phase 1 exit evidence
python -m tools.corpus_report

# verify a log's hash chain has not been tampered with
python -m adf.logstore data/logs/target-access.<stamp>.jsonl

# inspect the cost table and the decision bands derived from it
python -m adf.config
python -m adf.policy

pytest
```

> Add `--no-dwell` for a fast smoke run, but **never for a corpus you intend to
> train on**: it removes the think-times, and inter-request timing is the first
> automation feature in spec §6.3. `corpus_report` will tell you if timing has
> failed to separate.

### Why there are two benign generators

Spec §6.3 justifies the two-axis suspicion model with three cases: a scanner
(automated, hostile), a price-comparison bot (automated, harmless) and a
careful human attacker (manual, hostile). If the corpus contains only the
first and third, automation and malice are perfectly correlated — a single
combined score would do just as well, and the second axis is indefensible.

`benign_agents.py` supplies the missing class. It also supplies the hardest
negative in the corpus: a reporting integration that walks record ids in
ascending order over the API, which is the request shape of an IDOR sweep
from a client doing nothing wrong.

`benign_traffic.py` adds two awkward-but-honest human personas for the same
reason — one who looks up a colleague named *O'Connell* (the apostrophe hits
the concatenated SQL and returns the same verbose error an attacker sees while
probing), and one who forgets their password three to five times. Without
cases like these, "benign bait exposure rate" would be trivially zero and
would describe the corpus rather than the system.

Or with containers (spec NFR-12):

```bash
docker compose up target db      # Postgres backend, realistic SQL errors
```

### Sign-in details for the synthetic world

Seeded users are listed in `target_app/seed.py`. Second-factor codes are
computed by `target_app/otp.py` — deliberately predictable, which is the
OTP-bypass surface. The benign traffic generator computes them the same way,
because a legitimate user would have received the code by another channel.

## What is where

```
adf/                the deception framework
  schema.py         FROZEN record schema v3 — every log line and dataset row
  config.py         config loading + cost-table freeze enforcement
  logstore.py       append-only, hash-chained record store
  dataset.py        corpus assembly: joins labels to traffic, verifies coverage
  policy/           three-way decision + value-of-information  ✅
    voi.py          EVSI: why bait is ever worth deploying
    engine.py       score fusion, bait selection, randomised holdout
  features/         request -> numbers                        (Phase 3)
  meter/            dual suspicion meter                      (Phase 3)
  bait/             bait library + invisibility gate          (Phase 4)
  decoy/            Fact Notebook, planted credential         (Phase 5)
  proxy/            the reverse proxy everything sits behind  (Phase 3)
target_app/         the deliberately weak application — knows nothing of adf
decoy_app/          the fake site                             (Phase 5)
tools/
  benign_traffic.py simulated humans, incl. awkward-but-honest personas
  benign_agents.py  benign BUT automated clients (the §6.3 middle case)
  corpus_report.py  quantitative realism check — Phase 1 exit evidence
config/             costs.yaml (FROZEN), bait_library.yaml, system.yaml
data/               logs, labels, models — not committed
docs/               spec, decision log, spec review, novelty framing
```

## The two things that must not drift

Both are enforced by tests rather than trusted to discipline
(`tests/test_frozen_artefacts.py`):

1. **The cost table** (`config/costs.yaml`) is hashed. The system refuses to
   start if the numbers move, because thresholds are *derived* from them
   rather than tuned, and editing them after seeing results invalidates every
   baseline comparison (spec §6.5, §16). Re-freezing is deliberate and leaves
   a dated entry in `config/costs.CHANGELOG.md`.

2. **The record schema** (`adf/schema.py`) is fingerprinted. Spec §11: fixing
   the label format after collection begins means either re-running every
   experiment or abandoning the dataset release.

## Why bait is ever justified

Baiting has **no immediate benefit**. The request still reaches the real
application, so baiting an attacker costs exactly what letting them past
costs, plus a small residual risk to benign users. On cost accounting alone
the policy collapses to an ordinary two-outcome rule — PASS below p = 0.816,
DIVERT above it, **no middle band anywhere**.

The third action exists because a probe buys *information*, and that value is
computed rather than assumed:

```
V(p) = min_a E[C(a) | p]  −  E_Z[ min_a E[C(a) | p after observing Z] ]

effective_cost(bait) = E[C(bait) | p] − V(p)      # cheapest action wins
```

`V(p) ≥ 0` always (Jensen), and `V(0) = V(1) = 0` — when you are already
certain, probing is worth exactly nothing, so the band is bounded on both
sides by construction. With the frozen costs and current bait effectiveness:

```
PASS    p < 0.0426
BAIT    0.0426 ≤ p < 0.8595
DIVERT  p ≥ 0.8595
```

Nothing in those numbers was chosen. See [docs/NOVELTY.md](docs/NOVELTY.md);
inspect them with `python -m adf.policy`.

**Bait effectiveness is not yet calibrated.** `config/bait_library.yaml` ships
priors, and the policy refuses to produce reportable results from them. They
are estimated in the dedicated `calibrate` round — which exists because the
spec's own phase order left them uncalibratable (round 1 predates the bait
library; round 2 is the test set). See
[docs/SPEC_REVIEW.md](docs/SPEC_REVIEW.md) finding 1.

## Scope discipline

Spec §15 lists cuts already made, so they are not accidentally reintroduced:
three attack categories not six, no language model in the request path, no
live internet deployment, no online learning, no deep models. Section 15.2
lists the temptations to refuse — treat that list as binding.

If time runs short, drop in this order: dashboard → planted credential →
dataset release → baselines B0/B1 → two of the four ablations. **Never drop**
the invisibility gate, attack round 2, or the comparison against B2.
