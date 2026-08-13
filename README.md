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
| 1 | Target application + benign traffic generator | ✅ complete |
| 2 | Attack round 1 (training corpus) | ⬜ not started |
| 3 | Detection engine — features, dual meter, cost policy (baseline **B2**) | ⬜ not started |
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
python -m tools.benign_traffic --sessions 100

# verify a log's hash chain has not been tampered with
python -m adf.logstore data/logs/target-access.<stamp>.jsonl

# inspect the frozen cost table and the thresholds derived from it
python -m adf.config

pytest
```

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
  schema.py         FROZEN record schema v1 — every log line and dataset row
  config.py         config loading + cost-table freeze enforcement
  logstore.py       append-only, hash-chained record store
  features/         request -> numbers                        (Phase 3)
  meter/            dual suspicion meter                      (Phase 3)
  policy/           cost-weighted three-way decision          (Phase 3)
  bait/             bait library + invisibility gate          (Phase 4)
  decoy/            Fact Notebook, planted credential         (Phase 5)
  proxy/            the reverse proxy everything sits behind  (Phase 3)
target_app/         the deliberately weak application — knows nothing of adf
decoy_app/          the fake site                             (Phase 5)
tools/              traffic generators, fuzzer, analysis
config/             costs.yaml (FROZEN), system.yaml
data/               logs, labels, models — not committed
docs/               the specification and decision log
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

Current derived thresholds — solved from the cost matrix, not chosen:

```
PASS    while p(hostile) <  0.0556
BAIT    while 0.0556 <= p(hostile) < 0.8767
DIVERT  once p(hostile) >= 0.8767
```

The bait band is wide and starts low precisely because bait is nearly free.
That is the central claim of the research expressed as arithmetic.

## Scope discipline

Spec §15 lists cuts already made, so they are not accidentally reintroduced:
three attack categories not six, no language model in the request path, no
live internet deployment, no online learning, no deep models. Section 15.2
lists the temptations to refuse — treat that list as binding.

If time runs short, drop in this order: dashboard → planted credential →
dataset release → baselines B0/B1 → two of the four ablations. **Never drop**
the invisibility gate, attack round 2, or the comparison against B2.
