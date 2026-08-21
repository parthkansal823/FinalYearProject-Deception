# APPENDIX-1

# REPOSITORY LAYOUT

The submitted work is one repository. The runnable system and the written
deliverables are kept apart so that neither can silently change the other.

| Path | Contents |
|---|---|
| `adf/` | The framework: proxy, feature extractor, dual meter, policy engine, bait engine, invisibility gate, decoy, log store, freeze subsystem |
| `target_app/` | The deliberately vulnerable target application |
| `decoy_app/` | The parity-matched decoy served to diverted sessions |
| `config/` | The frozen cost table, the calibrated bait library, the invisibility certificates, the freeze manifest |
| `data/` | Generated corpora and evaluation dumps |
| `tools/` | Traffic generators, the evaluation harness, the statistical reporter, the figure and document builders |
| `tests/` | 369 automated tests across 26 files |
| `docs/` | Engineering documentation — decisions log, methodology, results, limitations |
| `writing/` | This report, the research paper, figures, diagrams and references |

**Table 32: Repository layout**

---

# APPENDIX-2

# THE FROZEN COST TABLE AND THE DERIVED BANDS

Reproduced here for reference; derived and discussed in Section 3.2.2.

**Table 33: The frozen cost matrix**

| | PASS | BAIT | DIVERT |
|---|---:|---:|---:|
| Session is benign | 0 | 1 | 200 |
| Session is an attack | 25 | 25 | −20 |

Expected costs as a function of the belief *p*:

```
E[C(pass)]   = 25p
E[C(bait)]   = 1 + 24p
E[C(divert)] = 200 − 220p
```

Under cost accounting alone, E[C(bait)] − E[C(pass)] = 1 − p > 0 for every
*p* < 1, so the BAIT band is empty and the rule collapses to a single boundary at
*p* = 200⁄245 = 0.8163. Subtracting the expected value of sample information
*V*(*p*) from the bait line opens the band:

**Table 34: Derived action bands**

| Boundary | Value | Origin |
|---|---:|---|
| `pass_to_bait` | 0.06465 | Where *V*(*p*) first exceeds the residual cost of baiting |
| `bait_to_divert` | 0.8793 | Where diverting becomes best even after the probe's value is credited |
| Cost-only boundary | 0.8163 | Where PASS and DIVERT cross with no information term |

The digest of the cost table is verified on every load; a modified table stops
every component that makes a decision.

---

# APPENDIX-3

# USER MANUAL

> **Safety notice.** This repository contains deliberately vulnerable software.
> Never expose any service in it to a network you do not fully control. All
> commands below bind to `127.0.0.1` for that reason.

## A3.1 Prerequisites

- Python 3.11 or later
- Approximately 2 GB of free disk space for generated corpora and logs
- Optional: Docker, only for the OWASP CRS baseline and the second target
  application used in Section 4.4.8

## A3.2 Installation

```
git clone <repository-url>
cd HoneypotDeception
python -m venv .venv
.venv\Scripts\activate            # Windows
source .venv/bin/activate          # Linux or macOS
pip install -r requirements.txt
```

## A3.3 Generating the labelled corpus

One command wipes previous state, seeds a fresh target database, starts a private
server, runs every traffic generator, stops the server, then assembles and
verifies the corpus:

```
python -m tools.generate_corpus
```

The build **refuses to emit a corpus** whose label-to-request join falls below the
coverage floor, so a silently broken dataset cannot reach the next step.

## A3.4 Training the detector

```
python -m tools.train_meter
```

This trains the two logistic heads on round-1 traffic only and writes the model.
Round-2 traffic is never used for training.

## A3.5 Running the system

Two terminals are needed. The target application listens on port 8001; the
framework's reverse proxy listens on 8000 and forwards to it.

```
# terminal 1 -- the application being protected
python -m uvicorn target_app.main:app --host 127.0.0.1 --port 8001

# terminal 2 -- the Active Deception Framework
python -m uvicorn adf.proxy:app --host 127.0.0.1 --port 8000
```

Clients then talk to **port 8000** and never to 8001 directly. Visiting
`http://127.0.0.1:8000/` in a browser shows the target application; nothing about
the defence is visible, which is the intended behaviour.

To see the framework act, submit a search containing a quote character — for
example `http://127.0.0.1:8000/search?q=widget'` — and then read the **raw**
response body rather than the rendered page. A probe will be present in the
markup that the browser does not display.

## A3.6 Reproducing the evaluation

```
python -m tools.multiseed_eval --seeds 99 --attack 120 --benign 80
python -m tools.stats_report --in data/eval/curious_v2/sessions.jsonl
python -m tools.make_figures
```

The evaluator verifies the freeze manifest before it produces any number and
raises if any artefact has changed since the model was frozen.

## A3.7 Running the tests

```
python -m pytest
```

All 369 tests must pass before a model can be frozen.

## A3.8 Rebuilding this report

```
python -m tools.build_report      # chapters -> writing/report/PROJECT_REPORT.md
python -m tools.make_docx         # -> writing/report/PROJECT_REPORT.docx
python -m tools.check_doc_numbers # every number against the evaluation data
```

## A3.9 Troubleshooting

**Table 35: Common problems and their causes**

| Symptom | Cause and remedy |
|---|---|
| `FrozenConfigError` on start-up | The cost table was edited after freezing. Restore it, or re-freeze deliberately with `python -m adf.config --refreeze`. |
| `FreezeError` when reporting | A model artefact changed since the freeze. The message names which one. |
| Port already in use | An earlier server is still running. Stop it, or pass a different port with `ADF_NETWORK__PROXY_PORT`. |
| Corpus build refuses to emit | Label-join coverage fell below the floor — usually stale logs in the working directory. Re-run `generate_corpus`, which wipes first. |
| `PermissionError` writing the report | The `.docx` is open in Word. Close it and re-run. |

---

# APPENDIX-4

# ACHIEVEMENTS

## A4.1 Deliverables produced

1. **A working framework** — approximately 6,600 lines of Python implementing a
   reverse proxy, an eighteen-feature two-axis detector, a cost-derived
   three-action policy, a certified bait library, and a state-consistent decoy.
2. **A reproducible evaluation harness** — a further 10,700 lines that generate
   seeded traffic, run every arm against one frozen model, and produce the
   statistical report and figures from which this document is written.
3. **A test suite of 369 automated tests** across 26 files, which must pass
   before a model can be frozen.
4. **A research paper** of roughly 19,000 words across twelve sections, prepared
   for double-blind submission, with a verified bibliography.
5. **This report**, whose every quantitative claim is checked against the
   evaluation data by an automated tool.

## A4.2 Results established

- The probe's causal effect on diversion, isolated by a randomised holdout:
  **+0.070 [+0.052, +0.088]**, Fisher exact *p* = 3.4 × 10⁻¹⁹.
- Attack recall raised from **0.889** to **0.943** over 11,880 matched sessions,
  exact paired McNemar *p* = 1.9 × 10⁻⁹⁵, ahead in **99 of 99 seeds**.
- **Zero** of 7,920 benign sessions diverted; of the 7,098 shown a probe, none
  acted on one.
- Decoy contradiction rate held at **0 %** over 286 adversarial probes, against
  **100 %** without the Fact Notebook — and the same result with a language model
  behind the same seam, establishing that the property belongs to the store
  rather than the generator.
- An autonomous language-model attacker, told nothing about bait, bit at a rate
  whose interval overlaps the range assumed for the scripted adversary.

## A4.3 Methodological contributions

- A **structural result**: under cost accounting alone the middle band is
  provably empty, so a priced third action is a different object from a tuned
  threshold.
- A **randomised holdout inside the treated arm**, which identifies the effect of
  deception rather than correlating it — a design the deception literature has
  rarely applied to a system evaluation.
- An **honest-failure record**: two pre-stated success criteria were not met and
  are reported as such in Section 4.6, and the analysis of why they failed
  produced the most informative findings in the project.

## A4.4 Engineering practices demonstrated

- Model artefacts hashed into a manifest that is verified before any reported
  number can be produced.
- An append-only, hash-chained decision log.
- A documentation consistency checker that recomputes every headline figure from
  the evaluation data and refuses to pass if a document has drifted.
- Deterministic, seeded traffic so that arms differ only in the code path under
  test.
