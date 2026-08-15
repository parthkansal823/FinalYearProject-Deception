# Paper draft — section files, in order

Draft in Markdown first, section by section; assemble into LNCS LaTeX last
(template in `../../ResearchPaper/`, class `llncs.cls`, bib style `splncs04`).
Prose is written to read as a human security-systems paper, not a generated one:
plain sentences, varied length, claims tied to a concrete artifact, no filler
connectives.

| File | Section | Needs the 100-seed (L4) numbers? |
|---|---|---|
| `00-abstract.md` | Title, abstract, keywords | draft last |
| `01-introduction.md` | Introduction + contributions | no |
| `02-threat-model.md` | Threat model and scope | no |
| `03-system.md` | System design | no |
| `04-decision-rule.md` | The decision rule *(spine)* | no — **done** |
| `05-calibration.md` | Calibrating the probe | no |
| `06-consistency.md` | Consistency: the Fact Notebook | no |
| `07-implementation.md` | Implementation & reproducibility | no |
| `08-evaluation.md` | Evaluation | **yes** |
| `09-ablations.md` | Ablations | **yes** |
| `10-limitations.md` | Limitations | partly |
| `11-related-work.md` | Related work | no |
| `12-conclusion.md` | Conclusion | no |

Backing material each section draws on: `../NOVELTY.md`, `../METHODOLOGY.md`,
`../RESULTS.md`, `../LIMITATIONS.md`, `../REAL_ATTACK_EVAL.md`,
`../LITERATURE_REVIEW.md`.
