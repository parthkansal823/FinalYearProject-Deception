# Project report — assembly guide

**The assembled document is [`writing/report/PROJECT_REPORT.md`](../PROJECT_REPORT.md).** That
is the file to convert and hand in.

It is *generated* from the chapter files in this directory, so it must not be edited
directly — edit a chapter, then rebuild:

```bash
python -m tools.build_report
```

The build rewrites image paths for the new directory depth, inserts a page break
between chapters, and fails if any referenced image is missing. Keeping one generated
copy rather than two hand-maintained ones is deliberate: two copies of a
thirty-eight-thousand-word document drift, and drift silently.

The chapters are written as separate files because they are easier to edit and review
that way. Read them in order; they assemble into a single document with the same
chapter structure as the department's report template.

| Order | File | Contents |
|---|---|---|
| 1 | `00-front-matter.md` | Title page, bonafide certificate, table of contents, abstract, graphical abstract, list of figures, list of tables, list of abbreviations |
| 2 | `01-introduction.md` | Chapter 1 — Introduction |
| 3 | `02-literature-survey.md` | Chapter 2 — Literature Survey |
| 4 | `03-design-flow-part1.md` | Chapter 3, §3.1–3.5 — concept, proposed design, constraints, alternatives, selection |
| 5 | `03-design-flow-part2.md` | Chapter 3, §3.6–3.9 — architecture, algorithms, flowcharts, implementation plan |
| 6 | `04-results.md` | Chapter 4 — Results Analysis and Validation |
| 7 | `05-conclusion.md` | Chapter 5 — Conclusion, Future Work, References |

Chapter 3 is split across two files only because of its length. There is no break in
the numbering: `03-design-flow-part2.md` begins at §3.6.

## Size

| | Count |
|---|---:|
| Words | ~38,000 |
| Tables | 31 (numbered 1–31, no gaps) |
| Figures | 28 (numbered 1–28, no gaps) — 17 ready-made images, 11 Mermaid to render |
| Pseudocode / algorithm blocks | 8 numbered algorithms plus supporting listings |
| References | 60 |

At typical thesis formatting (12 pt serif, 1.5 line spacing, A4, normal margins) this
comes to roughly **110–120 pages** including figures and tables.

## Figures

Seventeen of the twenty-eight figures are **rendered image files** already present in
`writing/figures/` as both SVG and PDF. They are referenced from the Markdown with relative
paths (`../img/name.svg` in the chapters, rewritten to `img/name.svg` in the built
document) and need no further work — insert the SVG, or the PDF from `writing/figures/pdf/`
if the word processor prefers it.

The remaining **eleven are Mermaid diagrams written inline** in the Markdown, and are
the ones that still need rendering:

| Figure | Diagram |
|---|---|
| 1 | Graphical abstract |
| 10 | Decoy consistency with and without the Fact Notebook |
| 11 | Layered system architecture |
| 12 | Overall system flow, including the randomised holdout |
| 13 | Sequence diagram (step-by-step execution) |
| 14 | DFD Level 0 (context diagram) |
| 15 | DFD Level 1 (detailed system flow) |
| 16 | Use case diagram |
| 17 | Class diagram |
| 18 | Session state machine |
| 20 | Evaluation harness and arm isolation |

These are the diagrams for which no plotted equivalent exists, because they describe
structure rather than data. Render them with any Mermaid renderer (mermaid.live, the
VS Code Mermaid extension, or `mmdc`) and paste the result in.

To regenerate the plotted figures from current data:

```bash
python -m tools.make_figures          # the fifteen main figures
python -m tools.make_report_figures   # reliability diagram + adaptive adversary
```

`make_figures` refuses to draw from a results file whose recorded digests no longer
match `config/`, so a figure in `writing/figures/` is either current or absent.

## Checking the numbers

Every quantitative claim in the report is checked against the evaluation data by an
automated tool, which recomputes the canonical facts and compares them against every
document in `README.md`, `docs/`, `writing/paper/` and `writing/report/`:

```bash
python -m tools.check_doc_numbers
```

A clean run prints `no disagreements found`. If a number is edited during formatting
and drifts from the data, this catches it. A line that legitimately quotes a different
measurement — a control run, a superseded figure named on purpose — carries the marker
`<!-- not-the-headline -->` and is skipped; there are two such lines in the report and
both are explained in the surrounding text.

## Before submission

1. **Fill in the placeholders** in `00-front-matter.md`: co-author roll numbers,
   supervisor name and employee code, HOD name and code, month and year.
2. **Confirm the title** against the registered project title.
3. **Re-confirm references [44]–[60]** against publisher records. References [1]–[43]
   were each verified during the research-paper work and their verification log is in
   `writing/paper/REFERENCE_VERIFICATION.md`; the classical and standards works added for
   this report were not put through the same process and should be checked before
   submission rather than accepted from the list.
4. **Regenerate the table of contents page numbers** once the document is formatted —
   the numbers in `00-front-matter.md` are estimates from the draft, not measured
   positions.
5. **Render the eleven Mermaid diagrams** listed above and insert them.
6. **Rebuild** with `python -m tools.build_report` after any chapter edit, and
   re-run `python -m tools.check_doc_numbers` before converting.

## Relationship to the research paper

`writing/paper/` contains a separate, much shorter treatment of the same work written for
a double-blind conference submission (roughly 19,000 words across twelve sections).
The two documents share their data and their claims but not their structure or their
audience: the paper argues a contribution to reviewers who know the field, while this
report explains a system end to end to examiners who may not. Where they differ in
emphasis, the paper is terser and the report is more explanatory; where they state a
number, they state the same number, and `check_doc_numbers` enforces that.
