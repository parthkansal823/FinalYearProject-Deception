# Writing

Everything that gets submitted. The runnable system lives outside this folder, at
the repository root; nothing in here is imported or executed by it.

| Folder | What it holds |
|---|---|
| `report/` | The project report — seven chapter files, the assembled `PROJECT_REPORT.md`, and the built `PROJECT_REPORT.docx`. Start at `report/README.md`. |
| `paper/` | The research paper — twelve sections, `refs.bib`, the reference verification log, the figure placement map, and the LNCS LaTeX template under `paper/latex/`. |
| `planning/` | Working documents behind the two above: the deadline abstract, the paper outline, and the content brief. Not submitted. |
| `figures/` | Every rendered figure: `*.svg` at the top, `pdf/` and `png/` beside them, and `diagrams/` for draw.io exports. |
| `diagrams/` | The `.drawio` sources for the eleven structural diagrams. See `diagrams/README.md`. |
| `archive/` | Superseded deliverables — the earlier synopses. Kept for the record. |

## The two documents

They share their data and their claims but not their structure or their audience.
The **paper** argues a contribution to reviewers who already know the field, in about
19,000 words. The **report** explains the system end to end to examiners who may not,
in about 37,000. Where they state a number, they state the same number, and the
consistency checker enforces that.

## Rebuilding

Run these from the **repository root**, not from this folder:

```bash
python -m tools.make_figures          # the plotted figures -> writing/figures/
python -m tools.make_report_figures   # reliability + adaptive adversary
python -m tools.make_drawio           # the .drawio sources -> writing/diagrams/
python -m tools.build_report          # chapters -> writing/report/PROJECT_REPORT.md
python -m tools.make_docx             # -> writing/report/PROJECT_REPORT.docx
python -m tools.check_doc_numbers     # every number against the evaluation data
```

`build_report` reports which draw.io diagrams have not been exported yet and treats
that as pending rather than as an error; any *other* missing image is a hard failure.
`make_docx` puts a visible note in the document wherever an export is still missing,
so the Word file is never quietly short of a figure.

## Outstanding before submission

1. Fill the placeholders in `report/00-front-matter.md` — co-author roll numbers,
   supervisor and HOD names and codes, month and year.
2. Confirm the title against the registered project title.
3. Export the eleven diagrams from `diagrams/drawio/` into `figures/diagrams/`
   (`diagrams/README.md` lists the exact filenames), then rebuild.
4. Re-confirm references [44]–[60] against publisher records. References [1]–[43]
   were verified during the paper work — see `paper/REFERENCE_VERIFICATION.md`.
5. Regenerate the table-of-contents page numbers once the document is formatted.
