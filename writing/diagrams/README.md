# Report diagrams

The eleven structural diagrams from the project report. The Mermaid versions have
been removed; **`drawio/` is now the only source.**

## The one remaining step

The report references each diagram as a PNG in `writing/figures/diagrams/`, and those PNGs
have to be exported by hand — there is no headless draw.io renderer on this machine,
so nothing in the toolchain can produce them automatically.

For each file in `drawio/`:

1. Open it in **app.diagrams.net** or the desktop app.
2. **File → Export as → PNG**, *Zoom* 300 % (or *Width* ≈ 2400 px), **Transparent
   Background unchecked**.
3. Save into `writing/figures/diagrams/` **keeping the same base name**.

| draw.io source | Export to | Figure |
|---|---|---|
| `drawio/fig01-graphical-abstract.drawio` | `writing/figures/diagrams/fig01-graphical-abstract.png` | 1 |
| `drawio/fig10-decoy-consistency.drawio` | `writing/figures/diagrams/fig10-decoy-consistency.png` | 10 |
| `drawio/fig11-layered-architecture.drawio` | `writing/figures/diagrams/fig11-layered-architecture.png` | 11 |
| `drawio/fig12-overall-system-flow.drawio` | `writing/figures/diagrams/fig12-overall-system-flow.png` | 12 |
| `drawio/fig13-sequence-diagram.drawio` | `writing/figures/diagrams/fig13-sequence-diagram.png` | 13 |
| `drawio/fig14-dfd-level-0.drawio` | `writing/figures/diagrams/fig14-dfd-level-0.png` | 14 |
| `drawio/fig15-dfd-level-1.drawio` | `writing/figures/diagrams/fig15-dfd-level-1.png` | 15 |
| `drawio/fig16-use-case-diagram.drawio` | `writing/figures/diagrams/fig16-use-case-diagram.png` | 16 |
| `drawio/fig17-class-diagram.drawio` | `writing/figures/diagrams/fig17-class-diagram.png` | 17 |
| `drawio/fig18-session-state-machine.drawio` | `writing/figures/diagrams/fig18-session-state-machine.png` | 18 |
| `drawio/fig20-evaluation-harness.drawio` | `writing/figures/diagrams/fig20-evaluation-harness.png` | 20 |

`drawio/ALL-diagrams.drawio` holds all eleven as separate tabs, which is usually
easier to work through than opening eleven files.

Then rebuild:

```bash
python -m tools.build_report    # reports which diagrams are still missing
python -m tools.make_docx       # writes writing/report/PROJECT_REPORT.docx
```

`build_report` lists any diagram it could not find and treats it as *pending* rather
than as an error; a missing image anywhere **else** is still a hard failure, so a
genuine broken reference cannot slip through. `make_docx` puts a red note in the
document wherever an export is still missing, naming the exact file it wants — so the
Word file is never silently short of a figure.

## Editing

The `.drawio` files were produced by `python -m tools.make_drawio`, which computes the
layout from a specification in `tools/make_drawio.py`. **Once you have tidied a
diagram by hand, do not re-run the generator for that file** — it will overwrite your
work. Either keep the edited file and stop regenerating it, or fold the change back
into the generator.

The generator's output is deterministic, so `git status` and a plain diff will tell
you which files carry hand edits and which are still untouched generator output.
