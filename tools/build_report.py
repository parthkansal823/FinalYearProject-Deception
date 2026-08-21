"""Concatenate the chapter files in `writing/report/` into one document.

The report is written as separate chapter files because they are easier to edit
and review that way, but what gets handed in is a single document. Rather than
maintaining two copies -- which drift, and drift silently -- the combined file is
generated from the chapters and carries a header saying so.

Two things need fixing during the join:

  * image paths. The chapters and the assembled file now live in the same
    directory (`writing/report/`), so `../figures/x.svg` resolves from both and
    no rewriting is needed -- but a chapter written before the move may still
    say `../img/`, so that older form is normalised.
  * page breaks. Chapters should start on a fresh page in the word processor, so
    an explicit break is inserted between them. The HTML form is what Word honours
    on paste; pandoc users can swap it for `\\newpage`.

Run:  python -m tools.build_report
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path("writing/report")
OUT = Path("writing/report/PROJECT_REPORT.md")

#: Chapter files in document order. README.md is the assembly guide, not content.
ORDER = [
    "00-front-matter.md",
    "01-introduction.md",
    "02-literature-survey.md",
    "03-design-flow-part1.md",
    "03-design-flow-part2.md",
    "04-results.md",
    "05-conclusion.md",
    "06-appendices.md",
]

PAGE_BREAK = '\n<div style="page-break-after: always;"></div>\n'

HEADER = """<!--
  GENERATED FILE -- do not edit directly.

  This document is built from the chapter files in writing/report/ by:

      python -m tools.build_report

  Edit the chapter files, then regenerate. Editing this file directly means the
  next regeneration silently discards the change.

  Before submission see writing/report/README.md: placeholders to fill,
  references to confirm against publisher records, table-of-contents page
  numbers to regenerate, and the draw.io diagrams to export.
-->

"""


def build() -> str:
    missing = [n for n in ORDER if not (SRC / n).exists()]
    if missing:
        raise SystemExit("missing chapter file(s): " + ", ".join(missing))

    parts = []
    for i, name in enumerate(ORDER):
        text = (SRC / name).read_text(encoding="utf-8")

        text = re.sub(r"\]\(\.\./img/", "](../figures/", text)
        text = re.sub(r"\]\(\.\./([A-Za-z0-9_./-]+\.md)", r"](\1", text)

        parts.append(text.rstrip() + "\n")
        if i < len(ORDER) - 1:
            parts.append(PAGE_BREAK)

    return HEADER + "\n".join(parts)


def main() -> None:
    doc = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(doc, encoding="utf-8")

    words = len(re.findall(r"\S+", doc))
    figs = len(re.findall(r"\*\*Figure\s+\d+\s*[:—-]", doc))
    tabs = len(re.findall(r"\*\*Table\s+\d+\s*[:—-]", doc))
    imgs = len(re.findall(r"!\[[^\]]*\]\(\.\./figures/", doc))
    mer = doc.count("```mermaid")

    refs = re.findall(r"!\[[^\]]*\]\(\.\./figures/([^)]+)\)", doc)
    missing = [m for m in refs if not (Path("writing/figures") / m).exists()]
    # A diagram that has not been exported from draw.io yet is expected, not an
    # error -- the .drawio source is the master and the PNG is produced by hand.
    # Anything else missing is a genuine broken reference.
    pending = sorted(m for m in missing if m.startswith("diagrams/"))
    broken = [m for m in missing if not m.startswith("diagrams/")]

    print(f"  wrote {OUT}")
    print(f"  {words:,} words | {tabs} numbered tables | {figs} numbered figures")
    print(f"  {imgs} image references | {mer} Mermaid diagrams to render")
    if pending:
        print(f"  {len(pending)} diagram(s) awaiting a draw.io export:")
        for b in pending:
            print("    " + b)
    # An export that predates its own .drawio shows the reader a picture the
    # source no longer draws. That is worse than a missing figure, because
    # nothing about it looks wrong.
    import hashlib, json
    manifest = Path("writing/figures/diagrams/exported-from.json")
    recorded = json.loads(manifest.read_text(encoding="utf-8")) if manifest.exists() else {}
    stale = []
    for m in refs:
        if not m.startswith("diagrams/"):
            continue
        png = Path("writing/figures") / m
        src = Path("writing/diagrams/drawio") / (Path(m).stem + ".drawio")
        if not (png.exists() and src.exists()):
            continue
        # compare what the source *draws*, not when it was touched: splitting or
        # reformatting a .drawio bumps its clock without changing the picture
        now = hashlib.sha256(src.read_bytes()).hexdigest()[:16]
        was = recorded.get(png.stem)
        if was is None or was != now:
            stale.append(m)
    if stale:
        print(f"  {len(stale)} export(s) older than the diagram they came from:")
        for b in sorted(stale):
            print("    " + b + "   -- re-export this one")

    if broken:
        print("  BROKEN IMAGE PATHS:")
        for b in sorted(set(broken)):
            print("    " + b)
        raise SystemExit(1)
    if not pending:
        print("  all image paths resolve")


if __name__ == "__main__":
    main()
