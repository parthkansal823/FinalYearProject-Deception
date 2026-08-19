"""Concatenate the chapter files in `docs/report/` into one document.

The report is written as separate chapter files because they are easier to edit
and review that way, but what gets handed in is a single document. Rather than
maintaining two copies -- which drift, and drift silently -- the combined file is
generated from the chapters and carries a header saying so.

Two things need fixing during the join:

  * image paths. The chapters live in `docs/report/` and reference `../img/x.svg`;
    the combined file lives in `docs/` and needs `img/x.svg`.
  * page breaks. Chapters should start on a fresh page in the word processor, so
    an explicit break is inserted between them. The HTML form is what Word honours
    on paste; pandoc users can swap it for `\\newpage`.

Run:  python -m tools.build_report
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path("docs/report")
OUT = Path("docs/PROJECT_REPORT.md")

#: Chapter files in document order. README.md is the assembly guide, not content.
ORDER = [
    "00-front-matter.md",
    "01-introduction.md",
    "02-literature-survey.md",
    "03-design-flow-part1.md",
    "03-design-flow-part2.md",
    "04-results.md",
    "05-conclusion.md",
]

PAGE_BREAK = '\n<div style="page-break-after: always;"></div>\n'

HEADER = """<!--
  GENERATED FILE -- do not edit directly.

  This document is built from the chapter files in docs/report/ by:

      python -m tools.build_report

  Edit the chapter files, then regenerate. Editing this file directly means the
  next regeneration silently discards the change.

  Before submission see docs/report/README.md: placeholders to fill, references
  [44]-[60] to confirm against publisher records, table-of-contents page numbers
  to regenerate, and eight Mermaid diagrams to render.
-->

"""


def build() -> str:
    missing = [n for n in ORDER if not (SRC / n).exists()]
    if missing:
        raise SystemExit("missing chapter file(s): " + ", ".join(missing))

    parts = []
    for i, name in enumerate(ORDER):
        text = (SRC / name).read_text(encoding="utf-8")

        # docs/report/x.md -> docs/PROJECT_REPORT.md changes the depth by one.
        text = re.sub(r"\]\(\.\./img/", "](img/", text)
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
    figs = len(re.findall(r"\*\*Figure\s+\d+\s*[—-]", doc))
    tabs = len(re.findall(r"\*\*Table\s+\d+\s*[—-]", doc))
    imgs = len(re.findall(r"!\[[^\]]*\]\(img/", doc))
    mer = doc.count("```mermaid")

    broken = [m for m in re.findall(r"!\[[^\]]*\]\((img/[^)]+)\)", doc)
              if not (Path("docs") / m).exists()]

    print(f"  wrote {OUT}")
    print(f"  {words:,} words | {tabs} numbered tables | {figs} numbered figures")
    print(f"  {imgs} image references | {mer} Mermaid diagrams to render")
    if broken:
        print("  BROKEN IMAGE PATHS:")
        for b in sorted(set(broken)):
            print("    " + b)
        raise SystemExit(1)
    print("  all image paths resolve")


if __name__ == "__main__":
    main()
