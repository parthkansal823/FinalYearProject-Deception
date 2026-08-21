"""Write each tab of ALL-diagrams.drawio back to its own diagram file.

`ALL-diagrams.drawio` is the convenient file to work in -- eleven tabs in one
window rather than eleven windows -- but it is a *generated* mirror of the
per-figure files, and the report exports from those. So work done in the
combined file has to travel back out again, or the next rebuild discards it.

This is the inverse of `make_drawio.rebuild_combined`: it reads the combined
file, matches each tab to a figure, and writes that tab out as a standalone
diagram. Tabs are matched by name, so reordering them in draw.io is harmless;
a tab whose name is not recognised is reported rather than guessed at.

Nothing is written unless the combined file parses and every tab has somewhere
to go, so a half-finished split cannot leave the sources in a mixed state.

Run:  python -m tools.split_combined            (dry run: what would change)
      python -m tools.split_combined --apply
"""
from __future__ import annotations

import hashlib
import sys
import xml.etree.ElementTree as ET
from html import escape
from pathlib import Path

from tools.drawio import render
from tools.make_drawio import FIGURES, OUT

COMBINED = OUT / "ALL-diagrams.drawio"


def _title_map() -> dict[str, str]:
    """Diagram title as shown on a tab -> the file it belongs in."""
    return {fn().name: name for name, fn in FIGURES.items()}


def _page_xml(page: ET.Element, title: str) -> str:
    """One tab rendered as a complete, standalone .drawio file."""
    inner = "".join(ET.tostring(c, encoding="unicode") for c in page)
    page_id = int(hashlib.md5(title.encode()).hexdigest()[:8], 16)
    return ('<mxfile host="app.diagrams.net" type="device">\n'
            f'  <diagram name="{escape(title)}" id="{page_id}">\n'
            f'{inner}\n'
            '  </diagram>\n'
            '</mxfile>\n')


def main() -> None:
    apply = "--apply" in sys.argv
    if not COMBINED.exists():
        raise SystemExit(f"{COMBINED} does not exist")

    try:
        pages = ET.parse(COMBINED).getroot().findall("diagram")
    except ET.ParseError as e:
        raise SystemExit(f"{COMBINED} is not valid XML: {e}")
    if not pages:
        raise SystemExit(f"{COMBINED} holds no diagrams")

    titles = _title_map()
    unknown = [p.get("name") for p in pages if p.get("name") not in titles]
    if unknown:
        print("  these tabs do not match any known figure:")
        for u in unknown:
            print(f"    {u!r}")
        raise SystemExit("  rename them to the figure titles, or split by hand")

    planned = []
    for page in pages:
        title = page.get("name")
        name = titles[title]
        target = OUT / f"{name}.drawio"
        new = _page_xml(page, title)
        old = target.read_text(encoding="utf-8") if target.exists() else ""
        gen = render(FIGURES[name]())
        # three states worth telling apart: unchanged, changed by hand in the
        # combined file, and still exactly what the generator last produced
        if old == new:
            state = "unchanged"
        elif old == gen:
            state = "takes an edit from the combined file"
        else:
            state = "differs from BOTH the file and the generator"
        planned.append((name, target, new, state))

    for name, _, _, state in planned:
        print(f"  {name:34s} {state}")

    if not apply:
        print("\n  dry run. re-run with --apply to write these back.")
        return

    written = 0
    for name, target, new, state in planned:
        if state == "unchanged":
            continue
        target.write_text(new, encoding="utf-8")
        written += 1
        print(f"  wrote {target}")
    print(f"\n  {written} diagram file(s) updated from {COMBINED.name}")
    if written:
        print("  now check them:  python -m tools.lint_diagrams")


if __name__ == "__main__":
    main()
