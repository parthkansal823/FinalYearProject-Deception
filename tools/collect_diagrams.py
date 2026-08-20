"""File draw.io exports from the Downloads folder into the report.

Exporting eleven diagrams from the draw.io web app means eleven files landing in
Downloads, each of which then has to be copied to the right place under two
different names. This does that step, and fixes the one export setting that
matters and is easy to leave wrong.

  *.png     -> writing/figures/diagrams/   (flattened onto white first)
  *.drawio  -> writing/diagrams/drawio/    (so the edited source is kept)

**Why the flattening.** draw.io defaults to "Transparent Background". A
transparent PNG is fine on a web page and unreliable in Word, where it picks up
whatever sits behind it -- usually white, sometimes grey, and on some printers
black. The report is printed on white paper, so the alpha channel is composited
onto white here rather than left to chance.

Only files whose names match a known diagram are touched, so nothing else in
Downloads is moved.

Run:  python -m tools.collect_diagrams            (dry run: lists what it would do)
      python -m tools.collect_diagrams --apply
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

DOWNLOADS = Path.home() / "Downloads"
PNG_OUT = Path("writing/figures/diagrams")
SRC_OUT = Path("writing/diagrams/drawio")

MIN_WIDTH_PX = 1800          # 6 inches at 300 dpi, the report's image width


def known() -> set[str]:
    return {p.stem for p in SRC_OUT.glob("*.drawio") if not p.name.startswith("ALL")}


def flatten(src: Path, dst: Path) -> tuple[int, int, bool]:
    from PIL import Image
    im = Image.open(src)
    w, h = im.size
    had_alpha = im.mode in ("RGBA", "LA") or "transparency" in im.info
    if had_alpha:
        bg = Image.new("RGB", im.size, (255, 255, 255))
        bg.paste(im.convert("RGBA"), mask=im.convert("RGBA").split()[-1])
        im = bg
    else:
        im = im.convert("RGB")
    dst.parent.mkdir(parents=True, exist_ok=True)
    im.save(dst, "PNG", optimize=True)
    return w, h, had_alpha


def main() -> None:
    apply = "--apply" in sys.argv
    names = known()
    if not names:
        raise SystemExit(f"no .drawio sources under {SRC_OUT}")

    found = 0
    sources = 0
    for f in sorted(DOWNLOADS.glob("*")):
        if f.stem not in names:
            continue
        if f.suffix.lower() == ".png":
            dst = PNG_OUT / f"{f.stem}.png"
            if apply:
                w, h, alpha = flatten(f, dst)
                note = "flattened onto white" if alpha else "already opaque"
                warn = "  <-- LOW RESOLUTION" if w < MIN_WIDTH_PX else ""
                print(f"  {f.name:44s} -> {dst}  ({w}x{h}, {note}){warn}")
            else:
                print(f"  would file image:  {f.name}  -> {dst}")
            found += 1
        elif f.suffix.lower() == ".drawio":
            dst = SRC_OUT / f"{f.stem}.drawio"
            if apply:
                shutil.copy2(f, dst)
                sources += 1
                print(f"  {f.name:44s} -> {dst}")
            else:
                print(f"  would file source: {f.name}  -> {dst}")
            found += 1

    if not found:
        print(f"  nothing matching a known diagram found in {DOWNLOADS}")
        return
    if not apply:
        print("\n  dry run. re-run with --apply to move them.")
    else:
        if sources:
            # keep the multi-tab file in step with the sources it mirrors,
            # otherwise opening it would hand back a pre-edit copy
            from tools.make_drawio import rebuild_combined
            rebuild_combined()
        have = sorted(p.stem for p in PNG_OUT.glob("*.png"))
        missing = sorted(names - set(have))
        print(f"\n  exported so far: {len(have)} of {len(names)}")
        if missing:
            print("  still to export:")
            for m in missing:
                print("    " + m)
        else:
            print("  all diagrams present -- rebuild with:")
            print("    python -m tools.build_report && python -m tools.make_docx")


if __name__ == "__main__":
    main()
