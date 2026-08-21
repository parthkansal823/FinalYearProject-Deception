"""Find layout faults in the .drawio diagrams by measuring them.

There is no headless draw.io here, so a diagram cannot be looked at without
exporting it by hand -- which means layout bugs are found late, one export at a
time. But the faults that make these diagrams hard to read are all geometric,
and the geometry is right there in the file:

  overlap     two boxes sitting on top of each other
  escape      a box hanging outside the group container it belongs to
  overflow    a label with more text than its box can hold
  crossing    an edge routed straight through a box it does not connect to
  detour      an edge that travels most of the way across the page to get
              somewhere close, which is what produces the long wandering lines

Each of those is measurable, so this measures them and prints what to fix.

Run:  python -m tools.lint_diagrams              (all diagrams)
      python -m tools.lint_diagrams fig11        (one, by name fragment)
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

from tools.render_drawio import read

SRC = Path("writing/diagrams/drawio")

CHAR_W = 0.55          # mean glyph width as a fraction of font size
LINE_H = 1.32          # line spacing draw.io applies to wrapped labels
PAD = 16               # horizontal padding inside a box before text wraps
DETOUR = 2.6           # route length over straight-line distance before it is a detour
MIN_SPAN = 140         # ignore detours on edges this short; they are just jogs


# ------------------------------------------------------------------ helpers --
def is_container(n: dict) -> bool:
    """A group box drawn around other things, not a thing in its own right.

    Matched on the style every group shares -- no fill, label pinned to the
    top -- rather than on size. Guessing from size got the short wide layer
    bands in fig11 wrong, and then every box inside a band read as an overlap
    and every edge entering one read as a crossing. Dashes are not part of the
    test: fig16's UML system boundary is drawn solid, as that notation asks.
    """
    st = n["style"]
    return (st.get("fillColor", "").lower() == "none"
            and st.get("verticalAlign") == "top")


def is_rule(n: dict) -> bool:
    """A lifeline or divider: a rectangle too thin to hold anything."""
    return n["w"] < 24 or n["h"] < 24


def rect(n: dict) -> tuple[float, float, float, float]:
    return n["x"], n["y"], n["x"] + n["w"], n["y"] + n["h"]


def overlap_area(a: dict, b: dict) -> float:
    ax1, ay1, ax2, ay2 = rect(a)
    bx1, by1, bx2, by2 = rect(b)
    dx = min(ax2, bx2) - max(ax1, bx1)
    dy = min(ay2, by2) - max(ay1, by1)
    return dx * dy if dx > 0 and dy > 0 else 0.0


def label_lines(n: dict) -> int:
    """How many lines the label needs at this box width."""
    text = n["label"]
    if not text:
        return 0
    size = float(n["style"].get("fontSize", 12))
    per_line = max(1, int((n["w"] - PAD) / (size * CHAR_W)))
    lines = 0
    for para in text.split("\n"):
        lines += max(1, math.ceil(len(para) / per_line))
    return lines


def anchors(e: dict, byid: dict) -> tuple | None:
    """Start and end points of an edge, honouring explicit exit/entry sides."""
    s, t = byid.get(e["src"]), byid.get(e["dst"])
    if not s or not t:
        return None
    st = e["style"]

    def point(n: dict, ax: str, ay: str, other: dict):
        if ax in st and ay in st:
            return n["x"] + float(st[ax]) * n["w"], n["y"] + float(st[ay]) * n["h"]
        ncx, ncy = n["x"] + n["w"] / 2, n["y"] + n["h"] / 2
        ocx, ocy = other["x"] + other["w"] / 2, other["y"] + other["h"] / 2
        if abs(ocx - ncx) > abs(ocy - ncy):
            return (n["x"] + n["w"], ncy) if ocx > ncx else (n["x"], ncy)
        return (ncx, n["y"] + n["h"]) if ocy > ncy else (ncx, n["y"])

    return (point(s, "exitX", "exitY", t), point(t, "entryX", "entryY", s), s, t)


def segments(p1: tuple, p2: tuple) -> list[tuple]:
    """The orthogonal route draw.io draws between two anchor points."""
    (x1, y1), (x2, y2) = p1, p2
    if abs(x1 - x2) < 1 or abs(y1 - y2) < 1:
        return [(x1, y1, x2, y2)]
    my = (y1 + y2) / 2
    return [(x1, y1, x1, my), (x1, my, x2, my), (x2, my, x2, y2)]


def seg_hits_box(seg: tuple, n: dict) -> bool:
    x1, y1, x2, y2 = seg
    bx1, by1, bx2, by2 = rect(n)
    bx1, by1, bx2, by2 = bx1 + 4, by1 + 4, bx2 - 4, by2 - 4     # ignore grazing
    if bx2 <= bx1 or by2 <= by1:
        return False
    if abs(x1 - x2) < 1:                                        # vertical
        return bx1 < x1 < bx2 and max(by1, min(y1, y2)) < min(by2, max(y1, y2))
    if abs(y1 - y2) < 1:                                        # horizontal
        return by1 < y1 < by2 and max(bx1, min(x1, x2)) < min(bx2, max(x1, x2))
    return False


def point_at(route: list[tuple], at: float) -> tuple[float, float]:
    """The point a fraction along an orthogonal route.

    draw.io measures an edge label's position from -1 at the source through 0
    at the midpoint to +1 at the target, so that is the scale used here.
    """
    frac = min(max((at + 1) / 2, 0.0), 1.0)
    lengths = [math.hypot(x2 - x1, y2 - y1) for x1, y1, x2, y2 in route]
    total = sum(lengths) or 1.0
    want = frac * total
    for (x1, y1, x2, y2), seg in zip(route, lengths):
        if want <= seg or seg == 0:
            t = (want / seg) if seg else 0.0
            return x1 + (x2 - x1) * t, y1 + (y2 - y1) * t
        want -= seg
    return route[-1][2], route[-1][3]


def _clash_at(route, at, lw, lh, dy, solid) -> bool:
    """Whether a label of this size collides once lifted dy off the line."""
    x, y = point_at(route, at)
    box = {"x": x - lw / 2, "y": y + dy - lh / 2, "w": lw, "h": lh}
    return any(overlap_area(box, n) > lw * lh * 0.3 for n in solid)


# -------------------------------------------------------------------- lint ---
def lint(path: Path) -> list[dict]:
    nodes, edges = read(path)
    if not nodes:
        return [{"kind": "empty", "msg": f"{path.name}: no nodes"}]
    byid = {n["id"]: n for n in nodes}
    boxes = [n for n in nodes if not is_container(n)]
    solid = [n for n in boxes if not is_rule(n)]      # overlap ignores lifelines
    groups = [n for n in nodes if is_container(n)]
    faults: list[str] = []

    # --- overlap ----------------------------------------------------------
    for i, a in enumerate(solid):
        for b in solid[i + 1:]:
            if a["parent"] == b["id"] or b["parent"] == a["id"]:
                continue
            area = overlap_area(a, b)
            if area > 60:
                faults.append({"kind": "overlap", "id": a["id"],
                    "msg": f"overlap   {a['label'][:26]!r} and {b['label'][:26]!r} "
                           f"share {area:.0f} sq units"})

    # --- escape -----------------------------------------------------------
    for g in groups:
        gx1, gy1, gx2, gy2 = rect(g)
        for n in solid:
            if overlap_area(n, g) <= 0:
                continue
            x1, y1, x2, y2 = rect(n)
            out = max(gx1 - x1, 0) + max(x2 - gx2, 0) + max(gy1 - y1, 0) + max(y2 - gy2, 0)
            if out > 6:
                faults.append({"kind": "escape", "id": n["id"],
                    "msg": f"escape    {n['label'][:26]!r} sticks {out:.0f} units "
                           f"out of {g['label'][:26]!r}"})

    # --- overflow ---------------------------------------------------------
    for n in boxes:
        # an actor's name is drawn under the stick figure, not inside it
        if n["style"].get("shape", "").startswith("umlActor"):
            continue
        lines = label_lines(n)
        if not lines:
            continue
        size = float(n["style"].get("fontSize", 12))
        # A single-line label sits happily in a tight row -- a class-diagram
        # attribute is 20 units by design. Only wrapped text needs breathing
        # room, so the padding is charged per extra line, not per box.
        need = lines * size * LINE_H + (0 if lines == 1 else 8)
        if need > n["h"] + 2:
            faults.append({"kind": "overflow", "id": n["id"], "height": need,
                "msg": f"overflow  {n['label'][:26]!r} needs ~{need:.0f} units of "
                       f"height, box is {n['h']:.0f}"})

    # --- crossing and detour ----------------------------------------------
    xs = [n["x"] for n in nodes] + [n["x"] + n["w"] for n in nodes]
    ys = [n["y"] for n in nodes] + [n["y"] + n["h"] for n in nodes]
    diag = math.hypot(max(xs) - min(xs), max(ys) - min(ys))

    for e in edges:
        a = anchors(e, byid)
        if not a:
            continue
        p1, p2, s, t = a
        route = segments(p1, p2)
        straight = math.hypot(p2[0] - p1[0], p2[1] - p1[1])
        length = sum(math.hypot(x2 - x1, y2 - y1) for x1, y1, x2, y2 in route)

        for n in solid:
            if n["id"] in (s["id"], t["id"]):
                continue
            if any(seg_hits_box(seg, n) for seg in route):
                faults.append({"kind": "crossing", "id": e.get("id"),
                    "msg": f"crossing  {s['label'][:20]!r} -> {t['label'][:20]!r} "
                           f"runs through {n['label'][:24]!r}"})
                break

        # an edge label is drawn at the midpoint of its route; if a box is
        # already there the two print on top of each other
        if e["label"]:
            size = float(e["style"].get("fontSize", 10))
            lw = len(e["label"]) * size * CHAR_W
            lh = size * LINE_H

            dy = e.get("label_dy", 0.0)

            def clash(at: float):
                x, y = point_at(route, at)
                box = {"x": x - lw / 2, "y": y + dy - lh / 2, "w": lw, "h": lh}
                for n in solid:
                    if overlap_area(box, n) > lw * lh * 0.3:
                        return n
                return None

            here = e.get("label_at", 0.0)
            hit = clash(here)
            if hit is not None:
                # a label can slide along its own route; report where it fits
                free = [c for c in (-0.75, -0.5, -0.25, 0.25, 0.5, 0.75)
                        if clash(c) is None]
                if free:
                    fix = f"  -- try label_at={free[0]:g}"
                else:
                    # nowhere along the line is clear, so lift it off instead
                    lift = next((d for d in (-34, -44, -54, 34, 44)
                                 if not _clash_at(route, here, lw, lh, d, solid)), None)
                    fix = (f"  -- try label_dy={lift}" if lift
                           else "  -- no clear spot; shorten it or open the gap")
                faults.append({"kind": "label", "id": e.get("id"),
                    "label_at": free[0] if free else None,
                    "label_dy": None if free else lift,
                    "msg": f"label     {e['label'][:24]!r} prints over "
                           f"{hit['label'][:24]!r}{fix}"})

        if straight > MIN_SPAN and length > straight * DETOUR:
            faults.append({"kind": "detour", "id": e.get("id"),
                "msg": f"detour    {s['label'][:20]!r} -> {t['label'][:20]!r} "
                       f"travels {length:.0f} to span {straight:.0f} "
                       f"({length / diag:.0%} of the page)"})

    return faults


def main() -> None:
    want = [a for a in sys.argv[1:] if not a.startswith("-")]
    files = sorted(p for p in SRC.glob("*.drawio") if not p.name.startswith("ALL"))
    if want:
        files = [p for p in files if any(w in p.name for w in want)]
    if not files:
        raise SystemExit("no matching diagrams")

    total = 0
    for f in files:
        faults = lint(f)
        total += len(faults)
        mark = "clean" if not faults else f"{len(faults)} fault(s)"
        print(f"\n  {f.stem}  --  {mark}")
        for x in faults:
            print(f"      {x['msg']}")
    print(f"\n  {total} fault(s) across {len(files)} diagram(s)")


if __name__ == "__main__":
    main()
