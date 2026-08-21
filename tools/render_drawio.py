"""Render .drawio files to PNG.

There is no headless draw.io on this machine, and the report needs the eleven
structural diagrams as images. The .drawio files are mxGraph XML and carry every
coordinate, so they can be drawn directly. That is what this does: parse the
geometry and the style strings, then draw with matplotlib in the same visual
language as the report's plotted figures.

Rendering the *files* rather than the generator's spec matters, because a diagram
that has been tidied by hand in draw.io keeps those edits.

Supported: rectangles and rounded rectangles, rhombus (decision), ellipse,
cylinder (data store), UML actor, notes, dashed group containers, plain lines,
and orthogonal edges with optional exit/entry anchors, arrowheads, dashes and
labels. That is everything these particular diagrams use; anything unrecognised
falls back to a plain rectangle rather than vanishing.

Run:  python -m tools.render_drawio        -> writing/figures/diagrams/*.png
"""
from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, FancyBboxPatch, Polygon, Rectangle

SRC = Path("writing/diagrams/drawio")
OUT = Path("writing/figures/diagrams")

FONT = "DejaVu Sans"
DPI = 220
SCALE = 0.013          # mxGraph units -> inches


# ------------------------------------------------------------------ style ----
def style_dict(style: str) -> dict:
    out = {}
    for part in (style or "").split(";"):
        if not part:
            continue
        k, _, v = part.partition("=")
        out[k.strip()] = v.strip()
    return out


def _colour(v: str | None, default: str) -> str:
    if not v or v.lower() == "none":
        return "none"
    return v if v.startswith("#") else default


def clean(label: str) -> str:
    """mxGraph labels carry HTML; reduce it to plain text with line breaks."""
    t = re.sub(r"<br\s*/?>", "\n", label or "")
    t = re.sub(r"<[^>]+>", "", t)
    return html.unescape(t).strip()


def _offset_y(geom) -> float:
    """How far an edge label is lifted off its line, in pixels."""
    if geom is None:
        return 0.0
    pt = geom.find("mxPoint[@as='offset']")
    return float(pt.get("y", 0) or 0) if pt is not None else 0.0


# ------------------------------------------------------------------- read ----
def read(path: Path) -> tuple[list[dict], list[dict]]:
    root = ET.parse(path).getroot()
    model = root.find("diagram/mxGraphModel/root")
    cells = model.findall("mxCell")

    nodes, edges = {}, []
    for c in cells:
        g = c.find("mxGeometry")
        st = style_dict(c.get("style"))
        if c.get("vertex") == "1" and g is not None:
            nodes[c.get("id")] = {
                "id": c.get("id"), "label": clean(c.get("value")), "style": st,
                "x": float(g.get("x", 0)), "y": float(g.get("y", 0)),
                "w": float(g.get("width", 0)), "h": float(g.get("height", 0)),
                "parent": c.get("parent"),
            }
        elif c.get("edge") == "1":
            eg = c.find("mxGeometry")
            edges.append({"src": c.get("source"), "dst": c.get("target"),
                          "label": clean(c.get("value")), "style": st,
                          # where along the route the label sits: draw.io
                          # stores -1 at the source, 0 mid, +1 at the target
                          "label_at": float(eg.get("x", 0) or 0)
                          if eg is not None else 0.0,
                          "label_dy": _offset_y(eg)})

    # children of a swimlane are positioned relative to it
    for n in nodes.values():
        p = nodes.get(n["parent"])
        if p is not None:
            n["x"] += p["x"]
            n["y"] += p["y"]
    return list(nodes.values()), edges


# ------------------------------------------------------------------ shapes ---
def draw_node(ax, n: dict) -> None:
    st, x, y, w, h = n["style"], n["x"], n["y"], n["w"], n["h"]
    fill = _colour(st.get("fillColor"), "#dae8fc")
    edge = _colour(st.get("strokeColor"), "#6c8ebf")
    dashed = st.get("dashed") == "1"
    ls = (0, (4, 3)) if dashed else "solid"
    shape = st.get("shape", "")
    cy = -(y + h / 2)

    if shape.startswith("umlActor"):
        r = min(w, h) * 0.22
        ax.add_patch(Ellipse((x + w / 2, -(y + r)), r * 2, r * 2,
                             facecolor="white", edgecolor=edge, lw=1.2, zorder=3))
        ax.plot([x + w / 2, x + w / 2], [-(y + 2 * r), -(y + h * 0.72)],
                color=edge, lw=1.2, zorder=3)
        ax.plot([x, x + w], [-(y + h * 0.45), -(y + h * 0.45)],
                color=edge, lw=1.2, zorder=3)
        ax.plot([x + w / 2, x], [-(y + h * 0.72), -(y + h)], color=edge, lw=1.2, zorder=3)
        ax.plot([x + w / 2, x + w], [-(y + h * 0.72), -(y + h)], color=edge, lw=1.2, zorder=3)
        if n["label"]:
            ax.text(x + w / 2, -(y + h + 12), n["label"], ha="center", va="top",
                    fontsize=7.4, family=FONT, zorder=6)
        return

    if shape.startswith("cylinder"):
        ax.add_patch(FancyBboxPatch((x, -(y + h) + 6), w, h - 12,
                                    boxstyle="round,pad=0,rounding_size=6",
                                    facecolor=fill, edgecolor=edge, lw=1.1, zorder=2))
        for yy in (-(y) - 6, -(y + h) + 6):
            ax.add_patch(Ellipse((x + w / 2, yy), w, 12, facecolor=fill,
                                 edgecolor=edge, lw=1.1, zorder=3))
    elif st.get("rhombus") == "" or "rhombus" in (n["style"].get("shape", "") or "") \
            or "rhombus" in str(st.keys()) or st.get("__rhombus__"):
        pass
    elif "ellipse" in st:
        ax.add_patch(Ellipse((x + w / 2, cy), w, h, facecolor=fill,
                             edgecolor=edge, lw=1.1, ls=ls, zorder=2))
    elif st.get("rounded") == "1":
        ax.add_patch(FancyBboxPatch((x + 6, -(y + h) + 6), w - 12, h - 12,
                                    boxstyle="round,pad=0,rounding_size=8",
                                    facecolor=fill, edgecolor=edge, lw=1.1,
                                    ls=ls, zorder=2))
    else:
        ax.add_patch(Rectangle((x, -(y + h)), w, h, facecolor=fill,
                               edgecolor=edge, lw=1.1, ls=ls, zorder=2))

    if n["label"]:
        va = "top" if st.get("verticalAlign") == "top" else "center"
        ty = -(y + 8) if va == "top" else cy
        ha = {"left": "left", "right": "right"}.get(st.get("align", "center"), "center")
        tx = x + 8 if ha == "left" else (x + w - 8 if ha == "right" else x + w / 2)
        size = float(st.get("fontSize", 12)) * 0.62
        ax.text(tx, ty, n["label"], ha=ha, va=va, fontsize=size, family=FONT,
                zorder=6, linespacing=1.35,
                fontweight="bold" if st.get("fontStyle") in ("1", "3") else "normal")


def draw_rhombus(ax, n: dict) -> None:
    st, x, y, w, h = n["style"], n["x"], n["y"], n["w"], n["h"]
    fill = _colour(st.get("fillColor"), "#ffe6cc")
    edge = _colour(st.get("strokeColor"), "#d79b00")
    cx, cy = x + w / 2, -(y + h / 2)
    ax.add_patch(Polygon([(cx, -y), (x + w, cy), (cx, -(y + h)), (x, cy)],
                         closed=True, facecolor=fill, edgecolor=edge, lw=1.1, zorder=2))
    if n["label"]:
        ax.text(cx, cy, n["label"], ha="center", va="center",
                fontsize=float(st.get("fontSize", 11)) * 0.60, family=FONT,
                zorder=6, linespacing=1.3)


def anchor(n: dict, ax_: float | None, ay: float | None,
           other: dict) -> tuple[float, float]:
    """Edge attachment point: an explicit anchor, else the nearest side."""
    if ax_ is not None and ay is not None:
        return n["x"] + ax_ * n["w"], -(n["y"] + ay * n["h"])
    ncx, ncy = n["x"] + n["w"] / 2, -(n["y"] + n["h"] / 2)
    ocx, ocy = other["x"] + other["w"] / 2, -(other["y"] + other["h"] / 2)
    if abs(ocx - ncx) > abs(ocy - ncy):
        return (n["x"] + n["w"], ncy) if ocx > ncx else (n["x"], ncy)
    return (ncx, -(n["y"] + n["h"])) if ocy < ncy else (ncx, -n["y"])


def draw_edge(ax, e: dict, byid: dict) -> None:
    s, t = byid.get(e["src"]), byid.get(e["dst"])
    if not s or not t:
        return
    st = e["style"]
    ex = float(st["exitX"]) if "exitX" in st else None
    ey = float(st["exitY"]) if "exitY" in st else None
    nx = float(st["entryX"]) if "entryX" in st else None
    ny = float(st["entryY"]) if "entryY" in st else None
    x1, y1 = anchor(s, ex, ey, t)
    x2, y2 = anchor(t, nx, ny, s)

    colour = _colour(st.get("strokeColor"), "#4d4d4d")
    dashed = st.get("dashed") == "1"
    ls = (0, (5, 4)) if dashed else "solid"

    # orthogonal route: leave along the axis the anchor implies
    horiz_exit = ex in (0.0, 1.0)
    if abs(x1 - x2) < 1 or abs(y1 - y2) < 1:
        pts = [(x1, y1), (x2, y2)]
    elif horiz_exit:
        mx = (x1 + x2) / 2
        pts = [(x1, y1), (mx, y1), (mx, y2), (x2, y2)]
    else:
        my = (y1 + y2) / 2
        pts = [(x1, y1), (x1, my), (x2, my), (x2, y2)]

    ax.plot([p[0] for p in pts], [p[1] for p in pts], color=colour,
            lw=1.15, ls=ls, zorder=1, solid_capstyle="round")

    if st.get("endArrow") != "none":
        (px, py), (qx, qy) = pts[-2], pts[-1]
        ax.annotate("", xy=(qx, qy), xytext=(px, py),
                    arrowprops=dict(arrowstyle="-|>", color=colour, lw=1.1,
                                    shrinkA=0, shrinkB=0), zorder=4)

    if e["label"]:
        mid = pts[len(pts) // 2]
        ax.text(mid[0], mid[1] + 7, e["label"], ha="center", va="bottom",
                fontsize=float(st.get("fontSize", 10)) * 0.60, family=FONT,
                color="#333333", zorder=7, linespacing=1.25,
                bbox=dict(boxstyle="round,pad=0.18", fc="white", ec="none", alpha=0.88))


# ------------------------------------------------------------------ render ---
def render(path: Path, out: Path) -> None:
    nodes, edges = read(path)
    if not nodes:
        return
    byid = {n["id"]: n for n in nodes}

    xs = [n["x"] for n in nodes] + [n["x"] + n["w"] for n in nodes]
    ys = [-(n["y"]) for n in nodes] + [-(n["y"] + n["h"]) for n in nodes]
    pad = 46
    W, H = (max(xs) - min(xs) + 2 * pad), (max(ys) - min(ys) + 2 * pad)

    fig, ax = plt.subplots(figsize=(W * SCALE, H * SCALE))
    ax.set_xlim(min(xs) - pad, max(xs) + pad)
    ax.set_ylim(min(ys) - pad, max(ys) + pad)
    ax.set_aspect("equal"); ax.axis("off")
    fig.patch.set_facecolor("white")

    # containers first, then edges, then the rest, so nothing is buried
    groups = [n for n in nodes if n["style"].get("fillColor") == "none"
              and n["w"] > 300 and n["h"] > 150]
    for n in groups:
        draw_node(ax, n)
    for e in edges:
        draw_edge(ax, e, byid)
    for n in nodes:
        if n in groups:
            continue
        if "rhombus" in (n["style"].get("shape", "") or "") or n["style"].get("rhombus") == "":
            draw_rhombus(ax, n)
        else:
            draw_node(ax, n)

    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=DPI, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  {out.name}  ({W:.0f}x{H:.0f} units)")


def main() -> None:
    files = sorted(p for p in SRC.glob("*.drawio") if not p.name.startswith("ALL"))
    if not files:
        raise SystemExit(f"no .drawio files under {SRC}")
    for f in files:
        render(f, OUT / f"{f.stem}.png")
    print(f"\n  {len(files)} diagram(s) rendered to {OUT}")


if __name__ == "__main__":
    main()
