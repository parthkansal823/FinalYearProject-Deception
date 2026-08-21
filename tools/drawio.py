"""A small mxGraph (draw.io) emitter.

The report's structural diagrams were first written in Mermaid, which is fine for
review but gives no control over routing or spacing -- the results were cramped and
the edges crossed. draw.io files are editable by hand, so this module emits native
`.drawio` XML with explicit coordinates and orthogonal edge routing. The layout is
computed from a layer specification rather than hand-placed, so a diagram can be
restructured without moving every box.

Nothing here is specific to this project; the diagram content lives in
`tools/make_drawio.py`.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from html import escape
from pathlib import Path


# ---------------------------------------------------------------- styles ----
# draw.io style strings. Kept as named constants so a diagram reads as content
# rather than as a wall of semicolons.
BASE = "rounded=0;whiteSpace=wrap;html=1;fontFamily=Georgia;fontSize=12;"
ROUND = "rounded=1;whiteSpace=wrap;html=1;fontFamily=Georgia;fontSize=12;arcSize=12;"

S_PROCESS = ROUND + "fillColor=#dae8fc;strokeColor=#6c8ebf;"
S_DECISION = ("rhombus;whiteSpace=wrap;html=1;fontFamily=Georgia;fontSize=11;"
              "fillColor=#ffe6cc;strokeColor=#d79b00;")
S_TERMINAL = ("rounded=1;whiteSpace=wrap;html=1;fontFamily=Georgia;fontSize=12;"
              "arcSize=50;fillColor=#d5e8d4;strokeColor=#82b366;")
S_DATA = ("shape=cylinder3;boundedLbl=1;backgroundOutline=1;size=8;whiteSpace=wrap;"
          "html=1;fontFamily=Georgia;fontSize=11;fillColor=#ffe6cc;strokeColor=#d79b00;")
S_EXTERNAL = BASE + "fillColor=#f5f5f5;strokeColor=#666666;"
S_ACCENT = ROUND + "fillColor=#d5e8d4;strokeColor=#82b366;"
S_WARN = ROUND + "fillColor=#f8cecc;strokeColor=#b85450;"
S_NOTE = ("shape=note;whiteSpace=wrap;html=1;fontFamily=Georgia;fontSize=10;size=14;"
          "fillColor=#fff2cc;strokeColor=#d6b656;align=left;verticalAlign=top;"
          "spacingLeft=6;spacingTop=2;")
S_GROUP = ("rounded=0;whiteSpace=wrap;html=1;fontFamily=Georgia;fontSize=12;"
           "fillColor=none;strokeColor=#9aa0a6;dashed=1;verticalAlign=top;"
           "align=left;spacingLeft=8;spacingTop=2;fontStyle=2;")
S_CIRCLE = ("ellipse;whiteSpace=wrap;html=1;fontFamily=Georgia;fontSize=11;"
            "fillColor=#dae8fc;strokeColor=#6c8ebf;")
S_ACTOR = ("shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;"
           "html=1;outlineConnect=0;fontFamily=Georgia;fontSize=11;")

E_ORTH = ("edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;jumpStyle=arc;jumpSize=8;"
          "fontFamily=Georgia;fontSize=10;strokeColor=#4d4d4d;endArrow=blockThin;"
          "endFill=1;labelBackgroundColor=#ffffff;")   # labels land on routes; keep
                                              # them readable wherever they fall
E_DASH = E_ORTH + "dashed=1;"
E_NONE = E_ORTH + "endArrow=none;"


def restyle(style: str, **kw) -> str:
    """Return `style` with each keyword set, replacing any existing value.

    Appending `fontSize=13` to a style that already says `fontSize=10` happens to
    work -- draw.io takes the last occurrence -- but it leaves two contradictory
    values in the file, which is confusing to anyone editing it by hand. This
    replaces in place instead.
    """
    for k, v in kw.items():
        pat = re.compile(rf"(^|;){re.escape(k)}=[^;]*;")
        if pat.search(style):
            style = pat.sub(rf"\g<1>{k}={v};", style, count=1)
        else:
            style = style.rstrip(";") + f";{k}={v};"
    return style


@dataclass
class Node:
    id: str
    label: str
    style: str = S_PROCESS
    w: int = 190
    h: int = 54
    x: int | None = None          # set by layout unless pinned
    y: int | None = None
    parent: str = "1"


@dataclass
class Edge:
    src: str
    dst: str
    label: str = ""
    style: str = E_ORTH
    exit_: str | None = None       # e.g. "0.5,1" bottom-centre
    entry: str | None = None
    #: where the label sits along the route: 0 is the midpoint, -1 the
    #: source end, +1 the target end. Used to slide a label off a box it
    #: would otherwise print on top of.
    label_at: float = 0.0
    #: pixels to lift the label off the line. Between two boxes a hand's
    #: breadth apart there is no room beside the edge, so the label goes
    #: above it instead of printing across both boxes.
    label_dy: int = 0


@dataclass
class Diagram:
    name: str
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    #: rows of node ids; laid out top-to-bottom, centred horizontally per row
    layers: list[list[str]] = field(default_factory=list)
    vgap: int = 74
    hgap: int = 46
    margin: int = 48
    horizontal: bool = False       # lay layers left-to-right instead

    # ------------------------------------------------------------ build ----
    def node(self, id: str, label: str, **kw) -> "Diagram":
        self.nodes.append(Node(id=id, label=label, **kw))
        return self

    def edge(self, src: str, dst: str, label: str = "", **kw) -> "Diagram":
        self.edges.append(Edge(src=src, dst=dst, label=label, **kw))
        return self

    def layer(self, *ids: str) -> "Diagram":
        self.layers.append(list(ids))
        return self

    def _by_id(self) -> dict[str, Node]:
        return {n.id: n for n in self.nodes}

    def _layout(self) -> None:
        idx = self._by_id()
        placed = {i for lay in self.layers for i in lay}
        loose = [n.id for n in self.nodes
                 if n.id not in placed and n.x is None and n.parent == "1"]
        layers = list(self.layers) + ([loose] if loose else [])

        if self.horizontal:
            widths = [max((idx[i].w for i in lay), default=0) for lay in layers]
            x = self.margin
            for lay, w in zip(layers, widths):
                total = sum(idx[i].h for i in lay) + self.vgap * (len(lay) - 1)
                y = self.margin + max(0, (self._span(layers, idx) - total) // 2)
                for i in lay:
                    n = idx[i]
                    if n.x is None:
                        n.x, n.y = x + (w - n.w) // 2, y
                    y += n.h + self.vgap
                x += w + self.hgap
        else:
            y = self.margin
            width = self._span(layers, idx)
            for lay in layers:
                total = sum(idx[i].w for i in lay) + self.hgap * (len(lay) - 1)
                x = self.margin + max(0, (width - total) // 2)
                rowh = max((idx[i].h for i in lay), default=0)
                for i in lay:
                    n = idx[i]
                    if n.x is None:
                        n.x, n.y = x, y + (rowh - n.h) // 2
                    x += n.w + self.hgap
                y += rowh + self.vgap

    def _span(self, layers, idx) -> int:
        if self.horizontal:
            return max((sum(idx[i].h for i in lay) + self.vgap * (len(lay) - 1)
                        for lay in layers), default=0)
        return max((sum(idx[i].w for i in lay) + self.hgap * (len(lay) - 1)
                    for lay in layers), default=0)

    # -------------------------------------------------------------- xml ----
    def to_xml(self) -> str:
        self._layout()
        out = []
        for n in self.nodes:
            out.append(
                f'        <mxCell id="{n.id}" value="{escape(n.label)}" '
                f'style="{n.style}" vertex="1" parent="{n.parent}">\n'
                f'          <mxGeometry x="{n.x or 0}" y="{n.y or 0}" '
                f'width="{n.w}" height="{n.h}" as="geometry" />\n'
                f'        </mxCell>')
        for k, e in enumerate(self.edges):
            style = e.style
            if e.exit_:
                ex, ey = e.exit_.split(",")
                style += f"exitX={ex};exitY={ey};exitDx=0;exitDy=0;"
            if e.entry:
                nx, ny = e.entry.split(",")
                style += f"entryX={nx};entryY={ny};entryDx=0;entryDy=0;"
            pos = f' x="{e.label_at:g}"' if e.label_at else ""
            off = (f'<mxPoint as="offset" y="{e.label_dy}" />'
                   if e.label_dy else "")
            out.append(
                f'        <mxCell id="e{k}" value="{escape(e.label)}" '
                f'style="{style}" edge="1" parent="1" '
                f'source="{e.src}" target="{e.dst}">\n'
                f'          <mxGeometry{pos} relative="1" as="geometry">{off}</mxGeometry>\n'
                f'        </mxCell>')
        cells = "\n".join(out)
        return (
            f'  <diagram name="{escape(self.name)}" id="{int(hashlib.md5(self.name.encode()).hexdigest()[:8], 16)}">\n'
            f'    <mxGraphModel dx="1400" dy="900" grid="1" gridSize="10" guides="1" '
            f'tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" '
            f'pageWidth="1169" pageHeight="826" math="0" shadow="0">\n'
            f'      <root>\n'
            f'        <mxCell id="0" />\n'
            f'        <mxCell id="1" parent="0" />\n'
            f'{cells}\n'
            f'      </root>\n'
            f'    </mxGraphModel>\n'
            f'  </diagram>\n')


def render(*diagrams: Diagram) -> str:
    """Exactly the bytes `write` would put on disk.

    Separated so a caller can compare a file against what it would have been
    regenerated as, and so tell a hand edit from a stale copy.
    """
    body = "".join(d.to_xml() for d in diagrams)
    return '<mxfile host="app.diagrams.net" type="device">\n' + body + '</mxfile>\n'


def write(path: Path, *diagrams: Diagram) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(*diagrams), encoding="utf-8")
    print(f"  wrote {path}")
