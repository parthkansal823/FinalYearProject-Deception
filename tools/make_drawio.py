"""Native draw.io sources for the report's eleven structural diagrams.

The Mermaid versions render, but the routing and spacing are not under our control
and the results were cramped. These are `.drawio` files: they open in
app.diagrams.net or the desktop app as ordinary editable shapes, so lines can be
nudged, boxes resized, and anything that still overlaps fixed by hand.

Run:  python -m tools.make_drawio          -> docs/diagrams/drawio/*.drawio
"""
from __future__ import annotations

from pathlib import Path

from tools.drawio import (Diagram, Node, Edge, write,
                          S_PROCESS, S_DECISION, S_TERMINAL, S_DATA, S_EXTERNAL,
                          S_ACCENT, S_WARN, S_NOTE, S_GROUP, S_CIRCLE, S_ACTOR,
                          E_ORTH, E_DASH, E_NONE, BASE, ROUND, restyle)

OUT = Path("docs/diagrams/drawio")


# ------------------------------------------------------------------------
# Figure 1 — Graphical abstract
# ------------------------------------------------------------------------
def fig01() -> Diagram:
    d = Diagram("Fig 1 - Graphical abstract", vgap=56, hgap=40)
    d.node("cli", "HTTP client\n(human, bot or attacker)", style=S_EXTERNAL, w=230, h=54)
    d.node("px", "Reverse proxy\nActive Deception Framework", style=S_PROCESS, w=250, h=54)
    d.node("sid", "Session identity\ncookie + fingerprint fallback", style=S_PROCESS, w=250, h=50)
    d.node("fx", "Feature extraction\n18 features, request-side only", style=S_PROCESS, w=250, h=50)
    d.node("auto", "Automation axis\n10 features: timing, assets,\nheaders, user-agent", style=S_PROCESS, w=210, h=66)
    d.node("mal", "Malice axis\n8 features: payload, errors,\nauth, object ids", style=S_PROCESS, w=210, h=66)
    d.node("meter", "Dual logistic meter\nfusion → belief p", style=S_ACCENT, w=250, h=50)
    d.node("pol", "Priced policy\nEVSI decision rule", style=S_DECISION, w=190, h=90)
    d.node("pass", "PASS\np &lt; 0.0647\nforward untouched", style=S_ACCENT, w=190, h=64)
    d.node("bait", "BAIT\n0.0647 ≤ p &lt; 0.8793\ninject invisible probe", style=S_PROCESS, w=210, h=64)
    d.node("div", "DIVERT\np ≥ 0.8793\nroute into decoy", style=S_WARN, w=190, h=64)
    d.node("gate", "Invisibility gate\ncertificate re-checked\nat run time", style=S_PROCESS, w=200, h=62)
    d.node("bite", "Client acts on\nthe planted token?", style=S_DECISION, w=180, h=86)
    d.node("lr", "BITE\nlogit(p) += log Λ⁺", style=S_ACCENT, w=180, h=50)
    d.node("dec", "no bite\nsurvival discount (1−β)ᵏ", style=S_PROCESS, w=200, h=50)
    d.node("fn", "Fact Notebook\nwrite-once entity store", style=S_DATA, w=200, h=60)
    d.node("log", "Hash-chained append-only log", style=S_DATA, w=280, h=56)
    d.node("frz", "Frozen model manifest\nverified before any reported number", style=S_DATA, w=280, h=60)

    d.layer("cli").layer("px").layer("sid").layer("fx").layer("auto", "mal")
    d.layer("meter").layer("pol").layer("pass", "bait", "div")
    d.layer("gate", "fn").layer("bite").layer("lr", "dec").layer("log").layer("frz")

    for a, b in [("cli", "px"), ("px", "sid"), ("sid", "fx")]:
        d.edge(a, b)
    d.edge("fx", "auto"); d.edge("fx", "mal")
    d.edge("auto", "meter"); d.edge("mal", "meter")
    d.edge("meter", "pol")
    d.edge("pol", "pass"); d.edge("pol", "bait"); d.edge("pol", "div")
    d.edge("bait", "gate"); d.edge("gate", "bite")
    d.edge("bite", "lr", "yes"); d.edge("bite", "dec", "no")
    d.edge("lr", "meter", "belief update", style=E_DASH)
    d.edge("dec", "meter", "value decays", style=E_DASH)
    d.edge("div", "fn")
    d.edge("pass", "log"); d.edge("fn", "log"); d.edge("lr", "log"); d.edge("dec", "log")
    d.edge("log", "frz", style=E_DASH)
    return d


# ------------------------------------------------------------------------
# Figure 10 — Decoy consistency with and without the Fact Notebook
# ------------------------------------------------------------------------
def fig10() -> Diagram:
    d = Diagram("Fig 10 - Decoy consistency", vgap=60, hgap=70)
    d.node("gA", "WITHOUT the Fact Notebook", style=S_GROUP, w=430, h=330, x=40, y=40)
    d.node("gB", "WITH the Fact Notebook", style=S_GROUP, w=470, h=330, x=530, y=40)

    d.node("q1", "Request:\nwho is user 1041?", style=S_EXTERNAL, w=180, h=50, x=70, y=90)
    d.node("g1", "Generator", style=S_PROCESS, w=150, h=44, x=85, y=170)
    d.node("a1", "“Rakesh Malhotra”", style=S_PROCESS, w=180, h=44, x=70, y=248)
    d.node("q2", "Same request,\nasked again", style=S_EXTERNAL, w=170, h=50, x=280, y=90)
    d.node("g2", "Generator", style=S_PROCESS, w=150, h=44, x=290, y=170)
    d.node("a2", "“Priya Nair”", style=S_PROCESS, w=170, h=44, x=280, y=248)
    d.node("bad", "CONTRADICTION\ndecoy detected — 100% rate", style=S_WARN, w=350, h=48, x=80, y=318)

    d.node("q3", "Request:\nwho is user 1041?", style=S_EXTERNAL, w=180, h=50, x=560, y=90)
    d.node("n1", "In notebook?", style=S_DECISION, w=140, h=64, x=580, y=162)
    d.node("g3", "Generator,\nthen write-once put", style=S_PROCESS, w=170, h=48, x=560, y=248)
    d.node("q4", "Same request,\nasked again", style=S_EXTERNAL, w=170, h=50, x=800, y=90)
    d.node("n2", "In notebook?", style=S_DECISION, w=140, h=64, x=815, y=162)
    d.node("a4", "“Rakesh Malhotra”\nsame value, by construction", style=S_ACCENT, w=220, h=48, x=775, y=248)
    d.node("good", "NO CONTRADICTION\n0% rate over 286 probes", style=S_ACCENT, w=380, h=48, x=575, y=318)

    d.edge("q1", "g1"); d.edge("g1", "a1"); d.edge("a1", "bad")
    d.edge("q2", "g2"); d.edge("g2", "a2"); d.edge("a2", "bad")
    d.edge("q3", "n1"); d.edge("n1", "g3", "no"); d.edge("g3", "good")
    d.edge("q4", "n2"); d.edge("n2", "a4", "yes"); d.edge("a4", "good")
    return d


# ------------------------------------------------------------------------
# Figure 11 — Layered system architecture
# ------------------------------------------------------------------------
def fig11() -> Diagram:
    d = Diagram("Fig 11 - Layered architecture")
    L = [("Layer 1 — Edge", ["Reverse proxy\nfail-open boundary",
                                  "Session identity\ncookie / fingerprint"]),
         ("Layer 2 — Perception", ["Feature extractor\n18 versioned features"]),
         ("Layer 3 — Belief", ["Automation head", "Malice head",
                                    "Fusion → belief p", "Log-odds update on bite"]),
         ("Layer 4 — Decision", ["Frozen cost table\nhash-verified on load",
                                      "EVSI calculator",
                                      "Policy\nPASS / BAIT / DIVERT"]),
         ("Layer 5 — Deception", ["Bait library", "Invisibility gate\ncertificates",
                                       "Bait engine", "Decoy application",
                                       "Fact Notebook\nwrite-once"]),
         ("Layer 6 — Evidence", ["Hash-chained log", "Freeze manifest"])]
    y = 40
    ids = {}
    for li, (title, items) in enumerate(L):
        cols = len(items)
        boxw, gap = 200, 24
        gw = cols * boxw + (cols - 1) * gap + 40
        d.node(f"g{li}", title, style=S_GROUP, w=gw, h=104, x=40, y=y)
        x = 60
        for k, lab in enumerate(items):
            nid = f"n{li}_{k}"
            style = (S_ACCENT if li == 5 else
                     S_DECISION if "Policy" in lab else
                     S_DATA if "Notebook" in lab or "cost table" in lab else S_PROCESS)
            d.node(nid, lab, style=style, w=boxw, h=54, x=x, y=y + 36)
            ids.setdefault(li, []).append(nid)
            x += boxw + gap
        y += 128

    d.node("cli", "HTTP client", style=S_EXTERNAL, w=150, h=44, x=40, y=y + 6)
    d.node("tgt", "Target application", style=S_EXTERNAL, w=190, h=44, x=230, y=y + 6)

    d.edge("cli", ids[0][0])
    d.edge(ids[0][0], ids[1][0]); d.edge(ids[1][0], ids[2][0]); d.edge(ids[1][0], ids[2][1])
    d.edge(ids[2][0], ids[2][2]); d.edge(ids[2][1], ids[2][2])
    d.edge(ids[2][2], ids[3][2]); d.edge(ids[3][0], ids[3][2]); d.edge(ids[3][1], ids[3][2])
    d.edge(ids[4][0], ids[3][1])
    d.edge(ids[3][2], ids[4][2], "BAIT"); d.edge(ids[4][2], ids[4][1], "certificate")
    d.edge(ids[3][2], ids[4][3], "DIVERT"); d.edge(ids[4][3], ids[4][4])
    d.edge(ids[3][2], ids[5][0], "every decision")
    d.edge(ids[5][1], ids[5][0], "verified before reporting", style=E_DASH)
    d.edge(ids[4][2], ids[2][3], "bite detected", style=E_DASH)
    d.edge(ids[2][3], ids[2][2], style=E_DASH)
    d.edge(ids[3][2], "tgt", "PASS / BAIT")
    return d


# ------------------------------------------------------------------------
# Figure 12 — Overall system flow (with the randomised holdout)
# ------------------------------------------------------------------------
def fig12() -> Diagram:
    d = Diagram("Fig 12 - Overall system flow", vgap=60, hgap=44)
    d.node("a", "Request arrives", style=S_TERMINAL, w=190, h=46)
    d.node("b", "Proxy establishes\nsession identity", style=S_PROCESS)
    d.node("c", "Extract 18 features from\nrequest + session history", style=S_PROCESS, w=230)
    d.node("dd", "Dual meter → belief p", style=S_PROCESS, w=210)
    d.node("e", "Bait planted\nearlier this session?", style=S_DECISION, w=190, h=90)
    d.node("f", "Request carries\nthe planted token?", style=S_DECISION, w=190, h=90)
    d.node("g1", "BITE\nlogit(p) += log Λ⁺", style=S_ACCENT, w=190, h=50)
    d.node("g2", "no bite\nlogit(p) += log Λ⁻\nexposures k += 1", style=S_PROCESS, w=190, h=62)
    d.node("h", "Policy: E[C(a)] per action,\nV(p) per deployable bait", style=S_PROCESS, w=250)
    d.node("i", "Least effective cost?", style=S_DECISION, w=200, h=90)
    d.node("j", "PASS\nforward untouched", style=S_ACCENT, w=180, h=50)
    d.node("k", "BAIT", style=S_PROCESS, w=130, h=44)
    d.node("l", "DIVERT\nroute to decoy\nfor the rest of the session", style=S_WARN, w=210, h=62)
    d.node("n", "Holdout draw:\nwithhold the probe?", style=S_DECISION, w=190, h=90)
    d.node("j2", "control (~10%)\nforward untouched,\nrecorded as withheld", style=S_PROCESS, w=200, h=62)
    d.node("k2", "treated (~90%)\ncertificate re-checked,\nprobe injected", style=S_PROCESS, w=200, h=62)
    d.node("o", "Fact Notebook serves\na consistent fake world", style=S_DATA, w=220, h=56)
    d.node("m", "Hash-chained log record", style=S_DATA, w=230, h=48)
    d.node("p", "Response returned", style=S_TERMINAL, w=190, h=46)

    d.layer("a").layer("b").layer("c").layer("dd").layer("e").layer("f")
    d.layer("g1", "g2").layer("h").layer("i").layer("j", "k", "l")
    d.layer("n", "o").layer("j2", "k2").layer("m").layer("p")

    d.edge("a", "b"); d.edge("b", "c"); d.edge("c", "dd"); d.edge("dd", "e")
    d.edge("e", "f", "yes"); d.edge("e", "h", "no")
    d.edge("f", "g1", "yes"); d.edge("f", "g2", "no")
    d.edge("g1", "h"); d.edge("g2", "h")
    d.edge("h", "i"); d.edge("i", "j", "PASS"); d.edge("i", "k", "BAIT"); d.edge("i", "l", "DIVERT")
    d.edge("k", "n"); d.edge("n", "j2", "yes"); d.edge("n", "k2", "no")
    d.edge("l", "o")
    d.edge("j", "m"); d.edge("j2", "m"); d.edge("k2", "m"); d.edge("o", "m")
    d.edge("m", "p")
    return d


# ------------------------------------------------------------------------
# Figure 13 — Sequence diagram (hand-built lifelines)
# ------------------------------------------------------------------------
def fig13() -> Diagram:
    """Sequence diagram, built from lifelines and real edges.

    draw.io has no native sequence shape, so the diagram is assembled: a header
    box and a footer box per participant, a dashed vertical lifeline between
    them, and one orthogonal edge per message anchored to the lifelines at the
    right height via exitY/entryY fractions. Because the messages are real
    edges they carry arrowheads and stay attached when a lifeline is dragged.

    Type sizes are set explicitly here rather than inherited: the shared edge
    style is sized for compact flowchart labels, which is too small to read on a
    diagram this wide. Column width and row pitch are scaled to match, so the
    larger labels still fit between lifelines.
    """
    d = Diagram("Fig 13 - Sequence diagram")
    NL = chr(10)
    A_CLIENT = "Client"
    A_PROXY = "Reverse Proxy"
    A_FEAT = "Feature" + NL + "Extractor"
    A_METER = "Dual Meter"
    A_POLICY = "Policy Engine"
    A_BAIT = "Bait Engine"
    A_TARGET = "Target App"
    A_DECOY = "Decoy +" + NL + "Notebook"
    A_LOG = "Hash-Chained" + NL + "Log"

    actors = [A_CLIENT, A_PROXY, A_FEAT, A_METER, A_POLICY,
              A_BAIT, A_TARGET, A_DECOY, A_LOG]

    # Message labels sit on the edges; 13 pt reads at print size where the
    # inherited 10 pt did not.
    CALL = restyle(E_ORTH, fontSize=13, strokeWidth=1.3)
    RET = restyle(E_DASH, fontSize=13, strokeWidth=1.2, strokeColor="#6b6b6b")

    steps = [
        (A_CLIENT, A_PROXY, "1  HTTP request", CALL),
        (A_PROXY, A_PROXY, "2  resolve session identity", CALL),
        (A_PROXY, A_FEAT, "3  request + session history", CALL),
        (A_FEAT, A_PROXY, "4  18 features", RET),
        (A_PROXY, A_BAIT, "5  check pending baits", CALL),
        (A_BAIT, A_METER, "6  BITE (bait id, Λ⁺)  or  no bite (Λ⁻)", RET),
        (A_METER, A_METER, "7  logit(p) += log Λ", CALL),
        (A_PROXY, A_METER, "8  features", CALL),
        (A_METER, A_PROXY, "9  belief p", RET),
        (A_PROXY, A_POLICY, "10  p, session state", CALL),
        (A_POLICY, A_POLICY, "11  E[C(a)] and V(p) per bait", CALL),
        (A_POLICY, A_PROXY, "12  action + reasons", RET),
        (A_PROXY, A_TARGET, "13  [PASS or BAIT] forward — always served", CALL),
        (A_TARGET, A_PROXY, "14  response", RET),
        (A_PROXY, A_BAIT, "15  [BAIT] holdout draw", CALL),
        (A_BAIT, A_PROXY, "16  treated: verify certificate, inject", RET),
        (A_PROXY, A_DECOY, "17  [DIVERT] session pinned to decoy", CALL),
        (A_DECOY, A_PROXY, "18  consistent fake response", RET),
        (A_PROXY, A_LOG, "19  append record (chained hash)", CALL),
        (A_PROXY, A_CLIENT, "20  response", RET),
    ]

    # Wider columns and a taller pitch: the labels grew, so the space has to.
    x0, colw, boxw, boxh = 40, 205, 172, 58
    top, gap = 40, 68
    lifeh = gap * (len(steps) + 1)

    idx = {}
    head = ("rounded=0;whiteSpace=wrap;html=1;fontFamily=Georgia;fontSize=14;"
            "fontStyle=1;fillColor=#dae8fc;strokeColor=#6c8ebf;")
    for k, a in enumerate(actors):
        x = x0 + k * colw
        idx[a] = k
        d.node("h%d" % k, a, style=head, w=boxw, h=boxh, x=x, y=top)
        d.node("lf%d" % k, "", style=(
            "html=1;fillColor=none;strokeColor=#9aa0a6;dashed=1;dashPattern=6 6;"
            "strokeWidth=1.4;"),
            w=2, h=lifeh, x=x + boxw // 2 - 1, y=top + boxh)
        d.node("f%d" % k, a, style=head, w=boxw, h=boxh, x=x, y=top + boxh + lifeh)

    for i, (s_, t_, lab, st) in enumerate(steps):
        frac = round(gap * (i + 1) / lifeh, 5)
        si, ti = idx[s_], idx[t_]
        if si == ti:
            d.node("sc%d" % i, lab, style=(
                "rounded=0;whiteSpace=wrap;html=1;fontFamily=Georgia;fontSize=13;"
                "fillColor=#fff2cc;strokeColor=#d6b656;align=left;spacingLeft=8;"),
                w=290, h=40,
                x=x0 + si * colw + boxw // 2 + 18,
                y=top + boxh + gap * (i + 1) - 20)
            d.edge("lf%d" % si, "sc%d" % i, "", style=CALL,
                   exit_="1,%s" % frac, entry="0,0.5")
        else:
            right = ti > si
            d.edge("lf%d" % si, "lf%d" % ti, lab, style=st,
                   exit_="%d,%s" % (1 if right else 0, frac),
                   entry="%d,%s" % (0 if right else 1, frac))
    return d


# ------------------------------------------------------------------------
# Figure 14 — DFD Level 0
# ------------------------------------------------------------------------
def fig14() -> Diagram:
    d = Diagram("Fig 14 - DFD Level 0")
    d.node("u", "Legitimate\nUser", style=S_EXTERNAL, w=150, h=60, x=40, y=150)
    d.node("a", "Attacker", style=S_EXTERNAL, w=150, h=60, x=40, y=280)
    d.node("s", "Active Deception\nFramework", style=S_CIRCLE, w=210, h=210, x=300, y=140)
    d.node("app", "Protected\nApplication", style=S_EXTERNAL, w=160, h=60, x=620, y=150)
    d.node("log", "Hash-chained\naudit log", style=S_DATA, w=180, h=64, x=610, y=290)
    d.node("fn", "Fact Notebook", style=S_DATA, w=180, h=56, x=610, y=390)
    d.node("fz", "Frozen model\nmanifest", style=S_DATA, w=180, h=60, x=300, y=406)

    d.edge("u", "s", "request"); d.edge("s", "u", "unmodified response")
    d.edge("a", "s", "request")
    d.edge("s", "a", "response, sometimes\ncarrying an inert probe")
    d.edge("s", "app", "forwarded traffic"); d.edge("app", "s", "application response")
    d.edge("s", "log", "decision records"); d.edge("s", "fn", "asserted facts")
    d.edge("fz", "s", "verified artefacts", style=E_DASH)
    return d


# ------------------------------------------------------------------------
# Figure 15 — DFD Level 1
# ------------------------------------------------------------------------
def fig15() -> Diagram:
    d = Diagram("Fig 15 - DFD Level 1", vgap=62, hgap=50)
    d.node("u", "User / Attacker", style=S_EXTERNAL, w=180, h=46)
    d.node("p1", "1  Session Resolution", style=S_CIRCLE, w=190, h=62)
    d.node("p2", "2  Feature Extraction", style=S_CIRCLE, w=190, h=62)
    d.node("p3", "3  Belief Estimation", style=S_CIRCLE, w=190, h=62)
    d.node("p4", "4  Priced Decision", style=S_CIRCLE, w=190, h=62)
    d.node("p5", "5  Upstream Forwarding", style=S_CIRCLE, w=200, h=62)
    d.node("p6", "6  Decoy Service", style=S_CIRCLE, w=180, h=62)
    d.node("p7", "7  Bait Injection", style=S_CIRCLE, w=180, h=62)
    d.node("p8", "8  Bite Detection", style=S_CIRCLE, w=180, h=62)
    d.node("p9", "9  Tamper-Evident Logging", style=S_CIRCLE, w=220, h=62)
    d.node("d1", "Session store", style=S_DATA, w=170, h=54)
    d.node("d2", "Frozen meter weights", style=S_DATA, w=200, h=54)
    d.node("d3", "Frozen cost table", style=S_DATA, w=190, h=54)
    d.node("d4", "Calibrated bait library", style=S_DATA, w=200, h=54)
    d.node("d5", "Fact Notebook (write-once)", style=S_DATA, w=230, h=54)
    d.node("d6", "Invisibility certificates", style=S_DATA, w=210, h=54)
    d.node("d7", "Append-only hash-chained log", style=S_DATA, w=250, h=54)
    d.node("app", "Target application", style=S_EXTERNAL, w=180, h=46)

    d.layer("u").layer("p1", "d1").layer("p2", "p8").layer("p3", "d2")
    d.layer("p4", "d3", "d4").layer("p5", "p6", "p7").layer("app", "d5", "d6")
    d.layer("p9").layer("d7")

    d.edge("u", "p1", "1  request"); d.edge("p1", "d1", style=E_NONE)
    d.edge("p1", "p2", "2  session + history")
    d.edge("p2", "p3", "3  18 features"); d.edge("d2", "p3", style=E_DASH)
    d.edge("p3", "p4", "4  belief p")
    d.edge("d3", "p4", style=E_DASH); d.edge("d4", "p4", style=E_DASH)
    d.edge("p4", "p5", "5a  PASS / BAIT"); d.edge("p4", "p6", "5b  DIVERT")
    d.edge("p5", "app"); d.edge("p6", "d5")
    d.edge("p4", "p7", "6  bait selected"); d.edge("d6", "p7", style=E_DASH)
    d.edge("p5", "p7", "response"); d.edge("p7", "u", "7  response + probe")
    d.edge("p7", "d1", "8  pending bait", style=E_DASH)
    d.edge("d1", "p8", style=E_DASH); d.edge("p2", "p8", "token present?")
    d.edge("p8", "p3", "9  Λ⁺ or Λ⁻")
    d.edge("p4", "p9", "10  decision record"); d.edge("p7", "p9"); d.edge("p8", "p9")
    d.edge("p9", "d7")
    return d


# ------------------------------------------------------------------------
# Figure 16 — Use case diagram
# ------------------------------------------------------------------------
def fig16() -> Diagram:
    """Use case diagram.

    The use cases sit in two columns rather than one. With a single column the
    actor edges and the include/extend edges all competed for the same vertical
    corridor and the diagram was unreadable; splitting user-initiated cases from
    system behaviour lets almost every relation be a short horizontal or vertical
    hop. Exit and entry sides are pinned so the two edges that skip past
    intermediate cases take opposite sides of the column instead of overlapping.
    """
    d = Diagram("Fig 16 - Use case diagram")

    UC = ("ellipse;whiteSpace=wrap;html=1;fontFamily=Georgia;fontSize=13;"
          "fillColor=#dae8fc;strokeColor=#6c8ebf;verticalAlign=middle;")
    ACT = ("shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;"
           "outlineConnect=0;fontFamily=Georgia;fontSize=13;fontStyle=1;"
           "strokeColor=#333333;")
    REL = ("edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;jumpStyle=arc;jumpSize=8;"
           "fontFamily=Georgia;fontSize=11;fontStyle=2;strokeColor=#7a7a7a;"
           "dashed=1;endArrow=open;endSize=8;")
    ASSOC = ("edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;jumpStyle=arc;jumpSize=8;"
             "fontFamily=Georgia;fontSize=11;strokeColor=#4d4d4d;endArrow=none;")

    # system boundary, sized to actually contain every case
    d.node("sys", "Active Deception Framework", style=(
        "rounded=0;whiteSpace=wrap;html=1;fontFamily=Georgia;fontSize=14;"
        "fontStyle=1;fillColor=none;strokeColor=#8a8a8a;verticalAlign=top;"
        "align=center;spacingTop=6;"), w=620, h=630, x=250, y=40)

    # actors
    d.node("au", "Legitimate User", style=ACT, w=42, h=76, x=80, y=150)
    d.node("at", "Attacker", style=ACT, w=42, h=76, x=80, y=420)
    d.node("an", "Security Analyst", style=ACT, w=42, h=76, x=960, y=470)
    d.node("ev", "Evaluation Harness", style=ACT, w=42, h=76, x=960, y=590)

    # column A -- what an actor initiates
    d.node("u1", "Browse application", style=UC, w=210, h=62, x=290, y=100)
    d.node("u2", "Authenticate", style=UC, w=210, h=62, x=290, y=195)
    d.node("u3", "Submit search /\naccess record", style=UC, w=210, h=68, x=290, y=290)
    d.node("u7", "Be diverted\nto the decoy", style=UC, w=210, h=68, x=290, y=470)

    # column B -- what the framework does in response
    d.node("u4", "Be scored on\ntwo axes", style=UC, w=210, h=68, x=590, y=195)
    d.node("u5", "Receive an\ninvisible probe", style=UC, w=210, h=68, x=590, y=320)
    d.node("u6", "Act on a\nplanted token", style=UC, w=210, h=68, x=590, y=445)
    d.node("u8", "Have decisions logged\ntamper-evidently", style=UC, w=230, h=68, x=580, y=570)

    # associations -- actor to use case
    for a, t in (("au", "u1"), ("au", "u2"), ("au", "u3")):
        d.edge(a, t, style=ASSOC, exit_="1,0.4", entry="0,0.5")
    for a, t in (("at", "u1"), ("at", "u2"), ("at", "u3")):
        d.edge(a, t, style=ASSOC, exit_="1,0.4", entry="0,0.5")
    d.edge("at", "u6", style=ASSOC, exit_="0.5,1", entry="0,0.5")
    d.edge("an", "u8", style=ASSOC, exit_="0,0.4", entry="1,0.5")
    d.edge("ev", "u8", style=ASSOC, exit_="0,0.4", entry="1,0.5")

    # relations -- kept short, and pinned to opposite sides where they skip past
    d.edge("u3", "u4", "«include»", style=REL, exit_="1,0.5", entry="0,0.5")
    d.edge("u4", "u5", "«extend»\nwhen p is in the BAIT band",
           style=REL, exit_="0.5,1", entry="0.5,0")
    d.edge("u5", "u6", "«extend»\nonly if the client probes",
           style=REL, exit_="0.5,1", entry="0.5,0")
    d.edge("u6", "u4", "«include»\nbelief update",
           style=REL, exit_="1,0.5", entry="1,0.5")          # loops right
    d.edge("u4", "u7", "«extend»\nwhen p ≥ 0.8793",
           style=REL, exit_="0,0.35", entry="1,0.5")          # left, into column A
    d.edge("u4", "u8", "«include»", style=REL,
           exit_="0,0.75", entry="0,0.5")                     # left of column B
    return d


# ------------------------------------------------------------------------
# Figure 17 — Class diagram
# ------------------------------------------------------------------------
def _uml(d: Diagram, nid: str, name: str, attrs: list[str], ops: list[str],
         x: int, y: int, w: int = 230) -> None:
    lh = 20
    h = 30 + lh * (len(attrs) + len(ops)) + 8
    d.node(nid, name, style=(
        "swimlane;fontStyle=1;align=center;childLayout=stackLayout;horizontal=1;"
        "startSize=28;horizontalStack=0;resizeParent=1;resizeParentMax=0;html=1;"
        "fontFamily=Georgia;fontSize=12;fillColor=#dae8fc;strokeColor=#6c8ebf;"),
        w=w, h=h, x=x, y=y)
    yy = 28
    for k, t in enumerate(attrs + ["__SEP__"] + ops if ops else attrs):
        if t == "__SEP__":
            d.node(f"{nid}_sep", "", style="line;strokeWidth=1;fillColor=none;align=left;"
                   "verticalAlign=middle;spacingTop=-1;spacingLeft=3;spacingRight=3;"
                   "rotatable=0;labelPosition=right;points=[];portConstraint=eastwest;html=1;",
                   w=w, h=8, x=0, y=yy, parent=nid)
            yy += 8
            continue
        d.node(f"{nid}_{k}", t, style=(
            "text;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;"
            "spacingLeft=6;html=1;fontFamily=Georgia;fontSize=10.5;"),
            w=w, h=lh, x=0, y=yy, parent=nid)
        yy += lh


def fig17() -> Diagram:
    d = Diagram("Fig 17 - Class diagram")
    _uml(d, "Session", "Session",
         ["+ session_id: String", "+ belief_p: float", "+ diverted: bool",
          "+ exposures: Map", "+ pending_baits: List"],
         ["+ update_logodds(Λ)"], 40, 40)
    _uml(d, "FeatureVector", "FeatureVector",
         ["+ automation: float[10]", "+ malice: float[8]", "+ feature_version: String"],
         ["+ to_array()"], 330, 40)
    _uml(d, "DualMeter", "DualMeter",
         ["+ w_automation: float[]", "+ w_malice: float[]", "+ w_auto_fusion = 0.0"],
         ["+ automation_score(x)", "+ malice_score(x)", "+ fuse(a, m)"], 620, 40)
    _uml(d, "CostTable", "CostTable",
         ["+ matrix: Map", "+ digest: String"],
         ["+ expected_cost(a, p)", "+ verify_or_raise()"], 40, 260)
    _uml(d, "PolicyEngine", "PolicyEngine",
         ["+ costs: CostTable", "+ library: BaitLibrary"],
         ["+ evsi(p, bait)", "+ survival_discount(V, β, k)", "+ decide(p, session)"],
         330, 260)
    _uml(d, "Decision", "Decision",
         ["+ action: String", "+ bait: Bait", "+ expected_costs: Map", "+ assignment: String"],
         ["+ reason(): String[]"], 620, 260)
    _uml(d, "Bait", "Bait",
         ["+ bait_id: String", "+ channel: String", "+ bite_kind: String",
          "+ beta_attack: float", "+ beta_benign: float"],
         ["+ lambda_plus()", "+ lambda_minus()"], 40, 500)
    _uml(d, "Certificate", "Certificate",
         ["+ bait_id: String", "+ passed: bool", "+ median_overhead_ms: float",
          "+ p95_overhead_ms: float"], [], 330, 500)
    _uml(d, "BaitEngine", "BaitEngine", [],
         ["+ select(p, session)", "+ inject(resp, bait, session)",
          "+ detect_bite(req, session)"], 620, 500)
    _uml(d, "FactNotebook", "FactNotebook", [],
         ["+ get(kind, key)", "+ put(kind, key, value)", "+ has(kind, key)"], 40, 700)
    _uml(d, "DecoyWorld", "DecoyWorld",
         ["+ notebook: FactNotebook", "+ generator: Generator"],
         ["+ fact(kind, key)"], 330, 700)
    _uml(d, "LogStore", "LogStore", ["+ last_hash: String"],
         ["+ append(record)", "+ verify_chain()"], 620, 700)
    _uml(d, "FreezeManifest", "FreezeManifest", ["+ digests: Map"],
         ["+ freeze()", "+ require_frozen()"], 900, 700)

    d.edge("Session", "FeatureVector", "produces")
    d.edge("FeatureVector", "DualMeter", "scored by")
    d.edge("DualMeter", "PolicyEngine", "belief p")
    d.edge("CostTable", "PolicyEngine", "loss matrix")
    d.edge("Bait", "Certificate", "must hold")
    d.edge("PolicyEngine", "Decision", "returns")
    d.edge("PolicyEngine", "Bait", "selects by max V", style=E_DASH)
    d.edge("Decision", "BaitEngine", "if BAIT")
    d.edge("BaitEngine", "Session", "records / detects", style=E_DASH)
    d.edge("Decision", "DecoyWorld", "if DIVERT")
    d.edge("DecoyWorld", "FactNotebook", "write-once reads")
    d.edge("Decision", "LogStore", "appended, chained")
    d.edge("FreezeManifest", "CostTable", "hashes", style=E_DASH)
    d.edge("FreezeManifest", "Bait", "hashes", style=E_DASH)
    return d


# ------------------------------------------------------------------------
# Figure 18 — Session state machine
# ------------------------------------------------------------------------
def fig18() -> Diagram:
    d = Diagram("Fig 18 - Session state machine")
    d.node("start", "", style="ellipse;html=1;fillColor=#000000;strokeColor=#000000;",
           w=26, h=26, x=90, y=40)
    d.node("obs", "Observed", style=S_ACCENT, w=180, h=56, x=40, y=120)
    d.node("prb", "Probed", style=S_PROCESS, w=180, h=56, x=40, y=280)
    d.node("wth", "Withheld\n(holdout control)", style=S_PROCESS, w=190, h=56, x=330, y=280)
    d.node("con", "Contained\n(absorbing)", style=S_WARN, w=190, h=56, x=40, y=450)
    d.node("end", "", style="ellipse;html=1;fillColor=none;strokeColor=#000000;"
           "strokeWidth=2;", w=26, h=26, x=118, y=560)
    d.node("note", "As k grows, V → 0 and the rule\ncollapses to the two-action policy:\n"
           "the limiting-rule guarantee of §3.2.2", style=S_NOTE, w=280, h=76, x=330, y=380)

    d.edge("start", "obs", "first request")
    d.edge("obs", "obs", "p &lt; 0.0647  (PASS)")
    d.edge("obs", "prb", "0.0647 ≤ p &lt; 0.8793  (BAIT)")
    d.edge("obs", "con", "p ≥ 0.8793  (DIVERT)")
    d.edge("prb", "prb", "probe ignored: k += 1,\nV decays by (1−β)ᵏ")
    d.edge("prb", "con", "BITE: logit(p) += log Λ⁺,\np crosses 0.8793")
    d.edge("prb", "obs", "belief falls below 0.0647")
    d.edge("prb", "wth", "holdout draw")
    d.edge("wth", "obs", "no probe served")
    d.edge("wth", "con", "passive evidence alone\ncrosses the edge")
    d.edge("con", "con", "all further requests\nserved by the decoy")
    d.edge("con", "end", "session ends")
    d.edge("note", "prb", style=E_DASH)
    return d


# ------------------------------------------------------------------------
# Figure 20 — Evaluation harness and arm isolation
# ------------------------------------------------------------------------
def fig20() -> Diagram:
    d = Diagram("Fig 20 - Evaluation harness", vgap=64, hgap=48)
    d.node("seed", "Seed s", style=S_TERMINAL, w=150, h=46)
    d.node("gen", "Deterministic traffic generation\n120 attack + 80 benign sessions",
           style=S_PROCESS, w=290, h=54)
    d.node("t1", "Arm B1\nown port, log dir, database", style=S_PROCESS, w=210, h=54)
    d.node("t2", "Arm B2\nown port, log dir, database", style=S_PROCESS, w=210, h=54)
    d.node("t4", "Arm B4\nown port, log dir, database", style=S_PROCESS, w=210, h=54)
    d.node("r1", "sessions.jsonl", style=S_DATA, w=160, h=48)
    d.node("r2", "sessions.jsonl", style=S_DATA, w=160, h=48)
    d.node("r4", "sessions.jsonl", style=S_DATA, w=160, h=48)
    d.node("mrg", "Merge\nrefuses overlapping seed ranges", style=S_PROCESS, w=270, h=54)
    d.node("st", "Statistical report\nWilson CIs, paired McNemar,\nFisher exact, bootstrap",
           style=S_PROCESS, w=250, h=68)
    d.node("gd", "Digests match\ncurrent config?", style=S_DECISION, w=190, h=90)
    d.node("stop", "REFUSE to plot or report", style=S_WARN, w=210, h=48)
    d.node("fig", "Figures and tables", style=S_ACCENT, w=200, h=48)

    d.layer("seed").layer("gen").layer("t1", "t2", "t4").layer("r1", "r2", "r4")
    d.layer("mrg").layer("st").layer("gd").layer("stop", "fig")

    d.edge("seed", "gen")
    for t in ("t1", "t2", "t4"):
        d.edge("gen", t, "byte-identical")
    d.edge("t1", "r1"); d.edge("t2", "r2"); d.edge("t4", "r4")
    for r in ("r1", "r2", "r4"):
        d.edge(r, "mrg")
    d.edge("mrg", "st"); d.edge("st", "gd")
    d.edge("gd", "stop", "no"); d.edge("gd", "fig", "yes")
    return d


FIGURES = {
    "fig01-graphical-abstract": fig01,
    "fig10-decoy-consistency": fig10,
    "fig11-layered-architecture": fig11,
    "fig12-overall-system-flow": fig12,
    "fig13-sequence-diagram": fig13,
    "fig14-dfd-level-0": fig14,
    "fig15-dfd-level-1": fig15,
    "fig16-use-case-diagram": fig16,
    "fig17-class-diagram": fig17,
    "fig18-session-state-machine": fig18,
    "fig20-evaluation-harness": fig20,
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, fn in FIGURES.items():
        write(OUT / f"{name}.drawio", fn())
    # one combined file with every diagram as a separate page/tab
    write(OUT / "ALL-diagrams.drawio", *[fn() for fn in FIGURES.values()])
    print(f"\n  {len(FIGURES)} diagrams + one combined multi-page file in {OUT}")


if __name__ == "__main__":
    main()
