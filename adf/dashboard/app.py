"""
Read-only monitoring dashboard (spec §14, cut from the core build and restored).

Run it alongside a live proxy or after an evaluation:

    python -m uvicorn adf.dashboard.app:app --host 127.0.0.1 --port 8003

It shows, from the append-only proxy log and the evaluation summaries:
  * the derived decision bands, with each session plotted at its peak malice
    belief and coloured by the action taken -- the mechanism, made visible;
  * headline evaluation numbers (recall by arm, benign diversion, the holdout);
  * every session, and a per-request timeline for any one of them.

It writes nothing and loads no model state beyond the policy's derived bands, so
it is safe to run against live or in-progress data.
"""

from __future__ import annotations

import html

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from adf.dashboard import reader

app = FastAPI(title="ADF Monitor")

# --- design tokens (security console; teal accent, one bold colour) ----------
_CSS = """
:root{--bg:#0e1513;--panel:#151d1a;--panel2:#1b2521;--ink:#e6ede9;--ink2:#9fb0a9;
--ink3:#6c7d76;--line:#26322d;--teal:#54c7a8;--teal2:#2e7d68;--amber:#d9a441;
--red:#e0745e;--grey:#5c6b64}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--teal);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1100px;margin:0 auto;padding:1.5rem}
header{display:flex;flex-wrap:wrap;align-items:baseline;gap:.5rem 1rem;
border-bottom:1px solid var(--line);padding-bottom:1rem;margin-bottom:1.5rem}
h1{font-size:1.25rem;margin:0;font-weight:650;letter-spacing:-.01em}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.muted{color:var(--ink3)}.dim{color:var(--ink2)}
.tag{font-family:ui-monospace,monospace;font-size:.7rem;text-transform:uppercase;
letter-spacing:.08em;padding:.15rem .5rem;border:1px solid var(--line);border-radius:3px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;
background:var(--line);border:1px solid var(--line);border-radius:6px;overflow:hidden;
margin-bottom:1.5rem}
.kpi{background:var(--panel);padding:.9rem 1rem;display:flex;flex-direction:column;gap:.2rem}
.kpi .v{font-size:1.5rem;font-weight:650;font-variant-numeric:tabular-nums}
.kpi .l{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--ink3)}
.kpi .s{font-size:.72rem;color:var(--ink2);font-family:ui-monospace,monospace}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;
padding:1.1rem 1.2rem;margin-bottom:1.5rem}
.panel h2{font-size:.8rem;text-transform:uppercase;letter-spacing:.1em;color:var(--ink2);
margin:0 0 .9rem;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;font-size:.68rem;text-transform:uppercase;letter-spacing:.07em;
color:var(--ink3);font-weight:500;padding:.5rem .6rem;border-bottom:1px solid var(--line)}
td{padding:.5rem .6rem;border-bottom:1px solid var(--line);
font-variant-numeric:tabular-nums;vertical-align:top}
tr:last-child td{border-bottom:none}
.pill{font-family:ui-monospace,monospace;font-size:.68rem;padding:.12rem .45rem;
border-radius:3px;font-weight:600}
.pass{background:#1c2b26;color:var(--grey)}
.bait{background:#2e2513;color:var(--amber)}
.divert{background:#2c1815;color:var(--red)}
.yes{color:var(--teal)}.no{color:var(--ink3)}
.scroll{overflow-x:auto}
.bar{height:6px;border-radius:3px;background:var(--panel2);position:relative;overflow:hidden}
.bar>span{position:absolute;top:0;bottom:0;left:0;background:var(--teal)}
.foot{color:var(--ink3);font-size:.75rem;margin-top:2rem;
border-top:1px solid var(--line);padding-top:1rem}
.health{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.6rem;margin-bottom:1.5rem}
.hc{display:flex;align-items:center;gap:.6rem;background:var(--panel);border:1px solid var(--line);
border-radius:6px;padding:.6rem .8rem}
.dot{width:9px;height:9px;border-radius:50%;flex:none;box-shadow:0 0 0 3px rgba(0,0,0,.25)}
.dot.ok{background:var(--teal)}.dot.warn{background:var(--amber)}.dot.idle{background:var(--grey)}
.hc .n{font-weight:600;font-size:.82rem}.hc .d{font-size:.7rem;color:var(--ink3);
font-family:ui-monospace,monospace}
.flow{stroke-dasharray:6 6;animation:march 1s linear infinite}
@keyframes march{to{stroke-dashoffset:-12}}
@media (prefers-reduced-motion:reduce){.flow{animation:none}}
.dist{display:grid;grid-template-columns:1fr 1fr;gap:1.2rem}
@media (max-width:640px){.dist{grid-template-columns:1fr}}
.stack{display:flex;height:26px;border-radius:4px;overflow:hidden;border:1px solid var(--line);margin:.3rem 0 .1rem}
.stack>span{display:flex;align-items:center;justify-content:center;font-size:.68rem;
font-family:ui-monospace,monospace;color:#0e1513;font-weight:700}
.leg{display:flex;gap:1rem;flex-wrap:wrap;font-size:.72rem;color:var(--ink2);margin-top:.3rem}
.leg i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:.3rem;vertical-align:middle}
"""


def _page(title: str, body: str) -> str:
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{_CSS}</style></head>"
            f"<body><div class='wrap'>{body}</div></body></html>")


def _pill(action: str) -> str:
    a = action if action in ("pass", "bait", "divert") else "pass"
    return f"<span class='pill {a}'>{a}</span>"


def _band_svg(bands: dict, cost_only: float, sessions) -> str:
    """The p-axis 0..1 with PASS/BAIT/DIVERT regions, and each session as a dot
    at its peak malice, coloured by the action taken."""
    W, H, ml, mr = 1040, 150, 20, 20
    x0, x1 = ml, W - mr
    def X(p): return x0 + (x1 - x0) * max(0.0, min(1.0, p))
    p2b, b2d = bands["pass_to_bait"], bands["bait_to_divert"]
    axy = 96  # axis y
    parts = [f"<svg viewBox='0 0 {W} {H}' width='100%' role='img' "
             f"aria-label='Decision bands with sessions plotted by belief'>"]
    # region rects
    parts.append(f"<rect x='{X(0):.1f}' y='{axy-16}' width='{X(p2b)-X(0):.1f}' height='16' fill='#1c2b26'/>")
    parts.append(f"<rect x='{X(p2b):.1f}' y='{axy-16}' width='{X(b2d)-X(p2b):.1f}' height='16' fill='#2e2513'/>")
    parts.append(f"<rect x='{X(b2d):.1f}' y='{axy-16}' width='{X(1)-X(b2d):.1f}' height='16' fill='#2c1815'/>")
    # boundary lines + labels
    for p, lab, col in ((p2b, f"PASS|BAIT  p={p2b:.4f}", "#54c7a8"),
                        (b2d, f"BAIT|DIVERT  p={b2d:.4f}", "#e0745e")):
        parts.append(f"<line x1='{X(p):.1f}' y1='{axy-22}' x2='{X(p):.1f}' y2='{axy+6}' stroke='{col}' stroke-width='1'/>")
    # cost-only boundary (dashed) -- where the two-action rule would divert
    parts.append(f"<line x1='{X(cost_only):.1f}' y1='{axy-28}' x2='{X(cost_only):.1f}' y2='{axy+6}' "
                 f"stroke='#6c7d76' stroke-width='1' stroke-dasharray='3 3'/>")
    parts.append(f"<text x='{X(cost_only):.1f}' y='{axy-32}' fill='#6c7d76' font-size='10' "
                 f"text-anchor='middle' font-family='monospace'>cost-only {cost_only:.3f}</text>")
    # region labels
    parts.append(f"<text x='{(X(0)+X(p2b))/2:.1f}' y='{axy-4}' fill='#9fb0a9' font-size='9' text-anchor='middle'>PASS</text>")
    parts.append(f"<text x='{(X(p2b)+X(b2d))/2:.1f}' y='{axy-4}' fill='#d9a441' font-size='9' text-anchor='middle'>BAIT</text>")
    parts.append(f"<text x='{(X(b2d)+X(1))/2:.1f}' y='{axy-4}' fill='#e0745e' font-size='9' text-anchor='middle'>DIVERT</text>")
    # axis ticks
    for t in (0, 0.25, 0.5, 0.75, 1.0):
        parts.append(f"<text x='{X(t):.1f}' y='{axy+22}' fill='#6c7d76' font-size='9' "
                     f"text-anchor='middle' font-family='monospace'>{t:g}</text>")
    # session dots, jittered vertically so overlaps are visible
    colmap = {"pass": "#5c6b64", "bait": "#d9a441", "divert": "#e0745e"}
    for i, s in enumerate(sessions[:120]):
        col = colmap.get(s.action, "#5c6b64")
        jitter = (i % 7 - 3) * 3
        cy = axy - 40 + jitter
        edge = "#0e1513"
        parts.append(f"<circle cx='{X(s.peak_malice):.1f}' cy='{cy}' r='3.2' "
                     f"fill='{col}' stroke='{edge}' stroke-width='.5'><title>"
                     f"{html.escape(s.session_id[:16])}  p={s.peak_malice:.3f}  {s.action}</title></circle>")
    parts.append("</svg>")
    return "".join(parts)


def _status_color(status: str) -> str:
    return {"ok": "#54c7a8", "warn": "#d9a441", "idle": "#5c6b64"}.get(status, "#5c6b64")


def _topology_svg(traffic: dict, health_by: dict) -> str:
    """A Packet-Tracer-style view: client -> reverse proxy (features -> meter ->
    policy) -> {target | decoy}, with live per-edge traffic counts and animated
    flow. Node borders show component health."""
    f = traffic["flows"]
    def node(x, y, w, h, title, sub, comp, fill="#151d1a"):
        col = _status_color(health_by.get(comp, {}).get("status", "idle"))
        s = (f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='7' fill='{fill}' "
             f"stroke='{col}' stroke-width='1.5'/>"
             f"<circle cx='{x+14}' cy='{y+15}' r='4' fill='{col}'/>"
             f"<text x='{x+26}' y='{y+19}' fill='#e6ede9' font-size='12' font-weight='700'>{title}</text>")
        if sub:
            s += f"<text x='{x+12}' y='{y+h-10}' fill='#9fb0a9' font-size='9.5' font-family='monospace'>{sub}</text>"
        return s
    def edge(x1, y1, x2, y2, label, col, count, up=True):
        mx = (x1 + x2) / 2
        s = (f"<line x1='{x1}' y1='{y1}' x2='{x2}' y2='{y2}' stroke='{col}' stroke-width='2' "
             f"opacity='.55'/>"
             f"<line class='flow' x1='{x1}' y1='{y1}' x2='{x2}' y2='{y2}' stroke='{col}' stroke-width='2'/>"
             f"<polygon points='{x2},{y2} {x2-8},{y2-4} {x2-8},{y2+4}' fill='{col}'/>")
        ly = min(y1, y2) - 8 if up else max(y1, y2) + 16
        s += (f"<text x='{mx}' y='{ly}' fill='#e6ede9' font-size='11' text-anchor='middle' "
              f"font-family='monospace'>{label} <tspan fill='{col}' font-weight='700'>{count}</tspan></text>")
        return s
    p = ["<svg viewBox='0 0 1040 380' width='100%' role='img' aria-label='System topology with live traffic'>"]
    # nodes
    p.append(node(30, 150, 130, 70, "Client", "attacker / user", "_client"))
    # proxy container + internal pipeline
    p.append(node(300, 60, 250, 250, "Reverse Proxy", "adf/proxy · session → decision", "proxy log", "#141d1a"))
    for i,(t,sub) in enumerate([("Feature Extractor","18 features · 2 axes"),
                                 ("Dual Meter","automation · malice"),
                                 ("Cost Policy","EVSI · derived bands")]):
        yy = 108 + i*62
        p.append(f"<rect x='320' y='{yy}' width='210' height='48' rx='5' fill='#1b2521' stroke='#26322d'/>")
        p.append(f"<text x='332' y='{yy+20}' fill='#e6ede9' font-size='11' font-weight='600'>{t}</text>")
        p.append(f"<text x='332' y='{yy+37}' fill='#6c7d76' font-size='9' font-family='monospace'>{sub}</text>")
    # target + decoy
    p.append(node(720, 55, 260, 90, "Target App", "the real, weak application", "target app"))
    p.append(node(720, 205, 260, 110, "Decoy + Fact Notebook", "state-consistent fake site", "decoy app"))
    # edges
    p.append(edge(160, 185, 300, 185, "requests", "#54c7a8", f["client_to_proxy"]))
    p.append(edge(550, 120, 720, 100, "pass / bait", "#5c6b64", f["proxy_to_target"]))
    p.append(edge(550, 250, 720, 250, "divert", "#e0745e", f["proxy_to_decoy"], up=False))
    # bait / bite badges
    p.append(f"<rect x='585' y='150' width='120' height='40' rx='5' fill='#2e2513' stroke='#5a4a1f'/>")
    p.append(f"<text x='645' y='166' fill='#d9a441' font-size='10' text-anchor='middle' font-weight='700'>BAIT injected</text>")
    p.append(f"<text x='645' y='182' fill='#d9a441' font-size='11' text-anchor='middle' font-family='monospace'>{f['baits_injected']}  ·  bites {f['bites']}</text>")
    p.append("</svg>")
    return "".join(p)


def _distribution(traffic: dict) -> str:
    """Two stacked bars: overall action mix, and diversions by class."""
    a = traffic["action_sessions"]; tot = max(1, sum(a.values()))
    def seg(v, col, lab):
        pct = v / tot * 100
        if pct < 0.5: return ""
        txt = str(v) if pct > 6 else ""
        return f"<span style='width:{pct:.1f}%;background:{col}'>{txt}</span>"
    action_bar = ("<div class='stack'>"
                  + seg(a["pass"], "#5c6b64", "pass") + seg(a["bait"], "#d9a441", "bait")
                  + seg(a["divert"], "#e0745e", "divert") + "</div>"
                  "<div class='leg'><span><i style='background:#5c6b64'></i>pass</span>"
                  "<span><i style='background:#d9a441'></i>bait</span>"
                  "<span><i style='background:#e0745e'></i>divert</span></div>")

    # by class rows
    rows = []
    for cls, col in (("attack", "#e0745e"), ("benign", "#54c7a8")):
        c = traffic["by_class"][cls]
        n = c["sessions"]
        if n == 0:
            rows.append(f"<tr><td class='dim'>{cls}</td><td colspan='4' class='muted'>none labelled in this log</td></tr>")
            continue
        rows.append(f"<tr><td class='{'yes' if cls=='attack' else 'dim'}'>{cls}</td>"
                    f"<td>{n}</td><td>{c['diverted']} ({c['diverted']*100//max(1,n)}%)</td>"
                    f"<td>{c['baited']}</td><td class='yes'>{c['bitten']}</td></tr>")
    class_tbl = ("<table style='margin-top:.3rem'><thead><tr><th>class</th><th>sessions</th>"
                 "<th>diverted</th><th>baited</th><th>bit</th></tr></thead><tbody>"
                 + "".join(rows) + "</tbody></table>")

    # who bit
    biters = traffic["biters"]
    if biters:
        bl = "".join(f"<tr><td class='mono' style='font-size:.75rem'>"
                     f"<a href='/session/{html.escape(b['session_id'])}'>{html.escape(b['session_id'][:16])}</a></td>"
                     f"<td class='{'yes' if b['label']=='attack' else 'dim'}'>{b['label']}</td>"
                     f"<td>{b['peak']:.3f}</td></tr>" for b in biters)
        biters_tbl = ("<table><thead><tr><th>session that bit</th><th>class</th><th>peak p</th></tr></thead>"
                      "<tbody>" + bl + "</tbody></table>")
    else:
        biters_tbl = "<p class='muted' style='font-size:.8rem'>no bait was bitten in this log</p>"

    return (f"<div class='dist'>"
            f"<div><h2 style='font-size:.72rem;color:var(--ink3);text-transform:uppercase;letter-spacing:.08em;margin:0 0 .3rem'>Action mix (sessions)</h2>"
            f"{action_bar}<div style='margin-top:1rem'>{class_tbl}</div></div>"
            f"<div><h2 style='font-size:.72rem;color:var(--ink3);text-transform:uppercase;letter-spacing:.08em;margin:0 0 .3rem'>Who bit the bait</h2>"
            f"{biters_tbl}</div></div>")


@app.get("/", response_class=HTMLResponse)
def overview() -> str:
    sessions = reader.load_sessions()
    bands = reader.decision_bands()
    kpis = reader.load_kpis()
    log = reader.latest_proxy_log()

    # --- KPI tiles -----------------------------------------------------------
    tiles = []
    ms = kpis.get("multiseed")
    arms = kpis.get("arms", {})
    def tile(v, l, s=""):
        return (f"<div class='kpi'><span class='v'>{v}</span>"
                f"<span class='l'>{l}</span><span class='s'>{s}</span></div>")
    if ms and ms.get("arms", {}).get("b4_full", {}).get("recall_pooled") is not None:
        b2 = ms["arms"].get("b2_passive", {}); b4 = ms["arms"].get("b4_full", {})
        ci = b4.get("recall_ci95") or [0, 0]
        tiles.append(tile(f"{b4['recall_pooled']:.3f}", "B4 recall (pooled)",
                          f"CI [{ci[0]:.3f},{ci[1]:.3f}] · {ms.get('seeds')} seeds"))
        if b2.get("recall_pooled") is not None:
            tiles.append(tile(f"{b2['recall_pooled']:.3f}", "B2 recall (pooled)", "passive baseline"))
        ho = ms.get("holdout") or {}
        if ho.get("effect") is not None:
            tiles.append(tile(f"+{ho['effect']:.3f}", "holdout effect", f"Fisher p={ho.get('p')}"))
    elif arms:
        for k, lab in (("b4_full", "B4 recall"), ("b2_passive", "B2 recall")):
            if arms.get(k, {}).get("recall") is not None:
                tiles.append(tile(f"{arms[k]['recall']:.2f}", lab, "single draw"))
    if arms.get("b4_full", {}).get("benign_diversion") is not None:
        tiles.append(tile(f"{arms['b4_full']['benign_diversion']:.3f}", "benign diversion", "safety (lower=better)"))
    live_div = sum(1 for s in sessions if s.action == "divert")
    tiles.append(tile(str(len(sessions)), "sessions in log", f"{live_div} diverted"))

    # --- session table -------------------------------------------------------
    rows = []
    for s in sessions[:60]:
        bait = "<span class='yes'>bait</span>" if s.baited else "<span class='no'>·</span>"
        bite = "<span class='yes'>BITE</span>" if s.bitten else "<span class='no'>·</span>"
        lbl = s.label if s.label in ("attack", "benign") else "?"
        lblc = "yes" if lbl == "attack" else ("dim" if lbl == "benign" else "muted")
        pw = int(s.peak_malice * 100)
        rows.append(
            f"<tr><td><a href='/session/{html.escape(s.session_id)}' class='mono'>"
            f"{html.escape(s.session_id[:18])}</a></td>"
            f"<td class='{lblc}'>{lbl}</td><td>{s.n_requests}</td>"
            f"<td><div class='bar'><span style='width:{pw}%'></span></div>"
            f"<span class='muted mono' style='font-size:.7rem'>{s.peak_malice:.3f}</span></td>"
            f"<td>{_pill(s.action)}</td><td>{bait}</td><td>{bite}</td>"
            f"<td class='muted'>{s.first_divert_req or '—'}</td></tr>")
    table = ("<div class='scroll'><table><thead><tr><th>session</th><th>class</th>"
             "<th>reqs</th><th>peak malice p</th><th>action</th><th>bait</th>"
             "<th>bite</th><th>req→divert</th></tr></thead><tbody>"
             + ("".join(rows) or "<tr><td colspan='8' class='muted'>no sessions in the log yet — "
                "run the proxy and send some traffic</td></tr>") + "</tbody></table></div>")

    # --- component health + traffic ------------------------------------------
    health = reader.system_health()
    health_by = {h["component"]: h for h in health}
    traffic = reader.traffic_stats()
    health_cards = "".join(
        f"<div class='hc'><span class='dot {h['status']}'></span>"
        f"<div><div class='n'>{html.escape(h['component'])}</div>"
        f"<div class='d'>{html.escape(str(h['detail']))}</div></div></div>"
        for h in health)

    log_name = log.name if log else "none"
    head = (f"<header><h1>ADF Monitor</h1>"
            f"<span class='tag'>read-only</span>"
            f"<span class='muted mono' style='margin-left:auto'>{html.escape(log_name)}</span></header>")
    health_panel = (f"<div class='panel'><h2>Project health — what is running</h2>"
                    f"<div class='health'>{health_cards}</div></div>")
    topo_panel = (f"<div class='panel'><h2>System topology — live traffic</h2>"
                  f"{_topology_svg(traffic, health_by)}"
                  f"<p class='muted' style='font-size:.78rem;margin:.4rem 0 0'>Every request "
                  f"flows client → proxy → the decision pipeline, then to the real target "
                  f"(pass/bait) or the decoy (divert). Counts and flow are read from the log; "
                  f"node borders show component health.</p></div>")
    dist_panel = f"<div class='panel'><h2>Traffic distribution</h2>{_distribution(traffic)}</div>"
    band_panel = (f"<div class='panel'><h2>Decision bands — sessions by belief</h2>"
                  f"{_band_svg(bands, reader.cost_only_boundary(), sessions)}"
                  f"<p class='muted' style='font-size:.78rem;margin:.4rem 0 0'>Each dot is a "
                  f"session at its peak malice belief, coloured by the action taken. The dashed "
                  f"line is where a two-action rule would divert; the BAIT band exists only "
                  f"because the probe's information value is priced in.</p></div>")
    kpi_row = f"<div class='kpis'>{''.join(tiles)}</div>" if tiles else ""
    body = (head + kpi_row + health_panel + topo_panel + dist_panel + band_panel
            + f"<div class='panel'><h2>Sessions</h2>{table}</div>"
            + "<div class='foot'>Reads the append-only proxy log and the evaluation "
              "summaries. Writes nothing. <a href='/api/kpis'>JSON</a> · "
              "<span class='mono'>python -m uvicorn adf.dashboard.app:app --port 8003</span></div>")
    return _page("ADF Monitor", body)


@app.get("/session/{sid}", response_class=HTMLResponse)
def session_page(sid: str) -> str:
    v = reader.session_detail(sid)
    if v is None:
        return _page("not found", "<header><h1>Session not found</h1></header>"
                     "<p><a href='/'>← back</a></p>")
    rows = []
    for r in v.requests:
        sc = r["scores"]
        act = r["decision"].get("action", "")
        mal = sc.get("p_attack", sc.get("after", {}).get("malice", 0.0))
        auto = sc.get("after", {}).get("automation", 0.0)
        bait = r["bait"].get("bait_id") if r["bait"].get("injected") else ""
        bite = "BITE" if r["bite"].get("occurred") else ""
        status = r["response"].get("status", "")
        path = r["request"].get("path", "")
        q = r["request"].get("query", "")
        pathq = html.escape((path + ("?" + q if q else ""))[:70])
        rows.append(
            f"<tr><td class='muted'>{r.get('seq','')}</td>"
            f"<td class='mono' style='font-size:.78rem'>{pathq}</td>"
            f"<td class='muted'>{status}</td>"
            f"<td>{mal:.3f}</td><td class='muted'>{auto:.3f}</td>"
            f"<td>{_pill(act)}</td>"
            f"<td class='dim mono' style='font-size:.72rem'>{html.escape(bait or '')}</td>"
            f"<td class='yes mono' style='font-size:.72rem'>{bite}</td></tr>")
    meta = (f"<div class='kpis'>"
            f"<div class='kpi'><span class='v'>{v.n_requests}</span><span class='l'>requests</span></div>"
            f"<div class='kpi'><span class='v'>{v.peak_malice:.3f}</span><span class='l'>peak malice</span></div>"
            f"<div class='kpi'><span class='v'>{_pill(v.action)}</span><span class='l'>final action</span></div>"
            f"<div class='kpi'><span class='v'>{'yes' if v.bitten else 'no'}</span><span class='l'>bit a bait</span></div>"
            f"</div>")
    table = ("<div class='scroll'><table><thead><tr><th>seq</th><th>path</th><th>status</th>"
             "<th>malice p</th><th>automation</th><th>action</th><th>bait</th><th>bite</th>"
             "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>")
    lbl = f"<span class='tag'>{v.label}</span>" if v.label in ("attack", "benign") else ""
    body = (f"<header><h1 class='mono'>{html.escape(v.session_id[:24])}</h1>{lbl}"
            f"<span style='margin-left:auto'><a href='/'>← all sessions</a></span></header>"
            + meta + f"<div class='panel'><h2>Request timeline</h2>{table}</div>")
    return _page(f"session {v.session_id[:12]}", body)


@app.get("/api/kpis")
def api_kpis() -> JSONResponse:
    return JSONResponse(reader.load_kpis())


@app.get("/healthz")
def healthz() -> dict:
    log = reader.latest_proxy_log()
    return {"ok": True, "log": log.name if log else None}
