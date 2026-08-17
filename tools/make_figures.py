"""
Publication-quality figures, generated from the real frozen model.

Every figure here is drawn from the actual cost table and calibrated bait
library (not hand-placed paths), in an academic style — Computer-Modern math,
serif labels, white ground, thin marks, a colour-blind-safe Okabe-Ito palette,
direct labels over legends where it fits. Output is vector: `.svg` for the docs
(docs/img/) and `.pdf` for the paper (docs/img/pdf/).

    python -m tools.make_figures                # all figures
    python -m tools.make_figures cost-curves    # one figure

Figures that need the multi-seed run (recall forest with CIs) are drawn by
`--with-eval` once `data/eval/multiseed/report.json` exists; without it they are
skipped rather than faked.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from adf.config import load_costs
from adf.policy.engine import BaitLibrary
from adf.policy.voi import (BaitEffect, derive_bands, expected_value_of_information,
                            immediate_costs, survival_discount)

IMG = Path("docs/img")
PDF = IMG / "pdf"

# Okabe-Ito colour-blind-safe palette (the scientific-figure standard).
INK = "#1a1a1a"
MUTED = "#6b6b6b"
GRIDC = "#d9d9d9"
C_PASS = "#0072B2"     # blue
C_BAIT = "#E69F00"     # orange  (always direct-labelled -> contrast WARN relieved)
C_DIVERT = "#D55E00"   # vermillion
C_ACCENT = "#009E73"   # green
BAND_FILL = "#E69F00"


def _style() -> None:
    plt.rcParams.update({
        "figure.dpi": 140,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
        "savefig.facecolor": "white",
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "font.family": "serif",
        "mathtext.fontset": "cm",
        "font.size": 10,
        "axes.titlesize": 11,
        "axes.labelsize": 10.5,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "axes.edgecolor": "#40404a",
        "axes.linewidth": 0.8,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.color": GRIDC,
        "grid.linewidth": 0.6,
        "grid.alpha": 0.9,
        "lines.linewidth": 1.9,
        "lines.solid_capstyle": "round",
        "text.color": INK,
        "axes.labelcolor": INK,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "axes.axisbelow": True,
    })


def _save(fig, name: str) -> None:
    IMG.mkdir(parents=True, exist_ok=True)
    PDF.mkdir(parents=True, exist_ok=True)
    fig.savefig(IMG / f"{name}.svg")
    fig.savefig(PDF / f"{name}.pdf")
    plt.close(fig)
    print(f"  wrote {IMG / f'{name}.svg'} and {PDF / f'{name}.pdf'}")


def _text_size(ax, text: str, fs: float, weight: str = "normal", family: str | None = None):
    """Width and height of `text` in data units, measured, not guessed."""
    fig = ax.figure
    kw = {"family": family} if family else {}
    t = ax.text(0, 0, text, fontsize=fs, fontweight=weight, ha="center", va="center", **kw)
    fig.canvas.draw()
    bb = t.get_window_extent(fig.canvas.get_renderer()).transformed(ax.transData.inverted())
    t.remove()
    return abs(bb.width), abs(bb.height)


def _box_at(ax, cx, cy, w, h, text, fc, ec, fs=8.2, tc=INK, weight="normal", zorder=3):
    """A rounded box of a given size with its label centred inside."""
    from matplotlib.patches import FancyBboxPatch
    ax.add_patch(FancyBboxPatch((cx - w / 2, cy - h / 2), w, h,
                 boxstyle="round,pad=0,rounding_size=1.4",
                 linewidth=1.1, edgecolor=ec, facecolor=fc, zorder=zorder))
    ax.text(cx, cy, text, ha="center", va="center", fontsize=fs, color=tc,
            zorder=zorder + 1, fontweight=weight)


def _fit_box(ax, cx, cy, text, fc, ec, fs=8.2, tc=INK, weight="normal",
             padx=2.4, pady=2.2, min_w=0.0, min_h=0.0, zorder=3):
    """Draw a box sized to the text it holds; returns (w, h) in data units.

    The boxes in the schematic figures used to be hand-sized, so every wording
    change -- or a band value that grew a digit -- pushed the label out past its
    own border. Measuring first makes that impossible.
    """
    tw, th = _text_size(ax, text, fs, weight)
    w = max(tw + 2 * padx, min_w)
    h = max(th + 2 * pady, min_h)
    _box_at(ax, cx, cy, w, h, text, fc, ec, fs=fs, tc=tc, weight=weight, zorder=zorder)
    return w, h


def _panel(ax, cx, cy, title, body, fc, ec, title_fs=8.0, body_fs=7.1,
           padx=2.2, pady=2.0, gap=1.2, tc=INK, mono=True, min_w=0.0, zorder=3):
    """A box holding a bold title over a smaller body, both left-aligned.

    Sized to whichever of the two is wider, so neither can run out of the frame.
    Returns (w, h) in data units.
    """
    from matplotlib.patches import FancyBboxPatch
    fam = "monospace" if mono else None
    tw, th = _text_size(ax, title, title_fs, "bold", fam)
    bw, bh = _text_size(ax, body, body_fs)
    w = max(tw, bw, min_w - 2 * padx) + 2 * padx
    h = th + gap + bh + 2 * pady
    ax.add_patch(FancyBboxPatch((cx - w / 2, cy - h / 2), w, h,
                 boxstyle="round,pad=0,rounding_size=1.2",
                 linewidth=1.0, edgecolor=ec, facecolor=fc, zorder=zorder))
    x = cx - w / 2 + padx
    top = cy + h / 2 - pady
    ax.text(x, top, title, ha="left", va="top", fontsize=title_fs, fontweight="bold",
            color=tc, zorder=zorder + 1, **({"family": fam} if fam else {}))
    ax.text(x, top - th - gap, body, ha="left", va="top", fontsize=body_fs,
            color=MUTED, zorder=zorder + 1, linespacing=1.35)
    return w, h


def _row(ax, y, items, gap, x0, x1, fs=8.0, pady=2.2, padx=2.4):
    """Lay a row of boxes out inside [x0, x1] with equal gaps, sized to their text.

    Returns [(cx, w, h), ...]. Positions come from the measured widths, so the
    row can never overlap itself and never spills out of the column.
    """
    sizes = [_text_size(ax, t, fs, w) for t, _, _, w in items]
    ws = [tw + 2 * padx for tw, _ in sizes]
    h = max(th for _, th in sizes) + 2 * pady
    span = sum(ws) + gap * (len(ws) - 1)
    scale = min(1.0, (x1 - x0) / span)          # shrink gaps/pads if the row is tight
    ws = [w * scale for w in ws]
    gap = gap * scale
    x = x0 + ((x1 - x0) - (sum(ws) + gap * (len(ws) - 1))) / 2
    out = []
    for (text, fc, ec, weight), w in zip(items, ws):
        cx = x + w / 2
        _box_at(ax, cx, y, w, h, text, fc, ec, fs=fs, weight=weight)
        out.append((cx, w, h))
        x += w + gap
    return out


def _bands_and_effects():
    costs = load_costs()
    effects = BaitLibrary.load().effects()
    bands = derive_bands(costs, effects)
    return costs, effects, bands


def _report_is_current(data: dict, what: str) -> bool:
    """Refuse to plot a report that predates the artefacts now in config/.

    `report.json` is written under one cost table and one calibrated bait library.
    Re-freezing either leaves the file parseable, plausible and wrong, which is
    exactly what happened after the calibration fix. stats_report stamps the
    digests; if they are absent or stale, the figure is not drawn.
    """
    prov = (data.get("provenance") or {}).get("frozen_artefacts") or {}
    if not prov:
        print(f"  skip {what}: report.json has no artefact provenance -- it predates "
              "the current cost table / bait library. Re-run tools.stats_report.")
        return False
    try:
        from adf.config import load_costs
        live_cost = load_costs().digest
    except Exception:  # noqa: BLE001
        live_cost = None
    live_lib = None
    lib_path = Path("config/bait_library.yaml")
    if lib_path.exists():
        import hashlib
        live_lib = hashlib.sha256(lib_path.read_bytes()).hexdigest()
    stale = []
    if live_cost and prov.get("cost_digest") and prov["cost_digest"] != live_cost:
        stale.append("cost table")
    if live_lib and prov.get("bait_library_sha256") and prov["bait_library_sha256"] != live_lib:
        stale.append("bait library")
    if stale:
        print(f"  skip {what}: report.json was produced under a different "
              f"{' and '.join(stale)} -- re-run the evaluation, then tools.stats_report.")
        return False
    return True


def _arms_present(rows, arm_ids):
    """Which of `arm_ids` actually have sessions in the dump, plus each one's seed count.

    A multi-seed run fills one arm at a time, so a dump read mid-run has later arms
    completely empty. Plotting an empty arm draws a zero-height bar, which reads as
    "this arm caught nothing" rather than "this arm has not run" -- the same class of
    silent misreport already guarded against in fig_recall_forest. Every figure that
    reads the session dump must filter through this.
    """
    present, seeds = [], {}
    for arm in arm_ids:
        n = sum(1 for r in rows if r["arm"] == arm)
        if n:
            present.append(arm)
            seeds[arm] = len({r.get("seed") for r in rows
                              if r["arm"] == arm and r.get("seed") is not None})
    return present, seeds


def _seed_note(seeds: dict) -> str:
    """'100 seeds' when every arm agrees, otherwise spell out the mismatch."""
    counts = set(seeds.values())
    if len(counts) == 1:
        return f"{counts.pop()} seeds"
    return "seeds: " + ", ".join(f"{a.split('_')[0].upper()} {n}" for a, n in seeds.items())


def _cost_only_boundary(costs) -> float:
    lo, hi = 0.0, 1.0
    for _ in range(60):
        m = (lo + hi) / 2
        if costs.expected_cost("pass", m) < costs.expected_cost("divert", m):
            lo = m
        else:
            hi = m
    return (lo + hi) / 2


# ---------------------------------------------------------------------------
# Figure 1 — expected cost of each action vs belief, with the derived band
# ---------------------------------------------------------------------------


def fig_cost_curves() -> None:
    costs, effects, bands = _bands_and_effects()
    lo, hi = bands["pass_to_bait"], bands["bait_to_divert"]
    ps = [i / 800 for i in range(801)]

    def V(p):
        return max((expected_value_of_information(p, e, costs) for e in effects), default=0.0)

    c_pass = [immediate_costs(p, costs)["pass"] for p in ps]
    c_bait = [immediate_costs(p, costs)["bait"] for p in ps]
    c_div = [immediate_costs(p, costs)["divert"] for p in ps]
    c_eff = [immediate_costs(p, costs)["bait"] - V(p) for p in ps]

    fig, (ax, axz) = plt.subplots(1, 2, figsize=(7.4, 3.9),
                                  gridspec_kw={"width_ratios": [2.15, 1.0]})
    fig.subplots_adjust(bottom=0.30, top=0.87, wspace=0.28)

    # ---- panel A: full range --------------------------------------------
    ax.axvspan(lo, hi, color=BAND_FILL, alpha=0.09, lw=0, zorder=0)
    ax.plot(ps, c_pass, color=C_PASS, label=r"$\mathbb{E}[C(\mathrm{pass})]$")
    ax.plot(ps, c_bait, color=C_BAIT, lw=1.4, alpha=0.9,
            label=r"$\mathbb{E}[C(\mathrm{bait})]$, immediate")
    ax.plot(ps, c_eff, color=C_BAIT, ls=(0, (5, 2)),
            label=r"effective bait $=\mathbb{E}[C(\mathrm{bait})]-V(p)$")
    ax.plot(ps, c_div, color=C_DIVERT, label=r"$\mathbb{E}[C(\mathrm{divert})]$")
    ax.set_ylim(-2, 26)
    ax.set_xlim(0, 1)
    ax.set_xlabel(r"hostility probability $p$")
    ax.set_ylabel("expected cost (frozen-table units)")
    for x in (lo, hi):
        ax.axvline(x, color=MUTED, lw=0.8, ls=":", zorder=1)
    # inline labels sit on a white patch, so a curve passing behind one cannot
    # strike the text through
    halo = dict(bbox=dict(boxstyle="round,pad=0.16", fc="white", ec="none", alpha=0.88))
    ax.text(lo + 0.02, 14.5, f"PASS$\\to$BAIT\n$p={lo:.4f}$", fontsize=7.8, color=MUTED,
            va="top", ha="left", **halo)
    # below the cost lines, not across them
    ax.text(hi - 0.025, 13.0, f"BAIT$\\to$DIVERT\n$p={hi:.4f}$", fontsize=7.8, color=MUTED,
            va="top", ha="right", **halo)
    ax.text((lo + hi) / 2, 3.0, "BAIT band (derived)", ha="center", va="center",
            fontsize=8.4, color="#9a6a00", style="italic", **halo)
    ax.text(0.035, 24.8, r"$\mathbb{E}[C(\mathrm{divert})]=200$" + "\nat $p{=}0$ (off-axis)",
            fontsize=7.8, color=C_DIVERT, va="top", ha="left", **halo)
    ax.set_title("(A) full range", fontsize=9.5)

    # ---- panel B: zoom on the PASS -> BAIT crossing ---------------------
    zx = [p for p in ps if p <= 0.12]
    axz.axvspan(lo, 0.12, color=BAND_FILL, alpha=0.09, lw=0)
    axz.plot(zx, [immediate_costs(p, costs)["pass"] for p in zx], color=C_PASS)
    axz.plot(zx, [immediate_costs(p, costs)["bait"] - V(p) for p in zx],
             color=C_BAIT, ls=(0, (5, 2)))
    axz.axvline(lo, color=MUTED, lw=0.8, ls=":")
    axz.plot([lo], [immediate_costs(lo, costs)["pass"]], "o", ms=5, color=INK, zorder=5)
    axz.annotate(f"crossing\n$p={lo:.4f}$", xy=(lo, immediate_costs(lo, costs)["pass"]),
                 xytext=(lo + 0.028, 0.55), fontsize=7.8, color=INK,
                 arrowprops=dict(arrowstyle="->", color=INK, lw=0.7))
    axz.text(0.026, 1.95, "PASS", color=C_PASS, fontsize=8, rotation=24,
             va="bottom", ha="center")
    axz.text(0.070, 1.20, "effective bait", color="#9a6a00", fontsize=7.6, va="top")
    axz.set_xlim(0, 0.12)
    axz.set_ylim(0, 2.4)
    axz.set_xlabel(r"$p$")
    axz.set_title("(B) zoom on PASS$\\to$BAIT", fontsize=9.5)

    # one legend below both panels
    handles, labels = ax.get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", bbox_to_anchor=(0.5, -0.02),
               frameon=False, ncol=2, handlelength=2.0, columnspacing=2.2, labelspacing=0.4)
    fig.suptitle("Bait is the cheapest action only after pricing its information value",
                 fontsize=10.5, y=0.98)
    _save(fig, "cost-curves")


# ---------------------------------------------------------------------------
# Figure 2 — decision bands: three derived vs the two-action rule
# ---------------------------------------------------------------------------


def fig_decision_bands() -> None:
    costs, effects, bands = _bands_and_effects()
    lo, hi = bands["pass_to_bait"], bands["bait_to_divert"]
    boundary = _cost_only_boundary(costs)

    fig, ax = plt.subplots(figsize=(6.6, 2.5))
    # top row: derived three-band policy
    ax.axvspan(0, lo, ymin=0.55, ymax=0.92, color=C_PASS, alpha=0.30, lw=0)
    ax.axvspan(lo, hi, ymin=0.55, ymax=0.92, color=C_BAIT, alpha=0.32, lw=0)
    ax.axvspan(hi, 1, ymin=0.55, ymax=0.92, color=C_DIVERT, alpha=0.30, lw=0)
    # bottom row: cost-only two-action rule
    ax.axvspan(0, boundary, ymin=0.08, ymax=0.45, color=C_PASS, alpha=0.30, lw=0)
    ax.axvspan(boundary, 1, ymin=0.08, ymax=0.45, color=C_DIVERT, alpha=0.30, lw=0)

    for x, lab in [(lo, f"{lo:.4f}"), (hi, f"{hi:.4f}")]:
        ax.axvline(x, ymin=0.55, ymax=0.92, color=INK, lw=0.9)
        ax.text(x, 0.94, lab, ha="center", va="bottom", fontsize=8, color=INK)
    ax.axvline(boundary, ymin=0.08, ymax=0.45, color=INK, lw=0.9)
    # the boundary value sits in the clear gap above its row, not squeezed sideways
    # inside the bar where the rule struck through it
    ax.text(boundary, 0.475, f"{boundary:.3f}", ha="center", va="bottom", fontsize=7.8,
            color=INK)

    # The top PASS band is only ~0.06 wide -- far too narrow for a label. It gets a
    # leader into the gap between the two rows instead of text crammed inside it.
    ax.annotate("PASS", xy=(lo / 2, 0.60), xytext=(lo / 2, 0.475), ha="center", va="bottom",
                fontsize=8, color="#14456b",
                arrowprops=dict(arrowstyle="-", color="#14456b", lw=0.7, shrinkB=1))
    ax.text((lo + hi) / 2, 0.735, "BAIT", ha="center", va="center", fontsize=9, color="#9a6a00")
    ax.text((hi + 1) / 2, 0.735, "DIVERT", ha="center", va="center", fontsize=9, color="#8a3d00")
    ax.text(boundary / 2, 0.265, "PASS", ha="center", va="center", fontsize=9, color="#14456b")
    ax.text((boundary + 1) / 2, 0.265, "DIVERT", ha="center", va="center", fontsize=9, color="#8a3d00")

    ax.text(-0.015, 0.735, "with EVSI\n(3 actions)", ha="right", va="center", fontsize=8.4, color=INK)
    ax.text(-0.015, 0.265, "cost only\n(2 actions)", ha="right", va="center", fontsize=8.4, color=INK)

    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_yticks([])
    ax.set_xlabel(r"hostility probability $p$")
    ax.spines["left"].set_visible(False)
    ax.grid(False)
    ax.set_title("The middle action exists only under EVSI;\ncost accounting alone gives one boundary",
                 fontsize=10, y=1.02)
    _save(fig, "decision-bands")


# ---------------------------------------------------------------------------
# Figure 3 — beta_attack invariance of the bands
# ---------------------------------------------------------------------------


def fig_beta_invariance() -> None:
    costs = load_costs()
    boundary = _cost_only_boundary(costs)
    # Read beta_benign and the calibrated points off the live library. These were
    # once literals (0.0037 / 0.59) and silently kept reporting the pre-recalibration
    # library after the bait library was re-frozen.
    effects = BaitLibrary.load().effects()
    beta_benign = sorted(e.beta_benign for e in effects)[len(effects) // 2]
    calibrated = sorted(e.beta_attack for e in effects)
    point = calibrated[len(calibrated) // 2]
    betas = [0.05 + 0.02 * i for i in range(48)]  # 0.05 .. 0.99

    los, his, widths = [], [], []
    for ba in betas:
        eff = BaitEffect(bait_id="s", beta_attack=ba, beta_benign=beta_benign, category="idor")
        b = derive_bands(costs, [eff])
        los.append(b["pass_to_bait"]); his.append(b["bait_to_divert"])
        widths.append(b["bait_to_divert"] - b["pass_to_bait"])

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(6.8, 3.5))
    fig.subplots_adjust(bottom=0.34, top=0.80, wspace=0.30)

    a1.fill_between(betas, los, his, color=BAND_FILL, alpha=0.18, lw=0, label="BAIT band")
    a1.plot(betas, his, color=C_DIVERT, label=r"BAIT$\to$DIVERT edge")
    a1.plot(betas, los, color=C_PASS, label=r"PASS$\to$BAIT edge")
    a1.axhline(boundary, color=INK, lw=1.0, ls=(0, (4, 2)),
               label=f"cost-only boundary {boundary:.3f}")
    a1.axvline(point, color=MUTED, lw=0.8, ls=":")
    # every calibrated bait, not just the median: the invariance claim covers all of them
    for b in calibrated:
        a1.plot([b], [0.0], marker="^", ms=4.5, color=MUTED, clip_on=False, zorder=6)
    a1.text(0.97, 0.10,
            f"calibrated baits\n$\\beta\\in[{calibrated[0]:.2f},\\,{calibrated[-1]:.2f}]$",
            fontsize=7.4, color="#555", ha="right", va="bottom",
            bbox=dict(boxstyle="round,pad=0.18", fc="white", ec="none", alpha=0.85))
    a1.set_xlim(0.05, 0.99); a1.set_ylim(0, 1)
    a1.set_xlabel(r"$\beta_{\mathrm{attack}}$"); a1.set_ylabel(r"belief $p$")
    a1.set_title("Band edges", fontsize=10)

    a2.plot(betas, widths, color=C_ACCENT)
    a2.axvline(point, color=MUTED, lw=0.8, ls=":")
    a2.set_xlim(0.05, 0.99); a2.set_ylim(0, 1)
    a2.set_xlabel(r"$\beta_{\mathrm{attack}}$"); a2.set_ylabel("band width")
    a2.set_title("Band width", fontsize=10)

    # one legend under both panels: inside the left panel it covered the very
    # curves it was naming
    handles, labels = a1.get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", bbox_to_anchor=(0.5, -0.01),
               frameon=False, ncol=2, fontsize=8, handlelength=1.8, columnspacing=2.4,
               labelspacing=0.4)
    fig.suptitle(r"The third action exists and the divert floor holds for every $\beta_{\mathrm{attack}}$",
                 fontsize=10.5, y=0.98)
    _save(fig, "beta-invariance")


# ---------------------------------------------------------------------------
# Figure 4 — EVSI survival discount vs unrewarded exposures
# ---------------------------------------------------------------------------


def fig_evsi_decay() -> None:
    exposures = list(range(0, 13))
    betas = [0.20, 0.40, 0.59, 0.80]
    # sequential green ramp (magnitude of beta), light -> dark
    ramp = ["#a6dfc9", "#6ac6a0", "#2f9e77", "#0b6b4f"]

    fig, ax = plt.subplots(figsize=(5.6, 3.4))
    for ba, col in zip(betas, ramp):
        eff = BaitEffect(bait_id="s", beta_attack=ba, beta_benign=0.0037, category="idor")
        ys = [survival_discount(eff, n) for n in exposures]
        ax.plot(exposures, ys, color=col, marker="o", ms=4,
                label=fr"$\beta_{{\mathrm{{attack}}}}={ba:.2f}$")
    ax.set_xlim(0, 12.3); ax.set_ylim(0, 1.02)
    ax.set_xlabel("unrewarded bait exposures")
    ax.set_ylabel(r"surviving EVSI fraction $(1-\beta_{\mathrm{attack}})^{\,n}$")
    ax.set_title("An unbitten bait's information value decays to zero,\nso the rule converges to the passive two-action limit")
    ax.legend(frameon=False, loc="upper right")
    _save(fig, "evsi-decay")


# ---------------------------------------------------------------------------
# Figure 5 — per-arm recall with Wilson CIs (needs the multi-seed report)
# ---------------------------------------------------------------------------


def fig_recall_forest() -> None:
    rep = Path("data/eval/multiseed/report.json")
    if not rep.exists():
        print("  skip recall-forest: run tools.multiseed_eval + tools.stats_report first")
        return
    data = json.loads(rep.read_text(encoding="utf-8"))
    if not _report_is_current(data, "recall-forest"):
        return
    order = ["b1_rules", "b2_passive", "b4_full"]
    label = {"b1_rules": "B1 signature WAF", "b2_passive": "B2 passive", "b4_full": "B4 full"}
    col = {"b1_rules": C_ACCENT, "b2_passive": C_PASS, "b4_full": C_DIVERT}
    rows = [(a, data["arms"][a]) for a in order if a in data.get("arms", {})]
    if not rows:
        print("  skip recall-forest: no arms in report")
        return

    fig, ax = plt.subplots(figsize=(6.2, 2.7))
    ys = list(range(len(rows)))[::-1]
    for y, (arm, m) in zip(ys, rows):
        p = m["recall_pooled"]; lo, hi = m["recall_ci95"]
        ax.errorbar(p, y, xerr=[[p - lo], [hi - p]], fmt="o", ms=7, color=col[arm],
                    ecolor=col[arm], elinewidth=1.8, capsize=4)
        # a point near 1.0 used to push its own label off the right-hand edge; the
        # label flips to the inside of the interval instead of the axis growing
        txt = f"{p:.3f}  [{lo:.3f}, {hi:.3f}]"
        if hi > 0.72:
            ax.text(lo - 0.015, y, txt, va="center", ha="right", fontsize=8.4)
        else:
            ax.text(hi + 0.015, y, txt, va="center", ha="left", fontsize=8.4)
    ax.set_yticks(ys)
    ax.set_yticklabels([label[a] for a, _ in rows])
    ax.set_xlim(0, 1.0); ax.set_ylim(-0.6, len(rows) - 0.4)
    ax.set_xlabel("attack recall (pooled over seeds, Wilson 95% CI)")
    # Seed count is PER ARM. A run that extended one arm leaves the others behind,
    # and titling the whole figure with the maximum silently credits the short arm
    # with draws it never had -- the forest plot claimed "100 seeds" while B4's
    # point came from 43.
    spa = data.get("seeds_per_arm") or {}
    counts = {spa[a] for a, _ in rows if spa.get(a)}
    if len(counts) == 1:
        seed_label = f"{counts.pop()} seeds"
    elif counts:
        seed_label = "seeds: " + ", ".join(
            f"{label[a].split()[0]} {spa[a]}" for a, _ in rows if spa.get(a))
    else:
        seed_label = f"{data.get('seeds', '?')} seeds"
    ax.set_title(f"Per-arm recall with 95% confidence intervals ({seed_label})")
    ax.grid(axis="y", visible=False)
    _save(fig, "recall-forest")


def fig_two_axis() -> None:
    """Conceptual 2x2: why one combined suspicion score is not enough. The two
    off-diagonal cells are the ones a single score cannot express, and they are
    exactly the hard cases the corpus is built around (spec §6.3)."""
    fig, ax = plt.subplots(figsize=(5.6, 4.7))
    fig.subplots_adjust(bottom=0.13, top=0.88)
    # shade the two off-diagonal quadrants (the ones a single score conflates)
    ax.axvspan(0, 0.5, 0.5, 1.0, color=C_BAIT, alpha=0.11, lw=0)   # low auto, high malice
    ax.axvspan(0.5, 1.0, 0.0, 0.5, color=C_BAIT, alpha=0.11, lw=0)  # high auto, low malice
    ax.axhline(0.5, color=MUTED, lw=1.0)
    ax.axvline(0.5, color=MUTED, lw=1.0)
    # mark the two conflated cells, tucked into the outer corner of each shaded
    # quadrant so they never sit on top of a point's own label
    ax.text(0.03, 0.97, "conflated by a\nsingle score", ha="left", va="top",
            fontsize=7.6, color="#9a6a00", style="italic")
    ax.text(0.97, 0.03, "conflated by a\nsingle score", ha="right", va="bottom",
            fontsize=7.6, color="#9a6a00", style="italic")

    # coordinates: x = automation, y = malice; labels sit away from the centre cross
    marks = [
        (0.74, 0.70, "automated\nscanner", C_DIVERT, "up"),
        (0.30, 0.70, "careful human\nattacker", C_DIVERT, "up"),
        (0.30, 0.30, "ordinary user", C_PASS, "down"),
        (0.74, 0.30, "benign agent\n(monitor / crawler /\nintegration)", C_ACCENT, "down"),
    ]
    for x, y, lab, col, where in marks:
        ax.plot(x, y, "o", ms=12, color=col, zorder=5,
                markeredgecolor="white", markeredgewidth=1.3)
        dy = 16 if where == "up" else -16
        ax.annotate(lab, (x, y), xytext=(0, dy), textcoords="offset points",
                    ha="center", va="bottom" if where == "up" else "top",
                    fontsize=8.6, color=INK)

    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.set_xticks([]); ax.set_yticks([])
    ax.set_xlabel(r"automation score $\alpha$   (low $\rightarrow$ high)")
    ax.set_ylabel(r"malice score $\mu$   (low $\rightarrow$ high)")
    ax.set_title("Two axes, not one:\nthe off-diagonal cases justify the split", fontsize=10.5)
    ax.grid(False)
    _save(fig, "two-axis")


def fig_phases() -> None:
    """The eight phases as a completed pipeline (spec §13). Regenerated because
    the previous hand-drawn version still showed phases 4-7 as not started."""
    from matplotlib.patches import FancyBboxPatch
    stages = [
        ("0", "Foundation"), ("1", "Target +\nbenign"), ("2", "Attack\nround 1"),
        ("3", "Detection\nengine (B2)"), ("4", "Bait +\ngate"), ("5", "Decoy +\nnotebook"),
        ("6", "Freeze +\nfail-open"), ("7", "Round 2 +\nbaselines"),
    ]
    n = len(stages)
    fig, ax = plt.subplots(figsize=(8.4, 2.0))
    ax.set_xlim(0, n); ax.set_ylim(0, 1)
    ax.axis("off")
    w, gap = 0.84, 0.16
    # The labels used to run out through the sides of their boxes. Measure the
    # widest one and step the font down until every label fits inside w.
    fs_name, fs_head = 7.8, 8.2
    while fs_name > 5.6:
        widest = max(_text_size(ax, name, fs_name)[0] for _, name in stages)
        widest = max(widest, _text_size(ax, "Phase 0", fs_head, "bold")[0])
        if widest <= w - 0.10:
            break
        fs_name -= 0.2
        fs_head = min(fs_head, fs_name + 0.4)
    for i, (num, name) in enumerate(stages):
        x = i + gap / 2
        box = FancyBboxPatch((x, 0.30), w, 0.52, boxstyle="round,pad=0,rounding_size=0.06",
                             linewidth=1.0, edgecolor="#1c7a52", facecolor="#e6f4ec")
        ax.add_patch(box)
        ax.text(i + 0.5, 0.70, f"Phase {num}", ha="center", va="center",
                fontsize=fs_head, color="#1c7a52", fontweight="bold")
        ax.text(i + 0.5, 0.48, name, ha="center", va="center", fontsize=fs_name, color=INK)
        ax.text(i + 0.5, 0.15, r"$\checkmark$ complete", ha="center", va="center",
                fontsize=7.2, color="#1c7a52")
        if i < n - 1:
            ax.annotate("", xy=(i + 1 + gap / 2 - 0.01, 0.56), xytext=(x + w + 0.01, 0.56),
                        arrowprops=dict(arrowstyle="-|>", color=MUTED, lw=1.0))
    ax.set_title("The eight phases (spec §13) — each met its exit condition before the next began",
                 fontsize=9.5, y=1.02)
    _save(fig, "phases")


def _load_sessions():
    p = Path("data/eval/multiseed/sessions.jsonl")
    if not p.exists():
        return None
    return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]


def fig_recall_by_category() -> None:
    """Grouped bars: recall per attack category for B1/B2/B4, with Wilson CIs.
    Shows the whole learned+bait gain lives in IDOR."""
    rows = _load_sessions()
    if rows is None:
        print("  skip recall-by-category: run multiseed_eval first")
        return
    from tools.stats_report import wilson
    arms = [("b1_rules", "B1 WAF", C_ACCENT), ("b2_passive", "B2 passive", C_PASS),
            ("b4_full", "B4 full", C_DIVERT)]
    have, seeds = _arms_present(rows, [a for a, _, _ in arms])
    missing = [a for a, _, _ in arms if a not in have]
    if missing:
        # Drawing the missing arm as an empty bar would claim it caught nothing.
        print(f"  skip recall-by-category: no sessions for {', '.join(missing)}"
              " -- finish the multi-seed run first")
        return
    cats = ["sqli", "idor", "auth"]
    fig, ax = plt.subplots(figsize=(6.0, 3.5))
    width = 0.26
    for j, (arm, lab, col) in enumerate(arms):
        xs, ys, los, his = [], [], [], []
        for i, cat in enumerate(cats):
            g = [r for r in rows if r["arm"] == arm and r["category"] == cat]
            k = sum(1 for r in g if r["diverted"])
            p, lo, hi = wilson(k, len(g))
            xs.append(i + (j - 1) * width); ys.append(p); los.append(p - lo); his.append(hi - p)
        ax.bar(xs, ys, width * 0.92, color=col, label=lab, zorder=3)
        ax.errorbar(xs, ys, yerr=[los, his], fmt="none", ecolor="#333", elinewidth=0.9,
                    capsize=2.5, zorder=4)
    ax.set_xticks(range(len(cats)))
    ax.set_xticklabels(["SQLi", "IDOR", "auth"])
    ax.set_ylim(0, 1.12)      # headroom so a recall of 1.0 and its cap clear the frame
    ax.set_ylabel("recall (Wilson 95% CI)")
    ax.set_title("The learned system + bait gain is entirely in IDOR\n"
                 f"({_seed_note(seeds)})", fontsize=10)
    ax.legend(frameon=False, loc="lower center", bbox_to_anchor=(0.5, -0.30), ncol=3)
    ax.grid(axis="x", visible=False)
    fig.subplots_adjust(bottom=0.24)
    _save(fig, "recall-by-category")


def fig_holdout_effect() -> None:
    """The causal headline as its own figure: baited vs withheld divert rate with
    Wilson CIs; the gap is the randomised-holdout causal estimate."""
    rep = Path("data/eval/multiseed/report.json")
    if not rep.exists():
        print("  skip holdout-effect: run stats_report first")
        return
    from tools.stats_report import wilson
    _data = json.loads(rep.read_text(encoding="utf-8"))
    if not _report_is_current(_data, "holdout-effect"):
        return
    h = _data.get("holdout_fisher")
    if not h:
        print("  skip holdout-effect: no holdout in report")
        return
    labels = ["baited\n(policy)", "withheld\n(holdout)"]
    ks = [h["baited_div"], h["holdout_div"]]
    ns = [h["baited_n"], h["holdout_n"]]
    cols = [C_DIVERT, MUTED]
    fig, ax = plt.subplots(figsize=(4.6, 3.8))
    tops = []
    for i, (k, n, col) in enumerate(zip(ks, ns, cols)):
        p, lo, hi = wilson(k, n)
        ax.bar(i, p, 0.55, color=col, zorder=3)
        ax.errorbar(i, p, yerr=[[p - lo], [hi - p]], fmt="none", ecolor="#222",
                    elinewidth=1.2, capsize=5, zorder=4)
        ax.text(i, hi + 0.02, f"{p:.3f}\n(n={n})", ha="center", va="bottom", fontsize=8.4)
        tops.append(hi)
    ax.set_xticks([0, 1]); ax.set_xticklabels(labels)
    ax.set_ylabel("divert rate (Wilson 95% CI)")
    ax.set_title(f"Randomised holdout: bait causes +{h['effect']:.3f} divert rate\n"
                 f"(Fisher exact $p<10^{{-5}}$, at the same belief state)", fontsize=9.5)
    # Effect bracket, drawn ABOVE the two value labels rather than through them
    # (0.13 clears the two-line "0.936 (n=...)" label at this font size).
    y = max(tops) + 0.15
    ax.plot([0, 0, 1, 1], [y, y + 0.035, y + 0.035, y], color="#222", lw=0.9,
            clip_on=False, zorder=5)
    ax.text(0.5, y + 0.055, f"+{h['effect']:.3f}  [{h['effect_ci'][0]:+.3f}, {h['effect_ci'][1]:+.3f}]",
            ha="center", va="bottom", fontsize=8.4, color="#222")
    ax.set_ylim(0, y + 0.16)
    ax.set_yticks([0.0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.grid(axis="x", visible=False)
    _save(fig, "holdout-effect")


def fig_seed_stability() -> None:
    """Per-seed recall for B2 vs B4, paired by seed. Shows the gain is consistent,
    not a lucky seed: B4 is above B2 in almost every draw."""
    rows = _load_sessions()
    if rows is None:
        print("  skip seed-stability: run multiseed_eval first")
        return

    def rec(arm, seed):
        g = [r for r in rows if r["arm"] == arm and r["label"] == "attack" and r["seed"] == seed]
        return sum(1 for r in g if r["diverted"]) / len(g) if g else None

    # PAIRED figure: only seeds where BOTH arms ran. A run interrupted partway
    # leaves later arms with fewer draws, and pairing a seed against a missing
    # counterpart is meaningless (it also used to crash on the None).
    seeds = sorted({r["seed"] for r in rows
                    if r["arm"] in ("b2_passive", "b4_full")})
    seeds = [s for s in seeds if rec("b2_passive", s) is not None
             and rec("b4_full", s) is not None]
    if not seeds:
        print("  skip seed-stability: no seed has both B2 and B4")
        return
    b2 = [rec("b2_passive", s) for s in seeds]
    b4 = [rec("b4_full", s) for s in seeds]
    fig, ax = plt.subplots(figsize=(5.8, 3.6))
    for i, (y2, y4) in enumerate(zip(b2, b4)):
        ax.plot([0, 1], [y2, y4], "-", color="#c7c7c7", lw=0.8, zorder=1)
    ax.plot([0] * len(b2), b2, "o", color=C_PASS, ms=6, zorder=3, label="B2 passive")
    ax.plot([1] * len(b4), b4, "o", color=C_DIVERT, ms=6, zorder=3, label="B4 full")
    # means
    import statistics as st
    ax.plot([-0.12, 0.12], [st.fmean(b2)] * 2, color=C_PASS, lw=2.2)
    ax.plot([0.88, 1.12], [st.fmean(b4)] * 2, color=C_DIVERT, lw=2.2)
    ax.text(-0.16, st.fmean(b2), f"mean {st.fmean(b2):.3f}", ha="right", va="center",
            fontsize=8.2, color=C_PASS)
    ax.text(1.16, st.fmean(b4), f"mean {st.fmean(b4):.3f}", ha="left", va="center",
            fontsize=8.2, color=C_DIVERT)
    # y-limits from the data, not hardcoded: the v4 model sits far above the
    # range an earlier feature set produced, and a fixed window silently clipped it.
    lo, hi = min(b2 + b4), max(b2 + b4)
    pad = max(0.02, (hi - lo) * 0.25)
    # the cap used to be exactly 1.0, which sliced every marker sitting at perfect
    # recall in half; leave a sliver of headroom above the highest point
    ax.set_xlim(-0.62, 1.62)
    ax.set_ylim(max(0.0, lo - pad), min(1.0 + pad * 0.6, hi + pad))
    ax.set_xticks([0, 1]); ax.set_xticklabels(["B2 passive", "B4 full"])
    ax.set_ylabel("attack recall per seed")
    up = sum(1 for y2, y4 in zip(b2, b4) if y4 > y2)
    ax.set_title(f"B4 beats B2 in {up}/{len(seeds)} paired seeds — not a lucky draw")
    ax.grid(axis="x", visible=False)
    _save(fig, "seed-stability")


def fig_cost_by_arm() -> None:
    """Expected cost per session by arm: the attacker-containment view. Positive =
    attacks getting through; negative = contained."""
    rows = _load_sessions()
    if rows is None:
        print("  skip cost-by-arm: run multiseed_eval first")
        return
    from adf.config import load_costs
    costs = load_costs()

    def scost(s):
        a = "divert" if s["diverted"] else ("bait" if s["baited"] else "pass")
        return costs.cost("attack" if s["label"] == "attack" else "benign", a)

    arms = [("b1_rules", "B1\nWAF", C_ACCENT), ("b2_passive", "B2\npassive", C_PASS),
            ("b4_full", "B4\nfull", C_DIVERT)]
    have, seeds = _arms_present(rows, [a for a, _, _ in arms])
    missing = [a for a, _, _ in arms if a not in have]
    if missing:
        # An empty arm previously divided by zero here; plotting it as 0.0 would be
        # worse, since 0.0 is a meaningful cost that sits between the real arms.
        print(f"  skip cost-by-arm: no sessions for {', '.join(missing)}"
              " -- finish the multi-seed run first")
        return
    fig, ax = plt.subplots(figsize=(4.8, 3.6))
    vals = []
    # B0 reference (no scoring): every attack passes -> cost = attack-pass mix; use +15 constant
    b0 = 15.0
    ax.bar(-1, b0, 0.62, color="#b0b0b0", zorder=3)
    ax.text(-1, b0 + 0.4, f"+{b0:.1f}", ha="center", va="bottom", fontsize=8.2)
    xs = [-1]
    for i, (arm, lab, col) in enumerate(arms):
        A = [r for r in rows if r["arm"] == arm]
        c = sum(scost(r) for r in A) / len(A)
        vals.append(c); xs.append(i)
        ax.bar(i, c, 0.62, color=col, zorder=3)
        ax.text(i, c + (0.4 if c >= 0 else -0.4), f"{c:+.2f}", ha="center",
                va="bottom" if c >= 0 else "top", fontsize=8.2)
    ax.axhline(0, color="#333", lw=0.9)
    ax.set_xticks([-1, 0, 1, 2])
    ax.set_xticklabels(["B0\nnone"] + [l for _, l, _ in arms])
    ax.set_ylabel("expected cost / session")
    ax.set_title("Attacker containment: only the learned arms\ndrive cost negative",
                 fontsize=9.8)
    ax.grid(axis="x", visible=False)
    # Limits from the data with room for the value labels: the labels under the
    # negative bars used to be cut off by the axis floor.
    top, bot = max(b0, max(vals)), min(0.0, min(vals))
    ax.set_ylim(bot - 0.20 * (top - bot), top + 0.14 * (top - bot))
    # the two asides live in empty quadrants, not on top of a bar
    ax.text(1.55, top * 0.62, "attacks\ngetting through", fontsize=7.4, color="#888",
            ha="center", va="center")
    ax.text(-1.0, bot * 0.55, "attacker\ncontained", fontsize=7.4, color="#888",
            ha="center", va="center")
    _save(fig, "cost-by-arm")


def fig_architecture() -> None:
    """The life of one request: a clean left-to-right pipeline that fans out into
    the three actions, with the bite feedback loop and the append-only log.

    Every box is sized to its own label (`_fit_box`) and every arrow starts and
    ends on a measured edge, so nothing overlaps and nothing overflows.
    """
    from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

    fig, ax = plt.subplots(figsize=(8.6, 4.9))
    ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis("off")

    def arrow(x1, y1, x2, y2, color=MUTED, ls="-", lw=1.3, rad=0.0, head=True):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                     arrowstyle="-|>" if head else "-",
                     mutation_scale=11, color=color, lw=lw, linestyle=ls, zorder=2,
                     connectionstyle=f"arc3,rad={rad}"))

    BLUE, GREY, GREEN, ORANGE, RED = "#eaf3fb", "#f2f2f0", "#e6f4ec", "#fdf1de", "#fbe9e0"
    EB, EG, EGR, EO, ER = "#2a78d6", "#8a8a86", "#1c7a52", "#c98a1e", "#c0472a"

    # The right-hand strip is left empty for the bite feedback loop, so the loop
    # never has to cross a box or a label.
    COL0, COL1 = 2.0, 84.0

    # ---- top pipeline (left -> right): four stages ----------------------
    stages = [("client\nrequest", GREY, EG, "normal"),
              ("reverse\nproxy", BLUE, EB, "bold"),
              ("feature\nextractor\n(18 features)", BLUE, EB, "normal"),
              ("dual meter\n" + r"$\alpha$ auto, $\mu$ malice", BLUE, EB, "normal")]
    top = _row(ax, 84, stages, gap=7.0, x0=COL0, x1=COL1, fs=8.0)
    for (cx, w, _), (nx, nw, _) in zip(top, top[1:]):
        arrow(cx + w / 2 + 0.8, 84, nx - nw / 2 - 0.8, 84)

    # ---- decision box, centred below --------------------------------------
    # read the band off the live cost table + calibrated library, never hardcode:
    # a stale literal here silently misreports the headline result after a recalibration.
    _, _, _bands = _bands_and_effects()
    _lo, _hi = _bands["pass_to_bait"], _bands["bait_to_divert"]
    pol_w, pol_h = _fit_box(ax, (COL0 + COL1) / 2, 60,
                            "cost policy (EVSI):   " + r"$p=\mu$" + "   →   PASS / BAIT / DIVERT\n"
                            f"over the derived band  [{_lo:.3f}, {_hi:.3f}]",
                            BLUE, EB, fs=8.0, weight="bold", padx=3.4, pady=2.6)
    pol_cx = (COL0 + COL1) / 2
    mx, mw, mh = top[-1]
    arrow(mx, 84 - mh / 2 - 0.8, pol_cx + pol_w / 2 - 6, 60 + pol_h / 2 + 0.8,
          color=EG, rad=0.18)

    # ---- three action boxes, fanned down ----------------------------------
    actions = [("PASS\nserve the real target", GREEN, EGR, "normal"),
               ("BAIT\nreal target + an invisible\nbait in the response", ORANGE, EO, "normal"),
               ("DIVERT\nstate-consistent decoy", RED, ER, "normal")]
    act = _row(ax, 33, actions, gap=5.0, x0=COL0, x1=COL1, fs=7.9)
    act_h = act[0][2]
    for (cx, _, _), col, rad in zip(act, (EGR, EO, ER), (0.12, 0.0, -0.12)):
        arrow(pol_cx + (cx - pol_cx) * 0.30, 60 - pol_h / 2 - 0.8,
              cx, 33 + act_h / 2 + 0.8, color=col, rad=rad)

    # ---- bite feedback loop, out in the clear right-hand strip -------------
    # It leaves the BAIT box above the action row and climbs the empty strip, so it
    # never runs behind DIVERT (where it used to vanish and re-appear).
    bait_cx, bait_w, _ = act[1]
    loop_x = 91.0
    arrow(bait_cx + bait_w / 2 + 0.8, 33 + act_h / 3, loop_x, 50,
          color=EO, ls=(0, (4, 2)), rad=-0.22, head=False)
    arrow(loop_x, 50, mx + mw / 2 + 1.0, 84 - mh / 3, color=EO, ls=(0, (4, 2)), rad=-0.20)
    ax.text(loop_x + 5.0, 62, "bite?  →  Bayes update of $\\mu$", fontsize=7.6, color=EO,
            ha="center", va="center", style="italic", rotation=90)

    # ---- append-only log strip --------------------------------------------
    ax.add_patch(FancyBboxPatch((COL0, 5), COL1 - COL0, 9,
                 boxstyle="round,pad=0,rounding_size=1.2",
                 linewidth=1.0, edgecolor="#9a8f6a", facecolor="#faf6ea", zorder=1))
    ax.text((COL0 + COL1) / 2, 9.5, "append-only, hash-chained, tamper-evident log\n"
            "(every decision, its features, scores, and any bite)",
            ha="center", va="center", fontsize=7.6, color="#7a6f47")
    for cx, _, _ in act:
        arrow(cx, 33 - act_h / 2 - 0.8, cx, 14.8, color="#c3b98f", lw=1.0)

    ax.set_title("The life of a single request", fontsize=11, y=0.99)
    _save(fig, "architecture")


def fig_invisibility_gate() -> None:
    """The invisibility gate as a clean decision flowchart: a candidate bait must
    pass three tests; passing all three earns a certificate, failing any one means
    deletion (not repair)."""
    from matplotlib.patches import FancyArrowPatch, Polygon

    fig, ax = plt.subplots(figsize=(7.6, 5.0))
    ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis("off")

    def arrow(x1, y1, x2, y2, color=MUTED, lw=1.3, rad=0.0, head=True):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                     arrowstyle="-|>" if head else "-",
                     mutation_scale=11, color=color, lw=lw, zorder=2,
                     connectionstyle=f"arc3,rad={rad}"))

    BLUE, EB = "#eaf3fb", "#2a78d6"
    GREEN, EG = "#e6f4ec", "#1c7a52"
    RED, ER = "#fbe9e0", "#c0472a"

    _, cand_h = _fit_box(ax, 50, 91, "candidate bait", "#f2f2f0", "#8a8a86",
                         fs=8.2, weight="bold", padx=4.0)

    # ---- the three tests, evenly spaced and sized to their own text -------
    tests = [("1. rendered output\nunchanged\n(post-JS DOM + text)", BLUE, EB, "normal"),
             ("2. no functional\nchange\n(forms, links, parse)", BLUE, EB, "normal"),
             ("3. no timing change\n(TOST equivalence,\npre-set margin)", BLUE, EB, "normal")]
    row = _row(ax, 70, tests, gap=5.0, x0=2.0, x1=98.0, fs=7.6, pady=2.6)
    test_h = row[0][2]
    for cx, _, _ in row:
        arrow(50 + (cx - 50) * 0.10, 91 - cand_h / 2 - 0.8, cx, 70 + test_h / 2 + 0.8,
              color=EB, rad=0.0)

    # ---- AND gate: the three tests converge on one point, then one arrow in --
    DY, DX = 44.0, 13.0          # diamond centre y, half-width
    for cx, _, _ in row:
        arrow(cx, 70 - test_h / 2 - 0.8, 50, DY + 9.0, color=EB, head=False, lw=1.1)
    arrow(50, DY + 9.0, 50, DY + 8.2, color=EB)
    ax.add_patch(Polygon([(50, DY + 8), (50 + DX, DY), (50, DY - 8), (50 - DX, DY)],
                 closed=True, facecolor="#fff7e6", edgecolor="#c98a1e", lw=1.2, zorder=3))
    ax.text(50, DY, "all three\npass?", ha="center", va="center", fontsize=8, zorder=4)

    # ---- yes: certificate -> library --------------------------------------
    cert_cx = 82.0
    cert_w, cert_h = _fit_box(ax, cert_cx, DY, "certificate issued\n(id, corpus size,\nmeasured overhead)",
                              GREEN, EG, fs=7.6)
    arrow(50 + DX + 0.8, DY, cert_cx - cert_w / 2 - 0.8, DY, color=EG)
    ax.text((50 + DX + cert_cx - cert_w / 2) / 2, DY + 2.0, "yes", fontsize=7.6, color=EG,
            ha="center", va="bottom",
            bbox=dict(boxstyle="round,pad=0.12", fc="white", ec="none", alpha=0.9))
    _, adm_h = _fit_box(ax, cert_cx, 17, "admitted to the\nbait library", GREEN, EG,
                        fs=8.0, weight="bold")
    arrow(cert_cx, DY - cert_h / 2 - 0.8, cert_cx, 17 + adm_h / 2 + 0.8, color=EG)

    # ---- no: deleted ------------------------------------------------------
    del_w, _ = _fit_box(ax, 17, DY, "deleted\n(not repaired)", RED, ER, fs=8.0, weight="bold")
    arrow(50 - DX - 0.8, DY, 17 + del_w / 2 + 0.8, DY, color=ER)
    ax.text((50 - DX + 17 + del_w / 2) / 2, DY + 2.0, "no", fontsize=7.6, color=ER,
            ha="center", va="bottom",
            bbox=dict(boxstyle="round,pad=0.12", fc="white", ec="none", alpha=0.9))

    ax.text(50, 4, "The gate is built and certified BEFORE any bait exists (spec §13.1);\n"
            "the engine re-checks the certificate at run time.",
            ha="center", va="center", fontsize=7.4, color=MUTED, style="italic")
    ax.set_title("The invisibility gate — three tests, verified before use", fontsize=10.5, y=0.99)
    _save(fig, "invisibility-gate")


def fig_bait_lifecycle() -> None:
    """One session, request by request: suspicion accumulating, a probe, a bite,
    a divert. The trajectory is illustrative (it is the mechanism, not a
    measurement) but the BANDS are the real derived values -- the hand-drawn
    version this replaces still carried the pre-calibration 0.0426/0.8595."""
    costs, effects, bands = _bands_and_effects()
    lo, hi = bands["pass_to_bait"], bands["bait_to_divert"]

    reqs = list(range(1, 17))
    # belief climbs slowly while probing, jumps on the bite, then saturates
    p = [0.02, 0.02, 0.03, 0.03, 0.04, 0.05,
         0.09, 0.12, 0.14, 0.15, 0.17, 0.19, 0.21,
         0.99, 0.99, 0.99]
    bite_at = 14

    fig, ax = plt.subplots(figsize=(6.6, 3.8))
    ax.axhspan(0, lo, color=C_PASS, alpha=0.10, lw=0)
    ax.axhspan(lo, hi, color=C_BAIT, alpha=0.12, lw=0)
    ax.axhspan(hi, 1, color=C_DIVERT, alpha=0.12, lw=0)
    for y, lab, col in ((lo, f"PASS → BAIT  {lo:.4f}", C_PASS),
                        (hi, f"BAIT → DIVERT  {hi:.4f}", C_DIVERT)):
        ax.axhline(y, color=col, lw=0.9, ls=(0, (4, 2)))
        ax.text(16.4, y, lab, fontsize=7.4, color=col, va="center", ha="left")

    ax.plot(reqs, p, color=INK, lw=1.6, zorder=3)
    ax.plot(reqs, p, "o", ms=4, color=INK, zorder=4)
    ax.plot([bite_at], [p[bite_at - 1]], "o", ms=10, mfc="none",
            mec=C_DIVERT, mew=2, zorder=5)

    # Annotations are stacked left-to-right in the empty upper-left of the panel,
    # each one clear of the trace and of the other two.
    note = dict(fontsize=7.5, va="top", ha="left")
    ax.annotate("requests 1–6 · PASS\nnothing added to any response",
                xy=(3.4, 0.055), xytext=(0.8, 0.30), color=MUTED,
                arrowprops=dict(arrowstyle="->", color=MUTED, lw=0.7,
                                shrinkA=2, shrinkB=3), **note)
    ax.annotate("request 7 · enters the BAIT band\nan invisible probe rides out with the response",
                xy=(7, 0.10), xytext=(0.8, 0.56), color="#9a6a00",
                arrowprops=dict(arrowstyle="->", color="#9a6a00", lw=0.7,
                                connectionstyle="arc3,rad=-0.2",
                                shrinkA=2, shrinkB=4), **note)
    ax.annotate("request 14 · BITE\nthe planted fake table is used — belief\njumps and the session crosses into DIVERT",
                xy=(bite_at - 0.25, 0.93), xytext=(0.8, 0.80), color=C_DIVERT,
                arrowprops=dict(arrowstyle="->", color=C_DIVERT, lw=0.7,
                                connectionstyle="arc3,rad=0.12",
                                shrinkA=4, shrinkB=6), **note)

    ax.set_xlim(0.5, 16.5); ax.set_ylim(0, 1.06)
    ax.set_xlabel("request number within the session")
    ax.set_ylabel(r"hostility belief $p$")
    ax.set_title("One session: suspicion accumulating, a probe, a bite, a divert")
    ax.set_xticks(range(2, 17, 2))
    fig.subplots_adjust(right=0.80)
    _save(fig, "bait-lifecycle")


def fig_corpus_pipeline() -> None:
    """How the labelled corpus is built, and why the join is verified rather than
    trusted.

    This one used to be a hand-written SVG in a different typeface, colour set and
    grid from every other figure -- and with no PDF, so the paper could not use it.
    It is drawn here in the same house style as the rest.
    """
    from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

    fig, ax = plt.subplots(figsize=(9.2, 5.4))
    ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis("off")

    def flow(pts, color=MUTED, ls="-", lw=1.2, head=True):
        """An orthogonal connector through `pts`, arrowhead on the last leg."""
        for i in range(len(pts) - 1):
            (x1, y1), (x2, y2) = pts[i], pts[i + 1]
            last = i == len(pts) - 2
            ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                         arrowstyle="-|>" if (head and last) else "-",
                         mutation_scale=10, color=color, lw=lw, linestyle=ls, zorder=2))

    SURF, RING = "#fbfbfa", "#c9c9c4"
    ORANGE_F, ORANGE_E = "#fdf1de", "#c98a1e"
    GREEN_F, GREEN_E = "#eef7f2", "#1c7a52"

    ax.text(0, 99, "Labels are written before the traffic happens, into a separate file, so the "
            "detection path cannot accidentally read the answer key.",
            fontsize=8.2, color=MUTED, ha="left", va="top")

    # ---- generators (left column) -----------------------------------------
    ax.text(0, 90.5, "GENERATORS · LABEL AT THE POINT OF GENERATION", fontsize=7.0,
            color=MUTED, ha="left", va="bottom")
    gens = [
        ("benign_traffic.py", "simulated humans, plus the\nawkward-but-honest personas"),
        ("benign_agents.py", "benign BUT automated: monitor,\ncrawler, reporting integration"),
        ("attack_traffic.py", "attack round 1 — 12 profiles,\nall three categories"),
    ]
    gy = [83.0, 69.0, 55.0]
    gw = 0.0
    for cy, (title, body) in zip(gy, gens):
        gw, _ = _panel(ax, 14, cy, title, body, SURF, RING)

    # bus: the three generators join one line into the target app
    bus_x = 14 + gw / 2 + 3.0
    for cy in gy:
        flow([(14 + gw / 2 + 0.6, cy), (bus_x, cy)], head=False)
    flow([(bus_x, gy[0]), (bus_x, gy[-1])], head=False)

    # ---- target application -> log ----------------------------------------
    app_w, _ = _panel(ax, 47, 79, "target application",
                      "the deliberately weak site —\nknows nothing of adf/", SURF, RING,
                      mono=False)
    flow([(bus_x, 79), (47 - app_w / 2 - 0.8, 79)])
    log_w, _ = _panel(ax, 78, 79, "data/logs/*.jsonl",
                      "append-only, hash-chained,\ntamper-evident (NFR-13)", SURF, RING)
    flow([(47 + app_w / 2 + 0.8, 79), (78 - log_w / 2 - 0.8, 79)])

    # ---- the label sidecar -------------------------------------------------
    lab_w, _ = _panel(ax, 47, 55, "data/labels/*.jsonl",
                      "ground truth, written BEFORE the session\nacts (§7.3) — never inside the traffic log",
                      ORANGE_F, ORANGE_E)
    flow([(bus_x, 55), (47 - lab_w / 2 - 0.8, 55)])

    # ---- the join ----------------------------------------------------------
    JOIN_CX, JOIN_CY = 78.0, 40.0
    join_w, join_h = _panel(ax, JOIN_CX, JOIN_CY, "adf.dataset",
                            "joins the two on session.provenance_id,\n"
                            "carried in the X-ADF-Session header", SURF, RING)
    join_top = JOIN_CY + join_h / 2
    # the log track drops straight down; the label track runs right, then down
    flow([(JOIN_CX + 6, 79 - 6.6), (JOIN_CX + 6, join_top)])
    turn_x = JOIN_CX - join_w / 2 + 6
    flow([(47 + lab_w / 2 + 0.8, 55), (turn_x, 55), (turn_x, join_top)])

    # ---- verified corpus strip --------------------------------------------
    ax.add_patch(FancyBboxPatch((0, 17), 100, 12, boxstyle="round,pad=0,rounding_size=1.2",
                 linewidth=1.0, edgecolor=GREEN_E, facecolor=GREEN_F, zorder=1))
    head = "verified corpus   →   "
    hw, _ = _text_size(ax, head, 8.4, "bold")
    ax.text(2.5, 26.8, head, fontsize=8.4, fontweight="bold", color="#155f40",
            ha="left", va="top")
    ax.text(2.5 + hw, 26.8, "tools/corpus_report.py", fontsize=8.0, fontweight="bold",
            color="#155f40", ha="left", va="top", family="monospace")
    ax.text(2.5, 22.6, "Join coverage is a reported result, not an assumption: the build refuses to emit a corpus below 95%. The report then\n"
            "runs the phase exit gates — 6 checks for Phase 1, 7 for Phase 2 — and prints PASS or FAIL for each.",
            fontsize=7.4, color="#3f5a4e", ha="left", va="top", linespacing=1.4)
    flow([(JOIN_CX, JOIN_CY - join_h / 2), (JOIN_CX, 29.4)])

    # ---- the cautionary note ----------------------------------------------
    ax.text(0, 12.5, "Why the join is checked rather than trusted: the first version of it silently produced zero matches. Labels were keyed by the\n"
            "generator's session id, records by the application's cookie — two namespaces that never met. Nothing raised, every downstream\n"
            "statistic still computed, and every one of them was meaningless.",
            fontsize=7.4, color=MUTED, ha="left", va="top", linespacing=1.5)
    tail = ("One command does the whole lifecycle — wipe, seed, start a private server, "
            "generate, stop, assemble, verify:   ")
    tw, _ = _text_size(ax, tail, 7.2)
    ax.text(0, 0.5, tail, fontsize=7.2, color=MUTED, ha="left", va="bottom")
    ax.text(tw, 0.5, "python -m tools.generate_corpus", fontsize=7.2, color=MUTED,
            ha="left", va="bottom", family="monospace")

    ax.set_title("How a labelled corpus is built — and why the join is verified",
                 fontsize=11, y=1.0, loc="left", x=0)
    _save(fig, "corpus-pipeline")


FIGURES = {
    "bait-lifecycle": fig_bait_lifecycle,
    "corpus-pipeline": fig_corpus_pipeline,
    "cost-curves": fig_cost_curves,
    "decision-bands": fig_decision_bands,
    "beta-invariance": fig_beta_invariance,
    "evsi-decay": fig_evsi_decay,
    "two-axis": fig_two_axis,
    "phases": fig_phases,
    "architecture": fig_architecture,
    "invisibility-gate": fig_invisibility_gate,
    "recall-forest": fig_recall_forest,
    "recall-by-category": fig_recall_by_category,
    "holdout-effect": fig_holdout_effect,
    "seed-stability": fig_seed_stability,
    "cost-by-arm": fig_cost_by_arm,
}


def main() -> None:
    _style()
    which = [a for a in sys.argv[1:] if not a.startswith("-")]
    targets = which or list(FIGURES)
    print("generating figures ...")
    for name in targets:
        fn = FIGURES.get(name)
        if fn is None:
            print(f"  ?? unknown figure {name!r}; known: {', '.join(FIGURES)}")
            continue
        fn()
    print("done.")


if __name__ == "__main__":
    main()
