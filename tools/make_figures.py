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
from matplotlib.patches import Patch

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


def _bands_and_effects():
    costs = load_costs()
    effects = BaitLibrary.load().effects()
    bands = derive_bands(costs, effects)
    return costs, effects, bands


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
    ax.text(lo + 0.02, 15.5, f"PASS$\\to$BAIT\n$p={lo:.4f}$", fontsize=7.8, color=MUTED,
            va="top", ha="left")
    ax.text(hi - 0.02, 24.4, f"BAIT$\\to$DIVERT\n$p={hi:.4f}$", fontsize=7.8, color=MUTED,
            va="top", ha="right")
    ax.text((lo + hi) / 2, 3.0, "BAIT band (derived)", ha="center", va="center",
            fontsize=8.4, color="#9a6a00", style="italic")
    ax.text(0.03, 22.5, r"$\mathbb{E}[C(\mathrm{divert})]=200$" + "\nat $p{=}0$ (off-axis)",
            fontsize=7.8, color=C_DIVERT, va="top", ha="left")
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
    axz.text(0.028, 1.9, "PASS", color=C_PASS, fontsize=8, rotation=22)
    axz.text(0.052, 1.15, "effective bait", color="#9a6a00", fontsize=7.6)
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

    fig, ax = plt.subplots(figsize=(6.2, 2.35))
    # top row: derived three-band policy
    ax.axvspan(0, lo, ymin=0.55, ymax=0.92, color=C_PASS, alpha=0.30, lw=0)
    ax.axvspan(lo, hi, ymin=0.55, ymax=0.92, color=C_BAIT, alpha=0.32, lw=0)
    ax.axvspan(hi, 1, ymin=0.55, ymax=0.92, color=C_DIVERT, alpha=0.30, lw=0)
    # bottom row: cost-only two-action rule
    ax.axvspan(0, boundary, ymin=0.08, ymax=0.45, color=C_PASS, alpha=0.30, lw=0)
    ax.axvspan(boundary, 1, ymin=0.08, ymax=0.45, color=C_DIVERT, alpha=0.30, lw=0)

    for x, lab in [(lo, f"{lo:.4f}"), (hi, f"{hi:.4f}")]:
        ax.axvline(x, ymin=0.55, ymax=0.92, color=INK, lw=0.9)
        ax.text(x, 0.95, lab, ha="center", va="bottom", fontsize=8, color=INK)
    ax.axvline(boundary, ymin=0.08, ymax=0.45, color=INK, lw=0.9)
    ax.text(boundary, 0.265, f"{boundary:.3f}", ha="center", va="center", fontsize=7.5,
            color=INK, rotation=90,
            bbox=dict(boxstyle="round,pad=0.12", fc="white", ec="none", alpha=0.85))

    # the top PASS band is only ~0.05 wide, so its label rides vertically inside it
    ax.text(lo / 2, 0.735, "PASS", ha="center", va="center", fontsize=7.5,
            color="#14456b", rotation=90)
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
    ax.set_title("The middle action exists only under EVSI; cost accounting alone gives one boundary")
    _save(fig, "decision-bands")


# ---------------------------------------------------------------------------
# Figure 3 — beta_attack invariance of the bands
# ---------------------------------------------------------------------------


def fig_beta_invariance() -> None:
    costs = load_costs()
    boundary = _cost_only_boundary(costs)
    beta_benign = 0.0037
    point = 0.59
    betas = [0.05 + 0.02 * i for i in range(48)]  # 0.05 .. 0.99

    los, his, widths = [], [], []
    for ba in betas:
        eff = BaitEffect(bait_id="s", beta_attack=ba, beta_benign=beta_benign, category="idor")
        b = derive_bands(costs, [eff])
        los.append(b["pass_to_bait"]); his.append(b["bait_to_divert"])
        widths.append(b["bait_to_divert"] - b["pass_to_bait"])

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(6.6, 3.1))

    a1.fill_between(betas, los, his, color=BAND_FILL, alpha=0.18, lw=0, label="BAIT band")
    a1.plot(betas, his, color=C_DIVERT, label=r"BAIT$\to$DIVERT edge")
    a1.plot(betas, los, color=C_PASS, label=r"PASS$\to$BAIT edge")
    a1.axhline(boundary, color=INK, lw=1.0, ls=(0, (4, 2)),
               label=f"cost-only boundary {boundary:.3f}")
    a1.axvline(point, color=MUTED, lw=0.8, ls=":")
    a1.text(point + 0.015, 0.14, "calibrated\n$\\beta{=}0.59$", fontsize=7.4, color="#555",
            bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.75))
    a1.set_xlim(0.05, 0.99); a1.set_ylim(0, 1)
    a1.set_xlabel(r"$\beta_{\mathrm{attack}}$"); a1.set_ylabel(r"belief $p$")
    a1.set_title("Band edges", fontsize=10)
    a1.legend(loc="center left", bbox_to_anchor=(-0.02, 0.5), frameon=False,
              fontsize=7.6, handlelength=1.6, labelspacing=0.3)

    a2.plot(betas, widths, color=C_ACCENT)
    a2.axvline(point, color=MUTED, lw=0.8, ls=":")
    a2.set_xlim(0.05, 0.99); a2.set_ylim(0, 1)
    a2.set_xlabel(r"$\beta_{\mathrm{attack}}$"); a2.set_ylabel("band width")
    a2.set_title("Band width", fontsize=10)

    fig.suptitle(r"The third action exists and the divert floor holds for every $\beta_{\mathrm{attack}}$",
                 fontsize=10.5, y=1.02)
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
    from tools.stats_report import wilson
    data = json.loads(rep.read_text(encoding="utf-8"))
    order = ["b1_rules", "b2_passive", "b4_full"]
    label = {"b1_rules": "B1 signature WAF", "b2_passive": "B2 passive", "b4_full": "B4 full"}
    col = {"b1_rules": C_ACCENT, "b2_passive": C_PASS, "b4_full": C_DIVERT}
    rows = [(a, data["arms"][a]) for a in order if a in data.get("arms", {})]
    if not rows:
        print("  skip recall-forest: no arms in report")
        return

    fig, ax = plt.subplots(figsize=(6.0, 2.6))
    ys = list(range(len(rows)))[::-1]
    for y, (arm, m) in zip(ys, rows):
        p = m["recall_pooled"]; lo, hi = m["recall_ci95"]
        ax.errorbar(p, y, xerr=[[p - lo], [hi - p]], fmt="o", ms=7, color=col[arm],
                    ecolor=col[arm], elinewidth=1.8, capsize=4)
        ax.text(hi + 0.012, y, f"{p:.3f}  [{lo:.3f}, {hi:.3f}]", va="center", fontsize=8.4)
    ax.set_yticks(ys)
    ax.set_yticklabels([label[a] for a, _ in rows])
    ax.set_xlim(0, 1.0); ax.set_ylim(-0.6, len(rows) - 0.4)
    ax.set_xlabel("attack recall (pooled over seeds, Wilson 95% CI)")
    n = data.get("seeds", "?")
    ax.set_title(f"Per-arm recall with 95% confidence intervals ({n} seeds)")
    ax.grid(axis="y", visible=False)
    _save(fig, "recall-forest")


FIGURES = {
    "cost-curves": fig_cost_curves,
    "decision-bands": fig_decision_bands,
    "beta-invariance": fig_beta_invariance,
    "evsi-decay": fig_evsi_decay,
    "recall-forest": fig_recall_forest,
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
