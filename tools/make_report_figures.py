"""Two figures the project report needs that `make_figures` does not produce.

Both draw from data already on disk, in the same style as `tools/make_figures.py`
(Okabe-Ito palette, serif + computer-modern maths), so they sit alongside the
existing fifteen without looking foreign.

  fig_reliability   -- the reliability diagram behind Section 4.5.3. The report
                       quotes two of its bins; a diagram makes the sign flip
                       around 0.6 visible at a glance rather than by reading a
                       fourteen-row table.
  fig_adaptive      -- the adaptive-adversary sweep of Section 4.4.9: the bite
                       rate collapses to zero as awareness reaches one while the
                       diversion rate does not move, which is the whole point.

Run:  python -m tools.make_report_figures
"""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from tools.make_figures import _style, _save, C_PASS, C_BAIT, C_DIVERT, C_ACCENT, INK, MUTED
from tools.fit_calibration import load_draw, SPLIT


NBINS = 15


def _reliability_bins():
    """(bin_centres, mean_belief, actual_rate, counts, total) over the held-out split."""
    rows = []
    for d in sorted(SPLIT.glob("s*")):
        rows += list(load_draw(d) or [])
    if not rows:
        raise SystemExit("no calibration draws found under " + str(SPLIT))
    ps = np.array([r[0] for r in rows], dtype=float)
    ys = np.array([r[1] for r in rows], dtype=float)

    centres, means, actuals, counts = [], [], [], []
    for i in range(NBINS):
        lo, hi = i / NBINS, (i + 1) / NBINS
        sel = (ps >= lo) & (ps < hi)
        if i == NBINS - 1:
            sel |= ps == 1.0
        n = int(sel.sum())
        if n == 0:
            continue
        centres.append((lo + hi) / 2)
        means.append(float(ps[sel].mean()))
        actuals.append(float(ys[sel].mean()))
        counts.append(n)
    return (np.array(centres), np.array(means), np.array(actuals),
            np.array(counts), len(ps))


def fig_reliability() -> None:
    """Reliability diagram of the shipped belief, with bin populations beneath.

    The shipped meter is over-confident below about 0.6 and under-confident above
    it. Plotting mean predicted against observed frequency puts that sign flip on
    one axis. The population strip beneath, and the fading of sparse bins, exist
    so a reader does not over-weight the two bins that hold four and five
    requests respectively -- joining every bin with a line would draw a zig-zag
    implying a continuity the data does not have, so no line is drawn.
    """
    _style()
    centres, means, actuals, counts, total = _reliability_bins()

    fig, (ax, axn) = plt.subplots(
        2, 1, figsize=(6.2, 5.6), height_ratios=[3.0, 1.0], sharex=True)

    ax.axvspan(0.0, 0.6, color=C_DIVERT, alpha=0.05, zorder=0)
    ax.axvspan(0.6, 1.0, color=C_ACCENT, alpha=0.05, zorder=0)

    ax.plot([0, 1], [0, 1], ls=(0, (4, 3)), lw=1.3, color=MUTED, zorder=1,
            label="perfect calibration")

    sizes = 22 + 190 * (counts / counts.max())
    big = counts >= 100
    ax.scatter(means[big], actuals[big], s=sizes[big], color=C_PASS,
               edgecolor="white", linewidth=0.9, zorder=4,
               label="observed  (bin n ≥ 100)")
    ax.scatter(means[~big], actuals[~big], s=sizes[~big], color=C_PASS,
               edgecolor="white", linewidth=0.7, alpha=0.30, zorder=3,
               label="observed  (bin n < 100)")

    ax.text(0.26, 0.965, "over-confident region\n(predicted > observed)",
            ha="center", va="top", fontsize=8.3, color=C_DIVERT)
    ax.text(0.815, 0.30, "under-confident region\n(predicted < observed)",
            ha="center", va="center", fontsize=8.3, color=C_ACCENT)

    def _annotate(target_centre, text, tx, ty):
        idx = int(np.argmin(np.abs(centres - target_centre)))
        ax.annotate(text, xy=(means[idx], actuals[idx]), xytext=(tx, ty),
                    fontsize=8.2, color=INK, ha="left", va="center",
                    arrowprops=dict(arrowstyle="-", lw=0.8, color=MUTED,
                                    shrinkA=0, shrinkB=6))

    _annotate(0.1667,
              "[0.13, 0.20)   n = 2,225\nmean belief 0.163,\nbut 0.4% are attacks",
              0.24, 0.16)
    _annotate(0.6333,
              "[0.60, 0.67)   n = 555\nmean belief 0.633,\nbut 87% are attacks",
              0.055, 0.735)

    ax.set_ylabel("observed attack rate")
    ax.set_xlim(0, 1)
    ax.set_ylim(-0.04, 1.06)
    ax.set_title("Reliability of the shipped belief\n"
                 f"({total:,} held-out requests, {NBINS} equal-width bins)",
                 fontsize=10.5, pad=8)
    ax.legend(loc="lower right", frameon=False, fontsize=8.3)

    axn.bar(centres, counts, width=(1.0 / NBINS) * 0.85, color=MUTED, alpha=0.5)
    axn.set_yscale("log")
    axn.set_ylabel("requests\nper bin (log)")
    axn.set_xlabel("mean predicted belief in bin")
    axn.grid(axis="x", visible=False)

    fig.align_ylabels([ax, axn])
    _save(fig, "reliability")


def fig_adaptive() -> None:
    """Bite rate against attacker bait-awareness, with the divert rate alongside.

    Section 4.4.9's table is easy to misread as "the system always wins". The
    figure is drawn to make the actual, narrower claim legible: the bite rate
    really does collapse to zero, and the diversion rate really does not move,
    because the passive floor carries the session on its own.
    """
    _style()
    awareness = np.array([0.00, 0.25, 0.50, 0.75, 1.00])
    bite_slow = np.array([0.925, 0.975, 0.850, 0.775, 0.000])
    div_slow = np.array([1.000, 1.000, 1.000, 1.000, 1.000])
    div_esc = np.array([0.952, 1.000, 1.000, 1.000, 1.000])

    fig, ax = plt.subplots(figsize=(6.4, 4.0))

    ax.plot(awareness, div_slow, "-o", color=C_PASS, ms=5.5,
            label="diverted — low-and-slow attacker")
    ax.plot(awareness, div_esc, "--s", color=C_ACCENT, ms=5.0,
            label="diverted — escalating attacker")
    ax.plot(awareness, bite_slow, "-^", color=C_BAIT, ms=5.5,
            label="bite rate — low-and-slow attacker")

    ax.annotate("bite rate reaches zero:\nevery probe is refused",
                xy=(1.00, 0.000), xytext=(0.74, 0.315), fontsize=8.4, color=INK,
                ha="center",
                arrowprops=dict(arrowstyle="->", lw=0.9, color=MUTED,
                                shrinkA=2, shrinkB=5))
    ax.annotate("diversion rate does not move —\nthe passive floor holds",
                xy=(0.50, 1.000), xytext=(0.34, 0.755), fontsize=8.4, color=INK,
                ha="center",
                arrowprops=dict(arrowstyle="->", lw=0.9, color=MUTED,
                                shrinkA=2, shrinkB=5))

    ax.set_xlabel("attacker bait-awareness   (0 = follows a hint, 1 = never bites)")
    ax.set_ylabel("rate")
    ax.set_ylim(-0.06, 1.10)
    ax.set_xlim(-0.04, 1.06)
    ax.set_xticks(awareness)
    ax.set_title("Adaptive adversary: withdrawing every bite\nleaves the passive floor intact",
                 fontsize=10.5, pad=8)
    ax.legend(loc="lower left", frameon=False, fontsize=8.4,
              bbox_to_anchor=(0.0, 0.02))
    _save(fig, "adaptive-adversary")


def main() -> None:
    fig_reliability()
    fig_adaptive()


if __name__ == "__main__":
    main()
