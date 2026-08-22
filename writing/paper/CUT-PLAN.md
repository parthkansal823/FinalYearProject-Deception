# Cut plan: 20,138 words → ~4,900, for ITI 2026 (Springer LNNS, 10–12 pages)

## The mandated structure, which is not the draft's structure

ITI 2026 requires every paper to carry, in order:

> abstract · keywords · introduction · **literature review** · **methodology** ·
> **results** · **discussion** · conclusion · references

The draft is organised as a systems paper — threat model, system, decision rule,
calibration, consistency, evaluation, ablations, limitations, related work. Six of
those top-level sections have to collapse into *Methodology*, and two new
headings (*Literature review* at the front, *Discussion* near the back) have to
exist. The remap:

| required section | comes from |
|---|---|
| Introduction | `01-introduction.md` |
| Literature review | `11-related-work.md` — **moves up** from the back |
| Methodology | `02` + `03` + `07` + `04` + `05` + `06` — **six sections merged** |
| Results | `08-evaluation.md` (+ one sentence of `09-ablations.md`) |
| Discussion | interpretation + `10-limitations.md` — **new heading** |
| Conclusion | `12-conclusion.md` |

**The consequence worth naming:** the decision rule — the contribution — stops
being a top-level section and becomes §3.2. That is a real risk: the thing the
paper is *for* now sits inside a merge of six sections. It gets the largest
subsection budget in the paper (900 words) and Figure 2 and Table 1, and the
introduction must point at it explicitly. Do not let the merge bury it.

## The constraint, measured rather than guessed

`latex/iti2026.tex` compiles today at **4 pages** carrying nothing but three
figures, two tables and the section headings. That is the fixed cost of the
scaffolding. A 12-page limit leaves roughly:

| | pages |
|---|---:|
| front matter (title, authors, abstract, keywords) | 0.6 |
| references (~24 entries; the draft cites 46) | 1.4 |
| figures (4, with captions) | 1.5 |
| tables (cost matrix, baselines, CRS) | 0.9 |
| **body text** | **7.6** |

At the LNCS single-column density of 450–500 words per page that is **3,400–3,800
words of prose**, or ~4,900 including table and caption text. The markdown draft
is **20,138**.

**This is not a trim — it is a shorter paper that reuses the material.** Editing
thirteen sections down by 78% each produces something uniformly thin. Picking
three contributions and writing them properly produces a paper.

## Section budget

| § | section | source | now | target |
|---|---|---|---:|---:|
| — | Abstract | `00-abstract.md` | 647 | 180 |
| 1 | Introduction | `01-introduction.md` | 1,366 | 600 |
| 2 | Literature review | `11-related-work.md` | 1,150 | 450 |
| 3 | **Methodology** | `02`+`03`+`07`+`04`+`05`+`06` | 9,940 | **2,100** |
| 3.1 | — System and threat model | `02`+`03`+`07` | 3,677 | 450 |
| 3.2 | — **Pricing the probe (EVSI)** | `04-decision-rule.md` | 1,869 | **900** |
| 3.3 | — Calibration | `05-calibration.md` | 1,143 | 350 |
| 3.4 | — Consistency (incl. boundary) | `06-consistency.md` | 1,210 | 400 |
| 4 | Results | `08-evaluation.md` | 3,427 | 1,100 |
| 5 | Discussion | interpretation + `10-limitations.md` | 1,416 | 450 |
| 6 | Conclusion | `12-conclusion.md` | 609 | 120 |
| — | *cut entirely* | `09-ablations.md` | 3,624 | **0** |
| | **total** | | **20,138** | **~4,900** |

`09-ablations.md` is the single largest section in the draft and it is the one
that has to go — one sentence in Results naming the ablations and citing the
artefact. Cutting it is what makes room for §3.2.

## Which three contributions

The draft lists seven. Twelve pages carries three well or seven badly.

1. **The priced third action** (§3.2) — the structural result, and the only one
   that does not depend on the sample. Under cost accounting alone the band is
   empty, so the middle action is derived, not tuned. This is the paper.
2. **Bait as a randomised treatment** (§4) — the holdout gives a *causal*
   estimate rather than a system-vs-system comparison: +0.070 [+0.052, +0.088].
3. **Consistency across the divert** (§3.4) — self-consistency is the wrong
   estimand for a decoy an attacker is moved into: 0 over 4,600 fields, 90.8%
   control.

The other four (derived evidence weight, the hard benign corpus, never-worse-than-
passive, the agentic attacker check) each become **one sentence** in the
subsection they belong to, with the artefact cited. They are not deleted from the
project — only from this paper.

## Figures: 4, from the 17 already generated

`architecture.pdf` (§3.1) · `decision-bands.pdf` (§3.2) · `holdout-effect.pdf`
(§4), plus one of `recall-forest.pdf` / `beta-invariance.pdf` if space survives.
All are in `writing/figures/pdf/` and load correctly in the skeleton.

## Order of work (deadline: 4 September 2026)

1. **§3.2 first**, at its full 900 words. It is the contribution and everything
   else is sized around what it needs.
2. **§4 Results** — the three results, one table each.
3. §3.4, §3.3, §3.1 — mechanical compression against the budget.
4. §2 Literature review and §5 Discussion — both are *new shapes*, not trims, so
   they need writing rather than cutting.
5. **§1 and the abstract last.** They summarise; they cannot be written until the
   body has settled.
6. Trim `refs.bib` 46 → ~24, similarity check (<20%), then CMT.

## Two things to resolve before submitting

- `00-abstract.md` carries a **SPACE 2026 double-blind** banner. ITI's published
  rules do not mention double-blind. Confirm with the organisers, then keep
  exactly one of the two author blocks in `iti2026.tex`.
- The similarity limit is **20%**, and `writing/report/PROJECT_REPORT.md` shares
  ancestry with this text. If that report sits in a university repository that
  Turnitin indexes, it will match. Check before submitting, not after.
