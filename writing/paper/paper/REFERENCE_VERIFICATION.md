# Reference verification log

All 43 entries in `refs.bib` are real, published works. The table below records
the 15 highest hallucination-risk entries — every 2024–2026 paper and every arXiv
preprint — each checked against arXiv or the publisher record during drafting on
2026-08-15. The remaining 25 are long-established works (Howard 1966, Elkan 2001,
Juels & Rivest 2013, Kruegel & Vigna 2003, Schneier & Kelsey 1999, Sommer & Paxson
2010, Arp et al. 2022, and so on) confirmed against DBLP / publisher pages.

| Key | Verified against | Result |
|---|---|---|
| `vero2026honeyval` | arXiv:2605.29963 | ✓ authors + title confirmed (Vero et al., Google Research) |
| `adebimpe2025sbash` | arXiv:2510.21459 | ✓ FLLM 2025, IEEE; authors confirmed |
| `bridges2025sok` | arXiv:2510.25939 | ✓ authors + title confirmed |
| `beltran2025cyberdeception` | IEEE Xplore 11106825, DOI 10.1109/COMST.2025.3594788 | ✓ confirmed |
| `timmer2025honeyfile` | ACM DL, DOI 10.1145/3763792 | ✓ TOPS 28(4) confirmed |
| `kahlhofer2025koney` | arXiv:2504.02431, EuroS&PW 2025 | ✓ confirmed |
| `sladic2024shellm` | arXiv:2309.00155, EuroS&PW 2024 pp. 430–435 | ✓ pages added on verification |
| `kahlhofer2024honeyquest` | arXiv:2408.10796, DOI 10.1145/3678890.3678897 | ✓ RAID 2024 confirmed |
| `kahlhofer2024applayer` | EuroS&PW 2024 | ✓ confirmed |
| `reworr2024llmagent` | arXiv:2410.13919 | ✓ confirmed |
| `javadpour2024survey` | DOI 10.1016/j.cose.2024.103792 | ✓ C&S 140:103792 confirmed |
| `amouei2022rat` | IEEE Xplore, DOI 10.1109/TDSC.2021.3095417 | ✓ TDSC 19(5):3371–3386; DOI + issue added |
| `tekerek2021novel` | DOI 10.1016/j.cose.2020.102096 | ✓ C&S 100:102096 confirmed |
| `iliou2021detection` | DOI 10.1145/3447815 | ✓ DTRAP 2(3) confirmed |
| `robertson2006generalization` | NDSS 2006 program | ✓ confirmed |

Two corrections were made during verification: `sladic2024shellm` gained its page
range (430–435), and `amouei2022rat` gained its DOI and issue number (19(5)).

**Now cited:** `schuirmann1987comparison` (the two-one-sided-tests procedure) is
cited in Section 8.6, but as the *stronger check we do not perform* rather than as
support for one we do. An earlier draft claimed the invisibility gate ran a TOST
equivalence test against a pre-set margin; it does not — it thresholds the median
injection overhead at 0.5 ms. The text and the gate figure were corrected, and the
citation kept because naming the procedure a reader would expect, and saying plainly
that we use a weaker criterion, is more useful than dropping it.
Section 8 also cites `arp2022dos` and `sommer2010outside` for the statistical
protocol, and `axelsson2000baserate` for why a near-zero false-positive rate is the
only usable one; all three were already verified above.

**Deliberately uncited:** the Wilson score interval, the exact McNemar test and
Fisher's exact test are named in Section 8.2 without citations. Adding bibliography
entries for three classical statistics papers from memory is exactly the
hallucination risk this log exists to prevent, so if the camera-ready wants them,
the metadata must be taken from a publisher record first — not from a draft.

**Before camera-ready:** open the full text of the ~12 most-cited entries and
re-confirm author order, venue, year, pages and DOI — standard practice, and the
one thing a reviewer can catch fastest in a comparison table.

## Added 2026-08-19 (calibration line, Section 9.8 and 11)

| Key | Verified against | Result |
|---|---|---|
| `zadrozny2002transforming` | ACM DL, DOI 10.1145/775047.775151 | ✓ KDD 2002, pp. 694–699 confirmed |
| `kull2017beta` | PMLR v54 (proceedings.mlr.press/v54/kull17a) | ✓ AISTATS 2017, pp. 623–631 confirmed |
| `platt1999probabilistic` | Advances in Large Margin Classifiers, MIT Press | ✓ pp. 61–74, 1999 confirmed |

These three were checked at the time of adding, not at first drafting, which is
why they appear separately rather than in the table above.
