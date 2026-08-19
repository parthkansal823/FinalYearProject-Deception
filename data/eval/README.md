# Which evaluation directory is which

Several of these hold a full multi-arm run and differ only in the corpus or the
seed count they were produced at. Two of them once cost an afternoon to tell
apart, and one tool's default pointed at the wrong one for long enough that
running the consistency checker with no arguments reported 29 disagreements
against a correct paper. Hence this file.

| directory | what it is | reported in |
|---|---|---|
| `curious_v2/` | **canonical.** 99 seeds x 3 arms, v5 frozen library, mixed browser-driven corpus. B1 0.366, B2 0.889, B4 0.943. | Sections 8, 9.1, 10 |
| `curious/` | the same design on the **pre-browser** corpus (raw-HTTP attackers only). B1 0.408, B2 0.917, B4 0.951. Kept because Section 10 quotes it as the "before" of the corpus-hardening result. | Section 10 |
| `browser0/` | a controlled 20-seed re-measurement with `--browser-driven 0.0` on the current frozen model, confirming that the `curious` -> `curious_v2` difference is the corpus and not the model. | Section 10 |
| `fixed_threshold_all/` | **canonical** hand-set-threshold sweep: 6 arms x 48 seeds (9,600 sessions, 3,840 benign each). | Sections 9.7, 9.8 |
| `fixed_threshold/`, `_v2/`, `_v3a/`, `_v3b/`, `_v3c/` | earlier and partial sweeps at 2-20 seeds. Superseded; kept only as provenance. | nothing |
| `multiseed/` | the pre-recalibration (v4) 100-seed run. | nothing; historical |
| `calibration/`, `calibration_v2/` | held-out draws for fitting the calibration maps. Seeds are far below the evaluation range by construction, so nothing fitted here can reach a reported number. | Section 9.8 |
| `waf/`, `waf_v2/` | OWASP CRS replay baselines. | Section 8.4 |
| `llm_sweep/` | autonomous language-model attacker sessions. | Section 9.6 |

**Rule of thumb:** if a tool's default points at a directory not marked
*canonical* above, that is a bug, not a preference.
