# Multi-seed session dumps — what each file is

`tools/multiseed_eval.py` **truncates `sessions.jsonl` at start** (it opens the
path with `"w"`), and it fills the file one arm at a time — the arm loop is the
outer loop. Two consequences that have each cost a day of work already:

* a run that dies partway leaves a dump whose **later arms are missing
  entirely**, not merely thinner;
* re-running a single arm to extend it **discards the other two**.

So the dumps below coexist deliberately. Do not tidy them away on the basis of
their names; check this table first. `tools/stats_report.py` records the source
path and its SHA-256 in `report.json` under `provenance`, so any number can be
traced back to the bytes it came from.

| file | arms × seeds | what it is |
|---|---|---|
| `sessions.jsonl` | *varies* | **Live working file.** Whatever the most recent `multiseed_eval` run left. Assume nothing about it — audit it (`stats_report` does this automatically). |
| `sessions_PRE_RECALIBRATION.jsonl` | B1 100, B2 100, **B4 100** | **The archive that backs every published number.** `sha256 a3c1bcae…`. Re-running `stats_report` against it reproduces the committed `report.json` exactly — verified. Despite the name, this is *not* obsolete data: it is the evidence for README/RESULTS as they currently stand. **Do not delete.** |
| `sessions.jsonl.bak` | B4 100 | Redundant. Its B4 arm is byte-identical to the archive's B4 arm (verified row by row). Kept only because `merge_multiseed.py` writes this path automatically. |
| `sessions_b1b2_backup.jsonl` | B1 100, B2 100, B4 43 | Superseded. The 43-seed B4 is the earlier salvaged run described in `docs/DECISIONS.md`. |

## The name `PRE_RECALIBRATION` is about the *bait library*, not about validity

The bait library was recalibrated on 2026-08-16 (see `config/bait_calibration_report.json`)
**after** these sessions were collected. That is why a full 100-seed × 3-arm
re-run was launched: the published numbers describe the pre-recalibration
library, and the frozen library on disk is now the corrected one. Until that
re-run lands and the docs are renumbered, this archive remains the only complete
evidence base — which is exactly why it must survive.

## Rules

1. **Never** run `stats_report` against a partial dump and let it write
   `report.json`. It now refuses by default; `--allow-partial` stamps
   `partial: true` into the output so a salvaged number is self-identifying.
2. Before re-running one arm, copy `sessions.jsonl` somewhere named for its
   *content*, then merge with `tools/merge_multiseed.py` (last input wins per
   `(arm, seed)`; it refuses a merge whose arms share no seeds).
3. Keep at least one dump in which **all three arms cover the same seeds**. The
   paired McNemar test is the paper's main comparison and it is worth zero
   without matched pairs.
