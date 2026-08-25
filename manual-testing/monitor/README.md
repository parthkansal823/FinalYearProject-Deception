# Live pentest monitor — output

Written by `python -m tools.pentest_monitor` (run it in a second shell while
you attack the stack). The monitor follows **all three log streams** in
`data/logs/` read-only — `proxy.*`, `target-access.*`, `decoy-access.*` — merges
them into one chronological feed tagged by source, and logs **everything** here
(one set of files per monitor run, stamped with the run's UTC start time).

Only the **proxy** scores requests (dual meter, PASS/BAIT/DIVERT). Target and
decoy records are the raw request/response at those hops and show as
`(unscored)`; findings (below) therefore run on proxy records only, while the
feed and activity log capture all three. Narrow with `--sources proxy` (etc.)
if the target/decoy hops are noise for a given session.

| file | for | holds |
|---|---|---|
| `activity.<stamp>.jsonl`| a machine        | **every request** — one complete structured row (request, response, scores, decision, bait, bite, full feature vector). Nothing is dropped. |
| `feed.<stamp>.log`      | a human          | **every request** as a plain-text transcript line (what scrolled past on screen) |
| `analysis.<stamp>.md`   | a human / Claude | the notable findings only, with _Why / Do / Ref_, plus per-session summary tables |
| `events.<stamp>.jsonl`  | a machine        | one structured finding per line (`type`, `severity`, `session`, `seq`, `title`, …) |

`activity` and `feed` log **everything**; `analysis` and `events` are the
distilled findings on top. The session is fully reconstructable from `activity`
alone. Read the newest `analysis.*.md` before the next session so each run
builds on the last.

## What the findings watch for

- **`idor_sweep_blindspot`** — a run of object-id reads with a flat meter (the
  headline gap, `docs/LIMITATIONS.md` §3).
- **`divert`** — the catch: which request/feature spiked `p_attack`, and what
  slipped beforehand.
- **`bite`** / bait-ignored — whether the curious-attacker assumption holds.
- **`post_divert_502`** — the loudest tell (decoy unreachable); run the full
  stack via `python -m tools.run_stack`.
- **`decoy_reread`** — a post-divert re-read of a page seen before the divert;
  compare the two responses for a cross-boundary tell (`docs/LIMITATIONS.md` §7).
- **`fail_open`**, **`planted_credential`**, **`band_violation`**.

## Usage

```bash
python -m tools.run_stack                       # shell 1: target + decoy + proxy
python -m tools.pentest_monitor                 # shell 2: follow new records live
python -m tools.pentest_monitor --from-start    # ... or replay the current log first
python -m tools.pentest_monitor --replay <log>  # process a finished log and exit
```

Point the browser at **http://127.0.0.1:8000** only (the proxy). Requests to the
target directly (`:8001`) never reach the proxy, so the monitor cannot see them.
If you start the monitor after a session is already underway, use `--from-start`
so it picks up the records already written.

The monitor is read-only w.r.t. everything except this directory; it never
touches the proxy log, the corpus, or the frozen artefacts. Output here is
disposable — delete freely; a fresh run regenerates it.
