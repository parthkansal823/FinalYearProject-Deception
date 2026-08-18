# Seeds to exclude from this dump

| arm | seed | rows | expected | cause |
|---|---|---|---|---|
| b2_passive | 20260930 | 31 | 200 | a concurrent LLM sweep starved this process mid-draw |

The draw reported an ordinary-looking recall (0.903) computed from 31 surviving
sessions, which is exactly why it needs recording: nothing in the dump marks it.
`multiseed_eval` now flags a draw that lands under 90% of its expected sessions
and writes `short_draws.json`, but this run predates that guard.

Drop this seed from BOTH arms before pooling, so the paired comparison stays
matched. One seed of 100 is a clean exclusion; salvaging it would mean pooling a
seed whose b2 side saw a sixth of the traffic its b4 side did.
