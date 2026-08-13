# Specification review — gaps found while implementing Phases 0 and 1

Findings from building against `PROJECT_SPEC.txt`. These are places where the
spec is under-determined, internally inconsistent, or where a reviewer would
push back — not disagreements with the research direction, which is sound.

Ordered by how much damage they do if left until late.

---

## 1. The bite weight cannot be learned from either attack round ⚠️ blocking

**The problem.** Spec §5.2 says that when a bait is acted upon, "the malice
score jumps sharply". How sharply? Everything else in the decision path is
*derived* rather than tuned (§6.5) — so a hand-picked constant here is exactly
the kind of magic number the project's own methodology rejects, and a reviewer
who has read §6.5 will go looking for it.

Worse, the phase order forbids learning it:

- **Phase 2** (attack round 1) produces the training corpus — but it runs
  *before* Phase 4 builds the bait library. Round 1 contains **no bait and
  therefore no bites**. There is nothing to learn the weight from.
- **Phase 7** (attack round 2) contains bites — but it is the test set. Fitting
  anything on it destroys the evaluation (§7.2).

So the single most important feature in the system, the one carrying
contribution #1, has no legitimate source of calibration data.

**Suggested fix.** Insert a small **calibration round (Round 1b)** between
Phases 4 and 6: a short attack campaign run after the bait library exists,
used *only* to estimate the bite likelihood ratio, and kept separate from both
round 1 and round 2. Add it to the round vocabulary and to §7.2's table so the
three-way separation is explicit and reportable.

Alternatively — and this is cheaper — derive the weight instead of fitting it.
The evidence value of a bite is a likelihood ratio:

```
LR(bite) = P(bite | attacker) / P(bite | benign)
```

`P(bite | benign)` is directly measurable from Phase 1 benign traffic once
bait exists, and by design it should be ~0, so it needs a stated smoothing
prior (e.g. Laplace, or a stated floor like 1e-4) to keep the ratio finite.
`P(bite | attacker)` can be bounded conservatively rather than estimated.
Either way, **write the derivation down before round 2**, because "the bite
weight" is the first thing a viva will probe.

---

## 2. "Byte-identical rendered output" is not achievable as literally written

**The problem.** §6.7 requires that "the page a real browser displays [...] must
be indistinguishable", phrased as *byte-identical*. But the entire mechanism
depends on the bait being **visible in the raw response**. The bytes must
differ — that is the point. Two different things are being conflated:

| Layer | Must differ | Must be identical |
|---|---|---|
| Raw HTTP response bytes | ✅ yes — this is the bait | — |
| Post-JavaScript DOM (structure + visible text) | — | ✅ yes |
| Rendered pixels | — | ✅ yes |
| Timing | — | ✅ yes (statistically) |

**Also**: the JSON baits (B-IDOR-1's `ref_uid`) *do* change what a client
parses. §6.7's "every API response still parses correctly" is a much weaker
claim than invisibility. An extra JSON field is invisible to the *UI* but
plainly visible to any consumer that enumerates keys.

**Suggested fix.** Restate NFR-01 as three separate, separately-tested
assertions: (a) normalised post-JS DOM equality, (b) no functional change,
(c) timing equivalence. And state honestly in the paper that JSON-field bait
is invisible *to the application's own client*, not to an arbitrary parser —
that is a limitation worth owning in §18 before a reviewer finds it.

---

## 3. Timing invisibility needs a pre-registered equivalence test

**The problem.** §6.7 asks for latency "statistically indistinguishable from
normal variation". The obvious implementation — a t-test or KS test, and
declaring success when p > 0.05 — is a well-known error: **failing to reject
the null is not evidence of equivalence**, and with a small sample it is
nearly guaranteed.

**Suggested fix.** Use **TOST (two one-sided tests)** against a pre-registered
equivalence margin — e.g. "median added latency is within ±2 ms, and the 95th
percentile within ±5 ms". Fix the margin in Phase 0 alongside the cost table,
for the same reason. Report the margin, not just the verdict.

---

## 4. `requests-to-decision` is undefined for sessions that never decide

**The problem.** This is one of the two metrics that, by §10.3's own account,
carry the paper. But it is not defined for:

- attack sessions that are **never** diverted (the passive baseline B2 will
  have many — that is the point being made about it);
- attack sessions diverted *after* the attacker already succeeded;
- benign sessions, which never get a decision at all.

Taking a median over only the sessions that *did* decide systematically
flatters whichever system decides on fewer sessions — which is the opposite of
the intended comparison, and is the kind of thing that gets a paper rejected.

**Suggested fix.** Treat undecided sessions as **censored observations** and
report a survival curve (Kaplan–Meier) with a median from it, or state a fixed
horizon (e.g. "requests-to-decision, capped at 50; sessions never decided are
counted at the cap") and report the decision *rate* alongside. Either is
defensible; silence is not.

---

## 5. Per-session bait tokens vs. cross-session bite detection

**The problem.** §6.6 requires bait content to be unique per session so it
cannot be published and burned (§16). But bite detection then only matches a
token against *the session that was given it*. That misses two informative
cases:

- an attacker who rotates cookies and replays a token in a **new** session;
- a token appearing from a **different source entirely** (shared, or published).

Both are strong evidence, and the second is the early-warning signal that a
bait has leaked.

**Suggested fix.** Keep a global token registry mapping token → issuing
session. On a bite, record whether the presenting session is the issued one.
"Token presented by a session other than the one it was issued to" deserves to
be its own logged signal — it is arguably *stronger* evidence of hostility
than an ordinary bite.

---

## 6. Session identity resets are free for the attacker

**The problem.** Scores accumulate per session (§6.4), and sessions are keyed
on "a cookie or a client fingerprint" (§5.2). An attacker who clears cookies
between requests resets their accumulated suspicion to zero and never reaches
any threshold. §18's threat model assumes the attacker does not know the
defence exists, which covers this — but only just, since cookie-clearing is
routine attacker hygiene, not an anti-deception measure.

**Suggested fix.** State the fingerprint composition explicitly (IP + UA +
header order + TLS/HTTP2 fingerprint if available), and treat **cookie
discontinuity with fingerprint continuity** as an automation feature in its own
right. Then say plainly in §18 that an attacker rotating both cookie and
network identity defeats accumulation, and that this is out of scope.

---

## 7. The divert transition must carry authentication state

**The problem.** §5.2 requires the switch into the decoy to be invisible. But
an attacker is typically **logged in** to the real app when diverted. If the
decoy does not present them as the same authenticated user, with the same
username and a plausible continuation of their session, the transition is
detectable in exactly one request — and "time to suspicion" (§10.3) collapses
to zero for reasons that have nothing to do with the Fact Notebook.

The spec does not mention mirroring session state into the decoy at all.

**Suggested fix.** Add it to Phase 5/6 explicitly: on divert, the decoy is
handed the session's authentication state and identity, and the Fact Notebook
is seeded with a decoy user matching the username the attacker had already
seen. Test it as part of the Phase 6 "confirm the transition is invisible"
exit condition.

---

## 8. B3 and the no-notebook ablation may be the same configuration

**The problem.** §10.1 defines B3 as "passive classifier plus a **static**
decoy" and calls it the state of the art. §10.2's fourth ablation is the full
system "with the Fact Notebook disabled". If "static" means "regenerates
content per request without persistence", these are the same thing measured
twice, and the paper will look like it is padding its comparison table.

**Suggested fix.** Define "static" precisely and distinguish the two: B3 =
passive detection + a fixed, hand-written decoy (no generation at all); the
ablation = full active system + on-demand generation without persistence.
If they cannot be distinguished, drop one and say why.

---

## 9. Publishing the dataset breaks the hash chain

**The problem.** NFR-13 makes the log tamper-evident via a hash chain. §11
requires the released dataset to be *cleaned* first (credentials, host
identifiers). Any cleaning invalidates every hash downstream of the first
edited record, so the released artefact cannot be verified — which removes
most of the value of having chained it.

**Suggested fix.** Publish the **root digest of the original chain** plus the
cleaning transformation as code, and re-chain the cleaned dataset with its own
digest. Then a third party can verify internal consistency of what they have,
and the researcher retains a verifiable original.

---

## 10. Fail-open produces records with no scores

**The problem.** NFR-04 requires the proxy to forward requests if any
detection component crashes. Those requests then appear in the corpus with
empty features and empty scores. If the evaluation counts them as `pass`
decisions, a crashing detector silently looks like a confident one.

**Partly addressed already**: the frozen schema carries
`decision.fail_open_triggered` so these are identifiable.

**Still needed.** A stated rule for how fail-open records are handled in every
metric — excluded, or counted as misses — fixed before Phase 7 rather than
chosen once the numbers are visible.

---

## Smaller notes

- **Response encoding.** If the target app gzips responses, bait injection must
  decompress and recompress, which affects both latency and `Content-Length`.
  Simplest fix: have the proxy request identity encoding from the upstream.
- **Benign bait exposure framing.** With the frozen cost table, BAIT is optimal
  from p ≥ 0.056, so a non-trivial fraction of benign sessions *will* receive
  bait. That is correct behaviour, but §10.3 lists benign bait exposure as a
  headline *safety* metric, which invites reading a high number as a failure.
  Frame it as "exposure is common and provably harmless" — the invisibility
  gate is what makes that claim, not a low exposure rate.
- **§13 has eight phases listed as Phase 0–7**, but §14.1 refers to "Phases 7
  and 8" and §13.1 says "Phases 7 and 8". Renumbering or a missing phase —
  worth resolving before the phase table goes into the paper.
