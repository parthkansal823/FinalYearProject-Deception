# 8  Evaluation

Section 4 makes a prediction that can fail: a priced probe should help where the
passive classifier is genuinely uncertain, and nowhere else. A probe that raised
recall everywhere would be a sign that the meter was weak, not that the pricing was
right. A probe that raised recall by diverting honest users would be worthless
whatever the arithmetic said. So the evaluation is built around three questions —
does the probe cause more attackers to be caught, where does the gain live, and
what does it cost the benign side — and the answers are reported in that order.

Every number below is produced by `tools/multiseed_eval.py` and
`tools/stats_report.py` from one frozen model and is reproduced by the two commands
in `docs/RESULTS.md`. The report records the digests of the cost table, the bait
library and the meter that produced it, and the figure script refuses to draw from
a report whose digests no longer match what is in `config/` — a guard added after a
stale report plotted perfectly happily and was wrong in a way nobody noticed.

## 8.1  Setup

Four configurations are compared, differing only in the code path selected by a
single mode flag against the same frozen model:

| arm | what it does |
|---|---|
| **B0** | no defence; the ceiling on attacker success |
| **B1** | signature WAF — regexes for injection, scripting, traversal and command injection, plus scanner user-agents |
| **B2** | the dual meter, passive: pass or divert, no probe |
| **B4** | the full system: meter, priced probe, decoy |

B1, B2 and B4 each ran over **100 independent seeded traffic draws** of 120 attack
and 80 benign sessions, which is 12,000 attack and 8,000 benign sessions per arm.
Within a seed every arm sees byte-identical traffic, so each attack session forms a
matched pair across arms. B0 is not part of that comparison: with nothing in front
of the application every attack succeeds by construction, and its only role here is
as the cost reference in Section 8.6.

The attack traffic is a held-out second round, written after the detector was built
and deliberately unlike the round it was tuned on: double-encoded and
comment-split SQLi, credential spray, a slow stealth prober, and scattered-stride
object access in two forms — over the JSON API and through the HTML UI. The benign
corpus contains ordinary users, awkward-but-honest ones (a user who forgets their
password, a user who mistypes URLs), and **automated-but-harmless clients**: a
monitor, a crawler, a reporting integration. That last group is not decoration. It
produced the most useful finding in the project, and it is the reason the benign
numbers in Section 8.5 mean anything (Section 10).

## 8.2  Statistical protocol

We fixed the primary comparison — B2 against B4 on attack recall — before the runs,
and label everything else exploratory. Security-ML results are easy to inflate by
choosing the comparison after seeing the data \cite{arp2022dos}, and easy to
overstate by reporting a single draw as though it were a population
\cite{sommer2010outside}, so the protocol is stated before the numbers rather than
after.

Proportions carry **Wilson intervals**, which behave sensibly near zero where the
normal approximation does not — and every benign rate in this evaluation is near
zero. B2 against B4 uses an **exact paired McNemar test** on the matched sessions:
only the discordant pairs, where one arm catches a session the other misses, carry
information about the difference, and using them is far more powerful than
comparing two pooled recall numbers as if they came from independent samples. The
randomised holdout uses **Fisher's exact test** with a bootstrap interval on the
difference. We also report the per-seed distribution, because a pooled interval
narrow enough to look decisive can still hide an effect that only appears in a
handful of draws.

## 8.3  The causal estimate

The comparison that matters is not B2 against B4. Those are two whole systems, and
they differ in more than the probe. The design that isolates the probe is a
**randomised holdout inside the treated arm**: whenever the policy decides to bait,
a deterministic pseudo-random draw over the session id withholds the probe from
about one session in ten (`adf/policy/engine.py::in_holdout`). Withheld sessions
sit at the same belief state, under the same policy, in the same band — they are
simply passed instead of probed, and recorded as controls. The gap between the two
groups is attributable to the probe rather than to any other difference between two
configurations.

| group | n | diverted | divert rate |
|---|---:|---:|---:|
| baited (policy) | 10,756 | 10,072 | **0.936** |
| withheld (holdout) | 1,244 | 1,129 | **0.908** |

Effect **+0.029**, bootstrap 95% CI **[+0.012, +0.046]**, odds ratio 1.50, Fisher
exact **p = 0.00024**. Probing causes diversions that would not otherwise have
happened, at the same belief state.

That number is smaller than earlier drafts of this work reported, and the history
belongs in the paper rather than in a footnote. A single draw once gave +0.23; a
20-seed run against an earlier meter gave +0.11; the previous bait library gave
+0.053. Two things shrank it, and both are real. The current meter is strong enough
on its own that there is less headroom for a probe to recover, and recalibrating the
bait library raised the derived divert edge from 0.863 to 0.879, so the probe now
defers diversions it used to make. What survives all of that is +0.029, and it is
still significant.

## 8.4  Baselines and recall

| arm | attack recall (Wilson 95% CI) | per-seed sd | benign diverted |
|---|---|---:|---:|
| **B1** signature WAF | 0.408 [0.399, 0.417] | 0.025 | 0 / 8,000 |
| **B2** passive | 0.915 [0.910, 0.920] | 0.021 | 4 / 8,000 |
| **B4** full | **0.933 [0.929, 0.938]** | 0.024 | **0 / 8,000** |

B1 is a fair reference rather than a straw man: it false-positives on zero benign
sessions, so its precision is 1.00, and it catches textbook payloads exactly as it
is supposed to. Its recall is 0.408 for two reasons that are properties of
signatures, not of this implementation. Round-2 payloads are obfuscated, and —
more decisively — reading another user's record by changing an id in a URL is
perfectly valid syntax with nothing for a regex to match. That blindness is pinned
as a test (`tests/test_rules.py::test_the_waf_is_blind_to_idor`) so it cannot be
quietly fixed into a different baseline.

The B2 and B4 intervals do not overlap, and the paired test confirms the difference
rather than merely restating it: of 12,000 matched attack sessions, 11,221 are
concordant, **499 are caught by B4 alone and 280 by B2 alone**, giving McNemar
**p < 10⁻⁴**. B4 is ahead in **78 of 100 seeds**, which is what rules out a lucky
draw.

The 280 sessions that go the other way are not noise, and we do not present them as
such. They are deferrals: sessions whose belief landed in the strip between the
cost-only boundary at 0.816 and the derived divert edge at 0.879, where B2 diverts
immediately and B4 buys information first. Some of those sessions end without the
probe ever being answered. That is the price of the third action, it is visible in
the discordant count, and Section 9 argues it is bounded rather than open-ended.

## 8.5  Where the probe acts, and where it cannot

Splitting the matched pairs by attack subcategory is the sharpest test of the
theory, because the theory says the gain must be concentrated.

| subcategory | n | B2 recall | B4 recall | gain | B4 bite rate |
|---|---:|---:|---:|---:|---:|
| sqli_obfuscated | 4,000 | 0.896 | 0.899 | +0.003 | **0.000** |
| sqli_stealth | 2,000 | 1.000 | 1.000 | +0.000 | 0.217 |
| idor_scattered (API) | 2,000 | 0.996 | 0.996 | +0.000 | 0.000 |
| auth_spray | 2,000 | 1.000 | 1.000 | +0.000 | 0.000 |
| **idor_html_scattered** | 2,000 | **0.704** | **0.807** | **+0.104** | **0.306** |

The entire net gain is in UI-based scattered object access: +0.104, with a paired
McNemar on that subcategory alone of b = 390 against c = 182, **p < 10⁻⁴**. That is
the one category a signature cannot see and the one where the passive meter is
genuinely undecided, which is precisely where Section 4 says information is worth
buying. Everywhere else the probe is neutral. `sqli_stealth` bites 22% of the time
and its recall does not move at all, because those sessions were already caught —
the information was bought and turned out not to be needed. Scattered access over
the API is caught passively, because an attacker walking ids collects 404s while a
reporting integration reads only ids that exist, and the error-ratio feature
separates them without any probe.

One subcategory cannot reach the probe at all, and it is worth stating plainly
because it is half of what B4 still misses. `sqli_obfuscated` has a bite rate of
exactly **0.000** even though nine in ten of its sessions are shown a probe, and it
accounts for **405 of B4's 799 misses** (`idor_html_scattered` accounts for 385,
and everything else for 9). The cause is in the attacker model, not the defence:
those profiles fire payloads and never read what comes back, so a response-side
probe cannot reach them by construction. The generator has since been given a
response-reading population; that measurement is running separately and is reported
as unfinished in Section 9 rather than folded in here.

## 8.6  Safety, and what it cost the benign side

| arm | benign diverted | rate (Wilson 95% CI) |
|---|---:|---|
| B1 signature WAF | 0 / 8,000 | 0.0000 [0.0000, 0.0005] |
| B2 passive | 4 / 8,000 | 0.0005 [0.0002, 0.0013] |
| **B4 full** | **0 / 8,000** | 0.0000 [0.0000, 0.0005] |

The probe costs nothing in false positives, and the arm that probes is the arm with
the cleanest benign record. This is the number the cost table was built around: with
benign traffic dominating the mix, a defence is only usable if its false-positive
rate is near zero \cite{axelsson2000baserate}, which is why diverting an honest user
is priced two orders of magnitude above any other error.

Exposure is high and consequence is nil. **7,187 of 8,000 benign sessions (90%)
were shown a probe and not one acted on it.** High exposure is acceptable only
because the probe is invisible, so the bite rate is the number that matters, and it
is zero across every benign class in the corpus. Invisibility is not asserted: every
candidate bait must pass three tests before it enters the library — rendered output
unchanged after JavaScript, no functional change to forms, links or parsing, and no
detectable timing difference under a two-one-sided-tests equivalence check against a
pre-set margin \cite{schuirmann1987comparison} — and the engine re-checks the
resulting certificate at run time. The 90% exposure figure is that gate holding at
scale rather than only on the bench.

Two benign false positives were removed earlier by auditing rather than by argument,
and both belong in the record because they are the reason the benign corpus looks
the way it does. Reporting-integration clients were once diverted **100%** of the
time, since a nightly integration walks record ids in ascending order exactly as an
attacker sweep does; no passive feature separates those two honestly, so that
detection was handed to the probe, which is what a probe is for. A user who forgets
their password was diverted three times in five until a feature counting distinct
usernames separated a forgetful login from credential spray, which fails against
many accounts rather than against one.

The same picture in cost terms, using the frozen table to price each session's
outcome: **B1 +3.98, B2 −9.67, B4 −9.84** expected cost per session, against the
**+15.0** the table implies when nothing is diverted at all. Only the learned arms
drive the cost negative — that is, make the attacker's session cost the attacker
more than it costs the defender — and the probe improves the figure slightly rather
than trading recall against safety.

Time to a decision is unchanged by probing: the median attack session is diverted on
the **5th request** in both B2 and B4, with a 90th percentile of 7. Buying
information does not mean waiting indefinitely, because unrewarded exposures decay
the information's value (Section 4, Section 9).

## 8.7  Outside the simulator

Synthetic attackers are our own construction, so the sharpest objection to
everything above is that the attacker model was chosen to suit the defence. We
bound that from one side by running real, third-party attack tools we did not write
against the full system on an isolated local stack: **sqlmap 1.10.8**, **ghauri
1.4.3** and **wapiti 3.2.3**.

Every cookie-persistent tool is diverted within a handful of requests — sqlmap on
its 3rd, wapiti on its 13th, both to `p → 1.0` — and **not one tool bites a probe,
in any configuration**. That is not a failure of the probe; it is the scope claim
measured. A blind injection engine does not read a planted HTML comment and decide
to chase a deprecated-endpoint hint, and it does not need to be caught that way,
because its own behaviour is loud enough for the passive meter. The probe exists for
the adversary the scanner is not.

One tool found a real evasion. ghauri refuses the proxy's cookie, so every request
arrives session-less and the accumulating meter is reset before it can build a case
— the score-resetting attack the design anticipates. Even so, 46% of its individual
requests are diverted on their own lexical evidence, and enabling the fingerprint
fallback the system already ships collapses its 1,321 requests into a single session
that is diverted outright. The evasion is real, it was anticipated, and the
mitigation is a configuration flag rather than a redesign.

Transfer was checked by putting the same frozen model in front of a second,
structurally unlike application — OWASP Juice Shop, a Node/Express single-page app
with a JSON API — and attacking it through the proxy. sqlmap is diverted on its 2nd
request. A browser-driven ZAP scan that crawled 589 endpoints and mixed benign
spidering with payloads was separated correctly rather than blanket-diverted:
diverted requests carry a mean of 0.91 SQL-keyword hits, passed requests 0.00. What
transfers is the app-agnostic core — lexical context, error ratio, timing, header
shape. What does not is the app-specific auth features, which key on our target's
form-POST login and stay silent against a JSON login endpoint; they would need
re-pointing, and we say so rather than presenting the transfer as complete.

These tool runs predate the bait recalibration and were made against the previous
freeze. Nothing in them depends on the bait weights, because no tool bit anything.

## 8.8  What this section does not establish

The traffic is synthetic, so every rate here is a statement about this distribution
rather than about production traffic, and the tool study bounds the automated end of
the adversary spectrum rather than the human one the recall gain depends on. The
structural results of Section 4 and the holdout design do not need the traffic to be
real; the magnitudes do. Section 10 separates those limitations we retired by fixing
the underlying problem from those that are irreducible in a study of this shape.
