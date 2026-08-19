# What the paper has to say, section by section

This is a working document, not the paper. It sets down what each section needs to
establish, which numbers belong in it, and — just as important — what must not be
claimed. Write the actual prose in your own words. Every figure below has been
checked against the data on disk; if you change one, run
`python -m tools.check_doc_numbers --dump data/eval/curious_v2/sessions.jsonl`
and it will tell you what no longer matches.

A note on tone before anything else. The strongest thing this paper has going for
it is that it reports what it found rather than what it hoped for. Two of its own
results go against it, and they are in the paper on purpose. Do not soften them
while rewriting. A reviewer who sees a negative result reported plainly starts
trusting the positive ones.

---

## 1. Introduction

Start with the trap a web application firewall is in. It sees one request and has
to decide: let it through, or block it. Decide early on thin evidence and you block
real customers. Wait for evidence you can act on and the attacker has already had
five or six requests. Learned detectors make the edges softer but they are in the
same trap — they watch, they accumulate a score, and eventually they have to commit.

Then the observation the paper is built on. Deception is the usual escape from
being passive: honeypots, honeytokens, decoy files. But look at where the deception
sits in almost every deployment. Something is judged hostile *first*, and only then
is it moved into a honeypot or shown a planted file. The deception is a consequence
of the decision. Nobody seems to treat it as a *move the detector can make while it
is still unsure* — a way of manufacturing the evidence it would otherwise sit and
wait for.

That is the paper. When the system is uncertain about a visitor, it adds something
to the response that a browser never renders but anyone reading raw bytes will see:
a database error naming a table that does not exist, an unused field in a JSON
body, a hint at a deprecated login endpoint. An honest user never notices. Someone
probing the application acts on it — and the moment they do, they have said
something about their intent that no passive score could have told you.

Be precise about what is new. The parts are all old: LLM-written fake content,
machine-learned web attack detection, redirecting a caught attacker into a
honeypot, planting a credential as a tripwire. What is new is the rule that decides
*when* to deceive, and the fact that its two thresholds are computed rather than
chosen.

The key argument, and it is worth stating early because it is the sharpest thing in
the paper: a probe has no immediate benefit at all. The request it rides on still
reaches the real application, so baiting an attacker costs exactly what letting one
through costs. Its whole value is the information a bite reveals. Price that value
as the expected value of sample information and probing becomes the cheapest action
over a band of belief — and that band does not exist if you leave the information
term out. So the middle action cannot be a tuned threshold, because without pricing
the information there is no middle action to tune.

List the contributions plainly: the priced third action, the derived evidence
weight, bait as a randomised treatment, a benign corpus built to be hard, and the
guarantee that the system never ends up worse than the passive detector it is built
on.

Close the section by saying where the approach does not win — hand-set thresholds
beat the derived ones on expected cost, and Section 9 gives the measured reason. A
reader who finds that out for themselves in Section 9 after an introduction that
did not mention it will trust the rest of the paper less.

---

## 2. Threat model

The attacker sends ordinary HTTP to a public application. Some requests carry
payloads that can be obfuscated — SQL injection split across comments or
double-encoded, XSS with mixed case, path traversal — so a signature written for
the textbook form misses the variant. Others carry no payload at all, and this is
the case the paper leans on: a request for `/records/5` is syntactically identical
to a request for `/records/6`. If the second record is not yours, that request is
an attack, and nothing in its bytes says so. A signature cannot catch it because
there is no signature to write. A behavioural detector struggles because a benign
reporting integration reading its own records in order produces exactly the same
shape of traffic. That is where a passive score is genuinely undecided, and it is
where manufacturing evidence has value.

Two axes, not one. The attacker may be a person or a script, and separately may be
hostile or harmless. A scanner is automated and hostile. A price-comparison bot is
automated and harmless. A careful human working by hand is manual and hostile. That
is why the meter scores automation and malice separately and why only malice drives
the decision.

Say what the simulated adversary does, because a reviewer will ask. Half of the
attack sessions drive a real browser: browser headers, and they fetch the page
sub-resources a browser fetches. The other half speak raw HTTP. This matters
because a lot of current tooling is built on Selenium or Playwright and inherits
browser behaviour whether the operator wants it or not. An earlier version of the
corpus had none of the first kind and the consequence is reported in Section 10.

Out of scope: network and transport attacks, denial of service, client-side attacks
against other users. And one assumption stated plainly — the attacker is assumed
not to have mapped the decoy world in advance. Someone who has could recognise it.
Countering that fully is out of scope, but a weaker version of it is measured: an
attacker who knows the defence exists and refuses every probe on principle. Section
9 shows the system degrades to passive detection against that adversary rather than
below it.

---

## 3. System design

Everything sits behind a reverse proxy. Clients only ever talk to the proxy; the
real application never sees an unfiltered request and knows nothing about the
deception. One request travels the same path every time: identify the session,
extract features, update a two-part score, price the three actions, take the
cheapest, write the whole decision to an append-only hash-chained log.

Sessions are grouped by a cookie the proxy sets on first contact. A client that
refuses cookies gets a fresh identity each request by default — the safe choice for
measurement, because a coarse fingerprint on one host would merge distinct clients.
The proxy *can* link cookieless requests by fingerprint instead, and Section 8 shows
why that switch exists: an attack tool that drops its cookie to reset its score is
defeated by exactly that.

Eighteen features, computed only from what a live proxy can see. Ten describe how
the client behaves — inter-request timing and its regularity, whether static assets
are fetched, how complete the browser header set is, whether a cookie is carried.
Eight describe what the client is trying to do — special-character density in
client-controlled input, database keywords in syntactic context, error-response
ratio, failed authentications, and the number of distinct accounts a session has
tried to log in as.

That last one deserves a sentence of its own. A user who forgets their password
fails repeatedly against one account and then succeeds. An attacker spraying
credentials walks many accounts. Counting distinct usernames separates them on the
axis that actually differs, rather than on the number of failures, which is the same
for both. This feature was added after a false positive on a forgetful user, and
saying so is worth more than pretending it was designed in from the start.

Two logistic heads produce an automation score and a malice score, each accumulated
across the session. Keeping them apart earns its keep twice: cost depends on
hostility alone, so the belief that drives the policy is the malice score, while the
automation score is spent on choosing *which* probe to deploy, because a scripted
scanner and a careful human take different bait at different rates.

Baits are placed on a *channel* — an HTML comment, an unused JSON field, a
fabricated error string — chosen so a browser renders the response identically with
and without them. Invisibility is not asserted, it is tested. Every bait passes an
invisibility gate before it can be used, and the gate was built before any bait
existed, so a bait carries a certificate the policy checks at run time rather than a
promise.

A diverted session is moved into a decoy: a consistent fake copy of the application
in a separate process where nothing is real and everything is recorded. Section 6
handles the hard part, which is not looking real once but staying consistent.

---

## 4. The decision rule

This is the centre of the paper. Give it room.

Set it up as a three-action cost problem. At each point the defender holds a belief
`p` that the client is hostile. It can **pass**, **divert**, or **bait**. Each
action-outcome pair has a cost, fixed and hashed before any data was collected:

|                | pass | bait | divert |
|----------------|-----:|-----:|-------:|
| client benign  |  0   |  1   |  200   |
| client hostile | 25   | 25   |  −20   |

Three of those entries carry the argument and should be explained. Diverting a
benign user is the outcome that must almost never happen, so it is priced two orders
of magnitude above any other error. Baiting a hostile client costs exactly what
passing one costs, because the request still reaches the real application — the
immediate exposure is identical. And the only difference between pass and bait is
the small nuisance cost borne by the benign mass.

Take expectations and each action is linear in `p`:

```
E[C(pass)]   = 25p
E[C(bait)]   = 1(1−p) + 25p = 1 + 24p
E[C(divert)] = 200(1−p) − 20p = 200 − 220p
```

Now the result that makes the paper. `E[C(bait)] − E[C(pass)] = 1 − p ≥ 0` at every
belief. Baiting is strictly more expensive than passing everywhere. So on immediate
cost the middle action is never chosen and the policy collapses to a two-way rule,
crossing over at `25p = 200 − 220p`, that is `p = 200/245 = 0.8163`. **There is no
band. There is nothing in the middle to tune.**

Then price the probe as an information purchase. It produces an observation — bite
or no bite — that sharpens the belief and therefore the next decision. The expected
value of sample information is the expected reduction in optimal cost from making
that observation. Bait is priced at its immediate cost minus that value.

Two properties bound the band by construction and both are elementary. Information
never hurts, so the value is non-negative — a minimum of affine functions is
concave, and Jensen does the rest. And at certainty no observation can change the
decision, so the value is exactly zero at `p = 0` and `p = 1`. The band therefore
cannot swallow the whole range and cannot be widened by tuning.

With the frozen table and the calibrated library the derived bands come out as
PASS below 0.0647, BAIT from 0.0647 to 0.8793, DIVERT above 0.8793. The two edges
come from two different baits, which is what taking a maximum over the library
means. The lower edge comes from the `internal_view` probe (β_attack 0.753,
β_benign 0.0067, measured over 183 hostile and 74 benign sessions); the upper from
the unused-JSON-field probe, whose higher bite rate is worth more once belief is
already high.

Point out that offering the probe *raises* the divert threshold from 0.8163 to
0.8793. The defender is willing to wait a little longer before doing the expensive
thing, precisely because it now has a cheaper way to buy certainty.

Then the invariance work, because a derived band is only as trustworthy as the two
things it is derived from. Sweep β_attack across 0.05 to 0.99 — the band stays
non-empty and the divert threshold never falls below the cost-only boundary. Sweep
the cost ratio from 0.5 to 128, two orders of magnitude either side of the frozen
8 — same. What moves is *where* the boundaries sit, meaning how conservative the
system is; what never moves is whether the third action exists, or whether the probe
can make the system divert earlier than cost accounting alone would (it cannot).

---

## 5. Calibrating the probe

The rule needs one empirical input: how much a bite tells you. If that number is
set by hand to make the system work, the derived band is a fiction with a
derivation painted on it. So it is measured, and both sides of it are measured.

The evidence a bite carries is a likelihood ratio — how much more likely a hostile
session is to take the probe than a benign one. Report the no-bite ratio too. A
system that only ever revises suspicion upward accumulates without bound and will
eventually divert somebody for browsing slowly. Declining a probe is weak evidence
of innocence and the model should say so.

For the bait that carries most of the results, the planted `internal_view`
reference: **138 of 183 hostile sessions shown the probe took it, and 0 of 74 benign
ones did**, giving β_hostile 0.753 and β_benign 0.0067 after smoothing — a bite
likelihood ratio of about 112 and a no-bite ratio of 0.25.

Explain the problem the phase order created, because it is a genuinely
transferable methodological point. These rates have no legitimate source in the
obvious data. The training corpus was collected before the baits existed, so it
contains no bites. The held-out corpus is the test set and must not be touched.
There was no third option in the original plan, so one was added: a dedicated
calibration round, run after the baits exist and frozen before the evaluation, whose
only permitted use is estimating probe effectiveness. The round vocabulary —
train, calibrate, evaluate — is enforced in the record schema so a rerun of one
round cannot quietly become another.

Say why β_benign is measured rather than set to zero. It is tempting: bait is
invisible to a browser, so a real user has nothing to act on. But a hard zero makes
the likelihood ratio infinite and the arithmetic degenerate, and it assumes away
exactly the safety property the project exists to measure. Every benign count is in
fact zero, so the reported rates are posterior means of a Jeffreys-smoothed estimate
with a stated floor of one bite in two thousand sessions.

Then the provenance point. The library holds five baits. Four are measured — the
one above, a fake table name in a database error (β 0.563 over 181 sessions), a
deprecated-endpoint hint in a login failure (0.580 over 181), and an unused JSON
field (0.794 over 50) — and their likelihood ratios run from about 41 to 112. One,
a fake column list in an HTML comment, was shown to no hostile session in the round
and keeps a prior; it is almost never selected on this application's response
shapes, so it moves no reported number. Provenance is recorded per bait, measured
or prior, with session counts, because a library whose whole claim is that its
parameters are measured has to say which ones are not.

That principle cost an entry, and this is worth telling. A sixth bait — a debug
token in a JSON authentication failure — was withdrawn rather than kept, because
this target's login and OTP endpoints return HTML, so it was shown to zero sessions
of either kind and its β was still the prior invented before any data existed.
Withdrawing it moved the derived PASS→BAIT edge, which had been computed partly
from that prior.

Finally, the calibration-harness failure, which can be short but should be there.
The first calibration was wrong in a way that looked like a result: the simulated
bait-following attacker bit whichever planted token it met first rather than the one
belonging to the category being measured, so sessions meant to measure one probe
were often diverted during warm-up by another. One probe's effectiveness was
understated by roughly a factor of seven. Nothing raised an error. The library was
internally consistent and the bands derived from it were plausible.

---

## 6. Consistency: the Fact Notebook

A decoy that is convincing on the first request and contradicts itself on the third
has not fooled anyone; it has announced that it is a trap. Name the four properties
that consistency actually decomposes into: answering the same query the same way
twice, keeping a value the same when it is reached by a different route, returning
what was written if the attacker writes and then reads, and having references
between objects resolve.

One component meets all four. It sits between the decoy's generators and its
responses: the first time a value is needed it records what was produced, and on
every later reference it serves the recorded value. The generator can be anything —
a deterministic function here, a language model in principle — because the notebook
does not care how a value was first produced, only that it never changes.

Two mechanisms give all four together: values come from a generator seeded by run
seed, namespace and key, so the same key yields the same value even when first
reached months later through a different endpoint; and the first write wins, with
anything the attacker writes stored at higher precedence than a generated default.

The ablation is a single switch and the numbers are stark. With the notebook, the
contradiction rate over **286 adversarial probes** from a consistency fuzzer is
**zero**. With it disabled, **one hundred percent**.

Then answer the sceptic before they ask. A deterministic function is already
self-consistent, so perhaps the notebook is doing nothing a seeded RNG could not.
The ablation was repeated against a genuinely stochastic generator, a local language
model, which cannot be self-consistent by construction. Over fifteen entities it
contradicted itself on every one without the notebook and on none with it. The
guarantee belongs to the notebook, not to whatever produces the content.

---

## 7. Implementation and reproducibility

Keep this short. The defence is about six thousand lines of Python behind an
asynchronous proxy, with the target application and the decoy as separate services;
the evaluation harness and tests add another eleven thousand.

Three mechanisms matter. The model is frozen before evaluation — a manifest hashes
the two logistic heads, the cost table, the feature set and its version, the
calibrated bait library and the invisibility certificates, and the system refuses to
start if any of it has moved. Traffic is seeded and replayed, so each baseline sees
byte-identical traffic and the comparison is of *systems* rather than of *samples*.
The log is append-only and hash-chained, so a later edit breaks the chain.

Worth one sentence: the feature extractor is versioned and a model trained on one
feature version refuses to load against another, which turns a subtle silent error —
features drifting out of step with the weights that consume them — into a loud one.

---

## 8. Evaluation

**Setup.** Three arms: B1 a signature firewall, B2 the passive meter, B4 the full
system. Each ran over **99 independent seeded traffic draws** of 120 attack and 80
benign sessions — **11,880 attack and 7,920 benign sessions per arm**. One further
seed was discarded from every arm because it lost sessions to a resource fault
mid-draw; dropping it from all three keeps the pairing matched. Within a seed every
arm sees byte-identical traffic, so each attack session forms a matched pair.

Proportions carry Wilson intervals, which behave sensibly near zero. B2 against B4
uses an exact paired McNemar test. The holdout uses Fisher's exact test with a
bootstrap interval on the difference.

**The causal estimate — lead with this.** A fixed fraction of the sessions that
reach the bait band are deliberately not baited. Assignment is random conditional on
the same belief state, so the difference between baited and withheld is an unbiased
estimate of the causal effect of baiting rather than a comparison of two systems.

| group | n | diverted | rate |
|---|---:|---:|---:|
| baited (policy) | 10,643 | 10,112 | **0.950** |
| withheld (holdout) | 1,237 | 1,089 | **0.880** |

Effect **+0.070**, bootstrap 95% CI **[+0.052, +0.088]**, odds ratio **2.59**,
Fisher exact **p = 3.4 × 10⁻¹⁹**.

Say that this number is smaller than earlier drafts of the work reported, and why.
A single draw once gave +0.23; a 20-seed run against an earlier meter gave +0.11;
the previous bait library gave +0.053. The current meter is strong enough on its own
that there is less headroom for a probe to recover, and recalibrating the library
raised the divert edge so the probe now defers diversions it used to make.

**Baselines and recall.**

| arm | attack recall (95% CI) | benign diverted |
|---|---|---|
| B1 signature WAF | 0.366 [0.358, 0.375] | 0 / 7,920 |
| B2 passive | 0.889 [0.883, 0.894] | 4 / 7,920 |
| B4 full | **0.943 [0.939, 0.947]** | **0 / 7,920** |

The intervals for B2 and B4 do not overlap, and the paired test confirms rather than
restates it: of 11,880 matched attack sessions, **10,841 are concordant, 842 are
caught by B4 alone and 197 by B2 alone**, giving McNemar **p = 1.9 × 10⁻⁹⁵**. B4 is
ahead in **99 of 99 seeds**, which is what rules out a lucky draw.

Do not hide the 197. They are diversions the probe defers — B4 waits inside the band
between 0.816 and 0.879 where B2 would already have acted.

**A real WAF, not only ours.** This is the strongest single addition and it should
be prominent. B1 is fifteen regexes we wrote, and a reader is entitled to distrust a
baseline its authors built. So the same traffic was replayed through **OWASP
ModSecurity CRS** at every paranoia level the ruleset defines. A WAF decides from
one request with no cross-request state, so a replayed request gets the verdict it
would have got inline, and the traffic comes from an undefended arm so nothing is
cut short by a defence acting on it.

| CRS paranoia | attack recall (95% CI) | benign sessions blocked |
|---|---|---|
| 1 (default) | 0.353 [0.305, 0.404] | **0 / 240** |
| 2 | 0.544 [0.493, 0.595] | **0 / 240** |
| 3 | 0.544 [0.493, 0.595] | **0 / 240** |
| 4 (maximum) | **1.000** | **72 / 240 (30%)** |

Two things follow. At its default the real ruleset scores 0.353 against B1's 0.366
with heavily overlapping intervals, so B1 is not a weakened stand-in. And the
ceiling is not a tuning question: CRS reaches perfect recall only by blocking
**thirty per cent of legitimate sessions**, which no operator can run. Across every
setting that leaves benign traffic alone a signature ruleset tops out near 0.54,
against 0.943 at zero benign diversions here.

State the one asymmetry in CRS's favour rather than letting a reviewer find it: CRS
is judged on blocking any request of a session while our arms are judged on
diverting the session, and blocking is the easier task because it needs no decision
about who the visitor is.

**Where the gain lives.** Splitting the matched pairs by subcategory is the sharpest
test of the theory, because the theory says the gain must be concentrated.

| subcategory | n | B2 | B4 | gain | B4 bite rate |
|---|---:|---:|---:|---:|---:|
| **idor_html_scattered** | 1,980 | **0.540** | **0.823** | **+0.282** | **0.620** |
| sqli_obfuscated | 3,960 | 0.898 | 0.921 | +0.022 | 0.162 |
| sqli_stealth | 1,980 | 1.000 | 1.000 | +0.000 | 0.503 |
| idor_scattered (API) | 1,980 | 0.994 | 0.993 | −0.001 | 0.000 |
| auth_spray | 1,980 | 1.000 | 1.000 | +0.000 | 0.000 |

Almost the entire gain is in UI-based scattered object access: **+0.282**, with a
paired McNemar on that subcategory alone of **b = 639 against c = 80**. That is the
one category a signature cannot see and the one where the passive meter is genuinely
undecided — precisely where Section 4 says information is worth buying.

Everywhere else the probe is neutral, and the reasons are worth giving.
`sqli_stealth` bites half the time and its recall does not move at all, because
those sessions were already caught: the information was bought and turned out not to
be needed. Scattered access over the JSON API is caught passively, because an
attacker walking ids collects 404s while a reporting integration reads only ids that
exist, and the error-ratio feature separates them without any probe.

**Safety.** Zero of 7,920 benign sessions diverted. **7,098 of 7,920 (90%) were
shown a probe and not one acted on it.** High exposure, nil consequence — which is
the whole point of the invisibility gate, and the number that makes the nuisance
cost of 1 defensible.

---

## 9. Ablations

Cover the ones that already work: removing the probe (that is B2 against B4),
removing the decoy's memory (Section 6), the adaptive adversary who refuses every
probe, and removing each estimated input in turn.

Then the two that go against the paper. Write these carefully; they are the most
valuable pages in it.

**Hand-set thresholds.** The obvious challenge is that someone could have picked the
two edges by hand and done as well. Answering it needs a policy variant that scores
baiting on immediate cost alone, without subtracting the information value —
otherwise the derived rule is being compared against itself in a disguise. That
variant was built and run on the same frozen model, seeds and traffic.

**The derived edges do not win on expected cost.** Report the table. Two hand-set
pairs beat them. Then give the three measured reasons, none of which is that a
person guessed better:

The gap is benign nuisance baiting, not detection — the derived arm shows a probe to
89% of benign sessions (3,433 of 3,840) against 65% for the arms that beat it, at
one unit each.

The edge is not choosing a value, it is choosing a side. The belief takes only a
handful of distinct values, and **two of them account for 56% of every decision the
policy makes** (0.163 and 0.476). Every edge below 0.163 behaves identically, and so
does every edge between 0.163 and 0.463. The measured benign-bait rates confirm it:
0.897, 0.896 and 0.903 for the three arms whose edge falls below 0.163, against
**0.650, 0.650 and 0.650** for the three above it — identical to three decimals
even though that group's lower edge runs from 0.187 to 0.300. Four decimal places of derived
precision are not doing the work they appear to.

The derived DIVERT edge is what buys zero benign diversion. Benign belief ceilings
top out at **0.829**; the derived edge sits at **0.879**, above all of them. That is
a consequence of the derivation rather than a coincidence — the edge is placed by the
cost table's 200:25 ratio, and the ratio pushes it clear of the benign distribution.
Three arms divert no benign session at all, and among those the derived edges are
best on both axes. Every arm that beats them on cost does so by diverting benign
users.

So the honest claim is narrower than "derived beats hand-set", and it is the claim
the cost table actually supports: within the configurations that never divert a
benign user, the derived edges are the best available.

**Calibrating the belief.** Every band edge is a threshold on a probability, and the
meter that produces it was given its weights by hand and never fitted to a label.
Measured on four draws held out by seed range, **it is not calibrated**:
over-confident below about 0.6 — requests it calls 0.163 are attacks 0.4% of the
time — and under-confident above it. Three standard maps were fitted and chosen
between by leave-one-draw-out held-out expected calibration error, so the winner is
the one that survives a withheld draw rather than the one that fits best. Isotonic
wins: held-out ECE **0.157 as shipped against 0.018 calibrated**.

Measuring the consequence needed no change to any frozen artefact, and this is a
neat point worth making explicitly. A calibration map is monotone, so applying the
derived edges to a calibrated belief is arithmetically the same policy as applying
inverse-mapped edges to the raw one — which the fixed-threshold arm already
implements. The derived pair becomes (0.187, 0.619) on the raw belief.

Calibrating gives the best recall of anything measured — **0.979 against 0.940**, and
on matched attack sessions 245 are caught by it alone against 21 by the shipped
policy (McNemar p = 1.3 × 10⁻⁴⁹) — and costs the zero-benign-diversion property,
diverting 81 of 3,840. Under
the frozen table that decides it: the break-even price of a benign diversion is
**134**, and the table, written before any data existed, prices it at 200.

Then the reading that is most useful, and the one to end on. Two modelling errors
are present and they point opposite ways. The belief is under-confident at the top,
which pushes the derived edge higher on the raw scale than the cost model intends.
And the rule is derived for one decision but deployed as a first-crossing test over
a whole session, which means the cost-optimal edge is *higher* than the per-decision
indifference point. The shipped configuration sits close to the session-level
optimum because those two errors nearly cancel. Correcting either alone moves it
away. A rule that is right for compensating reasons is a different object from a
rule that is right, and a reader deciding whether to adopt the method is entitled to
know which one this is.

---

## 10. Limitations

Separate the ones retired by fixing the problem from the ones that are irreducible,
because how a project retired its weaknesses is evidence about the ones it kept.

**Retired.** An earlier version diverted every benign reporting-integration client,
because two features treated any API access and any run of ascending ids as hostile —
the exact shape of a harmless integration. A human-only benign set had hidden this
completely; adding automated-but-harmless clients exposed it. A false positive on a
forgetful user turned out not to be inherent either: a missing feature plus a double
count.

The second retirement is worth reporting for how it was found. The attack generator
spoke raw HTTP and never fetched a page sub-resource; the benign one fetched them
like a browser. So the corpus contained no attack session that fetched an asset and
almost no human-paced benign session that did not, and a logistic regression on the
automation features alone separated the two at an out-of-sample **AUC of 0.9935** —
on a property of two scripts, not of hostility.

No reported number was affected, and say why with the evidence: automation carries
weight zero in the hostility belief, and the logs confirm it — across 12,954 scored
requests the belief equals the malice score exactly while the automation score ranges
over its whole domain. But the corpus was easier than reality, so half the attackers
now drive a browser. The automation-only figure falls to 0.898, every arm gets
harder, and every measure of the probe's contribution rises. All numbers in the paper
are the harder ones. The browser-driven fraction was deliberately not raised further
to drive the AUC down, which would be fitting the corpus to a desired measurement.

**Irreducible.** The traffic is synthetic. The benign mix approximates office traffic;
it is not a sample of it, and every rate is a statement about this distribution.
Replaying a public labelled corpus and recruiting human browsers would bound the
benign side and is the natural next step.

The probe's effectiveness is a property of an attacker model we chose. This is
addressed two ways rather than caveated: the adaptive-adversary result shows the gain
decaying to the passive floor, and the parameter sweep shows the band's existence and
the safety direction holding across the whole plausible range. What does not transfer
is the magnitude.

One application. Transfer is checked by putting the frozen model in front of a
second, structurally different one and attacking it with real tools — app-agnostic
features fire correctly, app-specific ones would need re-pointing, a full evaluation
with a matched decoy on a second application remains future work.

The cost table is a reasoned estimate, not a real organisation's incident data. It is
frozen so it cannot be tuned to the results, and the sweep shows the conclusions
survive two orders of magnitude of the ratio it encodes, but the level of
conservatism it sets is a judgement.

And the one that matters most: the deception is assessed by the researchers and a
consistency fuzzer, not by independent human participants. Whether a human attacker
*feels* something is off is not measured, and it is the single most valuable thing
left to measure.

---

## 11. Related work

Position against five bodies of work, and be exact about the gap in each rather than
listing citations.

*Web attack detection* — signatures are brittle to obfuscation and blind to attacks
that are valid syntax; learned detectors trade brittleness for a model but keep the
passive stance. Our detector is one of these and the two-axis meter is not the
contribution; a signature firewall and the passive meter are the two honest
baselines precisely because the contribution is what sits on top of them.

*Bot and automation detection* — the useful finding is a negative one: advanced bots
imitate browser fingerprints and human pacing closely enough that automation signals
alone stop separating them from people. That is why the meter keeps the two axes
apart.

*Honeypots and cyber deception* — well studied, but in almost all of it the deception
is a *destination*: a caught attacker is moved somewhere, and the move follows a
decision already made. We treat deception as an instrument the detector uses while
the decision is still open.

*Honeytokens and decoys* — old and widely deployed, but treated as always-on
tripwires. The question here is *when* to deploy one, given that deploying it is not
free. The invisibility requirement and its verification by a gate do not appear as a
measured property elsewhere.

*Application-layer and LLM-generated deception* — the closest neighbours. Be exact:
the application-layer survey counts nineteen technical methods and reports that
everything beyond honeypots and reverse proxies has received little research
interest, which both defines the space and says it is nearly empty. Work that
measures how tempting a deception looks does it by questionnaire, so it captures what
people say they would click rather than what they do against a live system. Work that
automates honeytoken deployment and rotation stops exactly where this begins: it does
not decide *when* to deploy one based on a belief about the visitor being served.

*Probability calibration and value of information* — both textbook, and the paper
claims no new theory in either. Calibration is used as a diagnostic. The observation
not found stated elsewhere is that a per-decision cost-sensitive threshold, deployed
as a first-crossing test over a whole session, is subject to two errors of opposite
sign that can partly cancel — so a rule can be close to optimal for compensating
reasons rather than correct ones.

---

## 12. Conclusion

Passive defences force a choice between acting early on weak evidence and acting late
on strong evidence, and the paper's claim is that the choice is avoidable: a defender
can manufacture evidence, and when to do so follows from the value of the information
it buys. The one thing to carry away is that without the information term there is no
third action at all, so the probe cannot be a tuned threshold.

The evaluation supports the mechanism rather than a headline number. The probe helps
where the theory says it should — in the one region of belief the passive classifier
is genuinely unsure about — and a randomised holdout attributes that help causally to
the probe rather than to the rest of the system.

Then the honest paragraph. Deriving the edges did not beat setting them by hand on
expected cost, and the measured reason is given rather than the claim. That is a
narrower result than the work set out to establish and a more useful one, because it
says what the derivation actually buys: a placement that clears the benign belief
distribution by construction.

Close on what the setting cannot support — synthetic traffic, one tuned application,
one laboratory — and on the next step the laboratory cannot supply: whether a human
attacker, not a tool, takes the bait.

---

## Things to be careful about while writing

Do not write "we prove" for anything except the two elementary properties in Section
4. Everything else is measured, and measured under a stated model.

Do not round a p-value to "p < 0.05" when the actual figure is 10⁻⁹⁵. It reads as
though you did not look.

Every table in the paper should be reproducible from a command. Where it is, say so.

If you shorten a number — 0.9428 to 0.943 — do it everywhere, and re-run the checker
afterwards. Half the errors found while preparing this were a figure updated in one
place and not the other.

The agentic-attacker result in Section 9 is currently **retracted** pending a re-run,
because the agent's view of each response was truncated before the probe and the
measurement was of our harness rather than of the adversary. Do not write that
subsection until the new numbers land.

---

## How long each section should be

SPACE allows 20 pages in LNCS format. Once the references (43 entries, about a page
and a half), the figures and tables (roughly four pages), and the headings and
abstract block are accounted for, there are about fourteen pages left for prose —
call it **7,500 words**. The draft this brief was written from runs to 19,133, so
roughly half of it has to go. That is much easier to do while writing than
afterwards, which is why the targets are here rather than in a later editing pass.

| section | target | note |
|---|---:|---|
| 1 Introduction | 700 | the trap, the move, the pricing argument, contributions |
| 2 Threat model | 400 | in scope, the two axes, the browser-driven adversary, out of scope |
| 3 System design | 600 | proxy, sessions, features, meter, bait, decoy — one paragraph each |
| 4 Decision rule | 1,100 | the largest section, and it should stay that way |
| 5 Calibration | 600 | the numbers, the phase-order problem, the withdrawn bait |
| 6 Consistency | 350 | four properties, one component, the ablation, the LLM repeat |
| 7 Implementation | 300 | three mechanisms, nothing else |
| 8 Evaluation | 1,500 | setup, holdout, baselines, CRS, subcategories, safety |
| 9 Ablations | 1,200 | the working ones briefly; 9.7 and 9.8 in full |
| 10 Limitations | 450 | retired, then irreducible |
| 11 Related work | 600 | five paragraphs, one per body of work |
| 12 Conclusion | 250 | claim, evidence, the honest paragraph, next step |
| **total** | **8,050** | leaves a little slack for the abstract and headings |

Two things not to cut, whatever the pressure. **Sections 9.7 and 9.8** — the results
that go against the paper — because a reviewer's trust in everything else is built
there. And **Section 10**, for the same reason.

The easiest words to lose are usually: a sentence that restates the previous
sentence more carefully, a hedge in front of a number that already carries an
interval, and any passage explaining why something was *not* done when nobody asked.
Prefer cutting whole sentences to trimming clauses; the result reads better and
saves more.
