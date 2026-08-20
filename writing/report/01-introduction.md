# CHAPTER 1

# INTRODUCTION

## 1.1 Problem Definition

Almost every organisation now delivers its core services over the web. Banking,
healthcare records, student information systems, internal dashboards and customer
portals are all reachable over HTTP, and the application in front of that data is
frequently the only thing standing between a stranger and the records it holds.
Protecting that application is therefore not a peripheral concern; it is the
security boundary itself.

The standard control placed in front of a web application is a **Web Application
Firewall (WAF)**. A WAF inspects each incoming request, compares it against a body
of rules, and makes a decision. That decision is binary: the request is allowed
through to the application, or it is blocked. Modern learned detectors replace the
hand-written rules with a statistical model, but the shape of the decision does not
change — the system watches evidence accumulate and eventually commits to one of two
outcomes.

This binary structure creates a dilemma that cannot be resolved by improving the
classifier, because it is a property of the *action set* rather than of the
*evidence*. Consider what the defender faces at the moment a request arrives:

1. **Acting early on weak evidence.** If the system blocks whenever suspicion
   crosses a low threshold, it will interrupt legitimate users. A customer searching
   for a colleague named *O'Connell* sends an apostrophe in a query parameter, which
   is indistinguishable, at the level of a single request, from the opening move of
   an SQL injection. A staff member who has forgotten their password produces a run
   of failed logins that looks like a credential-stuffing attempt. A nightly
   reporting integration walks record identifiers in ascending order, which is
   exactly the access pattern of an object-reference sweep. Blocking these users
   damages the business more reliably than the attack would have.

2. **Acting late on strong evidence.** If the system waits until suspicion is
   overwhelming, it will be right when it finally acts — but by then the attacker
   has had many requests in which to succeed. An object-reference attack does not
   need a hundred requests; it needs the handful required to walk from record 1041
   to record 1042. Waiting for certainty means waiting past the point at which the
   damage is done.

Between those two failures lies a wide region in which the defender is *genuinely
uncertain*, and it is precisely in that region that a two-action system has nothing
useful to do. It must choose one of two bad options, and its only tuning knob — the
threshold — merely selects which of the two errors it prefers to make.

The problem is sharpest for attacks that are **valid syntax**. The canonical example
is the **Insecure Direct Object Reference (IDOR)**, in which an attacker changes an
identifier in a URL — `/records/1041` becomes `/records/1042` — and reads another
user's data. There is nothing malformed to match. There is no injection payload, no
suspicious character class, no signature. The request is exactly the request a
legitimate user would send if that record were theirs. A signature firewall is blind
to it by construction, and a learned detector must infer hostility from the *pattern
of access* rather than from the content of any single request, which takes time it
may not have.

A second structural weakness follows from the same binary design. Because a WAF must
commit, its verdict is a **terminal event**. Once a session is blocked, the defender
learns nothing further about it: the attacker simply changes address and returns. The
defence has spent its only move and gained no intelligence. Deception technologies —
honeypots and honeynets — do collect intelligence, but they are conventionally
deployed as *separate destinations*, and a session only reaches them once it has
already been judged hostile. Deception, in current practice, is something that
happens **after** the decision, not something that helps to **make** it.

Stated compactly, the problem this project addresses is:

> A web-attack detector is forced to commit to allowing or blocking a session using
> only the evidence that arrives on its own. In the region where the detector is
> genuinely uncertain — which is exactly where valid-syntax attacks such as IDOR
> live — neither action is defensible, and the detector has no mechanism by which it
> could *acquire* the evidence that would let it decide correctly.

An adequate solution must therefore satisfy several conditions simultaneously,
and it is the *simultaneity* that makes the problem hard:

1. It must give the detector a **third action** that neither allows nor blocks, so
   that uncertainty has a response other than a coin flip.
2. That third action must be **invisible to legitimate users**, since a defence that
   is felt by honest traffic has replaced one cost with another.
3. It must be **inert** — it can never grant real access, change application state,
   or produce behaviour a user could trip over.
4. The decision to use it must be **principled rather than tuned**, because a
   hand-set threshold in the middle of a two-action system is simply a third
   arbitrary number, and a reviewer is right to distrust it.
5. Its effect must be **measurable causally**, not merely correlated with better
   outcomes, since a system that improves for reasons its designers cannot identify
   has not been evaluated.
6. Everything it records must be **tamper-evident**, so that the audit trail retains
   value even when an attacker obtains privileges.

## 1.2 Problem Overview

The gap identified above is narrow but consequential, and it is worth being precise
about where existing work stops.

**Signature firewalls** encode known-bad patterns. They are fast, explainable and
widely deployed, and they perform well against textbook payloads. They fail in two
predictable ways: obfuscation, where the same injection is split across inline
comments, case-mixed, or URL-encoded twice until the canonical pattern no longer
matches; and valid-syntax attacks, where there is no pattern to match at all. This
project measured both failures directly. A signature ruleset built from regular
expressions for injection, scripting, traversal and command injection, plus scanner
user-agents, reaches an attack recall of only **0.366** on the evaluation corpus, and
its recall on user-interface IDOR is **exactly zero** — not low, but zero, because
nothing in such a request is anomalous at the byte level. To confirm this is not an
artefact of a weak in-house baseline, the industry-standard **OWASP ModSecurity Core
Rule Set** was replayed against identical traffic and scored **0.353** at its default
paranoia level, marginally *below* the project's own baseline.

**Learned detectors** replace signatures with a model and do materially better on
obfuscation, because they generalise over payload shape rather than matching it. But
they keep the passive stance. They observe, accumulate, and commit. Their improvement
is in *how well they read the evidence*, not in *whether they can obtain more of it*.
The passive detector built in this project reaches a recall of **0.889**, a large
improvement over signatures, and yet it still misses a substantial share of
user-interface IDOR sessions — precisely the ones on which its belief sits in the
uncertain middle and never rises far enough to act.

**Honeypots and cyber deception** are a mature field with decades of work behind
them, and this project reuses much of it. But in almost all of that literature the
deception is a **destination**: a caught attacker is moved somewhere. The move
follows a decision that has already been made by some other mechanism. The question
of *whether deception could contribute to making the decision in the first place* is
largely unasked.

**Honeytokens** — planting a fake credential, file or record as a tripwire — come
closest. A honeytoken is deception used as a sensor rather than as a destination,
which is the right idea. But the literature treats honeytokens as **always-on**: the
token is planted once and left in place. That is reasonable when planting is free.
It is not free here, because a probe placed in a response served to a real user
carries a small but genuine risk, and because a token that every visitor sees is a
token that will eventually be catalogued and published, burning it permanently. The
question the honeytoken literature does not ask is **when** to deploy one.

The gap, then, is a decision-theoretic one. There exists a body of work on *how to
build convincing deception* and a body of work on *how to detect attacks passively*,
and almost nothing on *how a detector should decide, at a given moment and for a
given visitor, whether deploying deception is worth what it costs*. That is the
question this project answers, and answering it requires treating the probe not as a
security gadget but as an **information purchase** with a price and a return.

## 1.3 Task Identification

From the problem definition and the gap analysis, the work decomposes into eight
concrete tasks. Each was treated as a phase with an explicit exit condition that had
to be met before the next phase began, and the sequencing is deliberate: several of
these tasks are impossible to do honestly if attempted in the wrong order.

**Task 1 — Build a deliberately vulnerable target and a labelled benign corpus.**
Before any detector can be evaluated, there must be an application to defend and
traffic to defend it against. The target is a small records application with genuine,
intentional weaknesses: an SQL-injectable search, object-reference endpoints with no
ownership check, and a login flow that leaks whether an account exists. The benign
generator must produce traffic that is *hard*, not merely normal — including honest
users who behave in ways an attacker also behaves.

**Task 2 — Construct a training attack corpus and verify the label join.**
Attack traffic must be generated with ground-truth labels attached, and — this is the
part that is easy to get wrong — those labels must actually join to the requests they
describe. An early version of this project produced a labelled corpus in which the
join matched **zero** requests, a failure that would have silently invalidated every
downstream number.

**Task 3 — Build the two-axis detection engine.**
Rather than collapsing everything into one suspicion score, the detector maintains
two independent axes: **automation** (is this client a script?) and **malice** (are
these inputs hostile?). The reason is that the interesting cases live in the
off-diagonal quadrants. A scanner is automated *and* hostile. A price-comparison bot
is automated *and* harmless. A careful human attacker is *neither* automated *nor*
obviously hostile. A single score cannot express the middle cases, and it is exactly
the middle cases the probe exists to resolve.

**Task 4 — Build the bait library, with the invisibility gate first.**
The ordering here is a hard requirement rather than a preference. A bait may not
enter the library until it holds a passing **invisibility certificate** proving that
injecting it leaves the rendered output unchanged, keeps JSON parseable, and adds
negligible latency. Building the gate after the baits would mean the baits were
designed without the constraint they must satisfy.

**Task 5 — Build the state-consistent decoy.**
A diverted attacker must land in a fake world that does not contradict itself. If the
decoy answers "user 1041 is Rakesh Malhotra" on one request and "user 1041 is Priya
Nair" on the next, it has announced itself. This requires separating *what the fake
world contains* from *what generates it*, so that the consistency guarantee holds
regardless of whether a deterministic generator or a language model produces the
content.

**Task 6 — Derive the decision rule and freeze the cost model.**
The core intellectual task. The cost of every kind of mistake must be written down
**before any results are seen**, hashed, and enforced, because the entire argument
depends on those numbers not having been chosen to make the results look good. The
decision rule is then *derived* from that table plus the measured effectiveness of
each probe, not tuned against outcomes.

**Task 7 — Evaluate against a held-out attack round with statistical rigour.**
A second attack corpus, written after the detector was built and deliberately unlike
the one it was tuned on, is run over many independent seeds against one frozen model.
Comparisons use paired tests because the harness gives every arm byte-identical
traffic. A randomised holdout inside the treated arm isolates the probe's causal
contribution from every other difference between two configurations.

**Task 8 — Validate against adversaries the project did not design.**
Because the attacker model is the project's own construction, the sharpest objection
is that it was chosen to suit the defence. This task answers it from three
directions: real third-party attack tools, a swept-parameter adversary population,
and an autonomous language-model attacker that chooses its own requests and is told
nothing about bait.

The overall goal is an **Active Deception Framework (ADF)**: a system that treats
deception as a priced, measurable action available to the detector during
uncertainty, rather than as a container for attackers who have already been caught.

## 1.4 Timeline

The project ran across eight phases. Each phase had a written exit condition, and
work on the next phase did not begin until that condition was met and verified —
the discipline that prevents discovering in the final week that data was collected
in the wrong format.

| Phase | Name | Exit condition | Period |
|---|---|---|---|
| 0 | Foundation | Cost table written and hashed; label schema fixed; logging skeleton in place | Week 1 |
| 1 | Target application + benign corpus | All six corpus verification checks pass | Weeks 2–3 |
| 2 | Attack round 1 (training) | 2 × 2 automation/malice coverage; clean label join | Weeks 3–4 |
| 3 | Detection engine (baseline B2) | Validated end-to-end on identical traffic; zero benign diversions among automated clients | Weeks 5–6 |
| 4 | Bait library — **gate first** | Gate built before any bait; every bait certified; bite rates calibrated | Weeks 7–8 |
| 5 | Decoy + Fact Notebook + fuzzer | 0 % contradiction rate over 286 adversarial probes; full target/decoy parity | Weeks 9–10 |
| 6 | Integration, fail-open, model freeze | Per-component fail-open verified; hash manifest frozen and verified | Week 11 |
| 7 | Attack round 2, baselines, ablations | 99-seed evaluation; statistical protocol pre-registered; all ablations reported | Weeks 12–14 |

![The eight development phases shown as a completed pipeline, each with its exit condition.](../figures/phases.svg)

**Figure 2: Project timeline** The phases are strictly ordered. Phase 4 in
particular could not be reordered: the invisibility gate had to exist before any
bait was written, because a bait designed without its acceptance criterion tends to
be a bait that fails it.

## 1.5 Organisation of This Report

The remainder of the report is organised as follows.

**Chapter 2** surveys the literature across seven themes — web attack detection, bot
and automation detection, honeypots and cyber deception, honeytokens,
application-layer and LLM-generated deception, probability calibration, and the
decision theory the pricing rests on — and identifies the specific gap this work
occupies.

**Chapter 3** is the design chapter and the longest. It develops the two-axis meter,
derives the three-action decision rule from the frozen cost table, presents the bait
library with its invisibility gate, describes the state-consistent decoy, states the
design constraints, compares three candidate architectures, presents the selected
architecture with full flowcharts and pseudocode, and sets out the phased
implementation plan.

**Chapter 4** reports the evaluation: the tools used, the testing strategy, the
headline results with confidence intervals and paired significance tests, the causal
holdout estimate, comparison against a real signature ruleset, the subcategory
breakdown that localises the entire effect, the calibration analysis, validation
against third-party tools and autonomous agents, and an honest account of the
system's limitations.

**Chapter 5** concludes, documents the ways in which results deviated from
expectations — including two measurement errors that were found and corrected —
proposes future work, and lists references.
