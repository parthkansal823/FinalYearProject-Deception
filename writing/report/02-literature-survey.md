# CHAPTER 2

# LITERATURE SURVEY

## 2.1 Literature Survey

The framework proposed in this report sits at the intersection of several
established research areas. None of the individual ingredients is new; what is new
is where the decision to deceive is placed and how its parameters are obtained. To
make that claim precisely, this survey is organised into **seven themes**, each of
which contributes something the design depends on, and each of which stops short of
the specific question this project answers.

### 2.1.1 Theme A — Web Attack Detection and Web Application Firewalls

The oldest and largest of the seven themes concerns how a defender recognises a
hostile HTTP request at all. The division that organises it, signature-based
detection against anomaly-based detection, is the one set out in NIST's guide to
intrusion detection and prevention systems [43], and it has held up well enough that
both branches are still deployed side by side.

**Signature-based detection** matches requests against a curated body of known-bad
patterns. It is fast, explainable, and remains the dominant deployed control. Its
limitations are equally well understood and are of two kinds. The first is
*obfuscation*: the same injection can be split across inline comments, case-mixed,
URL-encoded once or twice, or expressed through equivalent SQL constructs until the
canonical pattern no longer matches. Amouei, Rezvani and Fateh [3] make this
concrete by treating WAF evasion as a search problem, using reinforcement learning
to discover bypassing payloads automatically; their **RAT** system finds
bypass patterns 33.5 % more effectively than prior black-box testing techniques,
which is a direct statement about how fragile pattern matching is under adversarial
pressure. The second limitation is more fundamental: some attacks contain no
anomalous pattern whatsoever. An insecure direct object reference is a
syntactically perfect request that differs from a legitimate one only in *who is
sending it*. No amount of rule refinement addresses this, because the rule would
have to match a request that is, byte for byte, exactly what a legitimate user
sends.

**Broken access control** deserves a paragraph of its own here, because it is the
category in which this project's entire measured gain sits. OWASP ranks it first in
the Top Ten [34]. It earns that place not because the flaw is hard to exploit but
because the request carrying it is perfectly well formed. A URL such as
`/records/1042` is valid. The application will route it, parse it and answer it.
Whether it counts as an attack depends on who sent it, and that fact appears nowhere
in the request itself.

The consequence for pattern matching is not a matter of degree. The signature
baseline built for this project scores **exactly 0.000** on user-interface
object-reference sessions, a figure reported in Section 4.4.5. The baseline is not
misconfigured and the rules are not weak. There is nothing for a rule to match, and
writing more rules does not change that.

The literature answers this problem in two ways, and neither is available to a proxy
sitting in front of an application it did not write. One answer is to enforce
authorisation correctly inside the application, which is a development practice and
not a detection technique. The other is to infer intent from how a session moves
through the object space across many requests, which is the anomaly-based line
described next. That approach does work, but it has to wait for requests to
accumulate before it will commit, and the waiting period is exactly when the records
are being read. Shortening that period is what the third action of Chapter 3 is for.

**Anomaly-based detection** replaces signatures with a model of normality. Kruegel
and Vigna [30] established the approach for web requests, building per-parameter
statistical profiles, character distribution, length, token structure, presence and
ordering, and flagging deviations. Robertson et al. [41] extended this with
generalisation and characterisation techniques that allow anomalies to be grouped
into recognisable attack classes rather than reported as undifferentiated outliers,
addressing the practical problem that a raw anomaly score is difficult for an
operator to act on.

**Deep learning approaches** followed. Tekerek [51] applies a convolutional neural
network to web request payloads, treating the request as a sequence and letting the
network learn discriminative structure rather than hand-specifying it, evaluated on
the CSIC 2010 corpus [53]. Such models generalise better over obfuscation than
signature matching does, precisely because they operate on learned representations
rather than on literal patterns.

What every entry in this theme shares, signature, statistical, and deep alike, is
the **passive stance**. The detector watches a session accumulate evidence and then
commits. Its sophistication lies entirely in *how well it reads the evidence that
arrives*; none of these systems has any mechanism by which it could *cause more
evidence to arrive*. The detector built in this project is an ordinary member of
this family and is not offered as a contribution; it exists to be the honest
baseline against which the contribution is measured.

### 2.1.2 Theme B — Bot and Automation Detection

A separate line of work asks a different question: not *is this client hostile* but
*is this client a program*. The distinction matters because the two properties are
independent, and conflating them is a recognised source of error.

Iliou et al. [22] propose a framework for detecting advanced web bots from server
logs, and report a result that is uncomfortable for log-only approaches: while
conspicuous bots are detected with balanced accuracy above 95 %, bots that
deliberately present a browser fingerprint and human-like pacing are considerably
harder. Their follow-up work [23] responds by combining web logs with **mouse
behavioural biometrics**, showing that the fusion is more robust against evasive
bots than either signal alone.

The finding this project takes from Theme B is a **negative** one, and it directly
shaped the architecture. Advanced bots imitate browsers closely enough that
automation signals alone stop separating them from people. It follows that
automation must not be used as a proxy for hostility. This is why the meter
described in Chapter 3 keeps automation and malice on **separate axes** rather than
collapsing them into a single score: a vulnerability scanner is automated and
hostile, an uptime monitor is automated and harmless, and a careful human attacker
is neither automated nor obviously hostile. A single score cannot express the middle
cases, and the middle cases are exactly what the probe exists to resolve.

### 2.1.3 Theme C — Honeypots and Cyber Deception

Deception as a defensive strategy has a long and well-developed literature.

It starts before the vocabulary did. Stoll [50] spent the better part of a year in
the late 1980s tracking an intruder through Lawrence Berkeley Laboratory, and at one
point planted fabricated documents where the intruder would find them, in order to
keep the session alive long enough to trace it. Cheswick [12] turned the same instinct
into a deliberate experiment, building a fake environment around one attacker and
recording what he did inside it. Spitzner [48] later collected the accumulated
practice into the first systematic treatment and gave the field the definition it
still uses, that a honeypot is a resource whose value lies in being probed, attacked
or compromised. All three rest on an assumption this project keeps: a defender learns
more from an attacker who is still working than from one who has been shut out.

What changed after them is scale and automation. Provos [39] established the modern
practice with **Honeyd**, a framework for
instantiating large numbers of virtual hosts with configurable personalities,
demonstrating that deception could be deployed at scale rather than as a handful of
sacrificial machines. Nawrocki et al. [33] survey the resulting software ecosystem
and the analysis pipelines built around it.

The theoretical treatments matter more to this project than the software.
Almeshekah and Spafford [2] provide a model for *planning* deception rather than
bolting it on, arguing that a successful deception must present a plausible
alternative to the truth and must be designed against specific adversary biases,
a framing this project adopts directly, since a probe that looks planted warns the
attacker that the site is defended. Han, Kheir and Balzarotti [19] survey deception
techniques from a research perspective and identify precisely the weakness this
report tries not to repeat: it is unclear how the effectiveness of deception
solutions should be *measured*, and the field markets zero-false-positive claims
without the evaluation methodology to support them. Pawlick, Colbert and Zhu [37]
supply a game-theoretic taxonomy across six deception types, and Zhu et al. [59]
survey the game-theoretic and machine-learning approaches together. The most recent
comprehensive treatment is Beltrán-López, Gil Pérez and Nespoli [7], which builds a
unified taxonomy and explicitly lists the gaps that remain open. Cho et al. [13]
survey the adjacent moving-target-defence space, which shares the proactive
philosophy while changing the attack surface rather than populating it with lures.

Two empirical results in this theme are load-bearing for the present work. Barron
and Nikiforakis [6] ran 102 medium-interaction honeypots for four months while
varying location, break-in difficulty and file population, and found that **bots act
environment-agnostically while human attackers do not**, humans execute more
commands on honeypots with realistic file and folder structures. This is the
empirical justification for the Fact Notebook of Chapter 3: realism and consistency
change human behaviour, so they are worth engineering. Ferguson-Walter et al. [17]
provide the field's rare controlled human-subject study of decoy-based and
psychological deception, and it is the closest methodological ancestor of the
randomised holdout used in Chapter 4.

Against this, Vetterl and Clayton [55] demonstrate a *class break*: low- and
medium-interaction honeypots can be fingerprinted at internet scale with a single
packet at an equal error rate of 0.0183, because their protocol implementations
differ subtly from the systems they impersonate. Srinivasa, Pedersen and
Vasilomanolakis [49] extend fingerprinting to honeytokens specifically. Together
these say that **consistency is not free** and that a deception which can be
detected is worse than no deception at all, since it tells the attacker that they
are being watched.

The structural observation across this entire theme is that deception is treated as
a **destination**. A caught attacker is moved somewhere. The move follows a decision
that has already been made by some other mechanism, and the deception's job begins
after the detector's job ends.

### 2.1.4 Theme D — Honeytokens, Decoys and Bait

The sub-literature that comes closest to the present work treats deception as a
*sensor* rather than as a destination.

Yuill et al. [57] introduced **honeyfiles**: bait files on a file server that raise
an alarm when accessed, with the observation that they can increase internal
security without affecting normal operations. Bowen et al. [9] generalise this to
automatically generated **decoy documents** carrying bogus credentials and embedded
beacons, and, importantly for this project, *formalise properties* that a decoy
should satisfy in order to be effective. Juels and Rivest [26] propose **honeywords**:
storing decoy passwords alongside the real one so that an adversary who inverts the
password hash cannot tell which is genuine, with an auxiliary honeychecker raising
an alarm when a honeyword is used. Timmer et al. [52] move the field towards
measurement, comparing proposed honeyfile metrics for realism and enticement against
the judgements of human participants, and reporting the sobering finding that some
widely used metrics do not consistently align with human perception.

The gap in this theme is one of **timing**. Every scheme above is *always on*: the
token is planted once and left in place. That is entirely reasonable when planting
is free. It is not free in the setting studied here, for two reasons. First, a probe
placed in a response served to a real user carries a small but genuine cost, and a
system that probes everybody has simply moved its cost from false positives to
nuisance. Second, a token that every visitor sees will eventually be catalogued and
published, burning it permanently, which is the fingerprinting result of [49]
applied to tokens rather than to hosts. The question these papers do not ask is
**when** a token should be deployed.

### 2.1.5 Theme E — Application-Layer and LLM-Generated Deception

A recent line of work moves deception out of separate honeypot hosts and into the
application itself, which is the same architectural position this project occupies.

Kahlhofer and Rass [27] review **nineteen technical methods** for deploying
application-layer deception without developer interaction, that is, by an operator
who has the built artefact but not the source code. Their finding is doubly useful:
it defines the space, and it reports that everything beyond honeypots and reverse
proxies "seems to have received little research interest", which says the space is
nearly empty. Kahlhofer et al. [28] contribute **Honeyquest**, which measures the
*enticingness* of 25 deception techniques against 19 true security risks with 47
human participants, and reports that the presence of deception reduces the risk that
an adversary finds a real vulnerability by about 22 %. The methodological caveat the
authors themselves state is that Honeyquest uses code-based questionnaires, so it
captures what people say they would click rather than what they do against a live
system. Kahlhofer, Golinelli and Rass [29] then contribute **Koney**, a Kubernetes
operator that treats deception "as code" and automates the setup, rotation,
monitoring and removal of traps using service meshes and eBPF.

Koney is the closest neighbour to this project, and the boundary between them is
sharp and worth stating plainly: **Koney solves deployment; it does not decide
deployment.** It will place, rotate and tear down a trap reliably, but it does not
choose whether to deploy one *based on a belief about the visitor currently being
served*. That decision is the contribution of the present work.

A parallel line uses language models to *generate* deception. Sladić et al. [46]
build **shelLM**, an LLM-backed Linux shell honeypot, reporting a true-negative rate
of 0.90 in convincing cybersecurity researchers that they were interacting with a
real shell. Adebimpe, Neukirchen and Welsh [1] compare retrieval-augmented against
prompt-tuned LLM honeypots in the **SBASH** framework. Reworr and Volkov [40] deploy
an LLM-agent honeypot to monitor AI hacking agents in the wild, which is direct
evidence that autonomous attackers are becoming a real population rather than a
hypothetical one. Bridges et al. [10] systematise the whole area, producing a
taxonomy of honeypot detection vectors, a canonical architecture, an evaluation
tetrad and an attacker trichotomy, while noting that real-world deployments show
only incremental progress. Vero et al. [54] contribute **Honeyval**, an evaluation
framework for LLM-powered HTTP honeypots.

This project's relationship to the LLM line is **complementary rather than
competing**. The decoy's consistency layer described in Chapter 3 is
generator-agnostic by design, and a language model is exactly the kind of generator
it is built to sit in front of. What the LLM honeypot line tends to lack is a
guarantee of *self-consistency over an engagement*: evaluation frameworks measure
stealth and fidelity but not whether the same question asked twice receives the same
answer. Chapter 4 measures precisely that, and shows it is a property of the
consistency layer rather than of the generator.

### 2.1.6 Theme F — Probability Calibration

A cost-sensitive threshold is only meaningful if the score it is applied to behaves
like a probability. This is the subject of a mature literature that the present work
uses as a **diagnostic tool** rather than extending.

Platt [38] introduced logistic scaling of classifier outputs, fitting a
one-dimensional sigmoid to map uncalibrated scores onto probabilities. Zadrozny and
Elkan [58] developed non-parametric alternatives, most notably isotonic regression,
which fits an arbitrary monotone map and is therefore more flexible but more prone
to overfitting on small samples. Kull, Filho and Flach [31] identified a specific
failure of logistic calibration. It is designed for normally distributed per-class
scores and can *uncalibrate* an already-calibrated classifier, since the logistic
family does not contain the identity function, and proposed the three-parameter
**beta calibration** map to fix it.

Chapter 4 applies all three to the hand-weighted meter built here, selects between
them by leave-one-draw-out held-out expected calibration error, and reports a result
that is uncomfortable and therefore worth reporting: the shipped belief is **not
calibrated**.

### 2.1.7 Theme G — Value of Information and Cost-Sensitive Decision Making

The decision-theoretic machinery on which the contribution rests is textbook, and
this report is explicit about that.

Howard [21] introduced **information value theory**, arguing that no theory
concerned only with the probabilities of outcomes, and not with their consequences,
can describe the importance of uncertainty to a decision maker, and showing that a
numerical value can be assigned to the reduction of any uncertainty. This is the
**Expected Value of Sample Information (EVSI)**, and it is the object used in
Section 3.2.2 to price the probe.

Elkan [16] provides the complementary half: how to make optimal decisions when
different misclassification errors carry different penalties, how to tell whether a
cost matrix is economically coherent, and why the recommended procedure is to learn
a classifier and then compute optimal decisions explicitly from its probability
estimates rather than to bake costs into training. The frozen cost table of
Section 3.2.2 follows this prescription exactly.

Axelsson [5] supplies the constraint that dominates intrusion detection in
practice: the **base-rate fallacy**. Because intrusions are rare, the false-alarm
rate, not the detection rate, is the limiting factor on usable performance. This
is the reason benign diversion is priced so severely in the cost table and why
Chapter 4 leads with the benign side of every result.

Pawlick, Colbert and Zhu [36] model deception with a detector that emits
probabilistic warnings, deriving equilibria for *leaky* deception, which is the
game-theoretic counterpart of the situation studied here.

Finally, the methodological guidance. Sommer and Paxson [47] set out why machine
learning for intrusion detection is harder than it looks and why laboratory results
so rarely survive deployment. Arp et al. [4] catalogue the specific pitfalls,
sampling bias, label inaccuracy, spurious correlations, inappropriate baselines,
data snooping, and base-rate neglect among them. Both are used in Chapter 4 not as
decoration but as a checklist; several design decisions in this project (freezing the
model before evaluation, pre-registering the primary comparison, replaying a real
ruleset rather than only an in-house baseline) exist specifically because of them.

## 2.2 Research Gaps

Reading across the seven themes, four gaps emerge. Each is stated as an observation
about what the literature does *not* do, followed by what this project does instead.

**Gap 1 — Deception is a destination, not an instrument.**
In Themes C and D, deception is deployed either after a decision has been made
(honeypots) or independently of any decision at all (always-on honeytokens). No
surveyed work treats deception as an action available to a detector *during*
uncertainty, whose deployment is chosen per-visitor on the basis of current belief.

**Gap 2 — The middle action, where it exists, is a tuned heuristic.**
Systems that offer something between allow and block, step-up authentication,
additional verification, escalation to review, select that action by a hand-set
threshold. A threshold is a free parameter, and a free parameter placed in the
middle of a two-action system can always be accused of having been tuned until the
results looked acceptable. No surveyed work *derives* the middle action's operating
region from stated costs.

**Gap 3 — Deception effectiveness is asserted, correlated, or questionnaire-based.**
Han et al. [19] identify this explicitly as an open problem for the field. Honeyquest
[28] measures enticingness by questionnaire and says so. Timmer et al. [52] find
that some standard realism metrics do not track human judgement. Ferguson-Walter et
al. [17] is the notable exception, and it is a human-subject study rather than a
system evaluation. No surveyed system-building work isolates the causal contribution
of its deception component from the rest of the system.

**Gap 4 — Generated decoys are not guaranteed self-consistent.**
Theme E's LLM honeypots are evaluated for stealth, fidelity and realism, but not for
whether the fake world answers the same question the same way twice. Vetterl and
Clayton [55] show that subtle inconsistency is exactly what fingerprinting exploits.

**Table 1: Research gaps and how this project addresses them**

| # | Gap in the literature | How this project addresses it | Where |
|---|---|---|---|
| 1 | Deception used only after the decision, or always-on regardless of it | A third action, **BAIT**, available to the detector while the decision is still open, chosen per session from the current belief | §3.2.2 |
| 2 | The middle action is a hand-set threshold | Both band edges are *derived* from a frozen cost table and a measured bite likelihood ratio; under cost alone the band is provably empty | §3.2.2, §4.4 |
| 3 | Deception effectiveness asserted or correlated, not identified | A **randomised holdout inside the treated arm** withholds the probe from ~10 % of sessions at the same belief state, giving a causal estimate | §3.7, §4.4.3 |
| 4 | Generated decoys not guaranteed self-consistent | A write-once **Fact Notebook** pins every entity the decoy has ever asserted; consistency is a property of the store, not of the generator | §3.2.4, §4.4.7 |

Two of these claims, the priced band (Gap 2) and the randomised holdout (Gap 3),
do not, to our knowledge, appear together in the deception literature. They are also
the two cheapest to defend, and it is worth being precise about why. Neither is a
measurement. The band is a *derivation*: given the frozen cost table and a stated
bite rate, its edges follow by arithmetic that a reader can redo, and the decision
theory underneath is textbook [21], [16] rather than ours. The holdout is an
*experimental design*: it identifies the probe's effect by construction, whatever
magnitude that effect turns out to have. A replication could reasonably find a
smaller gain than reported here; it could not find that the arithmetic yields
different edges, or that the randomisation stopped identifying what it identifies.

## 2.3 Key Papers and Reading Order

For a reader approaching this project for the first time, the following eight works
are the ones on which the design most directly depends. They are ordered by how
early they are needed rather than by importance.

1. **Howard (1966)** [21], *Information Value Theory.* The source of the EVSI
   object used to price the probe. Read first; nothing in Section 3.2.2 makes sense
   without it.
2. **Elkan (2001)** [16], *The Foundations of Cost-Sensitive Learning.* Establishes
   how to make decisions under a loss matrix and what makes a cost matrix coherent.
   The frozen cost table follows its prescription.
3. **Axelsson (2000)** [5], *The Base-Rate Fallacy and the Difficulty of Intrusion
   Detection.* Explains why the false-alarm rate, not the detection rate, is the
   binding constraint, and therefore why benign diversion is priced at 200.
4. **Kahlhofer, Golinelli & Rass (2025)** [29], *Koney.* The closest neighbour;
   read it to see exactly where automated trap deployment stops and where the
   decision problem this project solves begins.
5. **Kahlhofer & Rass (2024)** [27], *Application Layer Cyber Deception Without
   Developer Interaction.* Defines the application-layer deception space and reports
   how sparsely populated it is.
6. **Ferguson-Walter et al. (2021)** [17], *Examining the Efficacy of Decoy-based
   and Psychological Cyber Deception.* The field's controlled study of whether
   deception changes attacker behaviour; the methodological ancestor of the holdout.
7. **Arp et al. (2022)** [4], *Dos and Don'ts of Machine Learning in Computer
   Security.* Used as an evaluation checklist throughout Chapter 4.
8. **Iliou et al. (2021)** [23], *Detection of Advanced Web Bots.* The negative
   result that forced automation and malice onto separate axes.

## 2.4 Research Paper Summaries

**Table 2: Summary of research papers surveyed**

| Theme | Citation | Year | Relevance (1–5) |
|---|---|---|---|
| Deception planning model | Almeshekah & Spafford — *Planning and Integrating Deception* [2] | 2014 | 4 |
| Deception survey, measurement critique | Han, Kheir & Balzarotti — *Deception Techniques* [19] | 2018 | 5 |
| Game-theoretic deception taxonomy | Pawlick, Colbert & Zhu [37] | 2019 | 3 |
| Deception survey (GT + ML) | Zhu et al. [59] | 2021 | 3 |
| Cyber deception taxonomy, open challenges | Beltrán-López, Gil Pérez & Nespoli [7] | 2026 | 4 |
| Virtual honeypot framework | Provos — *Honeyd* [39] | 2004 | 3 |
| Honeypot software survey | Nawrocki et al. [33] | 2016 | 2 |
| Honeypot performance via deception | Javadpour et al. [24] | 2024 | 3 |
| Attacker behaviour vs environment realism | Barron & Nikiforakis — *Picky Attackers* [6] | 2017 | 5 |
| Honeypot fingerprinting at scale | Vetterl & Clayton — *Bitter Harvest* [55] | 2018 | 5 |
| Moving target defence survey | Cho et al. [13] | 2020 | 2 |
| LLM shell honeypot | Sladić et al. — *shelLM* [46] | 2024 | 4 |
| LLM agents attacking in the wild | Reworr & Volkov [40] | 2025 | 4 |
| SoK: honeypots and LLMs | Bridges et al. [10] | 2026 | 4 |
| LLM HTTP honeypot evaluation | Vero et al. — *Honeyval* [54] | 2026 | 4 |
| RAG vs prompt-tuned LLM honeypots | Adebimpe, Neukirchen & Welsh — *SBASH* [1] | 2025 | 3 |
| Honeyfiles as intrusion detection | Yuill et al. [57] | 2004 | 4 |
| Decoy documents, formal decoy properties | Bowen et al. [9] | 2009 | 5 |
| Honeywords | Juels & Rivest [26] | 2013 | 4 |
| Honeytoken fingerprinting | Srinivasa et al. [49] | 2021 | 4 |
| Honeyfile realism and enticement metrics | Timmer et al. [52] | 2025 | 4 |
| Application-layer deception, 19 methods | Kahlhofer & Rass [27] | 2024 | 5 |
| Enticingness by questionnaire | Kahlhofer et al. — *Honeyquest* [28] | 2024 | 4 |
| Deception orchestration for Kubernetes | Kahlhofer, Golinelli & Rass — *Koney* [29] | 2025 | 5 |
| Anomaly detection of web attacks | Kruegel & Vigna [30] | 2003 | 4 |
| Generalisation in web anomaly detection | Robertson et al. [41] | 2006 | 3 |
| CSIC 2010 HTTP dataset | Torrano-Giménez et al. [53] | 2010 | 3 |
| CNN for web attack detection | Tekerek [51] | 2021 | 3 |
| RL-driven WAF evasion discovery | Amouei, Rezvani & Fateh — *RAT* [3] | 2022 | 4 |
| Advanced web bot detection framework | Iliou et al. [22] | 2019 | 4 |
| Web bots + mouse biometrics | Iliou et al. [23] | 2021 | 5 |
| Information value theory (EVSI) | Howard [21] | 1966 | 5 |
| Cost-sensitive learning foundations | Elkan [16] | 2001 | 5 |
| Leaky deception signalling games | Pawlick, Colbert & Zhu [36] | 2019 | 3 |
| Base-rate fallacy in intrusion detection | Axelsson [5] | 2000 | 5 |
| Outside the closed world | Sommer & Paxson [47] | 2010 | 5 |
| Dos and don'ts of ML in security | Arp et al. [4] | 2022 | 5 |
| Efficacy of decoy-based cyber deception | Ferguson-Walter et al. [17] | 2021 | 5 |
| Tamper-evident audit logs | Schneier & Kelsey [44] | 1999 | 4 |
| Two one-sided tests (equivalence) | Schuirmann [45] | 1987 | 2 |
| Platt scaling | Platt [38] | 1999 | 3 |
| Isotonic calibration | Zadrozny & Elkan [58] | 2002 | 4 |
| Beta calibration | Kull, Filho & Flach [31] | 2017 | 3 |

### Extended summaries of the most load-bearing works

**Howard (1966), *Information Value Theory* [21].** Howard's argument begins with a
criticism of applying Shannon information outside communications: a measure that
depends only on the probability of an outcome, and not on its consequences, cannot
express how much an uncertainty matters to a decision maker. He develops instead a
theory in which the value of resolving an uncertainty is derived jointly from its
probabilistic structure *and* its economic impact, and shows that a numerical value
can be attached to the elimination or reduction of any uncertainty. **Relevance:**
this is exactly the structure of the probe decision. A probe changes no outcome by
itself; its entire worth is that it may change what the defender subsequently does.
Section 3.2.2 computes that worth as an expected value of sample information and
subtracts it from the probe's immediate cost.

**Elkan (2001), *The Foundations of Cost-Sensitive Learning* [16].** Elkan
characterises when a cost matrix is *reasonable*, showing how to avoid matrices
that are economically incoherent, and proves results about how class balance
interacts with cost-sensitive decisions. His practical recommendation is that in a
domain with differing misclassification costs, one should learn a classifier from
the data as given and then compute optimal decisions explicitly from its probability
estimates, rather than distorting training. **Relevance:** the framework follows
this exactly. The meter is trained on round-1 traffic without cost information; the
cost table is applied afterwards, at decision time, and is frozen and hashed so it
cannot be adjusted once results are visible.

**Axelsson (2000), *The Base-Rate Fallacy* [5].** Because intrusions are rare
relative to legitimate traffic, the posterior probability that an alarm indicates a
real intrusion is dominated by the false-alarm rate rather than by the detection
rate. Achieving a usable Bayesian detection rate therefore requires a false-alarm
rate that may be unattainably low. **Relevance:** this single result explains the
shape of the cost table in Section 3.2.2. Diverting a benign user is priced at 200
against 25 for missing an attack, a ratio of eight to one, not because a missed
attack is unimportant but because the base rate makes false positives the binding
constraint. It is also why Chapter 4 reports the benign column of every table before
the recall column.

**Barron & Nikiforakis (2017), *Picky Attackers* [6].** Over four months and 102
medium-interaction honeypots, the authors systematically varied honeypot location,
break-in difficulty and file population, and additionally leaked credentials for
hard-to-brute-force honeypots to hacking forums and paste sites in order to attract
human attackers. The central finding is a dissociation: **bots perform
environment-agnostic actions, while human attackers are measurably affected by the
environment**, executing more commands on honeypots with realistic file and folder
structures. **Relevance:** this is the empirical case for the Fact Notebook. If
realism and internal consistency change human attacker behaviour, then engineering
them is a security control rather than a cosmetic concern, and the correct design
question becomes how to *guarantee* consistency rather than how to make content look
plausible.

**Vetterl & Clayton (2018), *Bitter Harvest* [55].** The authors show that the
current generation of low- and medium-interaction honeypots can be fingerprinted at
internet scale using a single packet, at an equal error rate of 0.0183, because
their protocol implementations differ subtly from the systems being impersonated.
They identify 7,605 honeypot instances across nine implementations and argue this is
a *class break*, one not fixable by patching. **Relevance:** a decoy that can be
detected is worse than none, because it informs the attacker that they are being
observed. This is the direct motivation for the target/decoy parity requirement in
Section 3.2.4: the two applications must expose identical route surfaces, status
codes and content types, and this is enforced by tests rather than by inspection.

**Kahlhofer, Golinelli & Rass (2025), *Koney* [29].** Koney introduces deception
policy documents describing traps "as code", paired with a Kubernetes operator that
handles setup, rotation, monitoring and removal, using service meshes and eBPF to
add traps to containerised applications without source access. The authors
explicitly prioritise operational properties, maintainability, scalability,
simplicity, as the barrier to industry adoption. **Relevance:** Koney is the
closest neighbour and the cleanest way to state the present contribution by
contrast. Koney answers *how to deploy a trap reliably*. It does not answer *whether
to deploy one for this visitor, right now, given what is currently believed about
them*. The two are complementary: a production deployment would plausibly use a
Koney-style orchestrator as the mechanism and the priced policy of Section 3.2.2 as
the trigger.

**Ferguson-Walter et al. (2021), *Examining the Efficacy of Decoy-based and
Psychological Cyber Deception* [17].** A controlled experiment measuring whether
decoys and psychological deception actually change attacker behaviour, rather than
assuming that they do. **Relevance:** methodologically this is the ancestor of the
randomised holdout in Section 4.4.3. Both designs recognise that comparing two whole
systems confounds the deception with everything else that differs between them, and
both respond by randomising the deception itself.

**Arp et al. (2022), *Dos and Don'ts of Machine Learning in Computer Security*
[4].** A catalogue of recurring methodological pitfalls in security ML, sampling
bias, label inaccuracy, data snooping, spurious correlations, inappropriate
baselines, base-rate neglect, and inappropriate performance measures, with evidence
of how often each occurs in published work. **Relevance:** used as a checklist.
Freezing and hashing the model before evaluation addresses data snooping; replaying
the OWASP CRS addresses inappropriate baselines; pre-registering the primary
comparison addresses selective reporting; the corpus audit reported in Section 4.7
addresses spurious correlations, and it found one.

## 2.5 Datasets and Tools

**Table 3: Datasets, tools and platforms used**

| Name | Type | Licence | Role in this project |
|---|---|---|---|
| **Synthetic benign corpus** (this work) | Dataset | Project-internal | 80 sessions per draw: three-quarters simulated humans including hard negatives (apostrophe search, forgetful login, URL mistyping), one quarter automated-but-harmless clients (uptime monitor, crawler, reporting integration) |
| **Attack round 1** (this work) | Dataset | Project-internal | Training corpus for the dual meter; 2 × 2 automation/malice coverage |
| **Attack round 2** (this work) | Dataset | Project-internal | Held-out evaluation corpus, written after the detector was built; five subcategories, deliberately unlike round 1 |
| **CSIC 2010 HTTP dataset** [53] | Dataset | Public research use | Named in Section 5.3 as the natural next step for bounding the benign side against a public corpus; not used for any reported number |
| **OWASP ModSecurity Core Rule Set** | Rule set | Apache 2.0 | Replayed at paranoia levels 1–4 on identical traffic to prove the signature baseline is not a straw man |
| **OWASP Juice Shop** | Application | MIT | Second, structurally unlike target (Node/Express SPA with JSON API) used for the transfer check |
| **sqlmap 1.10.8** | Attack tool | GPLv2 | Third-party SQL injection engine used for external validation |
| **ghauri 1.4.3** | Attack tool | MIT | Third-party injection tool; notable for refusing the proxy's cookie, which exposed a real evasion |
| **wapiti 3.2.3** | Attack tool | GPLv2 | Third-party web vulnerability scanner |
| **OWASP ZAP** | Attack tool | Apache 2.0 | Browser-driven scanner used against the second application |
| **Python 3.11** | Language | PSF | Implementation language for the framework, harness and tests |
| **FastAPI + Uvicorn** | Web framework | MIT / BSD | Asynchronous reverse proxy, target application and decoy service |
| **httpx** | HTTP client | BSD | Upstream client inside the proxy and in every traffic generator |
| **scikit-learn** | ML library | BSD | Logistic heads of the dual meter; calibration maps (Platt, beta, isotonic) |
| **NumPy, pandas** | Numeric / data | BSD | Feature handling, evaluation statistics |
| **matplotlib** | Visualisation | PSF-based | Publication-quality figures (Okabe–Ito palette, serif + computer-modern maths) |
| **SQLite** | Database | Public domain | Target world, decoy world and Fact Notebook storage |
| **Ollama** (llama3.2:1b, llama3.2:3b, qwen2.5:7b) | Local LLM runtime | MIT | Two roles: decoy content generation behind the consistency seam, and — separately — the autonomous attacker of Section 4.4.9. Never in the request path of any reported arm |
| **Docker** | Containerisation | Apache 2.0 | Isolation for the CRS ruleset, the second target application and the browser-driven scanner |
| **pytest** | Test framework | MIT | 371 automated tests across 26 files; all must pass before a model may be frozen |
| **Git** | Version control | GPLv2 | Source management and the audit trail of decisions |

A note on the dataset row that is *absent*. This project does not use a public
labelled web-attack corpus for its headline numbers, and that is a genuine
limitation rather than an oversight; it is stated as such in Section 4.7 and
Section 5.2. The reason is that the contribution being measured is the effect of a
*response-side* probe, which requires a live application that can be probed and an
attacker that can react to what comes back. A recorded request log, however large
and however well labelled, contains no responses and no opportunity for an attacker
to act on one, so it cannot exercise the mechanism under test. Replaying CSIC 2010
[53] would bound the *passive* half of the system honestly and is proposed as future
work, but it cannot substitute for the interactive setting the probe requires.
