# Literature Review

**For the paper: _An Active Deception Framework for Web Attack Detection Using
Response-Side Probes and State-Consistent Decoys_**

This file is the raw material for the **Related Work** section. It is written
in simple English so it can be read quickly and copied into the paper with
small edits.

- **38 references.** All checked one by one against publisher records (ACM DL,
  IEEE Xplore, USENIX, Springer, arXiv, DBLP). Every entry has a working link.
- **17 of 38 are from 2020 or later.** The older ones are kept only where they
  are the original source of an idea the paper depends on (for example, the
  value of information, or cost-sensitive decisions).
- **11 comparison tables**, including a gap matrix that shows, paper by paper,
  which parts of this project already exist in the literature and which do not.

> **Honesty note — read before submitting.** Each paper below was verified for
> *title, authors, venue, year, pages and DOI*. The one-line summaries come
> from abstracts and publisher pages. The judgement columns in Tables 4–8
> (things like "invisibility measured?") are **my reading**, not a quote from
> the paper. Before the paper goes out, open the full text of the 10–12 papers
> you cite most and confirm those cells yourself. A wrong "No" in a comparison
> table is the easiest thing for a reviewer to catch.

---

## Contents

1. [How the papers were found](#1-how-the-papers-were-found)
2. [The story in one page](#2-the-story-in-one-page)
3. [Theme A — Cyber deception: theory and surveys](#3-theme-a--cyber-deception-theory-and-surveys)
4. [Theme B — Honeypots](#4-theme-b--honeypots)
5. [Theme C — LLM-based honeypots](#5-theme-c--llm-based-honeypots)
6. [Theme D — Honeytokens, decoys and bait](#6-theme-d--honeytokens-decoys-and-bait)
7. [Theme E — Deception inside the application layer](#7-theme-e--deception-inside-the-application-layer)
8. [Theme F — Web attack detection and WAFs](#8-theme-f--web-attack-detection-and-wafs)
9. [Theme G — Bot and automation detection](#9-theme-g--bot-and-automation-detection)
10. [Theme H — Decision theory and cost](#10-theme-h--decision-theory-and-cost)
11. [Theme I — How security ML should be evaluated](#11-theme-i--how-security-ml-should-be-evaluated)
12. [Theme J — Supporting work](#12-theme-j--supporting-work)
13. [Comparison tables](#13-comparison-tables)
14. [The research gaps](#14-the-research-gaps)
15. [What to cite in which section](#15-what-to-cite-in-which-section)
16. [Full reference list with links](#16-full-reference-list-with-links)
17. [BibTeX](#17-bibtex)

---

## 1. How the papers were found

| Item | Detail |
|---|---|
| Databases used | ACM Digital Library, IEEE Xplore, USENIX, SpringerLink, arXiv, DBLP |
| Main search terms | *cyber deception*, *defensive deception*, *honeypot*, *honeytoken*, *honeyfile*, *decoy document*, *application layer deception*, *web attack detection*, *web application firewall*, *web bot detection*, *value of information*, *cost-sensitive decision* |
| Time window | 1966–2025. Priority given to 2020–2025; older papers kept only when they are the original source of a concept |
| Inclusion rule | Peer-reviewed venue, or an arXiv preprint that is already well cited and directly on topic |
| Exclusion rule | Papers with no measurement, and papers only about network-level or IoT honeypots with no application-layer angle |
| Verification | Every entry opened on the publisher page. Title, author order, venue, year, pages and DOI all confirmed |

**Why this mix of old and new.** A literature review needs two kinds of
citation. The first kind shows you know the *current* state of the field —
those are the 2020–2025 papers. The second kind shows *where an idea came
from* — Howard's value of information [R29], Elkan's cost-sensitive learning
[R30], and Axelsson's base-rate work [R32] are the honest sources for the
maths this project uses, and citing a 2024 paper instead would be wrong.

---

## 2. The story in one page

This is the argument the Related Work section should make, in order:

1. **Defences today are passive.** A WAF matches patterns [R22, R23, R26]; a
   machine-learned detector watches and waits [R25]. Both must *wait* for the
   attacker to produce enough evidence. This forces a bad trade-off: act early
   and you hurt innocent users, act late and the attacker gets a head start
   [R32].

2. **Deception is the known answer to passivity, but it is placed wrongly.**
   Honeypots gather excellent intelligence [R6, R7, R8], but they sit
   *beside* the real system, so they only catch people who wander into them
   [R9]. Honeytokens sit *inside* the system, but they are planted once,
   statically, for everyone [R14, R15, R16].

3. **Deception theory already says the middle option should exist.** The
   surveys classify deception into families and note that the hard question is
   not *how* to deceive but *when* [R1, R2, R3, R4, R5]. Game-theoretic work
   models this as a signalling problem [R31]. But the decision of *when* is
   still usually a hand-set threshold.

4. **Application-layer deception is a very new and very small area.** Kahlhofer
   and Rass survey it and count only 19 technical methods, noting that most
   have had "little research interest" [R19]. Related tooling [R21] and
   enticement measurement [R20] appeared in 2024–2025. This is the closest
   neighbourhood to this project, and it is nearly empty.

5. **Nobody measures the two things this project measures.** Deception work
   measures whether a trap is *enticing* [R20] or *realistic* [R18], or whether
   it can be *fingerprinted* [R10, R17]. Almost nobody measures the cost the
   deception imposes on **honest users**, and almost nobody establishes the
   effect of deception **causally**. The one strong exception is
   Ferguson-Walter et al. [R35], who ran a controlled human experiment — and
   that paper is the model this project's randomised holdout follows.

6. **So the gap is:** a deception mechanism that lives in the *response* of a
   real application, is chosen *per session*, has a *derived* rather than tuned
   trigger point, and is evaluated for its cost to innocent traffic with a
   *randomised* design.

---

## 3. Theme A — Cyber deception: theory and surveys

**[R1] Almeshekah & Spafford, NSPW 2014 — _Planning and Integrating Deception into Computer Security Defenses_**
The paper that made deception a design discipline instead of a trick. It gives
a planning model: decide what you want the attacker to *believe*, then build
the deception backwards from that belief. **Use it for:** the framing sentence
that deception must be planned, not bolted on. **Limit:** it is a framework
paper with no measurement.

**[R2] Han, Kheir & Balzarotti, ACM Computing Surveys 2018 — _Deception Techniques in Computer Security: A Research Perspective_**
The standard survey. Splits deception by *what is faked* and *where it sits*.
**Use it for:** the taxonomy sentence, and to show your bait is a distinct
category (fake data placed in a real response). **Limit:** predates all LLM
work and all application-layer deception work.

**[R3] Pawlick, Colbert & Zhu, ACM Computing Surveys 2019 — _A Game-theoretic Taxonomy and Survey of Defensive Deception for Cybersecurity and Privacy_**
Defines six deception families: perturbation, moving target defence,
obfuscation, mixing, honey-x, and attacker engagement. **Use it for:** placing
your work in the "honey-x + attacker engagement" corner. **Limit:** models are
mostly analytical; few are implemented and measured.

**[R4] Zhu, Anwar, Wan, Cho, Kamhoua & Singh, IEEE Communications Surveys & Tutorials 2021 — _A Survey of Defensive Deception: Approaches Using Game Theory and Machine Learning_**
The best single "state of the field" citation for a 2021+ paper. Covers both
game-theory and ML approaches and lists open problems. **Use it for:** the
claim that deployment decisions are still mostly heuristic. **Limit:** survey
only.

**[R5] Beltrán López, Gil Pérez & Nespoli, IEEE Communications Surveys & Tutorials 2025 — _Cyber Deception: Taxonomy, State of the Art, Frameworks, Trends, and Open Challenges_**
The newest big survey. Builds a unified taxonomy and lists pending challenges.
**Use it for:** proving your related work is current (2025 citation), and for
the open-challenges list, which supports your gap statement.

---

## 4. Theme B — Honeypots

**[R6] Provos, USENIX Security 2004 — _A Virtual Honeypot Framework_ (Honeyd)**
The classic. Simulates many virtual machines on unused IP addresses. **Use it
for:** the definition of a honeypot as a *separate* system. **Limit:** by
design it is outside the real application, which is exactly the structural
problem your work attacks.

**[R7] Nawrocki, Wählisch, Schmidt, Keil & Schönfelder, arXiv 2016 — _A Survey on Honeypot Software and Data Analysis_**
Broad catalogue of honeypot software plus the methods used to analyse the data
they collect. **Use it for:** the low-/medium-/high-interaction vocabulary.

**[R8] Javadpour, Ja'fari, Taleb, Shojafar & Benzaïd, Computers & Security 2024 — _A Comprehensive Survey on Cyber Deception Techniques to Improve Honeypot Performance_**
Recent survey focused on making honeypots more convincing and more useful.
**Use it for:** a current citation on honeypot realism, and to show the field's
attention is on *realism*, not on *cost to honest users*.

**[R9] Barron & Nikiforakis, ACSAC 2017 — _Picky Attackers: Quantifying the Role of System Properties on Intruder Behavior_**
A four-month experiment with 102 medium-interaction honeypots. They varied
location, difficulty of break-in, and the files present, and measured how
attacker behaviour changed. They also deliberately leaked credentials to
hacking forums. **Use it for:** two things — (a) evidence that *what you plant*
changes attacker behaviour, which supports per-session bait selection, and
(b) as a model of a well-designed measurement study.

**[R10] Vetterl & Clayton, USENIX WOOT 2018 — _Bitter Harvest: Systematically Fingerprinting Low- and Medium-interaction Honeypots at Internet Scale_**
Fingerprints honeypots with a *single packet* at an equal error rate of 0.0183,
and finds 7,605 live honeypot instances across nine implementations. The cause
is that honeypots implement protocols subtly differently from the real thing.
**Use it for:** the strongest possible motivation for your invisibility gate
and your Fact Notebook. Deception that is detectable is worse than no
deception, because it teaches the attacker they were seen.

---

## 5. Theme C — LLM-based honeypots

**[R11] Sladić, Valeros, Catania & Garcia, IEEE EuroS&PW 2024 — _LLM in the Shell: Generative Honeypots_ (shelLM)**
Uses an LLM to generate Linux shell output on demand, so the honeypot is
dynamic rather than scripted. **Use it for:** the "LLM content generation is
not new" sentence in your contributions section — this is the paper that makes
it not new. **Limit:** the LLM sits *in the request path*, which brings latency
and unpredictability; your design deliberately moves generation offline.

**[R12] Reworr & Volkov, arXiv 2024 — _LLM Agent Honeypot: Monitoring AI Hacking Agents in the Wild_**
An SSH honeypot with prompt injection and timing analysis added, aimed at
spotting autonomous AI attackers. Collected 8,130,731 hacking attempts over
about three months. **Use it for:** an interesting parallel — they also
*inject something into the response to provoke a reaction*. This is the closest
published idea to your response-side probe, but at the shell level and aimed at
AI agents. Worth citing and distinguishing carefully.

**[R13] Bridges, Mitchell, Muñoz & Henriksson, arXiv 2025 — _SoK: Honeypots & LLMs, More Than the Sum of Their Parts?_**
A systematisation of the LLM-honeypot area. Its finding is useful to you: real
deployments show only *incremental* progress, and the field lacks agreed
evaluation methods. **Use it for:** the argument that this literature has a
measurement problem, which your metrics help fix.

---

## 6. Theme D — Honeytokens, decoys and bait

**[R14] Yuill, Zappe, Denning & Feer, IEEE SMC Information Assurance Workshop 2004 — _Honeyfiles: Deceptive Files for Intrusion Detection_**
The original honeyfile paper. Bait files on a file server; touching one raises
an alarm. **Use it for:** the origin of "planting bait raises an alarm".
**Limit:** static placement, same file for everyone, no measurement of effect
on legitimate users.

**[R15] Bowen, Hershkop, Keromytis & Stolfo, SecureComm 2009 — _Baiting Inside Attackers Using Decoy Documents_**
Automatically generates and places decoy documents, and — importantly — lists
*properties* a good decoy should have (believable, enticing, non-interfering,
detectable). **Use it for:** the closest prior art to your bait design
criteria. Your invisibility gate is a *measured, automated* version of their
"non-interfering" property.

**[R16] Juels & Rivest, ACM CCS 2013 — _Honeywords: Making Password-Cracking Detectable_**
Store fake passwords next to the real one; use of a fake one raises an alarm,
checked by a separate "honeychecker" server. **Use it for:** the cleanest
example of a *tripwire whose only job is to produce evidence*. This is
conceptually the nearest ancestor of your bait. **Limit:** one fixed tripwire
type, no belief model, no decision about when to deploy — it is always on.

**[R17] Srinivasa, Pedersen & Vasilomanolakis, SIN 2020 — _Towards Systematic Honeytoken Fingerprinting_**
The first paper to look specifically at fingerprinting *honeytokens*, with a
proof of concept that detects several honeytoken types. **Use it for:** direct
evidence that badly built tokens are detectable, which is exactly why your
gate issues a certificate the engine checks at run time.

**[R18] Timmer, Liebowitz, Nepal & Kanhere, ACM Transactions on Privacy and Security 2025 — _Evaluating Honeyfile Realism and Enticement Metrics_**
Studies the two qualities that matter for a decoy: **realism** (does it look
like the real thing?) and **enticement** (does it attract attention?). **Use it
for:** the observation that the field measures realism and enticement — but
not the *cost to honest users*, which is your third axis.

---

## 7. Theme E — Deception inside the application layer

This is the neighbourhood your paper lives in. It is small, new, and mostly
from one group — which is good news for a novelty claim.

**[R19] Kahlhofer & Rass, IEEE EuroS&PW 2024 (3rd Workshop on Active Defense and Deception) — _Application Layer Cyber Deception Without Developer Interaction_**
Reviews **19 technical methods** for doing deception at the application layer
and scores them on technical, topological, operational and efficacy
properties. Explicitly reports that some techniques beyond honeypots and
reverse proxies "have received little research interest". **This is your single
most important related-work citation.** It defines the space, and it says the
space is under-explored. Read the full text and place your system inside its
classification.

**[R20] Kahlhofer, Achleitner, Rass & Mayrhofer, RAID 2024 — _Honeyquest: Rapidly Measuring the Enticingness of Cyber Deception Techniques with Code-based Questionnaires_**
Turns 25 deception techniques (13 from prior work, 12 new) into a
machine-readable specification, then measures how enticing each one is using
questionnaires, without having to build them. Reports that the presence of
deception cut the risk of an adversary finding a true security risk by about
22% on average. **Use it for:** (a) a method for ranking bait candidates before
you build them, and (b) a published number for how much deception helps.
**Limit:** questionnaire-based, so it measures what people *say* they would
click, not what they do in a live system. Your bite rates are behavioural.

**[R21] Kahlhofer, Golinelli & Rass, IEEE EuroS&PW 2025 — _Koney: A Cyber Deception Orchestration Framework for Kubernetes_**
A Kubernetes operator that automates setting up, rotating and tearing down
honeytokens and **fake API endpoints**, using eBPF to detect and log access.
**Use it for:** the closest *engineering* neighbour. It solves deployment and
lifecycle. It does **not** decide *when* to deploy based on a belief about the
current visitor — that decision is your contribution.

---

## 8. Theme F — Web attack detection and WAFs

**[R22] Kruegel & Vigna, ACM CCS 2003 — _Anomaly Detection of Web-based Attacks_**
The foundational anomaly-detection paper for HTTP. Learns per-parameter models
(length, character distribution, structure) from normal traffic. **Use it for:**
the origin of feature-based web anomaly detection. Several of your 19 features
are descendants of these.

**[R23] Robertson, Vigna, Kruegel & Kemmerer, NDSS 2006 — _Using Generalization and Characterization Techniques in the Anomaly-based Detection of Web Attacks_**
Extends [R22] by generalising anomalies into classes so alerts can be grouped
and explained. **Use it for:** the point that anomaly detectors produce alerts
that are hard to act on — which motivates a system that produces *proof*
instead of an anomaly score.

**[R24] Torrano-Giménez, Pérez-Villegas & Álvarez-Marañón, CSIC 2010 — _HTTP DATASET CSIC 2010_**
About 36,000 normal and 25,000+ anomalous HTTP requests. Still the default
benchmark for web attack detection. **Use it for:** the standard-dataset
comparison in your baselines, and to explain *why you had to build your own
corpus*: CSIC 2010 has no sessions, no timing, no bait interactions and no
benign-but-automated class, so it cannot support any of your metrics.

**[R25] Tekerek, Computers & Security 2021 — _A Novel Architecture for Web-based Attack Detection Using Convolutional Neural Network_**
A CNN-based anomaly detector for HTTP. **Use it for:** a recent, representative
"deep learning WAF" citation showing where the mainstream is going —
better classifiers, still fully passive.

**[R26] Amouei, Rezvani & Fateh, IEEE Transactions on Dependable and Secure Computing 2022 — _RAT: Reinforcement-Learning-Driven and Adaptive Testing for Vulnerability Discovery in Web Application Firewalls_**
Uses reinforcement learning to automatically find payloads that bypass
well-configured WAFs, beating prior methods by 33.53% on average. **Use it
for:** hard evidence that pattern-matching defences are bypassable, which is
the motivation for evidence you *cause* rather than patterns you *match*.

---

## 9. Theme G — Bot and automation detection

**[R27] Iliou, Kostoulas, Tsikrika, Katos, Vrochidis & Kompatsiaris, ARES 2019 — _Towards a Framework for Detecting Advanced Web Bots_**
Two detection modules: one on web logs, one on mouse movement. **Use it for:**
the justification of your automation axis, and for the web-log feature family.

**[R28] Iliou, Kostoulas, Tsikrika, Katos, Vrochidis & Kompatsiaris, ACM Digital Threats: Research and Practice 2021 — _Detection of Advanced Web Bots by Combining Web Logs with Mouse Behavioural Biometrics_**
The journal version. Its key point for you: *advanced* bots imitate human
browser fingerprints and human-like behaviour, which lowers detectability.
**Use it for:** the argument that an automation score alone can never be
enough — which is precisely why your model has a second axis, and why bait is
needed when the automation signal is weak.

---

## 10. Theme H — Decision theory and cost

**[R29] Howard, IEEE Transactions on Systems Science and Cybernetics 1966 — _Information Value Theory_**
The original source for putting a *number* on the worth of an observation
before you make it. This is the direct ancestor of the V(p) term in your
policy. **Cite it as the source of EVSI.** Do not cite a modern paper for
this — this is where it comes from.

**[R30] Elkan, IJCAI 2001 — _The Foundations of Cost-Sensitive Learning_**
Shows how to make optimal decisions when different mistakes cost different
amounts, and — usefully for you — defines when a cost matrix is *coherent* and
when it is economically nonsense. **Use it for:** the justification of your
frozen cost table, and as the standard reference for cost-based thresholds.

**[R31] Pawlick, Colbert & Zhu, IEEE Transactions on Information Forensics and Security 2019 — _Modeling and Analysis of Leaky Deception Using Signaling Games with Evidence_**
Extends signalling games with a detector that gives probabilistic warnings when
the sender is deceptive. Findings include: high-quality detectors remove some
pure-strategy equilibria, and receivers do best with equal-error-rate
detectors. **Use it for:** the theoretical framing of "deception that can leak".
Your invisibility gate bounds exactly the leak this paper models.

---

## 11. Theme I — How security ML should be evaluated

These four are what stop a reviewer from dismissing your results.

**[R32] Axelsson, ACM Transactions on Information and System Security 2000 — _The Base-Rate Fallacy and the Difficulty of Intrusion Detection_**
Because attacks are rare, even a very accurate detector produces mostly false
alarms. **Use it for:** the reason you report expected cost per session instead
of accuracy, and the reason your benign-diversion rate is a headline number
rather than a footnote.

**[R33] Sommer & Paxson, IEEE Symposium on Security and Privacy 2010 — _Outside the Closed World: On Using Machine Learning for Network Intrusion Detection_**
Explains why ML anomaly detection is common in papers and rare in production:
the cost of a false positive, the lack of good ground truth, and the
"semantic gap" between an anomaly and an action. Won the 2020 Test of Time
award. **Use it for:** the strongest available motivation for your whole
design. Your bait closes the semantic gap by turning an anomaly into an act.

**[R34] Arp, Quiring, Pendlebury, Warnecke, Pierazzi, Wressnegger, Cavallaro & Rieck, USENIX Security 2022 — _Dos and Don'ts of Machine Learning in Computer Security_**
Names ten common pitfalls: sampling bias, label inaccuracy, data snooping,
spurious correlations, inappropriate baselines, and more. **Use it for:** a
short paragraph in your methodology showing that your frozen schema, frozen
cost table, separate calibration round, and refusal to mix attack rounds each
answer a *named* pitfall from this paper. This is cheap and very persuasive.

**[R35] Ferguson-Walter, Major, Johnson & Muhleman, USENIX Security 2021 — _Examining the Efficacy of Decoy-based and Psychological Cyber Deception_**
A controlled experiment with professional red teamers, testing both real decoys
and the *psychological* effect of merely telling attackers deception might be
present. **Use it for:** the model for your randomised holdout, and as evidence
that this field *can* support causal claims but rarely does. This is the paper
your Contribution 3 should be positioned against.

---

## 12. Theme J — Supporting work

**[R36] Schneier & Kelsey, ACM Transactions on Information and System Security 1999 — _Secure Audit Logs to Support Computer Forensics_**
A cheap method to make log entries written before a compromise impossible to
read, modify or destroy undetectably. **Use it for:** the citation behind your
hash-chained append-only log store.

**[R37] Cho, Sharma, Alavizadeh et al., IEEE Communications Surveys & Tutorials 2020 — _Toward Proactive, Adaptive Defense: A Survey on Moving Target Defense_**
MTD is the other main proactive defence family: keep changing the system so the
attacker's knowledge goes stale. **Use it for:** a one-line contrast. MTD
changes the *system* to confuse the attacker; deception changes the *attacker's
beliefs*. Your work is the second kind.

**[R38] Schuirmann, Journal of Pharmacokinetics and Biopharmaceutics 1987 — _A Comparison of the Two One-Sided Tests Procedure and the Power Approach for Assessing the Equivalence of Average Bioavailability_**
The origin of the TOST equivalence test. **Use it for:** the statistics behind
your invisibility gate. This matters: "we found no significant difference" is
*not* evidence of invisibility. TOST lets you state a bound and test *for*
equivalence, which is the correct claim.

---

## 13. Comparison tables

### Table 1 — Master map of all 38 references

| ID | Year | Authors (short) | Venue | Theme | In one line |
|---|---|---|---|---|---|
| R1 | 2014 | Almeshekah & Spafford | NSPW | A | Deception must be planned around a target belief |
| R2 | 2018 | Han, Kheir & Balzarotti | ACM CSUR | A | Standard taxonomy of deception techniques |
| R3 | 2019 | Pawlick, Colbert & Zhu | ACM CSUR | A | Six families of defensive deception, game-theoretic |
| R4 | 2021 | Zhu et al. | IEEE COMST | A | Game theory + ML approaches to deception |
| R5 | 2025 | Beltrán López, Gil Pérez & Nespoli | IEEE COMST | A | Newest unified taxonomy and open challenges |
| R6 | 2004 | Provos | USENIX Sec | B | Honeyd: virtual honeypots on unused addresses |
| R7 | 2016 | Nawrocki et al. | arXiv | B | Catalogue of honeypot software and data analysis |
| R8 | 2024 | Javadpour et al. | Comput. Secur. | B | Survey on making honeypots more convincing |
| R9 | 2017 | Barron & Nikiforakis | ACSAC | B | What you plant changes attacker behaviour (102 honeypots) |
| R10 | 2018 | Vetterl & Clayton | USENIX WOOT | B | Honeypots fingerprinted at scale with one packet |
| R11 | 2024 | Sladić et al. | IEEE EuroS&PW | C | LLM generates shell output live (shelLM) |
| R12 | 2024 | Reworr & Volkov | arXiv | C | Prompt injection in a honeypot to provoke AI agents |
| R13 | 2025 | Bridges et al. | arXiv | C | SoK: LLM honeypots show only incremental gains |
| R14 | 2004 | Yuill et al. | IEEE IAW | D | Honeyfiles: bait files that raise an alarm |
| R15 | 2009 | Bowen et al. | SecureComm | D | Decoy documents + properties a good decoy needs |
| R16 | 2013 | Juels & Rivest | ACM CCS | D | Honeywords: fake passwords as tripwires |
| R17 | 2020 | Srinivasa et al. | SIN | D | Honeytokens can be systematically fingerprinted |
| R18 | 2025 | Timmer et al. | ACM TOPS | D | Metrics for honeyfile realism and enticement |
| R19 | 2024 | Kahlhofer & Rass | IEEE EuroS&PW | E | 19 application-layer deception methods reviewed |
| R20 | 2024 | Kahlhofer et al. | RAID | E | Honeyquest: measure enticingness before building |
| R21 | 2025 | Kahlhofer et al. | IEEE EuroS&PW | E | Koney: orchestrating honeytokens and fake endpoints |
| R22 | 2003 | Kruegel & Vigna | ACM CCS | F | Per-parameter anomaly models for HTTP |
| R23 | 2006 | Robertson et al. | NDSS | F | Generalising web anomalies into explainable classes |
| R24 | 2010 | Torrano-Giménez et al. | dataset | F | CSIC 2010 HTTP benchmark dataset |
| R25 | 2021 | Tekerek | Comput. Secur. | F | CNN architecture for web attack detection |
| R26 | 2022 | Amouei, Rezvani & Fateh | IEEE TDSC | F | RL finds payloads that bypass real WAFs |
| R27 | 2019 | Iliou et al. | ARES | G | Web-log + mouse framework for bot detection |
| R28 | 2021 | Iliou et al. | ACM DTRAP | G | Advanced bots imitate humans and evade detection |
| R29 | 1966 | Howard | IEEE Trans. SSC | H | Value of information: price an observation |
| R30 | 2001 | Elkan | IJCAI | H | Foundations of cost-sensitive decisions |
| R31 | 2019 | Pawlick, Colbert & Zhu | IEEE TIFS | H | Signalling games where deception can leak |
| R32 | 2000 | Axelsson | ACM TISSEC | I | Base-rate fallacy makes IDS alerts mostly false |
| R33 | 2010 | Sommer & Paxson | IEEE S&P | I | Why ML intrusion detection fails in production |
| R34 | 2022 | Arp et al. | USENIX Sec | I | Ten named pitfalls in security ML |
| R35 | 2021 | Ferguson-Walter et al. | USENIX Sec | I | Controlled experiment on deception with red teamers |
| R36 | 1999 | Schneier & Kelsey | ACM TISSEC | J | Tamper-evident audit logs |
| R37 | 2020 | Cho et al. | IEEE COMST | J | Moving target defence survey |
| R38 | 1987 | Schuirmann | J. Pharmacokinet. Biopharm. | J | TOST: how to test *for* equivalence |

---

### Table 2 — The three existing defence families vs this work

| | Rule-based WAF | ML classifier | Honeypot | **This work** |
|---|---|---|---|---|
| Representative refs | R26 (bypassing them) | R22, R23, R25 | R6, R7, R8, R9 | — |
| Where it sits | in front of the app | in front of the app | beside the app | in front of, and inside, the app |
| Source of evidence | request matches a pattern | request looks unusual | attacker walks in | **defender provokes a reaction** |
| Evidence arrives | immediately, but wrong often | slowly | only if attacker strays | **on demand, when uncertain** |
| Attacker learns they were caught | yes (blocked) | often (blocked) | no | **no (silent divert)** |
| Handles a careful manual attacker | poorly | poorly | not at all | yes, that is the target case |
| Cost to honest users | false blocks | false alarms | none | **measured, bounded by the gate** |
| Threshold source | admin's choice | tuned on validation set | n/a | **derived from cost table + EVSI** |

---

### Table 3 — Where the deception is placed

| Layer | Refs | What is faked | Reaches attackers on the real site? | Per-visitor? |
|---|---|---|---|---|
| Network / host | R6, R7 | whole fake machines | No — separate address space | No |
| File system | R14, R15, R18 | fake documents | Only after break-in | No |
| Credential store | R16 | fake passwords | Only after DB theft | No |
| Container / cluster config | R21 | honeytokens, fake API endpoints | Yes, but statically placed | No |
| Shell session | R11, R12 | generated shell output | Only inside the honeypot | Partly (R12) |
| **HTTP response of the live app** | **this work** | **error text, JSON fields, endpoint hints** | **Yes, always** | **Yes, chosen per session** |

The bottom row is the gap. R19's survey of application-layer methods is the
only prior work that even maps this row properly, and it reports the area as
under-researched.

---

### Table 4 — Bait and honeytoken work compared in detail

| | R14 Honeyfiles | R15 Decoy docs | R16 Honeywords | R21 Koney | R20 Honeyquest | **This work** |
|---|---|---|---|---|---|---|
| Year | 2004 | 2009 | 2013 | 2025 | 2024 | — |
| Placed where | file server | file system | password DB | cluster config | (not deployed) | live HTTP response |
| Chosen per session | No | No | No | No | n/a | **Yes** |
| Trigger for deploying | always on | always on | always on | always on | n/a | **belief-dependent band** |
| Evidence weight on a bite | alarm (binary) | alarm | alarm | alarm | n/a | **likelihood ratio, calibrated** |
| Evidence value of *no* bite | not used | not used | not used | not used | n/a | **used (LR of no-bite)** |
| Invisibility to honest users | assumed | stated as a property | n/a | assumed | n/a | **tested + certified** |
| Enticingness measured | No | qualitative | No | No | **Yes (questionnaire)** | **Yes (behavioural bite rate)** |
| Detectable by attacker? | shown detectable in R17 | shown detectable in R17 | — | — | — | **bounded by gate; open risk** |

**Reading of this table.** Every prior tripwire is *always on and the same for
everybody*. The gap is not "another kind of token". The gap is **a rule for
deciding when a token is worth deploying to this particular visitor**.

---

### Table 5 — How the trigger point is decided

| Approach | Refs | How the threshold is set | Can a reviewer attack it? |
|---|---|---|---|
| Fixed rule set | R26 | admin writes rules | yes — trivially bypassable |
| Score threshold tuned on a validation set | R22, R23, R25 | pick the value with the best F1 | yes — "you tuned it to your data" |
| Game-theoretic equilibrium | R3, R31 | solve the game | partly — needs strong assumptions about the attacker |
| Always deploy the deception | R14, R15, R16, R21 | no threshold at all | yes — no cost control |
| Enticingness ranking | R20 | rank by questionnaire score | partly — says *which*, not *when* |
| **Cost + value of information** | **this work**, built on R29, R30 | **derived; nothing chosen by hand** | **hard — remove the EVSI term and the third action disappears entirely** |

---

### Table 6 — Keeping the fake world consistent

| Work | Fake content generated | Remembers what it said | Contradiction measured |
|---|---|---|---|
| R6 Honeyd | scripted | n/a | No |
| R11 shelLM | LLM, live | limited to context window | No |
| R12 LLM Agent Honeypot | LLM, live | session only | No |
| R13 SoK (survey) | — | reports this as an open problem | — |
| R8 survey | — | realism discussed | No |
| **This work** | **offline, before runtime (generator-agnostic)** | **persistent Fact Notebook** | **Yes — contradiction rate** |

**On the generator.** The point of difference from R11/R12 is *not* that this
work uses a language model — it is that generation happens **offline, before
runtime**, and is backed by a persistent consistency layer whose contradiction
rate is measured. The offline generator is deliberately pluggable: the spec
(§6.8, §12) envisages a batched LLM, and the evaluated implementation uses a
**deterministic synthetic generator** (`adf/decoy/world.py`) instead. That is a
strength for this work's purposes — it is seeded and reproducible (NFR-08), and
keyed per entity so an on-demand fact is byte-identical to a batch-generated one
— and, crucially, the contribution is generator-agnostic: the Fact Notebook and
the contradiction-rate metric do not depend on how a value was produced, only
that it is fixed once produced. Swapping an LLM into `world.GENERATORS` would
change nothing else. So this work does not claim LLM-generated content as a
contribution (that is R11/R12, and not new); it claims the offline+consistency
+measurement combination, which holds under either generator.

R13 is worth quoting directly here: the SoK finds the LLM-honeypot field
**lacks agreed evaluation paradigms**. A reported contradiction rate is a
concrete answer to that, and it applies whether the generator is a model or not.

---

### Table 7 — Evaluation rigour across the field

| Work | Real measurement | Causal claim | Hard negatives | Cost to honest users | Public dataset |
|---|---|---|---|---|---|
| R9 Barron & Nikiforakis | yes, 4 months | partly (varied conditions) | n/a | n/a | partly |
| R10 Vetterl & Clayton | yes, internet-wide | no | n/a | n/a | no |
| R20 Honeyquest | yes, questionnaire | no | n/a | no | yes (tool) |
| R35 Ferguson-Walter et al. | yes, human subjects | **yes — controlled** | n/a | no | no |
| R25 Tekerek | yes, CSIC 2010 | no | no | no | uses R24 |
| R26 RAT | yes | no | n/a | no | no |
| **This work** | yes | **yes — randomised holdout** | **yes, by design** | **yes — headline metric** | **planned** |

Only **one** prior work in this list makes a causal claim, and it does so with
human subjects, which is expensive and hard to repeat. A randomised holdout
inside a running system is cheaper and repeatable. That is a defensible
methodological contribution on its own.

---

### Table 8 — Gap matrix (the most useful table for the paper)

Six things this project claims. Which prior works have each?
`Y` = yes, `P` = partly, `–` = no.

| Ref | 1. Deception inside the live app response | 2. Chosen per session from a belief | 3. Trigger derived, not tuned | 4. Invisibility to honest users measured | 5. Decoy consistency measured | 6. Causal effect established |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| R6 Provos | – | – | – | – | – | – |
| R9 Barron & Nikiforakis | – | – | – | – | – | P |
| R10 Vetterl & Clayton | – | – | – | – | P | – |
| R11 shelLM | – | – | – | – | – | – |
| R12 LLM Agent Honeypot | P | – | – | – | – | – |
| R13 SoK LLM honeypots | – | – | – | – | – | – |
| R14 Honeyfiles | – | – | – | – | – | – |
| R15 Decoy documents | – | – | – | P | – | – |
| R16 Honeywords | – | – | – | – | – | – |
| R17 Honeytoken fingerprinting | – | – | – | P | – | – |
| R18 Honeyfile metrics | – | – | – | – | P | – |
| R19 App-layer deception survey | Y | – | – | P | – | – |
| R20 Honeyquest | Y | – | – | – | – | – |
| R21 Koney | Y | – | – | – | – | – |
| R22–R26 WAF / ML detection | – | – | – | n/a | n/a | – |
| R31 Signalling with evidence | – | P | P | P (theory) | – | – |
| R35 Ferguson-Walter et al. | – | – | – | – | – | **Y** |
| **This work** | **Y** | **Y** | **Y** | **Y** | **Y** | **Y** |

**No row other than the last has more than two Y marks.** That single sentence
is your novelty claim, and it is backed by a table a reviewer can check.

---

### Table 9 — Datasets

| Dataset | Ref | Size | Sessions? | Timing? | Benign-but-automated class? | Bait interactions? |
|---|---|---|---|---|---|---|
| CSIC 2010 | R24 | ~36k normal, 25k+ anomalous | No | No | No | No |
| Honeypot captures | R7, R9 | varies | Yes | Yes | No (all traffic hostile) | No |
| Honeyquest responses | R20 | questionnaire responses | n/a | n/a | n/a | simulated |
| **This project's corpus** | — | generated, labelled | **Yes** | **Yes** | **Yes** | **Yes** |

This table is the justification for building your own corpus. Without it, a
reviewer will ask "why not just use CSIC 2010?" — and the honest answer is that
CSIC 2010 cannot express a single one of your metrics.

---

### Table 10 — What each area reports as its metric

| Area | Usual metrics | What is missing |
|---|---|---|
| WAF / ML detection (R22–R26) | precision, recall, F1, AUC | cost of a mistake; requests needed to decide |
| Honeypots (R6–R9) | attacks captured, dwell time | effect on legitimate users (there are none) |
| Honeytokens (R14–R18) | alarms raised, realism, enticement | cost to honest users; when to deploy |
| Deception experiments (R35) | attacker time, task success | repeatability without human subjects |
| **This work** | expected cost per session, requests-to-decision, benign bait exposure, benign diversion, contradiction rate | — |

---

### Table 11 — Recency of the reference list

| Period | Count | IDs |
|---|---|---|
| 2024–2025 | 9 | R5, R8, R11, R12, R13, R18, R19, R20, R21 |
| 2020–2023 | 8 | R4, R17, R25, R26, R28, R34, R35, R37 |
| 2010–2019 | 11 | R1, R2, R3, R7, R9, R10, R16, R24, R27, R31, R33 |
| Pre-2010 (foundational only) | 10 | R6, R14, R15, R22, R23, R29, R30, R32, R36, R38 |
| **Total** | **38** | |

**17 of 38 references (45%) are from 2020 or later**, which is a healthy
balance for a systems paper. The ten pre-2010 entries are all "this is where
the idea came from" citations, not filler: Howard [R29] for the value of
information, Elkan [R30] for cost-sensitive decisions, Axelsson [R32] for the
base-rate problem, Schuirmann [R38] for equivalence testing, Kruegel & Vigna
[R22] and Robertson et al. [R23] for web anomaly detection, Provos [R6] for
honeypots, Yuill et al. [R14] and Bowen et al. [R15] for bait files, and
Schneier & Kelsey [R36] for tamper-evident logs.

---

## 14. The research gaps

State these in the paper as numbered gaps, then map each to a contribution.

**Gap 1 — Deception is placed outside the real request path.**
Honeypots are separate systems [R6, R7, R8]; decoys sit in files [R14, R15,
R18] or credential stores [R16]. Attackers hitting the real application are
never touched. Application-layer deception is the fix, and it is explicitly
under-researched [R19].
→ *Contribution: response-side probes injected into live responses.*

**Gap 2 — The decision of when to deceive is not modelled.**
Tokens are always on [R14, R15, R16, R21]. Where a decision exists, it is a
tuned threshold [R22, R23, R25] or a game-theoretic equilibrium with strong
assumptions [R3, R31].
→ *Contribution: a decision rule where probing is the cost-optimal action over
a band derived from the cost table and the measured effectiveness of the probe.
Remove the value-of-information term [R29] and the third action does not exist
at all.*

**Gap 3 — The evidence value of a trap is asserted, not measured.**
A bite raises an alarm [R14, R16]; nobody reports how much a bite should move a
belief, and nobody uses the information in *not* biting.
→ *Contribution: a likelihood ratio for both bite and no-bite, estimated in a
dedicated calibration round.*

**Gap 4 — The cost to honest users is not measured.**
The field measures realism and enticement [R18, R20] and detectability by
attackers [R10, R17]. It does not measure what deception does to people who
were never the target.
→ *Contribution: an invisibility gate with a stated equivalence bound [R38],
and a benign corpus deliberately built to be hard.*

**Gap 5 — Almost no causal claims.**
Only [R35] runs a controlled experiment, using expensive human subjects. Every
other "our deception helped" claim compares two different systems, so the
effect is confounded.
→ *Contribution: a randomised holdout inside one system, giving an unbiased
estimate of the effect of baiting on time-to-decision.*

**Gap 6 — Generated fake worlds contradict themselves, and nobody counts it.**
LLM honeypots generate live [R11, R12], and the SoK names evaluation as an open
problem [R13]. Contradiction is exactly how an experienced attacker detects a
trap [R10].
→ *Contribution: a persistent Fact Notebook and a reported contradiction rate.*

---

## 15. What to cite in which section

| Paper section | Cite | Purpose |
|---|---|---|
| Abstract | — | no citations |
| Introduction — the problem | R32, R33, R26 | defences are passive, bypassable, and drown in false alarms |
| Introduction — the idea | R1, R16 | deception is planned; tripwires create evidence |
| Related work — deception overall | R1, R2, R3, R4, R5 | taxonomy and current state |
| Related work — honeypots | R6, R7, R8, R9 | strengths, and the placement problem |
| Related work — honeypot detectability | R10, R17 | why invisibility must be measured |
| Related work — LLM honeypots | R11, R12, R13 | "LLM content is not new"; consistency is open |
| Related work — honeytokens | R14, R15, R16, R18 | closest ancestors of bait |
| Related work — application-layer deception | **R19, R20, R21** | the nearest neighbours; the gap statement |
| Related work — web attack detection | R22, R23, R24, R25, R26 | the passive baseline family |
| Related work — bot detection | R27, R28 | the automation axis |
| Threat model | R9, R26, R28 | what a real attacker does |
| Design — decision policy | **R29, R30**, R31 | EVSI and cost-sensitive decisions |
| Design — bait library | R15, R20 | decoy properties and enticingness |
| Design — invisibility gate | R38, R10, R17 | equivalence testing and detectability |
| Design — decoy / Fact Notebook | R11, R13 | consistency as an open problem |
| Design — logging | R36 | tamper-evident records |
| Experimental setup | R24, R34 | benchmark comparison and pitfall avoidance |
| Experimental setup — causal design | R35 | the model for the randomised holdout |
| Results | R32 | why expected cost, not accuracy |
| Limitations | R10, R17, R13 | detectability, small scale, consistency |
| Future work | R5, R37 | open challenges; the MTD contrast |

---

## 16. Full reference list with links

Numbered as `[R1]…[R38]`. Every link was opened during verification.

**[R1]** M. H. Almeshekah and E. H. Spafford, "Planning and Integrating Deception into Computer Security Defenses," in *Proc. 2014 New Security Paradigms Workshop (NSPW '14)*, 2014, pp. 127–138. DOI: 10.1145/2683467.2683482 — https://doi.org/10.1145/2683467.2683482

**[R2]** X. Han, N. Kheir, and D. Balzarotti, "Deception Techniques in Computer Security: A Research Perspective," *ACM Computing Surveys*, vol. 51, no. 4, art. 80, pp. 1–36, 2018. DOI: 10.1145/3214305 — https://dl.acm.org/doi/10.1145/3214305

**[R3]** J. Pawlick, E. Colbert, and Q. Zhu, "A Game-theoretic Taxonomy and Survey of Defensive Deception for Cybersecurity and Privacy," *ACM Computing Surveys*, vol. 52, no. 4, art. 82, pp. 1–28, 2019. DOI: 10.1145/3337772 — https://dl.acm.org/doi/10.1145/3337772 (preprint: https://arxiv.org/abs/1712.05441)

**[R4]** M. Zhu, A. H. Anwar, Z. Wan, J.-H. Cho, C. A. Kamhoua, and M. P. Singh, "A Survey of Defensive Deception: Approaches Using Game Theory and Machine Learning," *IEEE Communications Surveys & Tutorials*, vol. 23, no. 4, pp. 2460–2493, 2021. — https://arxiv.org/abs/2101.10121

**[R5]** P. Beltrán López, M. Gil Pérez, and P. Nespoli, "Cyber Deception: Taxonomy, State of the Art, Frameworks, Trends, and Open Challenges," *IEEE Communications Surveys & Tutorials*, 2025. DOI: 10.1109/COMST.2025.3594788 — https://doi.org/10.1109/COMST.2025.3594788
  *(The arXiv preprint carries an earlier title — "Cyber Deception: State of the art, Trends and Open challenges", arXiv:2409.07194, https://arxiv.org/abs/2409.07194. Cite the published COMST title.)*

**[R6]** N. Provos, "A Virtual Honeypot Framework," in *Proc. 13th USENIX Security Symposium*, 2004. — https://www.usenix.org/conference/13th-usenix-security-symposium/virtual-honeypot-framework

**[R7]** M. Nawrocki, M. Wählisch, T. C. Schmidt, C. Keil, and J. Schönfelder, "A Survey on Honeypot Software and Data Analysis," arXiv:1608.06249, 2016. — https://arxiv.org/abs/1608.06249

**[R8]** A. Javadpour, F. Ja'fari, T. Taleb, M. Shojafar, and C. Benzaïd, "A Comprehensive Survey on Cyber Deception Techniques to Improve Honeypot Performance," *Computers & Security*, vol. 140, art. 103792, 2024. DOI: 10.1016/j.cose.2024.103792 — https://doi.org/10.1016/j.cose.2024.103792

**[R9]** T. Barron and N. Nikiforakis, "Picky Attackers: Quantifying the Role of System Properties on Intruder Behavior," in *Proc. 33rd Annual Computer Security Applications Conference (ACSAC '17)*, 2017. DOI: 10.1145/3134600.3134614 — https://securitee.org/files/pickyattackers_acsac2017.pdf

**[R10]** A. Vetterl and R. Clayton, "Bitter Harvest: Systematically Fingerprinting Low- and Medium-interaction Honeypots at Internet Scale," in *Proc. 12th USENIX Workshop on Offensive Technologies (WOOT '18)*, 2018. — https://www.usenix.org/conference/woot18/presentation/vetterl

**[R11]** M. Sladić, V. Valeros, C. Catania, and S. Garcia, "LLM in the Shell: Generative Honeypots," in *2024 IEEE European Symposium on Security and Privacy Workshops (EuroS&PW)*, 2024. — https://arxiv.org/abs/2309.00155

**[R12]** Reworr and D. Volkov, "LLM Agent Honeypot: Monitoring AI Hacking Agents in the Wild," arXiv:2410.13919, 2024. — https://arxiv.org/abs/2410.13919

**[R13]** R. A. Bridges, T. R. Mitchell, M. Muñoz, and T. Henriksson, "SoK: Honeypots & LLMs, More Than the Sum of Their Parts?," arXiv:2510.25939, 2025. — https://arxiv.org/abs/2510.25939

**[R14]** J. Yuill, M. Zappe, D. Denning, and F. Feer, "Honeyfiles: Deceptive Files for Intrusion Detection," in *Proc. 5th Annual IEEE SMC Information Assurance Workshop*, 2004, pp. 116–122. — https://faculty.nps.edu/dedennin/publications/honeyfiles.pdf

**[R15]** B. M. Bowen, S. Hershkop, A. D. Keromytis, and S. J. Stolfo, "Baiting Inside Attackers Using Decoy Documents," in *Proc. 5th Int. ICST Conf. on Security and Privacy in Communication Networks (SecureComm 2009)*, 2009, pp. 51–70. DOI: 10.1007/978-3-642-05284-2_4 — https://link.springer.com/chapter/10.1007/978-3-642-05284-2_4

**[R16]** A. Juels and R. L. Rivest, "Honeywords: Making Password-Cracking Detectable," in *Proc. 2013 ACM SIGSAC Conf. on Computer and Communications Security (CCS '13)*, 2013, pp. 145–160. — https://people.csail.mit.edu/rivest/pubs/JR13.pdf

**[R17]** S. Srinivasa, J. M. Pedersen, and E. Vasilomanolakis, "Towards Systematic Honeytoken Fingerprinting," in *Proc. 13th Int. Conf. on Security of Information and Networks (SIN 2020)*, 2020. DOI: 10.1145/3433174.3433599 — https://dl.acm.org/doi/10.1145/3433174.3433599

**[R18]** R. Timmer, D. Liebowitz, S. Nepal, and S. Kanhere, "Evaluating Honeyfile Realism and Enticement Metrics," *ACM Transactions on Privacy and Security*, vol. 28, no. 4, 2025. DOI: 10.1145/3763792 — https://dl.acm.org/doi/10.1145/3763792

**[R19]** M. Kahlhofer and S. Rass, "Application Layer Cyber Deception Without Developer Interaction," in *2024 IEEE European Symposium on Security and Privacy Workshops (EuroS&PW)* — 3rd Workshop on Active Defense and Deception (ADnD 2024), 2024. — https://ieeexplore.ieee.org/document/10628607/ (preprint: https://arxiv.org/abs/2405.12852)

**[R20]** M. Kahlhofer, S. Achleitner, S. Rass, and R. Mayrhofer, "Honeyquest: Rapidly Measuring the Enticingness of Cyber Deception Techniques with Code-based Questionnaires," in *Proc. 27th Int. Symp. on Research in Attacks, Intrusions and Defenses (RAID 2024)*, 2024. DOI: 10.1145/3678890.3678897 — https://dl.acm.org/doi/10.1145/3678890.3678897

**[R21]** M. Kahlhofer, M. Golinelli, and S. Rass, "Koney: A Cyber Deception Orchestration Framework for Kubernetes," in *2025 IEEE European Symposium on Security and Privacy Workshops (EuroS&PW)*, 2025, pp. 690–702. — https://arxiv.org/abs/2504.02431

**[R22]** C. Kruegel and G. Vigna, "Anomaly Detection of Web-based Attacks," in *Proc. 10th ACM Conf. on Computer and Communications Security (CCS '03)*, 2003, pp. 251–261. DOI: 10.1145/948109.948144 — https://dl.acm.org/doi/10.1145/948109.948144

**[R23]** W. Robertson, G. Vigna, C. Kruegel, and R. A. Kemmerer, "Using Generalization and Characterization Techniques in the Anomaly-based Detection of Web Attacks," in *Proc. Network and Distributed System Security Symposium (NDSS 2006)*, 2006. — https://www.ndss-symposium.org/ndss2006/using-generalization-and-characterization-techniques-anomaly-based-detection-web-attacks/

**[R24]** C. Torrano-Giménez, A. Pérez-Villegas, and G. Álvarez-Marañón, "HTTP DATASET CSIC 2010," Information Security Institute, Spanish Research National Council (CSIC), 2010. — https://www.isi.csic.es/dataset/

**[R25]** A. Tekerek, "A Novel Architecture for Web-based Attack Detection Using Convolutional Neural Network," *Computers & Security*, vol. 100, art. 102096, 2021. DOI: 10.1016/j.cose.2020.102096 — https://doi.org/10.1016/j.cose.2020.102096

**[R26]** M. Amouei, M. Rezvani, and M. Fateh, "RAT: Reinforcement-Learning-Driven and Adaptive Testing for Vulnerability Discovery in Web Application Firewalls," *IEEE Transactions on Dependable and Secure Computing*, vol. 19, pp. 3371–3386, 2022. — https://ieeexplore.ieee.org/document/9477095/ (preprint: https://arxiv.org/abs/2312.07885)

**[R27]** C. Iliou, T. Kostoulas, T. Tsikrika, V. Katos, S. Vrochidis, and I. Kompatsiaris, "Towards a Framework for Detecting Advanced Web Bots," in *Proc. 14th Int. Conf. on Availability, Reliability and Security (ARES 2019)*, 2019. DOI: 10.1145/3339252.3339267 — https://dl.acm.org/doi/10.1145/3339252.3339267

**[R28]** C. Iliou, T. Kostoulas, T. Tsikrika, V. Katos, S. Vrochidis, and I. Kompatsiaris, "Detection of Advanced Web Bots by Combining Web Logs with Mouse Behavioural Biometrics," *Digital Threats: Research and Practice*, vol. 2, no. 3, 2021. DOI: 10.1145/3447815 — https://dl.acm.org/doi/10.1145/3447815

**[R29]** R. A. Howard, "Information Value Theory," *IEEE Transactions on Systems Science and Cybernetics*, vol. 2, no. 1, pp. 22–26, 1966. DOI: 10.1109/TSSC.1966.300074 — https://doi.org/10.1109/TSSC.1966.300074

**[R30]** C. Elkan, "The Foundations of Cost-Sensitive Learning," in *Proc. 17th Int. Joint Conf. on Artificial Intelligence (IJCAI 2001)*, 2001, pp. 973–978. — https://cseweb.ucsd.edu/~elkan/rescale.pdf

**[R31]** J. Pawlick, E. Colbert, and Q. Zhu, "Modeling and Analysis of Leaky Deception Using Signaling Games with Evidence," *IEEE Transactions on Information Forensics and Security*, vol. 14, no. 7, pp. 1871–1886, 2019. — https://arxiv.org/abs/1804.06831

**[R32]** S. Axelsson, "The Base-Rate Fallacy and the Difficulty of Intrusion Detection," *ACM Transactions on Information and System Security*, vol. 3, no. 3, pp. 186–205, 2000. DOI: 10.1145/357830.357849 — https://dl.acm.org/doi/10.1145/357830.357849

**[R33]** R. Sommer and V. Paxson, "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection," in *Proc. 2010 IEEE Symposium on Security and Privacy*, 2010, pp. 305–316. DOI: 10.1109/SP.2010.25 — https://dl.acm.org/doi/10.1109/SP.2010.25

**[R34]** D. Arp, E. Quiring, F. Pendlebury, A. Warnecke, F. Pierazzi, C. Wressnegger, L. Cavallaro, and K. Rieck, "Dos and Don'ts of Machine Learning in Computer Security," in *Proc. 31st USENIX Security Symposium*, 2022. — https://www.usenix.org/conference/usenixsecurity22/presentation/arp

**[R35]** K. J. Ferguson-Walter, M. M. Major, C. K. Johnson, and D. H. Muhleman, "Examining the Efficacy of Decoy-based and Psychological Cyber Deception," in *Proc. 30th USENIX Security Symposium*, 2021. — https://www.usenix.org/conference/usenixsecurity21/presentation/ferguson-walter

**[R36]** B. Schneier and J. Kelsey, "Secure Audit Logs to Support Computer Forensics," *ACM Transactions on Information and System Security*, vol. 2, no. 2, pp. 159–176, 1999. DOI: 10.1145/317087.317089 — https://dl.acm.org/doi/10.1145/317087.317089

**[R37]** J.-H. Cho, D. P. Sharma, H. Alavizadeh, S. Yoon, N. Ben-Asher, T. J. Moore, D. S. Kim, H. Lim, and F. F. Nelson, "Toward Proactive, Adaptive Defense: A Survey on Moving Target Defense," *IEEE Communications Surveys & Tutorials*, vol. 22, no. 1, pp. 709–745, 2020. DOI: 10.1109/COMST.2019.2963791 — https://arxiv.org/abs/1909.08092

**[R38]** D. J. Schuirmann, "A Comparison of the Two One-Sided Tests Procedure and the Power Approach for Assessing the Equivalence of Average Bioavailability," *Journal of Pharmacokinetics and Biopharmaceutics*, vol. 15, no. 6, pp. 657–680, 1987. DOI: 10.1007/BF01068419 — https://link.springer.com/article/10.1007/BF01068419

---

## 17. BibTeX

Copy this into `refs.bib`. Only fields that were verified are included.

```bibtex
@inproceedings{almeshekah2014planning,
  author    = {Almeshekah, Mohammed H. and Spafford, Eugene H.},
  title     = {Planning and Integrating Deception into Computer Security Defenses},
  booktitle = {Proceedings of the 2014 New Security Paradigms Workshop (NSPW '14)},
  pages     = {127--138},
  year      = {2014},
  doi       = {10.1145/2683467.2683482}
}

@article{han2018deception,
  author  = {Han, Xiao and Kheir, Nizar and Balzarotti, Davide},
  title   = {Deception Techniques in Computer Security: A Research Perspective},
  journal = {ACM Computing Surveys},
  volume  = {51},
  number  = {4},
  pages   = {1--36},
  year    = {2018},
  doi     = {10.1145/3214305}
}

@article{pawlick2019taxonomy,
  author  = {Pawlick, Jeffrey and Colbert, Edward and Zhu, Quanyan},
  title   = {A Game-theoretic Taxonomy and Survey of Defensive Deception for
             Cybersecurity and Privacy},
  journal = {ACM Computing Surveys},
  volume  = {52},
  number  = {4},
  pages   = {1--28},
  year    = {2019},
  doi     = {10.1145/3337772}
}

@article{zhu2021survey,
  author  = {Zhu, Mu and Anwar, Ahmed H. and Wan, Zelin and Cho, Jin-Hee and
             Kamhoua, Charles A. and Singh, Munindar P.},
  title   = {A Survey of Defensive Deception: Approaches Using Game Theory and
             Machine Learning},
  journal = {IEEE Communications Surveys \& Tutorials},
  volume  = {23},
  number  = {4},
  pages   = {2460--2493},
  year    = {2021}
}

@article{beltran2025cyberdeception,
  author  = {Beltr{\'a}n L{\'o}pez, Pedro and Gil P{\'e}rez, Manuel and
             Nespoli, Pantaleone},
  title   = {Cyber Deception: Taxonomy, State of the Art, Frameworks, Trends,
             and Open Challenges},
  journal = {IEEE Communications Surveys \& Tutorials},
  year    = {2025},
  doi     = {10.1109/COMST.2025.3594788}
}

@inproceedings{provos2004honeyd,
  author    = {Provos, Niels},
  title     = {A Virtual Honeypot Framework},
  booktitle = {Proceedings of the 13th USENIX Security Symposium},
  year      = {2004}
}

@article{nawrocki2016survey,
  author  = {Nawrocki, Marcin and W{\"a}hlisch, Matthias and Schmidt, Thomas C.
             and Keil, Christian and Sch{\"o}nfelder, Jochen},
  title   = {A Survey on Honeypot Software and Data Analysis},
  journal = {arXiv preprint arXiv:1608.06249},
  year    = {2016}
}

@article{javadpour2024survey,
  author  = {Javadpour, Amir and Ja'fari, Forough and Taleb, Tarik and
             Shojafar, Mohammad and Benza{\"i}d, Chafika},
  title   = {A Comprehensive Survey on Cyber Deception Techniques to Improve
             Honeypot Performance},
  journal = {Computers \& Security},
  volume  = {140},
  pages   = {103792},
  year    = {2024},
  doi     = {10.1016/j.cose.2024.103792}
}

@inproceedings{barron2017picky,
  author    = {Barron, Timothy and Nikiforakis, Nick},
  title     = {Picky Attackers: Quantifying the Role of System Properties on
               Intruder Behavior},
  booktitle = {Proceedings of the 33rd Annual Computer Security Applications
               Conference (ACSAC '17)},
  year      = {2017},
  doi       = {10.1145/3134600.3134614}
}

@inproceedings{vetterl2018bitter,
  author    = {Vetterl, Alexander and Clayton, Richard},
  title     = {Bitter Harvest: Systematically Fingerprinting Low- and
               Medium-interaction Honeypots at Internet Scale},
  booktitle = {12th USENIX Workshop on Offensive Technologies (WOOT '18)},
  year      = {2018}
}

@inproceedings{sladic2024shellm,
  author    = {Sladi{\'c}, Muris and Valeros, Veronica and Catania, Carlos and
               Garcia, Sebastian},
  title     = {{LLM} in the Shell: Generative Honeypots},
  booktitle = {2024 IEEE European Symposium on Security and Privacy Workshops
               (EuroS\&PW)},
  year      = {2024}
}

@article{reworr2024llmagent,
  author  = {Reworr and Volkov, Dmitrii},
  title   = {{LLM} Agent Honeypot: Monitoring {AI} Hacking Agents in the Wild},
  journal = {arXiv preprint arXiv:2410.13919},
  year    = {2024}
}

@article{bridges2025sok,
  author  = {Bridges, Robert A. and Mitchell, Thomas R. and Mu{\~n}oz, Mauricio
             and Henriksson, Ted},
  title   = {{SoK}: Honeypots \& {LLMs}, More Than the Sum of Their Parts?},
  journal = {arXiv preprint arXiv:2510.25939},
  year    = {2025}
}

@inproceedings{yuill2004honeyfiles,
  author    = {Yuill, Jim and Zappe, Mike and Denning, Dorothy and Feer, Fred},
  title     = {Honeyfiles: Deceptive Files for Intrusion Detection},
  booktitle = {Proceedings from the Fifth Annual IEEE SMC Information Assurance
               Workshop},
  pages     = {116--122},
  year      = {2004}
}

@inproceedings{bowen2009baiting,
  author    = {Bowen, Brian M. and Hershkop, Shlomo and Keromytis, Angelos D.
               and Stolfo, Salvatore J.},
  title     = {Baiting Inside Attackers Using Decoy Documents},
  booktitle = {Security and Privacy in Communication Networks (SecureComm 2009)},
  pages     = {51--70},
  year      = {2009},
  doi       = {10.1007/978-3-642-05284-2_4}
}

@inproceedings{juels2013honeywords,
  author    = {Juels, Ari and Rivest, Ronald L.},
  title     = {Honeywords: Making Password-Cracking Detectable},
  booktitle = {Proceedings of the 2013 ACM SIGSAC Conference on Computer and
               Communications Security (CCS '13)},
  pages     = {145--160},
  year      = {2013}
}

@inproceedings{srinivasa2020honeytoken,
  author    = {Srinivasa, Shreyas and Pedersen, Jens Myrup and
               Vasilomanolakis, Emmanouil},
  title     = {Towards Systematic Honeytoken Fingerprinting},
  booktitle = {13th International Conference on Security of Information and
               Networks (SIN 2020)},
  year      = {2020},
  doi       = {10.1145/3433174.3433599}
}

@article{timmer2025honeyfile,
  author  = {Timmer, Roelien and Liebowitz, David and Nepal, Surya and
             Kanhere, Salil},
  title   = {Evaluating Honeyfile Realism and Enticement Metrics},
  journal = {ACM Transactions on Privacy and Security},
  volume  = {28},
  number  = {4},
  year    = {2025},
  doi     = {10.1145/3763792}
}

@inproceedings{kahlhofer2024applayer,
  author    = {Kahlhofer, Mario and Rass, Stefan},
  title     = {Application Layer Cyber Deception Without Developer Interaction},
  booktitle = {2024 IEEE European Symposium on Security and Privacy Workshops
               (EuroS\&PW)},
  year      = {2024}
}

@inproceedings{kahlhofer2024honeyquest,
  author    = {Kahlhofer, Mario and Achleitner, Stefan and Rass, Stefan and
               Mayrhofer, Ren{\'e}},
  title     = {Honeyquest: Rapidly Measuring the Enticingness of Cyber Deception
               Techniques with Code-based Questionnaires},
  booktitle = {Proceedings of the 27th International Symposium on Research in
               Attacks, Intrusions and Defenses (RAID 2024)},
  year      = {2024},
  doi       = {10.1145/3678890.3678897}
}

@inproceedings{kahlhofer2025koney,
  author    = {Kahlhofer, Mario and Golinelli, Matteo and Rass, Stefan},
  title     = {Koney: A Cyber Deception Orchestration Framework for Kubernetes},
  booktitle = {2025 IEEE European Symposium on Security and Privacy Workshops
               (EuroS\&PW)},
  pages     = {690--702},
  year      = {2025}
}

@inproceedings{kruegel2003anomaly,
  author    = {Kruegel, Christopher and Vigna, Giovanni},
  title     = {Anomaly Detection of Web-based Attacks},
  booktitle = {Proceedings of the 10th ACM Conference on Computer and
               Communications Security (CCS '03)},
  pages     = {251--261},
  year      = {2003},
  doi       = {10.1145/948109.948144}
}

@inproceedings{robertson2006generalization,
  author    = {Robertson, William and Vigna, Giovanni and Kruegel, Christopher
               and Kemmerer, Richard A.},
  title     = {Using Generalization and Characterization Techniques in the
               Anomaly-based Detection of Web Attacks},
  booktitle = {Proceedings of the Network and Distributed System Security
               Symposium (NDSS 2006)},
  year      = {2006}
}

@misc{csic2010,
  author       = {Torrano-Gim{\'e}nez, Carmen and P{\'e}rez-Villegas, Alejandro
                  and {\'A}lvarez-Mara{\~n}{\'o}n, Gonzalo},
  title        = {{HTTP} {DATASET} {CSIC} 2010},
  howpublished = {Information Security Institute, Spanish Research National
                  Council (CSIC)},
  year         = {2010},
  url          = {https://www.isi.csic.es/dataset/}
}

@article{tekerek2021novel,
  author  = {Tekerek, Adem},
  title   = {A Novel Architecture for Web-based Attack Detection Using
             Convolutional Neural Network},
  journal = {Computers \& Security},
  volume  = {100},
  pages   = {102096},
  year    = {2021},
  doi     = {10.1016/j.cose.2020.102096}
}

@article{amouei2022rat,
  author  = {Amouei, Mohammadhossein and Rezvani, Mohsen and Fateh, Mansoor},
  title   = {{RAT}: Reinforcement-Learning-Driven and Adaptive Testing for
             Vulnerability Discovery in Web Application Firewalls},
  journal = {IEEE Transactions on Dependable and Secure Computing},
  volume  = {19},
  pages   = {3371--3386},
  year    = {2022}
}

@inproceedings{iliou2019towards,
  author    = {Iliou, Christos and Kostoulas, Theodoros and Tsikrika, Theodora
               and Katos, Vasilis and Vrochidis, Stefanos and
               Kompatsiaris, Ioannis},
  title     = {Towards a Framework for Detecting Advanced Web Bots},
  booktitle = {Proceedings of the 14th International Conference on Availability,
               Reliability and Security (ARES 2019)},
  year      = {2019},
  doi       = {10.1145/3339252.3339267}
}

@article{iliou2021detection,
  author  = {Iliou, Christos and Kostoulas, Theodoros and Tsikrika, Theodora
             and Katos, Vasilis and Vrochidis, Stefanos and
             Kompatsiaris, Ioannis},
  title   = {Detection of Advanced Web Bots by Combining Web Logs with Mouse
             Behavioural Biometrics},
  journal = {Digital Threats: Research and Practice},
  volume  = {2},
  number  = {3},
  year    = {2021},
  doi     = {10.1145/3447815}
}

@article{howard1966information,
  author  = {Howard, Ronald A.},
  title   = {Information Value Theory},
  journal = {IEEE Transactions on Systems Science and Cybernetics},
  volume  = {2},
  number  = {1},
  pages   = {22--26},
  year    = {1966},
  doi     = {10.1109/TSSC.1966.300074}
}

@inproceedings{elkan2001foundations,
  author    = {Elkan, Charles},
  title     = {The Foundations of Cost-Sensitive Learning},
  booktitle = {Proceedings of the 17th International Joint Conference on
               Artificial Intelligence (IJCAI 2001)},
  pages     = {973--978},
  year      = {2001}
}

@article{pawlick2019leaky,
  author  = {Pawlick, Jeffrey and Colbert, Edward and Zhu, Quanyan},
  title   = {Modeling and Analysis of Leaky Deception Using Signaling Games
             with Evidence},
  journal = {IEEE Transactions on Information Forensics and Security},
  volume  = {14},
  number  = {7},
  pages   = {1871--1886},
  year    = {2019}
}

@article{axelsson2000baserate,
  author  = {Axelsson, Stefan},
  title   = {The Base-Rate Fallacy and the Difficulty of Intrusion Detection},
  journal = {ACM Transactions on Information and System Security},
  volume  = {3},
  number  = {3},
  pages   = {186--205},
  year    = {2000},
  doi     = {10.1145/357830.357849}
}

@inproceedings{sommer2010outside,
  author    = {Sommer, Robin and Paxson, Vern},
  title     = {Outside the Closed World: On Using Machine Learning for Network
               Intrusion Detection},
  booktitle = {2010 IEEE Symposium on Security and Privacy},
  pages     = {305--316},
  year      = {2010},
  doi       = {10.1109/SP.2010.25}
}

@inproceedings{arp2022dos,
  author    = {Arp, Daniel and Quiring, Erwin and Pendlebury, Feargus and
               Warnecke, Alexander and Pierazzi, Fabio and
               Wressnegger, Christian and Cavallaro, Lorenzo and Rieck, Konrad},
  title     = {Dos and Don'ts of Machine Learning in Computer Security},
  booktitle = {31st USENIX Security Symposium},
  year      = {2022}
}

@inproceedings{fergusonwalter2021examining,
  author    = {Ferguson-Walter, Kimberly J. and Major, Maxine M. and
               Johnson, Chelsea K. and Muhleman, Daniel H.},
  title     = {Examining the Efficacy of Decoy-based and Psychological Cyber
               Deception},
  booktitle = {30th USENIX Security Symposium},
  year      = {2021}
}

@article{schneier1999secure,
  author  = {Schneier, Bruce and Kelsey, John},
  title   = {Secure Audit Logs to Support Computer Forensics},
  journal = {ACM Transactions on Information and System Security},
  volume  = {2},
  number  = {2},
  pages   = {159--176},
  year    = {1999},
  doi     = {10.1145/317087.317089}
}

@article{cho2020mtd,
  author  = {Cho, Jin-Hee and Sharma, Dilli P. and Alavizadeh, Hooman and
             Yoon, Seunghyun and Ben-Asher, Noam and Moore, Terrence J. and
             Kim, Dong Seong and Lim, Hyuk and Nelson, Frederica F.},
  title   = {Toward Proactive, Adaptive Defense: A Survey on Moving Target
             Defense},
  journal = {IEEE Communications Surveys \& Tutorials},
  volume  = {22},
  number  = {1},
  pages   = {709--745},
  year    = {2020},
  doi     = {10.1109/COMST.2019.2963791}
}

@article{schuirmann1987comparison,
  author  = {Schuirmann, Donald J.},
  title   = {A Comparison of the Two One-Sided Tests Procedure and the Power
             Approach for Assessing the Equivalence of Average Bioavailability},
  journal = {Journal of Pharmacokinetics and Biopharmaceutics},
  volume  = {15},
  number  = {6},
  pages   = {657--680},
  year    = {1987},
  doi     = {10.1007/BF01068419}
}
```

---

## Related documents

| Document | What it is for |
|---|---|
| [docs/NOVELTY.md](NOVELTY.md) | The contribution claims, written as arguments a reviewer can attack |
| [docs/OVERVIEW.md](OVERVIEW.md) | The whole system in plain language, with diagrams |
| [docs/PROJECT_SPEC.txt](PROJECT_SPEC.txt) | The specification — the authority on what is being built |
| [docs/SPEC_REVIEW.md](SPEC_REVIEW.md) | Gaps found in the spec while implementing it |
