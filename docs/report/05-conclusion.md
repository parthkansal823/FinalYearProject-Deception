# CHAPTER 5

# CONCLUSION AND FUTURE WORK

## 5.1 Conclusion

The objective of this project was to address a structural weakness in web attack
detection that cannot be fixed by improving the classifier. A web application firewall
must commit to allowing or blocking a session using only the evidence that arrives on
its own. In the region where the detector is genuinely uncertain — which is precisely
where valid-syntax attacks such as insecure direct object references live — neither
action is defensible, and the detector has no mechanism by which it could *acquire*
the evidence that would let it decide correctly.

The project's answer is to give the detector a **third action** and, more importantly,
to derive rather than tune the rule that governs it. When the belief that a session is
hostile is neither low enough to ignore nor high enough to act on, the framework adds
an invisible, inert **probe** to the response — a fake table name inside a database
error, an unused field in a JSON reply, a hint at a deprecated endpoint. A real
browser never renders any of it. A client reading raw traffic and probing the
application will act on it, and the moment it does, it has identified itself.

The contribution is not the probe but the pricing. Probing has no immediate benefit,
because the request still reaches the real application; its entire worth is the
information a bite would reveal. Modelling that worth as the **expected value of
sample information** [32] makes probing the cost-optimal action over a belief band
whose two edges are *outputs* of a frozen cost table and a measured bite likelihood
ratio. The strongest structural result in the report is a negative one: under cost
accounting alone, `E[C(bait)] − E[C(pass)] = 1 − p > 0` for every belief short of
certainty, so **the middle band is empty**. The third action cannot be reproduced by
tuning a threshold, because there is no threshold to tune — the region does not exist
until information is priced.

The evaluation supports the mechanism rather than a headline number.

- A **randomised holdout inside the treated arm** — the probe withheld from about one
  session in ten at the same belief state — estimates the probe's causal effect at
  **+0.070 [+0.052, +0.088]**, Fisher exact **p = 3.4 × 10⁻¹⁹**, with the treated and
  control groups verified balanced across attack subcategories (χ² = 2.58 on 4 df).
- Attack recall rises from **0.889** to **0.943** over 11,880 matched pairs, exact
  paired McNemar **p = 1.9 × 10⁻⁹⁵**, with the full system ahead in **99 of 99 seeds**.
- The gain is not distributed but **concentrated**: **+0.282** in user-interface
  object-reference attacks, and +0.022 or less everywhere else. This is exactly what
  the theory predicts — the probe helps only where the passive detector is genuinely
  uncertain, and a probe that raised recall everywhere would indicate a weak meter
  rather than correct pricing.
- **None of 7,920 benign sessions is diverted**, and of the **7,098 benign sessions
  shown a probe — 89.6 % — not one acted on it.**
- Against the **OWASP ModSecurity Core Rule Set** replayed on identical traffic, a
  real signature ruleset reaches 0.544 at settings that leave benign users alone, and
  1.000 only by blocking 30 % of legitimate sessions.

Two results test the parts a cost model cannot reach. A write-once **Fact Notebook**
holds the decoy's story together over 286 adversarial probes at a **0 %** contradiction
rate against **100 %** without it, and the same ablation with a language model behind
the same seam gives 0 against 15 of 15 — establishing that the consistency property
belongs to the store rather than to the generator. And an **autonomous language-model
attacker**, told nothing about bait and choosing its own requests, takes probes at a
rate (0.556) whose interval falls inside the range measured for the scripted adversary
the calibration assumed.

An unanticipated safety property fell out of the arithmetic and deserves the last
word. Introducing the probe raised the divert threshold from the cost-only boundary of
0.8163 to **0.8793**, because a defender with a cheap way to resolve uncertainty need
not gamble. Benign belief ceilings on this corpus top out at 0.829. The derived edge
therefore clears the entire benign belief distribution **by construction** rather than
by tuning, and that is what buys the zero-benign-diversion result. A system that can
probe is *more* reluctant to divert an honest user than the same system without one.

If a reader remembers one thing from this report, it should be that last point stated
generally: **without the information term there is no third action at all**, so the
middle option cannot be a tuned threshold. It is priced.

## 5.2 Deviation from Expected Results

Several results deviated from what was expected. Two of them were failures of
pre-stated success criteria, and both produced more useful findings than success would
have.

### 5.2.1 The derived edges did not beat hand-set edges on expected cost

**Expected:** that deriving the band edges from the cost table would produce a
configuration that dominates hand-set thresholds on expected cost.

**Observed:** it does not. Three hand-set configurations achieve lower cost per
session than the derived pair (Table 24).

**Why, and what it actually means.** The analysis is more informative than the
expectation would have been. First, **the gap is benign nuisance baiting, not
detection**: the derived arm shows a probe to 89 % of benign sessions against 65 % for
the arms that beat it, at one unit each, and that difference is most of the cost gap.
Second, **the edge is not choosing a value; it is choosing a side.** The belief takes
only a handful of distinct values, two of which account for 56 % of every decision the
policy makes (0.163 and 0.476). The measured benign-bait rates are 0.897, 0.896 and
0.903 for the three arms whose edge falls below 0.163, against **0.650, 0.650 and
0.650** for the three above it — identical to three decimal places even though that
group's lower edge runs from 0.187 to 0.300. Four decimal places of derived precision
are not doing the work their precision suggests. Third, **every configuration that
beats the derived pair on cost does so by diverting benign users** (3, 3 and 46
sessions). Among the configurations that divert none, the derived edges are the best
available.

The revised claim is narrower and more defensible: the derivation buys a *placement
that clears the benign belief distribution by construction*, not a superiority on
aggregate cost.

### 5.2.2 The belief is not calibrated

**Expected:** that a hand-weighted meter would be approximately calibrated, so that
thresholds on it would land where the derivation intends.

**Observed:** held-out expected calibration error is **0.157**, against 0.018 for an
isotonic map fitted on data that cannot reach any reported number. The meter is
over-confident below about 0.6 and under-confident above it, with the sign of the gap
flipping around 0.6.

**Why it matters, and the finding it produced.** Calibrating gives the best recall of
anything measured — 0.979 against 0.940, with 245 attack sessions caught by the
calibrated policy alone against 21 by the shipped one (p = 1.3 × 10⁻⁴⁹) — but costs
the zero-benign-diversion property, diverting 81 of 3,840. Under the frozen cost table
that decides it: the break-even price of a benign diversion is 137 and the table,
written before any data existed, prices it at 200. The calibrated policy is a better
*detector* and a worse *policy under this cost table*, and which of those is "the
improvement" is a question the cost table answers rather than the data.

The third reading is the most useful and was not anticipated at all. **Two modelling
errors are present and they point in opposite directions.** The belief is
under-confident at the top, which pushes the operating edge higher on the raw scale
than the cost model intends; and the rule is derived for a single decision but deployed
as a first-crossing test over a whole session, which puts the cost-optimal edge higher
still. The shipped configuration sits close to the session-level optimum **because
those two errors very nearly cancel.** Correcting either alone moves it away. A rule
that is right for compensating reasons is a different object from a rule that is right,
and this report states which one it has.

### 5.2.3 The corpus was easier than intended

**Expected:** that the attack and benign corpora differed in hostility.

**Observed:** they also differed in a property of the *generators*. The attack
generator spoke raw HTTP and never fetched a page sub-resource; the benign generator
fetched them like a browser. A logistic regression on the automation features alone
separated the two populations at an out-of-sample **AUC of 0.9935** — on script
behaviour, not on hostility.

**Response.** No reported number was contaminated, because automation carries weight
zero in the hostility belief and this was verified against the logs rather than the
configuration. But the corpus was easier than reality, so half the attackers now drive
a browser; the automation-only figure falls to 0.898, every arm loses recall, and the
probe's contribution **rises** from +0.034 to +0.054. All numbers in this report are
the harder ones. A pinned-parameter control confirms the attribution: setting the
browser fraction to zero on the current frozen model reproduces the pre-browser figures
to within 0.005 on every arm.

### 5.2.4 The auth probe appeared ineffective, and was not

**Expected:** that all five baits would show measurable bite rates.

**Observed:** the authentication probe initially measured 0.000.

**Response.** The round-1 attacker never read response bodies, so a probe planted in a
failure page was **unreachable by construction** rather than ineffective. Against an
otherwise identical attacker that reads bodies, the bite rate rises from 0.000 to 0.950
and the divert rate with it. This relocated the limitation from the defence to the
attacker model, and the headline arms are still reported against the response-reading
population rather than the more favourable one.

### 5.2.5 The agentic measurement was nearly wrong three times

**Expected:** that measuring an autonomous LLM attacker would be a straightforward
addition.

**Observed:** three independent harness defects each produced a confident, plausible,
wrong number, and none raised an error. The response was truncated before the probe
(0.000); the agent had no structured way to submit a parameter (0.000 across all three
models, while being shown *more* probes than in the corrected runs); and the prompt
enumerated the planted channels and used a real bait token as its example (0.650 and
1.000). The corrected measurement is 0.050 and 0.300 unconditionally.

**Response.** All four conditions are reported side by side (Table 30), because the
lesson generalises: an agentic evaluation can be wrong in **both directions** while
every number in it looks plausible. Harness adjustment was stopped at the point where
the remaining failures were the model's rather than ours; continuing would have been
coaching rather than measurement.

## 5.3 Future Work (Way Ahead)

### 5.3.1 Derive the rule for the sequential decision it actually makes

This is the most important theoretical gap and the project's own analysis exposed it.
The current rule is derived for a **single decision** at a given belief, but it is
deployed as a **first-crossing test over a whole session**: the session diverts the
first time the belief crosses the edge, and the policy is invoked many times per
session. These are different decision problems, and their optimal thresholds differ.

Deriving the band for the sequential problem — as an optimal stopping problem over the
belief trajectory rather than a one-shot comparison — would remove one of the two
compensating errors identified in §5.2.2, and would allow a calibrated belief to be
*adopted* rather than merely measured. This is the single most valuable extension of
the work.

### 5.3.2 Adopt calibration once the sequential rule exists

With the sequential derivation in place, an isotonic-calibrated belief [42] becomes
usable rather than merely better on paper. The measured gain is substantial — 0.940 to
0.979 recall — and the reason it is not adopted here is entirely the interaction with
the frozen cost table, not the calibration itself.

### 5.3.3 A human-participant deception study

The deception is currently assessed by the researchers and a consistency fuzzer.
Whether a human attacker *feels* that something is off is not measured, and it is the
single most valuable empirical gap. A block-randomised study in which participants
explore either the real application or the decoy, without being told the study concerns
deception, and are asked afterwards whether anything felt wrong, would bound this
directly. The protocol is designed and the analysis pre-specified; only the
participants remain. The comparison of interest is not whether anyone says "felt fake"
but whether the *rate* differs between the two groups.

### 5.3.4 Replay a public labelled corpus

Replaying CSIC 2010 [27] would bound the passive half of the system against traffic the
project did not generate, and would directly address the synthetic-traffic limitation.
It cannot exercise the probe — a recorded request log contains no responses for an
attacker to react to — but it would make the passive baseline's numbers comparable
against published work.

### 5.3.5 A second full deployment with a matched decoy

Transfer was checked against OWASP Juice Shop in a passive configuration. A complete
evaluation on a second application, with a decoy matched to *that* application and the
app-specific features re-pointed, would establish how much of the framework is
genuinely app-agnostic.

### 5.3.6 Learned bait selection

Bait selection currently maximises the survival-discounted value of information over
applicable baits. A contextual-bandit formulation would let the system learn which
bait works against which attacker profile, using the automation axis — which is
deliberately excluded from the hostility belief — as context. The exploration/
exploitation trade-off is well matched to the setting, since a bait that is never
deployed is never re-calibrated.

### 5.3.7 Stronger invisibility guarantees

The timing criterion is a threshold on the median rather than a formal equivalence
test. A two-one-sided-tests procedure [40] against a pre-registered margin would be the
stronger claim. Extending the gate to cover response-size distributions and header
ordering would close the remaining fingerprinting surfaces identified by [10] and [20].

### 5.3.8 Adaptive and continuously recalibrated bite rates

The bite rates β_attack and β_benign are measured once in a calibration round and then
frozen. In a live deployment they would drift as attacker populations change. A
mechanism that re-estimates them from observed bites — while preserving the freeze
discipline through explicit, dated re-freezes rather than silent updates — would keep
the derivation honest over time.

### 5.3.9 Integration with production identity and policy infrastructure

The framework is a reverse proxy and is deliberately independent of any identity
provider. Integrating the diversion decision with policy engines and identity systems
would let the framework contribute a risk signal to a wider Zero Trust architecture
[52] rather than acting alone.

### 5.3.10 Privacy-preserving deployment

Since the framework observes behaviour, a deployment in a regulated environment would
benefit from federated estimation of the meter's weights, keeping per-user behavioural
data on the serving node and sharing only model updates.

## 5.4 Final Remarks

This project began from a narrow observation — that a two-action detector has nothing
useful to do in the region where it is most uncertain — and ended with a framework in
which deception is an instrument of the decision rather than a consequence of it.

The result the authors consider most durable is not the recall figure. It is the
structural fact that **under cost accounting alone the middle band is empty**, and
therefore that a priced third action is a genuinely different object from a tuned
threshold. Everything else in the report follows from taking that seriously: the
derived edges, the causal holdout that measures what the probe actually contributes,
the frozen cost table that decides the calibration question rather than letting the
results decide it, and the safety property that emerged from the arithmetic rather than
from design.

What the study cannot claim is bounded by its setting: synthetic traffic, a single
tuned application, one laboratory. The parts meant to outlast that setting are not
measurements but a derivation, a design and a structural property — the priced band,
which follows by arithmetic from a frozen cost table; the randomised treatment, which
identifies the probe's effect whatever its size; and the convergence to passive
detection under an adaptive adversary, which is a property of the survival discount
rather than a result about this target.

The report has also tried to be useful about its own failures. Two pre-stated success
criteria were not met and are reported as such. A corpus artefact that would have
flattered the automation axis was found by asking what a classifier could separate the
corpus on, and the corpus was made harder rather than the finding softened. An agentic
measurement was wrong three times in two directions before it was right. These are
included because a security evaluation that hides its near-misses is worth less than
one that reports them, and because the guards added in response are, in the authors'
view, as much a part of the contribution as the headline number.

## 5.5 References

**Verification note.** References [1]–[43] are the entries used in the associated
research paper; the twelve highest-risk entries (2024–2026 publications and preprints)
were each verified individually against publisher or arXiv records, and the remainder
against DBLP or publisher pages. References [44]–[58] are classical and standards
works added for this report; their metadata should be re-confirmed against a publisher
record before final submission rather than accepted from this list.

### Deception: theory and surveys

[1] M. H. Almeshekah and E. H. Spafford, "Planning and Integrating Deception into Computer Security Defenses," in *Proc. 2014 New Security Paradigms Workshop (NSPW '14)*, ACM, 2014, pp. 127–138. doi: 10.1145/2683467.2683482.

[2] X. Han, N. Kheir, and D. Balzarotti, "Deception Techniques in Computer Security: A Research Perspective," *ACM Computing Surveys*, vol. 51, no. 4, art. 80, 2018. doi: 10.1145/3214305.

[3] J. Pawlick, E. Colbert, and Q. Zhu, "A Game-theoretic Taxonomy and Survey of Defensive Deception for Cybersecurity and Privacy," *ACM Computing Surveys*, vol. 52, no. 4, art. 82, 2019. doi: 10.1145/3337772.

[4] M. Zhu, A. H. Anwar, Z. Wan, J.-H. Cho, C. A. Kamhoua, and M. P. Singh, "A Survey of Defensive Deception: Approaches Using Game Theory and Machine Learning," *IEEE Communications Surveys & Tutorials*, vol. 23, no. 4, pp. 2460–2493, 2021. doi: 10.1109/COMST.2021.3102874.

[5] P. Beltrán-López, M. Gil Pérez, and P. Nespoli, "Cyber Deception: Taxonomy, State of the Art, Frameworks, Trends, and Open Challenges," *IEEE Communications Surveys & Tutorials*, vol. 28, pp. 1520–1556, 2026. doi: 10.1109/COMST.2025.3594788.

### Honeypots

[6] N. Provos, "A Virtual Honeypot Framework," in *Proc. 13th USENIX Security Symposium*, San Diego, CA, USA, 2004, pp. 1–14.

[7] M. Nawrocki, M. Wählisch, T. C. Schmidt, C. Keil, and J. Schönfelder, "A Survey on Honeypot Software and Data Analysis," arXiv:1608.06249, 2016.

[8] A. Javadpour, F. Ja'fari, T. Taleb, M. Shojafar, and C. Benzaïd, "A comprehensive survey on cyber deception techniques to improve honeypot performance," *Computers & Security*, vol. 140, art. 103792, 2024. doi: 10.1016/j.cose.2024.103792.

[9] T. Barron and N. Nikiforakis, "Picky Attackers: Quantifying the Role of System Properties on Intruder Behavior," in *Proc. 33rd Annual Computer Security Applications Conference (ACSAC '17)*, ACM, 2017, pp. 387–398. doi: 10.1145/3134600.3134614.

[10] A. Vetterl and R. Clayton, "Bitter harvest: systematically fingerprinting low- and medium-interaction honeypots at internet scale," in *Proc. 12th USENIX Workshop on Offensive Technologies (WOOT '18)*, 2018.

[11] J.-H. Cho, D. P. Sharma, H. Alavizadeh, S. Yoon, N. Ben-Asher, T. J. Moore, D. S. Kim, H. Lim, and F. F. Nelson, "Toward Proactive, Adaptive Defense: A Survey on Moving Target Defense," *IEEE Communications Surveys & Tutorials*, vol. 22, no. 1, pp. 709–745, 2020. doi: 10.1109/COMST.2019.2963791.

### LLM-based honeypots

[12] M. Sladić, V. Valeros, C. Catania, and S. Garcia, "LLM in the Shell: Generative Honeypots," in *2024 IEEE European Symposium on Security and Privacy Workshops (EuroS&PW)*, 2024, pp. 430–435. doi: 10.1109/EuroSPW61312.2024.00054.

[13] Reworr and D. Volkov, "LLM Agent Honeypot: Monitoring AI Hacking Agents in the Wild," arXiv:2410.13919, 2025.

[14] R. A. Bridges, T. R. Mitchell, M. Muñoz, and T. Henriksson, "SoK: Honeypots & LLMs, More Than the Sum of Their Parts?," in *2026 IEEE 11th European Symposium on Security and Privacy (EuroS&P)*, 2026, pp. 910–928. doi: 10.1109/EuroSP68448.2026.00063.

[15] M. Vero, F. Kaczmarczyck, I. Petrov, I. Shumailov, J. Hayes, N. Heinen, T. Fan, L. Invernizzi, and M. Vechev, "Honeyval: A Comprehensive Evaluation Framework for LLM-powered HTTP Honeypots," arXiv:2605.29963, 2026.

[16] A. Adebimpe, H. Neukirchen, and T. Welsh, "SBASH: a Framework for Designing and Evaluating RAG vs. Prompt-Tuned LLM Honeypots," in *2025 3rd International Conference on Foundation and Large Language Models (FLLM)*, IEEE, 2025, pp. 851–856.

### Honeytokens, decoys and bait

[17] J. Yuill, M. Zappe, D. Denning, and F. Feer, "Honeyfiles: deceptive files for intrusion detection," in *Proc. Fifth Annual IEEE SMC Information Assurance Workshop*, 2004, pp. 116–122. doi: 10.1109/IAW.2004.1437806.

[18] B. M. Bowen, S. Hershkop, A. D. Keromytis, and S. J. Stolfo, "Baiting Inside Attackers Using Decoy Documents," in *Security and Privacy in Communication Networks (SecureComm)*, Springer, 2009, pp. 51–70.

[19] A. Juels and R. L. Rivest, "Honeywords: making password-cracking detectable," in *Proc. 2013 ACM SIGSAC Conference on Computer & Communications Security (CCS '13)*, 2013, pp. 145–160. doi: 10.1145/2508859.2516671.

[20] S. Srinivasa, J. M. Pedersen, and E. Vasilomanolakis, "Towards systematic honeytoken fingerprinting," in *Proc. 13th International Conference on Security of Information and Networks (SIN 2020)*, ACM, 2021, art. 28. doi: 10.1145/3433174.3433599.

[21] R. Timmer, D. Liebowitz, S. Nepal, and S. Kanhere, "Evaluating Honeyfile Realism and Enticement Metrics," *ACM Transactions on Privacy and Security*, vol. 28, no. 4, art. 54, 2025. doi: 10.1145/3763792.

### Application-layer deception

[22] M. Kahlhofer and S. Rass, "Application Layer Cyber Deception Without Developer Interaction," in *2024 IEEE European Symposium on Security and Privacy Workshops (EuroS&PW)*, 2024, pp. 416–429. doi: 10.1109/EuroSPW61312.2024.00053.

[23] M. Kahlhofer, S. Achleitner, S. Rass, and R. Mayrhofer, "Honeyquest: Rapidly Measuring the Enticingness of Cyber Deception Techniques with Code-based Questionnaires," in *Proc. 27th International Symposium on Research in Attacks, Intrusions and Defenses (RAID '24)*, ACM, 2024, pp. 317–336. doi: 10.1145/3678890.3678897.

[24] M. Kahlhofer, M. Golinelli, and S. Rass, "Koney: A Cyber Deception Orchestration Framework for Kubernetes," in *2025 IEEE European Symposium on Security and Privacy Workshops (EuroS&PW)*, 2025, pp. 690–702. doi: 10.1109/EuroSPW67616.2025.00084.

### Web attack detection and web application firewalls

[25] C. Kruegel and G. Vigna, "Anomaly Detection of Web-based Attacks," in *Proc. 10th ACM Conference on Computer and Communications Security (CCS '03)*, 2003, pp. 251–261. doi: 10.1145/948109.948144.

[26] W. Robertson, G. Vigna, C. Kruegel, and R. A. Kemmerer, "Using generalization and characterization techniques in the anomaly-based detection of web attacks," in *Proc. Network and Distributed System Security Symposium (NDSS)*, 2006.

[27] C. Torrano-Giménez, A. Pérez-Villegas, and G. Álvarez-Marañón, "HTTP DATASET CSIC 2010," Information Security Institute, Spanish Research National Council (CSIC), 2010.

[28] A. Tekerek, "A novel architecture for web-based attack detection using convolutional neural network," *Computers & Security*, vol. 100, art. 102096, 2021. doi: 10.1016/j.cose.2020.102096.

[29] M. Amouei, M. Rezvani, and M. Fateh, "RAT: Reinforcement-Learning-Driven and Adaptive Testing for Vulnerability Discovery in Web Application Firewalls," *IEEE Transactions on Dependable and Secure Computing*, vol. 19, no. 5, pp. 3371–3386, 2022. doi: 10.1109/TDSC.2021.3095417.

### Bot and automation detection

[30] C. Iliou, T. Kostoulas, T. Tsikrika, V. Katos, S. Vrochidis, and Y. Kompatsiaris, "Towards a framework for detecting advanced Web bots," in *Proc. 14th International Conference on Availability, Reliability and Security (ARES '19)*, ACM, 2019, art. 18. doi: 10.1145/3339252.3339267.

[31] C. Iliou, T. Kostoulas, T. Tsikrika, V. Katos, S. Vrochidis, and I. Kompatsiaris, "Detection of Advanced Web Bots by Combining Web Logs with Mouse Behavioural Biometrics," *Digital Threats: Research and Practice*, vol. 2, no. 3, art. 24, 2021. doi: 10.1145/3447815.

### Decision theory and cost-sensitive learning

[32] R. A. Howard, "Information Value Theory," *IEEE Transactions on Systems Science and Cybernetics*, vol. 2, no. 1, pp. 22–26, 1966. doi: 10.1109/TSSC.1966.300074.

[33] C. Elkan, "The foundations of cost-sensitive learning," in *Proc. 17th International Joint Conference on Artificial Intelligence (IJCAI '01)*, Morgan Kaufmann, 2001, pp. 973–978.

[34] J. Pawlick, E. Colbert, and Q. Zhu, "Modeling and Analysis of Leaky Deception Using Signaling Games With Evidence," *IEEE Transactions on Information Forensics and Security*, vol. 14, no. 7, pp. 1871–1886, 2019. doi: 10.1109/TIFS.2018.2886472.

[35] S. Axelsson, "The base-rate fallacy and the difficulty of intrusion detection," *ACM Transactions on Information and System Security*, vol. 3, no. 3, pp. 186–205, 2000. doi: 10.1145/357830.357849.

### Evaluation methodology in security machine learning

[36] R. Sommer and V. Paxson, "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection," in *2010 IEEE Symposium on Security and Privacy*, 2010, pp. 305–316. doi: 10.1109/SP.2010.25.

[37] D. Arp, E. Quiring, F. Pendlebury, A. Warnecke, F. Pierazzi, C. Wressnegger, L. Cavallaro, and K. Rieck, "Dos and Don'ts of Machine Learning in Computer Security," in *Proc. 31st USENIX Security Symposium*, Boston, MA, USA, 2022, pp. 3971–3988.

[38] K. J. Ferguson-Walter, M. M. Major, C. K. Johnson, and D. H. Muhleman, "Examining the Efficacy of Decoy-based and Psychological Cyber Deception," in *Proc. 30th USENIX Security Symposium*, 2021, pp. 1127–1144.

### Supporting work

[39] B. Schneier and J. Kelsey, "Secure audit logs to support computer forensics," *ACM Transactions on Information and System Security*, vol. 2, no. 2, pp. 159–176, 1999. doi: 10.1145/317087.317089.

[40] D. J. Schuirmann, "A comparison of the two one-sided tests procedure and the power approach for assessing the equivalence of average bioavailability," *Journal of Pharmacokinetics and Biopharmaceutics*, vol. 15, no. 6, pp. 657–680, 1987.

[41] J. C. Platt, "Probabilistic Outputs for Support Vector Machines and Comparisons to Regularized Likelihood Methods," in *Advances in Large Margin Classifiers*, MIT Press, 1999, pp. 61–74.

[42] B. Zadrozny and C. Elkan, "Transforming classifier scores into accurate multiclass probability estimates," in *Proc. Eighth ACM SIGKDD International Conference on Knowledge Discovery and Data Mining (KDD '02)*, 2002, pp. 694–699. doi: 10.1145/775047.775151.

[43] M. Kull, T. S. Filho, and P. Flach, "Beta calibration: a well-founded and easily implemented improvement on logistic calibration for binary classifiers," in *Proc. 20th International Conference on Artificial Intelligence and Statistics (AISTATS)*, PMLR vol. 54, 2017, pp. 623–631.

### Additional references (classical, statistical and standards works)

[44] E. B. Wilson, "Probable Inference, the Law of Succession, and Statistical Inference," *Journal of the American Statistical Association*, vol. 22, no. 158, pp. 209–212, 1927.

[45] Q. McNemar, "Note on the sampling error of the difference between correlated proportions or percentages," *Psychometrika*, vol. 12, no. 2, pp. 153–157, 1947.

[46] R. A. Fisher, "On the Interpretation of χ² from Contingency Tables, and the Calculation of P," *Journal of the Royal Statistical Society*, vol. 85, no. 1, pp. 87–94, 1922.

[47] H. Jeffreys, "An Invariant Form for the Prior Probability in Estimation Problems," *Proceedings of the Royal Society of London A*, vol. 186, no. 1007, pp. 453–461, 1946.

[48] G. W. Brier, "Verification of Forecasts Expressed in Terms of Probability," *Monthly Weather Review*, vol. 78, no. 1, pp. 1–3, 1950.

[49] B. Efron, "Bootstrap Methods: Another Look at the Jackknife," *The Annals of Statistics*, vol. 7, no. 1, pp. 1–26, 1979.

[50] B. Efron and R. J. Tibshirani, *An Introduction to the Bootstrap*. New York, NY, USA: Chapman & Hall, 1993.

[51] T. Hastie, R. Tibshirani, and J. Friedman, *The Elements of Statistical Learning: Data Mining, Inference, and Prediction*, 2nd ed. New York, NY, USA: Springer, 2009.

[52] C. M. Bishop, *Pattern Recognition and Machine Learning*. New York, NY, USA: Springer, 2006.

[53] S. Rose, O. Borchert, S. Mitchell, and S. Connelly, "Zero Trust Architecture," NIST Special Publication 800-207, National Institute of Standards and Technology, 2020.

[54] K. Scarfone and P. Mell, "Guide to Intrusion Detection and Prevention Systems (IDPS)," NIST Special Publication 800-94, National Institute of Standards and Technology, 2007.

[55] L. Spitzner, *Honeypots: Tracking Hackers*. Boston, MA, USA: Addison-Wesley, 2002.

[56] B. Cheswick, "An Evening with Berferd in Which a Cracker is Lured, Endured, and Studied," in *Proc. Winter USENIX Conference*, San Francisco, CA, USA, 1992.

[57] C. Stoll, *The Cuckoo's Egg: Tracking a Spy Through the Maze of Computer Espionage*. New York, NY, USA: Doubleday, 1989.

[58] OWASP Foundation, "OWASP Top 10:2021 — The Ten Most Critical Web Application Security Risks," 2021. [Online]. Available: https://owasp.org/Top10/

[59] OWASP Foundation, "OWASP ModSecurity Core Rule Set (CRS)," 2024. [Online]. Available: https://coreruleset.org/

[60] R. Fielding and J. Reschke, "Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content," RFC 7231, Internet Engineering Task Force, 2014.
