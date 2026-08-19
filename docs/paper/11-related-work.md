# 11  Related Work

The pieces this paper assembles are all established; what is new is where the
decision to deceive is placed and how its parameters are set. We position the work
against seven bodies of literature: web attack detection, bot and automation
detection, honeypots and cyber deception, honeytokens, application-layer and
LLM-generated deception, probability calibration, and the decision theory the
pricing rests on.

**Web attack detection.** Signature firewalls match known-bad patterns and are
brittle to obfuscation and blind to attacks that are valid syntax, of which the
insecure direct object reference is the standard example. Learned detectors trade
the brittleness for a model, from the early anomaly-based detectors of web
requests \cite{kruegel2003anomaly,robertson2006generalization} to recent deep and
adaptive approaches \cite{tekerek2021novel,amouei2022rat}. What every one of them
shares is the passive stance: they watch a
session accumulate evidence and commit on a score. Our detector is one of these, and the
two-axis meter is not the contribution. We use a signature firewall and
the passive meter as our two honest baselines precisely because the contribution
is what we add on top of them, not a better version of them.

**Bot and automation detection.** A separate line of work asks whether a client
is a script rather than whether it is hostile, combining request-log features with
behavioural signals such as mouse movement \cite{iliou2019towards,iliou2021detection}.
Its most useful finding for us is a negative one: advanced bots imitate browser
fingerprints and human-like pacing closely enough that automation signals alone stop
separating them from people. That is precisely why our meter keeps automation and
malice on separate axes rather than collapsing them into one score. A scanner is
automated and hostile, a price-comparison bot is automated and harmless, and a
careful human attacker is neither automated nor harmless; a single score cannot
express the middle case, and it is the middle case the probe exists for.

**Honeypots and cyber deception.** Deception as a defensive strategy is well
studied, from virtual honeypot frameworks \cite{provos2004honeyd} through surveys
of the field and its game-theoretic treatments
\cite{almeshekah2014planning,han2018deception,pawlick2019taxonomy,zhu2021survey,beltran2025cyberdeception}
to the psychology of whether decoys actually change attacker behaviour
\cite{fergusonwalter2021examining,barron2017picky}. Surveys of honeypot software \cite{nawrocki2016survey,javadpour2024survey} and of
the broader proactive-defence space, including moving-target defence
\cite{cho2020mtd}, map the field. In almost all of it the deception is a
*destination*: a caught attacker is moved somewhere. The move follows a decision
that has already been made. We treat deception instead as an
instrument the detector can use while the decision is still open, which is a
different question from how to build a convincing honeypot, which this
literature has largely answered and we reuse. Fingerprinting work
\cite{vetterl2018bitter,srinivasa2020honeytoken} is a reminder that the
consistency of a decoy is not free, which motivates Section 6.

**Honeytokens and decoys.** Planting a fake credential, file, or record as a
tripwire is old and widely deployed
\cite{yuill2004honeyfiles,bowen2009baiting,juels2013honeywords}. Our baits are
honeytokens in spirit, but the literature treats them as always-on tripwires; the
question we ask is *when* to deploy one, given that deploying it is not free. The
invisibility requirement, meaning a token that changes the raw bytes but not the
rendered page, and its verification by a gate are, as far as we found, not treated as a
measured property elsewhere, though recent work on honeyfile realism and
enticingness moves in a related direction
\cite{timmer2025honeyfile,kahlhofer2024honeyquest}.

**Application-layer and LLM-generated deception.** A recent line of work embeds
deception directly in the application layer, without developer effort or with
orchestration frameworks
\cite{kahlhofer2024applayer,kahlhofer2025koney}, and another uses language models
to generate convincing interactive honeypots and to study how to evaluate them
\cite{sladic2024shellm,reworr2024llmagent,bridges2025sok,adebimpe2025sbash,vero2026honeyval}.
These are our closest neighbours, and it is worth being exact about the gap. The
application-layer survey \cite{kahlhofer2024applayer} counts nineteen technical
methods and reports that everything beyond honeypots and reverse proxies has
received little research interest, which both defines the space and says it is
nearly empty. Honeyquest \cite{kahlhofer2024honeyquest} measures how tempting a
deception technique looks, but by questionnaire, so it captures what people say
they would click rather than what they do against a live system. Koney
\cite{kahlhofer2025koney} automates the deployment, rotation and teardown of
honeytokens properly, and stops exactly where we begin: it does not decide *when*
to deploy one based on a belief about the visitor currently being served. The LLM
honeypot line is complementary rather than competing: our decoy's consistency layer
(Section 6) is generator-agnostic by design, and a language model is exactly the
kind of generator it is built to sit in front of. The consistency guarantee is what that
line of work tends to lack. Evaluation frameworks for LLM honeypots measure
stealth and fidelity \cite{vero2026honeyval} but not self-consistency over an
engagement, and self-consistency is what the Fact Notebook supplies.

**Probability calibration.** A cost-sensitive threshold is only meaningful if the
score it is applied to behaves like a probability, which is the subject of a long
line of work: logistic scaling of classifier outputs
\cite{platt1999probabilistic}, non-parametric isotonic regression
\cite{zadrozny2002transforming}, and the beta map that corrects the tails
independently \cite{kull2017beta}. We use this literature as a diagnostic rather
than a contribution. Section 9.8 reports that our hand-weighted meter is *not*
calibrated, what happens to the derived edges when it is corrected, and why the
shipped configuration nonetheless sits close to the session-level optimum. The
observation we have not found stated elsewhere is that a per-decision
cost-sensitive threshold, deployed as a first-crossing test over a whole session,
is subject to two errors of opposite sign that can partly cancel — so a rule can be
close to optimal for compensating reasons rather than correct ones.

**Value of information and cost-sensitive decisions.** The decision-theoretic
machinery we use is textbook: the expected value of sample information
\cite{howard1966information}, and cost-sensitive decision-making under a loss
matrix \cite{elkan2001foundations}, both decades old. Signalling-game models of
deception with evidence \cite{pawlick2019leaky} and the base-rate constraints on
any intrusion detector \cite{axelsson2000baserate} sit alongside them. We claim no
new decision theory. The contribution is the observation that a response-side
probe *is* a sample-information purchase, and that pricing it as one turns the
middle action from a heuristic into a derived one. Two of our claims, the priced band and
the randomised holdout that identifies the probe's causal effect, do not to our
knowledge appear together in the deception literature, and they are also the two
cheapest to defend. It is worth being precise about why. Neither is a
measurement. The band is a derivation: given the frozen cost table and a stated
β_attack, its edges follow by arithmetic a reader can redo, and Section 4 is
explicit that the decision theory underneath it is textbook rather than ours. The
holdout is an experimental design: it identifies the probe's effect by construction,
whatever magnitude that effect turns out to have. A replication could reasonably
find a smaller gain than we report; it could not find that the arithmetic gives
different edges, or that the randomisation stopped identifying what it identifies. We follow
the methodological cautions of \cite{sommer2010outside,arp2022dos} throughout the
evaluation.
