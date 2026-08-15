# 11  Related Work

The pieces this paper assembles are all established; what is new is where the
decision to deceive is placed and how its parameters are set. We position the work
against five bodies of literature.

**Web attack detection.** Signature firewalls match known-bad patterns and are
brittle to obfuscation and blind to attacks that are valid syntax, of which the
insecure direct object reference is the standard example. Learned detectors trade
the brittleness for a model, from the early anomaly-based detectors of web
requests \cite{kruegel2003anomaly,robertson2006generalization} to recent deep and
adaptive approaches \cite{tekerek2021novel,amouei2022rat} and, most recently,
LLM-assisted semantic detection. They keep the passive stance: they watch a
session accumulate evidence and commit on a score. Our detector is one of these —
the two-axis meter is not the contribution — and we use a signature firewall and
the passive meter as our two honest baselines precisely because the contribution
is what we add on top of them, not a better version of them.

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
different question from how to build a convincing honeypot — a question this
literature has largely answered and we reuse. Fingerprinting work
\cite{vetterl2018bitter,srinivasa2020honeytoken} is a reminder that the
consistency of a decoy is not free, which motivates Section 6.

**Honeytokens and decoys.** Planting a fake credential, file, or record as a
tripwire is old and widely deployed
\cite{yuill2004honeyfiles,bowen2009baiting,juels2013honeywords}. Our baits are
honeytokens in spirit, but the literature treats them as always-on tripwires; the
question we ask is *when* to deploy one, given that deploying it is not free. The
invisibility requirement — a token that changes the raw bytes but not the rendered
page — and its verification by a gate are, as far as we found, not treated as a
measured property elsewhere, though recent work on honeyfile realism and
enticingness moves in a related direction
\cite{timmer2025honeyfile,kahlhofer2024honeyquest}.

**Application-layer and LLM-generated deception.** A recent line of work embeds
deception directly in the application layer, without developer effort or with
orchestration frameworks
\cite{kahlhofer2024applayer,kahlhofer2025koney}, and another uses language models
to generate convincing interactive honeypots and to study how to evaluate them
\cite{sladic2024shellm,reworr2024llmagent,bridges2025sok,adebimpe2025sbash,vero2026honeyval}.
This is complementary to us: our decoy's consistency layer (Section 6) is
generator-agnostic by design, and a language model is exactly the kind of
generator it is built to sit in front of. The consistency guarantee is what that
line of work tends to lack — evaluation frameworks for LLM honeypots measure
stealth and fidelity \cite{vero2026honeyval} but not self-consistency over an
engagement — and it is what the Fact Notebook supplies.

**Value of information and cost-sensitive decisions.** The decision-theoretic
machinery we use is textbook — the expected value of sample information
\cite{howard1966information}, and cost-sensitive decision-making under a loss
matrix \cite{elkan2001foundations}, both decades old. Signalling-game models of
deception with evidence \cite{pawlick2019leaky} and the base-rate constraints on
any intrusion detector \cite{axelsson2000baserate} sit alongside them. We claim no
new decision theory. The contribution is the observation that a response-side
probe *is* a sample-information purchase, and that pricing it as one turns the
middle action from a heuristic into a derived one. Two of our claims — the priced
band and the randomised holdout that identifies the probe's causal effect — do
not, to our knowledge, appear together in the deception literature, and they are
the two cheapest to defend, because one is a proof and the other is an
experimental design rather than a result that could fail to replicate. We follow
the methodological cautions of \cite{sommer2010outside,arp2022dos} throughout the
evaluation.
