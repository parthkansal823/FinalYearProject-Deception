# Title, abstract, keywords

> **SPACE 2026 is DOUBLE-BLIND.** The submitted PDF must carry no author names, no
> affiliation, no acknowledgements, and no repository URL that identifies the group.
> Refer to your own prior work in the third person. The block below is for the
> CAMERA-READY version only.

## Authors (camera-ready only)

Parth Kansal, Amrit Singh Nijjar, and Siddhant Mehta

Department of AIT-CSE,
Chandigarh University, Gharuan, Mohali, Punjab, India

<!-- Names confirmed 2026-08-19 against the project presentation and by the
     first author: "Nijjar", not "Nijjer". Roll numbers 23BIS70035, 23BIS70062,
     23BIS70162. Supervisor: Ms. Sheetal Laroiya.

     TODO before camera-ready:
     - EMAILS still to be added (one per author, institutional preferred)
     - author order is a decision the three of you make, not a formatting detail
     - ask Ms. Laroiya whether she expects to be listed as an author
-->

**Title.** Pricing Deception: When a Web-Attack Detector Should Probe Rather Than
Decide

<!-- Title is PROVISIONAL, pending a check against the registered project title.
     Alternatives considered, strongest first:
       - Pricing the Probe: A Cost-Derived Third Action for Web Attack Detection
       - From Honeypot to Probe: Pricing Deception Inside the Live Application
       - Deception as an Information Purchase: When to Probe Rather Than Decide
     Note the trade-off: putting "honeypot" in the title invites reviewers to read
     this as another honeypot paper, when the contribution is that the deception is
     NOT in a separate honeypot. "honeypot" is better placed in the keywords, where
     it still does the indexing work without setting that expectation. -->

**Running head.** Pricing Deception

---

## Abstract

A web application firewall must commit — allow or block — on the evidence a single
request carries, and deception normally happens *after* that commitment: a session
already judged hostile is moved into a honeypot. We treat deception instead as a
move available while the detector is still undecided. When intent is uncertain the
defence adds an invisible, inert probe to the response: a fake table named in an
error, an unused JSON field, a hint at a deprecated endpoint. An honest client never
renders it; a probing one acts on it. The contribution is the rule that decides when
to deploy one. Probing has no immediate benefit, since the request still reaches the
real application, so its worth is entirely the information a bite reveals. Pricing
that worth as the expected value of sample information makes probing cost-optimal
over a belief band whose edges are outputs of a frozen cost table and a measured
bite likelihood ratio; under cost accounting alone the band is empty, so there is no
middle action to tune. Over 99 seeded traffic draws against one frozen model, a
randomised holdout estimates the probe's causal effect at +0.070 [+0.052, +0.088]
(Fisher exact, p = 3.4 × 10⁻¹⁹), and recall rises from 0.889 to 0.943 (paired
McNemar, p = 1.9 × 10⁻⁹⁵), concentrated in the one subcategory where the passive
detector is undecided. None of 7,920 benign sessions is diverted, and of the 90%
that were shown a probe, none acted on it. Against the OWASP ModSecurity Core Rule
Set on the same traffic, a signature ruleset reaches 0.54 at settings that leave
benign traffic alone, and 1.00 only by blocking 30% of legitimate sessions. Two
results test the parts a cost model cannot: a consistency layer holds the decoy's
story together over 286 adversarial probes, against a 100% contradiction rate
without it; and an autonomous language-model attacker, told nothing about the
probes, takes them at a rate that falls inside the range we had measured for the
scripted adversary the calibration assumed. We further show that self-consistency
is the wrong estimand for a decoy an attacker is *moved into*, and measure
consistency across the divert itself — zero contradictions over 4,600 fields,
against 90.8% when the mechanism is disabled.

**Keywords.** cyber deception · honeypots · value of information · cost-sensitive
detection · web application security · honeytokens · agentic attackers ·
intrusion detection evaluation

---
