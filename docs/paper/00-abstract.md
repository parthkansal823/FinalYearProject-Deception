# Title, abstract, keywords

> **SPACE 2026 is DOUBLE-BLIND.** The submitted PDF must carry no author names, no
> affiliation, no acknowledgements, and no repository URL that identifies the group.
> Refer to your own prior work in the third person. The block below is for the
> CAMERA-READY version only.

## Authors (camera-ready only)

Parth Kansal, Amrit Singh Nijjer, and Siddhant Suyog Mehta

Department of Computer Science and Engineering,
Chandigarh University, Punjab, India

<!-- TODO before camera-ready:
     - EMAILS still to be added (one per author, institutional preferred)
     - confirm the spelling of every author name; a published name cannot be fixed
     - author order is a decision the three of you make, not a formatting detail
     - ask the supervisor whether they expect to be listed as an author
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

A web application firewall must commit, allow or block, on the evidence a single
request carries, and deception normally happens *after* that commitment: a session
already judged hostile is moved into a honeypot. We treat deception instead as a
move available while the detector is still undecided. When intent is uncertain, the
defence adds an invisible, inert probe to the response: a fake table named in an
error, an unused JSON field, a hint at a deprecated endpoint. An honest client never
renders it; a probing one acts on it. The contribution is the rule that
decides when to deploy one. Probing has no immediate benefit, since the request
still reaches the real application, so its worth is entirely the information a bite
reveals. Pricing that worth as the expected value of sample information makes
probing cost-optimal over a belief band whose edges are outputs of a frozen cost
table and a measured bite likelihood ratio; under cost accounting alone the band is
empty, so there is no middle action to tune. Over 100 seeded traffic draws against
one frozen model, a randomised holdout estimates the probe's causal effect at +0.051
[+0.034, +0.068] (Fisher exact, p < 10⁻⁵), and recall rises from 0.917 to 0.951
(paired McNemar, p < 10⁻⁴), concentrated in the one subcategory where the passive
detector is undecided. None of 7,920 benign sessions is diverted.

**Keywords.** cyber deception · honeypots · value of information · cost-sensitive detection ·
web application security · honeytokens · intrusion detection evaluation

---
