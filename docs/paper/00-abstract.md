# Title, abstract, keywords

**Title.** Pricing Deception: When a Web-Attack Detector Should Probe Rather Than
Decide

**Running head.** Pricing Deception

---

## Abstract

A web application firewall has to commit — allow or block — on the evidence a
single request carries, and deception is usually what happens after that
commitment: a session already judged hostile is moved into a honeypot. We treat
deception instead as a move available while the detector is still unsure. When a
session's intent is uncertain, the defence adds an invisible, inert probe to the
response — a fake table named in an error, an unused field in a JSON body, a hint
at a deprecated endpoint — that an honest client never renders and a probing one
acts on. The contribution is not the probe but the rule that decides when to
deploy it. Probing has no immediate benefit, because the request still reaches the
real application, so its entire worth is the information a bite reveals. Pricing
that worth as the expected value of sample information makes probing the
cost-optimal action over a belief band whose edges are outputs of a frozen cost
table and a measured bite likelihood ratio; under cost accounting alone the band is
empty, so there is no middle action to tune. We evaluate over 100 seeded traffic
draws against one frozen model. A randomised holdout, withholding the probe from
one session in ten at the same belief state, estimates its causal effect at +0.029
[+0.012, +0.046] (Fisher exact, p = 0.00024). Attack recall rises from 0.915 to
0.933 (paired McNemar, p < 10⁻⁴), and the entire gain sits in the one attack
subcategory where the passive detector is genuinely undecided. No benign session in
8,000 is diverted, although nine in ten are shown a probe and none acts on it.

**Keywords.** cyber deception · value of information · cost-sensitive detection ·
web application security · honeytokens · intrusion detection evaluation

---

## Notes for assembly

- Word count of the abstract above: ~250. LNCS tolerates this; trim the holdout
  sentence first if a hard 200-word limit applies.
- The three numbers a reviewer will look for are all present in order: the
  structural result (no band without the information term), the causal estimate,
  and the benign cost. Keep that order — it is the order of Sections 4, 8.3, 8.6.
- Every figure of the twelve listed in `../PAPER_OUTLINE.md` exists as PDF in
  `../img/pdf/` for the LaTeX build.
