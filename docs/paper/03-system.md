# 3  System Design

The whole system sits behind a reverse proxy. Clients talk only to the proxy; the
real application never sees a request that has not passed through it, and never
knows the deception machinery exists. A single request travels the same path every
time (Fig. 1): the proxy identifies the session, extracts features from it,
updates a two-part suspicion score, prices the three actions, and takes the
cheapest — pass, bait, or divert — writing the whole decision to an append-only,
hash-chained log. What follows describes each stage; the decision itself is the
subject of Section 4.

## 3.1  Session identity

The proxy groups requests into sessions by a cookie it sets on first contact.
A client that carries the cookie is tracked cleanly. A client that refuses
cookies is, by default, given a fresh identity on each request. That is the safe
choice for measurement, because on a single host a coarse fingerprint would merge
distinct clients — but the proxy can instead link cookieless requests by
fingerprint, and Section 8 shows why: an attack tool that drops its cookie to
reset its score is defeated by exactly that switch.

## 3.2  Features and the two-axis meter

Each request is reduced to eighteen numbers, computed only from what the live
proxy can see, so that no feature depends on information a real deployment would
lack. They fall into two groups by design, because the threat model has two axes.
Ten *automation* features describe how the client behaves: inter-request timing
and its regularity, whether static assets are fetched, how complete the browser
header set is, whether a cookie is carried — the kind of signals used in web-bot
detection \cite{iliou2019towards,iliou2021detection}. Eight *malice* features describe what
the client is trying to do: the density of special characters in
client-controlled input, database-keyword hits in syntactic context, the ratio of
error responses, the number of failed authentications, and the number of distinct
accounts a session has tried to log in as.

That last feature is worth a sentence, because it is the one that separates two
sessions the earlier features could not. A user who forgets their password fails
repeatedly against a single account and then succeeds; an attacker spraying
credentials walks many accounts. Counting distinct usernames distinguishes them on
the axis that actually differs, rather than on the number of failures, which is the
same for both.

Two logistic heads, one per axis, turn the feature vector into an *automation*
score and a *malice* score, each accumulated across the session. Keeping them
separate earns its keep in two places. The cost of an action depends on hostility
alone, since a fully automated price-comparison bot is harmless, so the belief that
drives the policy is the malice score, and the automation score is spent instead
on choosing *which* probe to deploy, since a scripted scanner and a careful human
take different bait at different rates.

## 3.3  The cost policy

The policy prices the three actions under the current belief and takes the
cheapest. The prices come from a cost table that is fixed and hashed before any
data is collected, and the middle action, bait, is priced not at its immediate
cost but at that cost minus the expected value of the information the probe buys.
This is the core of the paper and Section 4 develops it in full; here it is enough
to say that the thresholds separating pass, bait and divert are never written down
as constants. They are computed from the cost table and the calibrated probe
effectiveness, and the system refuses to start if either has been altered.

## 3.4  Bait, and the gate in front of it

A bait is a token placed on a *channel* of the response, such as an HTML comment,
an unused JSON field or a fabricated error string, chosen so that a real browser
renders the response identically with and without it. Invisibility is not
asserted; it is tested. Every bait must pass an invisibility gate before it can be
used, and the gate was built before any bait existed, so that a bait carries a
certificate the policy checks at run time rather than a promise. A bait that
cannot be shown, byte-for-byte, to leave the rendered output unchanged is never
deployed.

## 3.5  The decoy and the Fact Notebook

A diverted session is moved into a decoy: a consistent fake copy of the
application, served from a separate process, in which everything the attacker does
is recorded and nothing they see is real. The decoy's hard problem is not looking
real once but *staying* consistent — a fake world that answers the same question
two different ways has given itself away. A component we call the Fact Notebook
solves this by remembering every value the decoy has ever emitted and serving the
remembered value on any later reference, so that repetition, cross-reference,
write-then-read and referential integrity all hold over an extended session.
Section 6 isolates its effect: with the notebook the decoy contradicts itself on
zero of several hundred adversarial probes; without it, on all of them.

## 3.6  Logging and reproducibility

Every decision is written to an append-only log: the features, both scores, the
action, the prices, whether a bait was injected and whether it was bitten. The log's
records are chained by hash, so that tampering is detectable after the fact. The
model that produces these decisions is frozen before evaluation: a manifest hashes
the meter, the cost table, the feature set, the bait library and the invisibility
certificates, and the system verifies the manifest at start-up. Section 7 returns
to this; it is what lets the evaluation in Section 8 replay byte-identical traffic
through every baseline.
