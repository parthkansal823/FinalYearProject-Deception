# 3  System Design

The whole system sits behind a reverse proxy. Clients talk only to the proxy; the
real application never sees a request that has not passed through it, and never
knows the deception machinery exists. A single request travels the same path every
time (Fig. 1): the proxy identifies the session, extracts features from it,
updates a two-part suspicion score, prices the three actions, and takes the
cheapest — pass, bait, or divert — writing the whole decision to an append-only,
hash-chained log. What follows describes each stage; the decision itself is the
subject of Section 4.

Written out, one request is:

```
on request r:
    sid   <- session_id(r)                     # cookie, or fingerprint fallback
    x     <- extract_features(sid, r)          # 18 numbers, live-observable only
    a, m  <- meter(x)                          # automation and malice, in [0,1]

    if r carries a token this session was shown:
        m <- sigmoid( logit(m) + log LR_bite ) # manufactured evidence, Section 5

    p     <- sigmoid( b0 + w_m*logit(m) + w_a*logit(a) )    # w_a = 0 by default
    act   <- policy(p, applicable_baits, exposures)         # Section 4
    resp  <- upstream(r)  if act != divert  else  decoy(r)
    if act == bait:
        resp <- inject(select_bait(a, suspected_categories), resp)
    log(x, a, m, p, act, prices, bait_id, bite)
    return resp
```

Every quantity in that loop is defined in the sections that follow: the features
and the two scores here, the policy and its prices in Section 4, and the
likelihood ratio in Section 5.

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

A bait is a token placed on a *channel* of the response — an HTML comment, an
unused JSON field, a fabricated error string — chosen so that a real browser renders
the response identically with and without it. Invisibility is not asserted; it is
tested, by a gate that was written before any bait existed so that it could not be
shaped around one.

The gate takes a candidate bait and a corpus of clean benign responses and runs four
checks. It refuses a bait that applies to *none* of the corpus, because a bait that
cannot be exercised cannot be verified. For each response it can inject into, it
compares the rendered output before and after: for HTML, the visible text, the forms
and the links must be identical, and for JSON the baited body must still parse. It
times the injection and requires the median added latency to stay under half a
millisecond, so that a client cannot separate a baited response from a clean one by
the clock; across the five baits in the shipped library the worst median is 0.32 ms.
A bait that fails any of these never enters the library.

What comes out is a certificate — which bait, how many responses it was tested
against, how many it could be injected into, the median and 95th-percentile
overhead, and when the test ran. The certificate is hashed into the frozen manifest
and the policy checks it at run time, so a bait cannot be edited after it was
verified and quietly keep its licence to deploy.

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

The decoy also carries one deliberate plant of its own. In a configuration file a
determined explorer would eventually reach sits a fake API key, derived from the
deployment seed so that it is stable within a run and reproducible across runs but
is not a constant anyone could publish. The key grants nothing. Its only function is
that the system watches for it: if it ever appears in a later request, three things
are established at once — that the attacker explored the decoy deeply, that they
harvested credentials from it, and that they tried to use what they harvested. That
turns the log from a record of what an attacker clicked into a record of what they
intended, which is the difference between an incident trace and threat
intelligence.

## 3.6  Logging and reproducibility

Every decision is written to an append-only log: the features, both scores, the
action, the prices, whether a bait was injected and whether it was bitten. The log's
records are chained by hash, so that tampering is detectable after the fact.

One property of that path is worth stating because it decides how the system behaves
on its worst day. Scoring, pricing and injection all sit between the client and the
real application, so a fault in any of them is a fault in front of production
traffic. The proxy therefore **fails open**: if the feature extractor, the meter or
the policy raises, the request is served normally, the fault is recorded in the log
with the decision marked as failed-open, and no session is diverted on the strength
of a component that did not run. The alternative — failing closed — would turn a
defect in the detector into an outage for legitimate users, which is a worse failure
than missing an attack, and the cost table already says so. The behaviour is pinned
by tests that break each of the three components in turn and assert the request is
still served. The
model that produces these decisions is frozen before evaluation: a manifest hashes
the meter, the cost table, the feature set, the bait library and the invisibility
certificates, and the system verifies the manifest at start-up. Section 7 returns
to this; it is what lets the evaluation in Section 8 replay byte-identical traffic
through every baseline.
