# 4  The Decision Rule
## 4.1  Setup: a three-action cost problem

At each point in a session the defender holds a belief `p ∈ [0,1]` that the
current client is hostile, which is the malice output of the meter (§3). It must
then choose one of three actions. **Pass** sends the request to the real
application. **Divert** moves the session into the decoy. **Bait** injects an
invisible, inert probe into the response and passes the request on unchanged.

Each (action, true-class) pair carries a cost, fixed in advance in a table that is
hashed and frozen before any data is collected. No threshold in what follows can
therefore be tuned to the results. This is a cost-sensitive decision under a loss
matrix \cite{elkan2001foundations}, and the hash is checked on every load:

|                | pass | bait | divert |
|----------------|-----:|-----:|-------:|
| client benign  |  0   |  1   |  **200** |
| client hostile | 25   | 25   |  **−20** |

Three of these entries carry the argument. Diverting a *benign* user is the
outcome that must almost never happen, so it is priced two orders of magnitude
above any other error (200). Baiting a *hostile* client costs exactly what passing
one costs (25 = 25). The request still reaches the real application, so the
immediate exposure is identical. **Bait buys no immediate benefit whatsoever.**
The only difference between `pass` and `bait` is the small nuisance cost (1) borne
by the benign probability mass, and that is paid only if a probe were ever
visible.

Taking expectations under belief `p`, the immediate expected cost of each action is
linear in `p`:

```
E[C(pass)   | p] = 25 p
E[C(bait)   | p] = 1 (1−p) + 25 p = 1 + 24 p
E[C(divert) | p] = 200 (1−p) − 20 p = 200 − 220 p
```

## 4.2  Under cost accounting alone, there is no third action

Compare the three lines. `E[C(bait)] − E[C(pass)] = 1 − p ≥ 0` for every `p`:
baiting is *strictly more expensive* than passing at every belief, by exactly the
residual benign-nuisance term. So on immediate cost the middle action is never
chosen, and the policy collapses to a two-way rule — pass while `E[C(pass)] <
E[C(divert)]`, divert once it is not. That crossover is

```
25 p = 200 − 220 p   ⇒   p* = 200 / 245 = 0.8163
```

a single PASS/DIVERT boundary at `p ≈ 0.816`, with **no band anywhere in
between** (`tests/test_frozen_artefacts.py::test_cost_accounting_alone_does_not_
justify_bait`). This matters because it is the sharpest possible answer to the
reviewer's first question, *"isn't your middle action just a tuned threshold?"*:
**there is no middle action to tune.** It appears only once the value of the
information a probe buys is priced in.

## 4.3  Pricing the probe as an information purchase

A probe's entire worth is informational: it produces an observation
`Z ∈ {bite, no-bite}` that sharpens the belief and therefore the next decision.
We price it by the **expected value of sample information** (EVSI)
\cite{howard1966information}:

```
V(p) = min_a E[C(a) | p]  −  E_Z[ min_a E[C(a) | p′(Z)] ]
```

the expected reduction in optimal cost from observing `Z`. Writing it out costs
four lines and makes the whole rule checkable by hand. Let `βₐ = P(bite | hostile)`
and `β_b = P(bite | benign)` be the two calibrated rates of §5. The probability of
seeing a bite at belief `p`, and the posterior in each case, are

```
P(bite | p) = p·βₐ + (1−p)·β_b

p′(bite)    =        p·βₐ      /  ( p·βₐ + (1−p)·β_b )
p′(no bite) =    p·(1−βₐ)      /  ( p·(1−βₐ) + (1−p)·(1−β_b) )
```

and the value of the observation is the expected improvement it makes to the
decision that follows:

```
V(p) = min_a E[C(a) | p]
       − [ P(bite|p)·min_a E[C(a) | p′(bite)]
         + (1−P(bite|p))·min_a E[C(a) | p′(no bite)] ]
```

Both inner minima are over the same three affine cost lines, so `V` can be evaluated
in closed form at any belief; nothing here needs simulation. The decision rule prices
`bait` at its immediate cost *net of* this value and takes the cheapest action:

```
effective(pass)   = 25 p
effective(divert) = 200 − 220 p
effective(bait)   = 1 + 24 p − V(p)
```

We claim **no new mathematics here.** EVSI is textbook, and the properties below
are elementary. The contribution is the *application*: recognising that a
response-side probe *is* a sample-information purchase, and that pricing it as one
turns the middle option from a hand-set heuristic into a derived action whose
operating band falls out of the cost table.

**Property 1 — `V(p) ≥ 0` for all `p` (information never hurts).**
`min_a E[C(a) | p]` is a minimum of affine functions of `p`, hence concave;
Jensen's inequality applied to the posterior mean of the belief gives
`E_Z[min_a E[C(a) | p′]] ≤ min_a E[C(a) | p]` immediately. This is a standard lemma and not
ours. We enforce it as a runtime invariant
(`tests/test_policy.py::test_information_is_never_harmful`), which is a stronger
and more checkable statement than the specification's informal "bait is cheap."

**Property 2 — `V(0) = V(1) = 0` (the band is bounded on both sides by
construction).** When the belief is already certain, no observation can change the
decision, so the probe is worth exactly nothing. The bait band therefore cannot
swallow the whole probability range and cannot be widened by tuning; its edges are
pinned by the cost geometry.

**Property 3 — the middle band exists exactly where `V(p)` exceeds the residual
cost of baiting.** `bait` is chosen when `effective(bait)` is least, i.e. when
`V(p) > 1 − p` (bait beats pass) and the belief is still below the divert line.
With the frozen table and the calibrated library (§5), from which the policy takes
the most informative bait applicable to the response in hand, the derived bands are

```
PASS    p < 0.0647
BAIT    0.0647 ≤ p < 0.8793
DIVERT  p ≥ 0.8793
```

— reproduced exactly by `python -m adf.policy`. The two edges are set by two
different baits, which is what taking a maximum over the library means. The lower
edge comes from the `internal_view` probe (`β_attack = 0.753`,
`β_benign = 0.0067`, measured over 183 hostile and 74 benign sessions), the most
informative probe while the belief is still low. The upper edge comes from the
unused-JSON-field probe, whose higher bite rate is worth more once the belief is
high, so it holds diversion off slightly longer.

Two things are worth stating.
First, offering the probe *raises* the divert threshold from the cost-only 0.816
to 0.879: the defender is willing to wait a little longer before the expensive act
of diverting, precisely because it now has a cheaper way to buy certainty.
Second, **nothing in these numbers was chosen.** Change the cost of a wrongly
diverted user, or measure a different bite rate, and the edges move on their own —
which is the content of the next subsection.

### The rule, written out

Two pieces of state make the rule implementable: the applicable baits for the
response being built, and how many times this session has already been shown each
of them without biting.

```
policy(p, B, exposures):
    # immediate expected costs, linear in the belief p
    c_pass   <- 25*p
    c_divert <- 200 - 220*p

    # the information a probe would buy, decayed by unrewarded exposures
    V <- 0 ; b* <- none
    for b in B:                                  # baits injectable into THIS response
        v <- EVSI(p, beta_attack[b], beta_benign[b])
        v <- v * (1 - beta_attack[b]) ** exposures[b]      # survival discount
        if v > V: V, b* <- v, b

    c_bait <- 1 + 24*p - V

    return argmin(c_pass, c_bait, c_divert), b*
```

`EVSI(p, ·)` is the expression of Section 4.3: the optimal cost at `p` minus the
expected optimal cost after observing a bite or its absence, with the posterior
formed by Bayes' rule from the two calibrated rates.

The survival discount is the one term not implied by the textbook derivation, and
it exists because of a regression the adaptive-adversary sweep found. EVSI prices a
probe as though its outcome were fresh information, which is true the first time and
false the tenth: a session shown the same probe repeatedly without biting has
already answered the question. Valuing every exposure at full price lets an attacker
who keeps the belief inside the band and never bites be baited indefinitely instead
of diverted — caught by the passive baseline and *not* by the full system. Decaying
the value geometrically in the number of unrewarded showings, `(1 - beta_attack)^k`,
restores the guarantee: as the probe stops answering, its price stops being
discounted, and the rule falls back to the two-action policy.

## 4.4  The conclusions are invariant to the two estimated inputs

A derived band is only as trustworthy as the two quantities it is derived from:
the cost table (argued, not taken from incident data, since a detector's operating
point is dominated by how rare attacks are \cite{axelsson2000baserate}) and `β_attack` (measured
against an attacker model we chose). We therefore sweep each across the full range
it could plausibly take, holding the other fixed, and report what survives. The
qualitative claims are invariant; only the *magnitude* of the band moves.

**Sweeping `β_attack`** (`tools/beta_sweep.py`; `β_benign` held at the library's
measured median, 0.0067, and the five calibrated baits spanning 0.51 to 0.79 marked
on the grid). Across `β_attack ∈ [0.05, 0.99]`, which covers every bait informative at all, the
BAIT band is non-empty and the divert threshold never falls below the cost-only
boundary. The existence of the third action, and the fact that the probe only ever
*raises* the divert threshold (the safety half of the never-worse-than-passive
guarantee, §9), do not depend on the value of `β_attack`; only the band width and
the bite's likelihood ratio do (`tests/test_stats_sensitivity.py`).

**Sweeping the cost table** (`tools/cost_sweep.py`; the frozen numbers are never
edited — scaled copies are built). The single judgement the table encodes is the
ratio of a wrongly-diverted user to a missed attacker, frozen at 200/25 = 8. Swept
from 0.5 to 128 — over two orders of magnitude in both directions:

| divert / miss | cost-only boundary | derived BAIT band | band? |
|---:|---:|:---:|:---:|
| 0.5 | 0.217 | [0.031, 0.305) | ✓ |
| **8 (frozen)** | **0.816** | **[0.065, 0.879)** | ✓ |
| 128 | 0.986 | [0.363, 0.992) | ✓ |

At every point the band is non-empty and the divert threshold stays above the
cost-only boundary. What moves is *where* the boundaries sit, meaning how
conservative the system is, never *whether* the third action exists or *whether* the probe can
make the system divert earlier than cost accounting alone (it cannot). The frozen
table is thus a choice about conservatism, not a choice that manufactures the
result (`tests/test_stats_sensitivity.py`).

## 4.5  What this section establishes

The middle action is **priced, not tuned.** It is absent under cost accounting
alone, appears exactly when the expected value of the probe's information exceeds
its residual cost, sits in a band whose edges are outputs of the cost table and
the calibrated bite rate. As the two sweeps show, it owes its *existence* and its
*safety direction* to neither of the two estimated inputs, only its *magnitude*.
Everything measured in §8 is a test of whether this priced action does, in
practice, what the pricing says it should: help where the classifier is genuinely
uncertain, and nowhere else.
