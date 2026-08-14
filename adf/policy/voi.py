"""
Value of information for response-side probes.

WHY THIS EXISTS
---------------
The specification's decision rule (§6.5) prices three actions against a
frozen cost table and takes the cheapest. That is correct as far as it goes,
but it hides the mechanism it is trying to describe. Baiting is not valuable
because it is cheap; it is valuable because it *generates evidence*. In the
spec that value appears twice, both times as a hand-set number:

  1. the cost of baiting an attacker is "discounted [...] to reflect that
     purchased information" (§6.5) -- a discount nobody computed;
  2. on a bite "the malice score jumps sharply" (§5.2) -- a jump nobody
     derived.

Both are the same quantity, counted twice and measured never. This module
computes it once, properly, from the cost table and the bait's measured
effectiveness:

    V(p) = min_a E[C(a) | p]  -  E_Z[ min_a E[C(a) | p after observing Z] ]

the expected reduction in optimal cost from observing the bait outcome Z.
This is the Expected Value of Sample Information (EVSI), a standard object in
statistical decision theory that this literature does not appear to apply.

Consequences worth stating in the paper:

  * `V(p) >= 0` always, because `min` over linear functions is concave and
    Jensen's inequality applies. Information never hurts. The proof is two
    lines and it is a stronger statement than "bait is cheap".
  * BAIT becomes optimal exactly where `V(p)` exceeds the residual nuisance
    cost borne by the benign probability mass. The bait band is therefore
    *derived*, like the thresholds, rather than asserted.
  * The immediate cost of bait can now be its TRUE immediate cost -- the
    attacker still reaches the real application, so the exposure is the same
    as PASS. No discount, no double counting.
  * Bait SELECTION falls out for free: among available baits, take the one
    with the highest `V(p)` for this attacker profile. Spec §6.6 asks for
    "a bait appropriate to the suspected attack category" without saying what
    appropriate means; this says it.

The only empirical inputs are the two bite rates, and they are estimated in
the dedicated `calibrate` round -- never on training or evaluation data.
"""

from __future__ import annotations

from dataclasses import dataclass

ACTIONS = ("pass", "bait", "divert")


@dataclass(frozen=True)
class BaitEffect:
    """How informative one bait is.

    beta_attack : P(bite | session is hostile)   -- estimated in `calibrate`
    beta_benign : P(bite | session is benign)    -- measured on benign traffic

    `beta_benign` should be ~0 by construction: bait is invisible to a real
    browser (NFR-01), so a benign user has nothing to act on. It is kept as a
    free parameter rather than assumed zero for two reasons: a hard zero makes
    the likelihood ratio infinite and the arithmetic degenerate, and asserting
    it would assume away exactly the safety property the project is supposed
    to be measuring.
    """

    bait_id: str
    beta_attack: float
    beta_benign: float
    category: str = "none"

    def __post_init__(self) -> None:
        for name, value in (("beta_attack", self.beta_attack), ("beta_benign", self.beta_benign)):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be a probability, got {value}")
        if self.beta_benign >= self.beta_attack:
            raise ValueError(
                f"bait {self.bait_id!r} is not informative: beta_benign "
                f"({self.beta_benign}) >= beta_attack ({self.beta_attack}). A bait that "
                "benign users act on at least as often as attackers carries no evidence "
                "and must not enter the library."
            )

    @property
    def likelihood_ratio(self) -> float:
        """P(bite | attack) / P(bite | benign) -- the evidence weight of a bite.

        This is the number spec §5.2 leaves as "jumps sharply". Because
        `beta_benign` is small, the ratio is large; because it is estimated
        rather than chosen, it is defensible.
        """
        return self.beta_attack / max(self.beta_benign, 1e-9)

    @property
    def negative_likelihood_ratio(self) -> float:
        """P(no bite | attack) / P(no bite | benign).

        Slightly below 1: declining the bait is weak evidence of innocence.
        Reporting it matters, because a system that only ever updates upward
        can accumulate suspicion without bound and will eventually divert
        somebody for browsing slowly.
        """
        return (1.0 - self.beta_attack) / max(1.0 - self.beta_benign, 1e-9)


def posterior(p: float, effect: BaitEffect, *, bite: bool) -> float:
    """Bayes update of the hostility belief after observing the bait outcome."""
    if bite:
        num = p * effect.beta_attack
        den = num + (1.0 - p) * effect.beta_benign
    else:
        num = p * (1.0 - effect.beta_attack)
        den = num + (1.0 - p) * (1.0 - effect.beta_benign)
    return num / den if den > 0.0 else p


def probability_of_bite(p: float, effect: BaitEffect) -> float:
    """Marginal P(bite) at belief p -- the mixture over both true classes."""
    return p * effect.beta_attack + (1.0 - p) * effect.beta_benign


def expected_value_of_information(p: float, effect: BaitEffect, cost_table) -> float:
    """EVSI of deploying `effect` at belief `p`, in cost units.

    Returns the expected reduction in optimal cost from learning the bait
    outcome. Always >= 0 up to floating point.
    """
    p = min(max(p, 0.0), 1.0)

    def best_cost(belief: float) -> float:
        return min(cost_table.expected_cost(a, belief) for a in ACTIONS)

    cost_now = best_cost(p)

    p_bite = probability_of_bite(p, effect)
    cost_after = (
        p_bite * best_cost(posterior(p, effect, bite=True))
        + (1.0 - p_bite) * best_cost(posterior(p, effect, bite=False))
    )

    # Clamped at zero: the quantity is provably non-negative, so anything
    # below zero is floating-point noise rather than a finding.
    return max(0.0, cost_now - cost_after)


def immediate_costs(p: float, cost_table) -> dict[str, float]:
    """Expected IMMEDIATE cost of each action, ignoring information value."""
    return {a: cost_table.expected_cost(a, p) for a in ACTIONS}


def survival_discount(effect: BaitEffect, exposures: int) -> float:
    """How much of a bait's EVSI survives after `exposures` unrewarded showings:
    `(1 - beta_attack) ** exposures`.

    THE PROBLEM THIS SOLVES (found by the adaptive-adversary evaluation, §18).
    EVSI prices a bait as though its outcome were fresh information. That is true
    the first time. It is false the tenth time: a session that has been shown a
    bait repeatedly and has never bitten has already answered the question, and
    re-asking it buys almost nothing. Valuing every exposure at full price makes
    the policy defer DIVERT indefinitely while it waits for information that is
    never coming -- which is exactly how a bait-aware adversary evades.

    Concretely: offering a third action raises the divert threshold (0.816 ->
    0.875 with the calibrated library). An attacker who keeps p inside that gap
    and never bites was baited forever instead of diverted, and was caught by the
    passive baseline B2 but NOT by the full system -- a regression the sweep
    measured directly (0% vs 100% divert).

    The fix is a modelling correction, not a tuned knob. The rate follows from
    the bait's OWN calibrated effectiveness: if an attacker bites with
    probability beta_attack per exposure, the chance a genuinely hostile session
    declines it `exposures` times in a row is (1 - beta_attack)^exposures. As
    that falls, so does the expected information from asking again, V -> 0, and
    the policy converges to the two-action comparison it would have made without
    bait at all. The system can then never be WORSE than its own passive
    baseline -- the property that matters.

    At `exposures = 0` this is exactly 1.0, so first-contact behaviour, and
    every theorem and derived band that rests on it, is unchanged.
    """
    if exposures <= 0:
        return 1.0
    return max(0.0, (1.0 - effect.beta_attack) ** exposures)


def choose_action(
    p: float,
    cost_table,
    effects: list[BaitEffect] | None = None,
    exposures: dict[str, int] | None = None,
) -> tuple[str, dict]:
    """The three-way decision, with bait priced as an information purchase.

    Returns `(action, detail)`. `detail` carries everything needed to explain
    the decision afterwards (NFR-07) and to reproduce it: the immediate cost
    of each action, the EVSI of the best available bait, the bait chosen, and
    the effective cost that won.

    The rule:

        effective_cost(pass)   = E[C(pass)   | p]
        effective_cost(divert) = E[C(divert) | p]
        effective_cost(bait)   = E[C(bait)   | p]  -  V(p)

    and the cheapest wins. PASS and DIVERT are terminal in the sense that
    neither buys information, so only BAIT gets the subtraction.
    """
    p = min(max(p, 0.0), 1.0)
    costs = immediate_costs(p, cost_table)
    exposures = exposures or {}

    best_effect: BaitEffect | None = None
    best_evsi = 0.0
    for effect in effects or []:
        # Discount by how many times this session has already been shown this
        # bait without biting: re-asking an answered question buys little
        # (see `survival_discount`). With no exposures this is exactly the
        # undiscounted EVSI, so first-contact behaviour is unchanged.
        value = (expected_value_of_information(p, effect, cost_table)
                 * survival_discount(effect, exposures.get(effect.bait_id, 0)))
        if value > best_evsi or best_effect is None:
            best_effect, best_evsi = effect, value

    effective = dict(costs)
    effective["bait"] = costs["bait"] - best_evsi

    action = min(effective, key=effective.get)

    return action, {
        "p_attack": p,
        "immediate_costs": {k: round(v, 6) for k, v in costs.items()},
        "effective_costs": {k: round(v, 6) for k, v in effective.items()},
        "evsi": round(best_evsi, 6),
        "selected_bait": best_effect.bait_id if best_effect else "",
        "selected_bait_category": best_effect.category if best_effect else "none",
        "likelihood_ratio": round(best_effect.likelihood_ratio, 4) if best_effect else 0.0,
    }


def derive_bands(cost_table, effects: list[BaitEffect], resolution: int = 20_000) -> dict[str, float]:
    """Sweep p from 0 to 1 and report where the chosen action changes.

    The resulting bait band is a *consequence* of the cost table and the
    measured bait effectiveness. Nothing here is a tuned threshold, which is
    the property the paper claims and this function demonstrates.
    """
    bands: dict[str, float] = {}
    previous, _ = choose_action(0.0, cost_table, effects)
    for i in range(1, resolution + 1):
        p = i / resolution
        current, _ = choose_action(p, cost_table, effects)
        if current != previous:
            bands[f"{previous}_to_{current}"] = round(p, 6)
            previous = current
    return bands
