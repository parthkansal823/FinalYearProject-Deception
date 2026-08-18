"""
The decision policy: two scores in, one of three actions out.

This is the component spec §5.2 step 5 and §6.5 describe, with the value of
information made explicit (see `voi.py` for why that matters). It contains no
tuned constants. Everything it does is determined by:

  * the frozen cost table            (config/costs.yaml)
  * the calibrated bait effectiveness (config/bait_library.yaml)
  * the fusion weights               (config/costs.yaml `fusion`)

and each decision it makes is fully explained in its returned reason, so the
log can answer "why was this request diverted?" months later (NFR-07).

THE RANDOMISED HOLDOUT
----------------------
A fraction of sessions that the policy WOULD have baited are deliberately not
baited. This costs a little detection performance and buys something the rest
of this literature does not have.

Comparing the full system against baseline B2 (spec §10.1) is a comparison
between two *different systems*, so any difference in time-to-decision is
confounded with every other difference between them. Withholding bait from a
random subset of sessions that reached the same belief state makes bait an
assigned treatment within a single system, and the treated/untreated
difference is an unbiased causal estimate of the effect of baiting.

That converts the paper's headline claim -- "provoking reduces the number of
requests needed to reach a confident decision" -- from a system comparison
into a randomised experiment. It is cheap, it is rigorous, and it is the
strongest available answer to a reviewer asking whether the improvement is
really attributable to the bait.

Assignment is deterministic given the session id and the run seed, so a run
replays identically (NFR-08) while remaining unpredictable to an attacker who
cannot see the seed.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from adf.config import CostTable, REPO_ROOT, costs as load_cost_table, system
from adf.policy.voi import (choose_action_fixed, 
    BaitEffect,
    choose_action,
    derive_bands,
)
from adf.schema import ReasonItem

POLICY_VERSION = "voi-1"
BAIT_LIBRARY_PATH = REPO_ROOT / "config" / "bait_library.yaml"


# ---------------------------------------------------------------------------
# Score fusion
# ---------------------------------------------------------------------------


def _logit(x: float, eps: float) -> float:
    x = min(max(x, eps), 1.0 - eps)
    return math.log(x / (1.0 - x))


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def fuse(automation: float, malice: float, fusion: dict) -> float:
    """Two suspicion scores -> one hostility probability.

    The cost table is indexed by true class, not by score pair, so something
    has to make this mapping; the spec does not say what. Keeping it here,
    explicit and configurable, means the assumption is visible and reportable
    rather than buried inside the policy.

    Default weights (w_malice=1, w_automation=0) make p = malice, following
    spec §6.3's own example: a price-comparison bot is fully automated and
    entirely harmless, so automation must not by itself imply hostility.
    Automation earns its keep in bait SELECTION instead.
    """
    eps = float(fusion.get("epsilon", 1e-6))
    z = (
        float(fusion.get("bias", 0.0))
        + float(fusion.get("w_malice", 1.0)) * _logit(malice, eps)
        + float(fusion.get("w_automation", 0.0)) * _logit(automation, eps)
    )
    return _sigmoid(z)


# ---------------------------------------------------------------------------
# Bait library
# ---------------------------------------------------------------------------


@dataclass
class BaitLibrary:
    entries: dict[str, dict]
    calibrated: bool
    estimation: dict

    @staticmethod
    def load(path: Path | None = None) -> "BaitLibrary":
        doc = yaml.safe_load((path or BAIT_LIBRARY_PATH).read_text(encoding="utf-8"))
        entries = {e["id"]: e for e in doc.get("baits", [])}
        return BaitLibrary(
            entries=entries,
            calibrated=bool(doc.get("calibrated", False)),
            estimation=doc.get("estimation", {}),
        )

    def effects(self, *, categories: list[str] | None = None) -> list[BaitEffect]:
        """Bait effects, optionally restricted to the suspected categories.

        Restricting by category is how the automation/malice split reaches the
        decision: the feature extractor's view of *what* is being attempted
        selects the candidate baits, and EVSI then picks the most informative
        among them.
        """
        out: list[BaitEffect] = []
        for entry in self.entries.values():
            if categories and entry.get("category") not in categories:
                continue
            effect = entry.get("effect", {})
            out.append(
                BaitEffect(
                    bait_id=entry["id"],
                    beta_attack=float(effect.get("beta_attack", 0.0)),
                    beta_benign=float(effect.get("beta_benign", 0.0005)),
                    category=str(entry.get("category", "none")),
                )
            )
        return out


# ---------------------------------------------------------------------------
# The policy
# ---------------------------------------------------------------------------


@dataclass
class Decision:
    action: str
    p_attack: float
    evsi: float
    bait_id: str
    bait_assignment: str
    immediate_costs: dict[str, float]
    effective_costs: dict[str, float]
    likelihood_ratio: float
    reason: list[ReasonItem] = field(default_factory=list)
    policy_version: str = POLICY_VERSION


def _parse_fixed_bands(raw) -> tuple[float, float] | None:
    """Read 'lo,hi' (or a two-item list) into band edges, or None."""
    if raw in (None, '', []):
        return None
    if isinstance(raw, str):
        parts = [x.strip() for x in raw.split(',') if x.strip()]
    else:
        parts = list(raw)
    if len(parts) != 2:
        raise ValueError(f'bait.fixed_bands needs exactly two edges, got {raw!r}')
    lo, hi = float(parts[0]), float(parts[1])
    if not 0.0 <= lo < hi <= 1.0:
        raise ValueError(f'bait.fixed_bands must satisfy 0 <= lo < hi <= 1, got {lo}, {hi}')
    return (lo, hi)


@dataclass
class DecisionPolicy:
    cost_table: CostTable
    library: BaitLibrary
    fusion: dict
    seed: int = 0
    holdout_fraction: float = 0.1
    mode: str = "b4_full"
    require_calibration: bool = False
    #: hand-set band edges for the b5_fixed ablation. None means the edges
    #: are derived, which is the contribution being ablated.
    fixed_bands: tuple[float, float] | None = None

    @staticmethod
    def from_config(*, require_calibration: bool = False) -> "DecisionPolicy":
        cfg = system()
        table = load_cost_table()
        return DecisionPolicy(
            cost_table=table,
            library=BaitLibrary.load(),
            fusion=table.fusion,
            seed=cfg.seed,
            holdout_fraction=float(cfg.get("bait.holdout_fraction", 0.1)),
            mode=cfg.mode,
            require_calibration=require_calibration,
            fixed_bands=_parse_fixed_bands(cfg.get('bait.fixed_bands')),
        )

    # -- holdout ----------------------------------------------------------

    def in_holdout(self, session_id: str) -> bool:
        """Deterministic pseudo-random assignment from (seed, session id).

        Deterministic so a run replays exactly (NFR-08); hashed with the seed
        so it is not predictable to anyone who cannot see the seed.
        """
        if self.holdout_fraction <= 0.0:
            return False
        digest = hashlib.sha256(f"{self.seed}:{session_id}".encode("utf-8")).digest()
        draw = int.from_bytes(digest[:8], "big") / float(1 << 64)
        return draw < self.holdout_fraction

    # -- the decision -----------------------------------------------------

    def decide(
        self,
        *,
        session_id: str,
        automation: float,
        malice: float,
        suspected_categories: list[str] | None = None,
        feature_contributions: list[ReasonItem] | None = None,
        exposures: dict[str, int] | None = None,
        applicable_baits: set[str] | None = None,
    ) -> Decision:
        if self.require_calibration and not self.library.calibrated:
            raise RuntimeError(
                "the bait library has not been calibrated. Its beta values are priors, "
                "and reporting a result computed from priors would present a guess as a "
                "finding. Run the `calibrate` round first (see config/bait_library.yaml)."
            )

        p = fuse(automation, malice, self.fusion)

        # Baselines B0-B3 must not bait, whatever the arithmetic says --
        # otherwise they quietly stop being baselines (spec §10.1).
        bait_permitted = self.mode in ("b4_full", "b5_fixed")
        effects = self.library.effects(categories=suspected_categories) if bait_permitted else []
        # Only consider baits that can actually be injected into THIS response.
        # Without this the policy could pick the highest-EVSI bait in a category
        # (e.g. B-IDOR-1, a JSON field) for an HTML page, "decide" to bait, and
        # then inject nothing -- so the uncertain IDOR case was never resolved.
        # The evaluation exposed exactly this (docs/RESULTS.md).
        if applicable_baits is not None:
            effects = [e for e in effects if e.bait_id in applicable_baits]

        # `exposures` carries how many times this session has already been shown
        # each bait without biting. It decays the EVSI so the policy cannot
        # defer DIVERT forever waiting for information that is not coming
        # (adf/policy/voi.py::survival_discount).
        if self.mode == 'b5_fixed':
            if not self.fixed_bands:
                raise RuntimeError(
                    'mode b5_fixed needs bait.fixed_bands (two edges). Without them '
                    'this arm would silently fall back to the derived policy it is '
                    'meant to ablate, and report itself as the ablation.')
            lo, hi = self.fixed_bands
            policy_action, detail = choose_action_fixed(
                p, self.cost_table, effects, pass_to_bait=lo,
                bait_to_divert=hi, exposures=exposures)
        else:
            policy_action, detail = choose_action(p, self.cost_table, effects, exposures)

        # `policy_action` is what the arithmetic chose; `action` is what the
        # session actually receives. They differ only for the holdout, and
        # keeping both is what makes the holdout analysable afterwards.
        action = policy_action
        assignment = "none"
        if policy_action == "bait":
            if self.in_holdout(session_id):
                # Withheld on purpose. The session stays in the bait band and
                # is recorded as such, which is exactly what makes it a usable
                # control for the causal estimate.
                assignment = "holdout"
                action = "pass"
            else:
                assignment = "policy"

        reason = list(feature_contributions or [])
        reason.append(
            ReasonItem(
                feature="p_attack",
                value=round(p, 6),
                weight=1.0,
                contribution=round(detail["effective_costs"][policy_action], 6),
            )
        )
        if detail["evsi"] > 0:
            reason.append(
                ReasonItem(
                    feature=f"evsi[{detail['selected_bait']}]",
                    value=round(detail["evsi"], 6),
                    weight=1.0,
                    contribution=round(-detail["evsi"], 6),
                )
            )

        return Decision(
            action=action,
            p_attack=p,
            evsi=detail["evsi"],
            bait_id=detail["selected_bait"] if assignment == "policy" else "",
            bait_assignment=assignment,
            immediate_costs=detail["immediate_costs"],
            effective_costs=detail["effective_costs"],
            likelihood_ratio=detail["likelihood_ratio"],
            reason=reason,
        )

    # -- reporting --------------------------------------------------------

    def bands(self, categories: list[str] | None = None) -> dict[str, float]:
        return derive_bands(self.cost_table, self.library.effects(categories=categories))


def main_cli() -> None:  # pragma: no cover - inspection CLI
    policy = DecisionPolicy.from_config()
    table, library = policy.cost_table, policy.library

    print(f"policy version : {POLICY_VERSION}")
    print(f"cost digest    : {table.digest}")
    print(f"bait library   : {len(library.entries)} baits, "
          f"calibrated={library.calibrated}")
    if not library.calibrated:
        print("                 ^ beta values are PRIORS; results computed from them "
              "are not reportable")

    print("\nbait effectiveness and evidence weight:")
    for effect in library.effects():
        print(f"  {effect.bait_id:<10} beta_a={effect.beta_attack:.3f} "
              f"beta_b={effect.beta_benign:.4f}  LR(bite)={effect.likelihood_ratio:>9.1f}  "
              f"LR(no bite)={effect.negative_likelihood_ratio:.3f}")

    print("\naction bands (DERIVED from cost table + bait effectiveness):")
    for name, value in policy.bands().items():
        print(f"  {name:<20} p = {value}")

    print("\n   p     immediate: pass    bait  divert  |    EVSI  effective(bait)  ->")
    for p in (0.0, 0.01, 0.02, 0.03, 0.05, 0.1, 0.3, 0.5, 0.7, 0.85, 0.9, 0.95, 1.0):
        action, detail = choose_action(p, table, library.effects())
        ic, ec = detail["immediate_costs"], detail["effective_costs"]
        print(f"  {p:<5} {ic['pass']:>13.3f} {ic['bait']:>7.3f} {ic['divert']:>7.2f}  |"
              f" {detail['evsi']:>7.3f} {ec['bait']:>15.3f}  -> {action.upper()}")


if __name__ == "__main__":  # pragma: no cover
    main_cli()
