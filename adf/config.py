"""
Configuration loading, with freeze enforcement for the cost table.

Spec §6.5 and §16 both identify the same failure mode: adjusting the cost
table after seeing disappointing results. That is not a discipline problem
that a comment can solve, so the integrity hash below makes an edit loud --
the system refuses to start against a cost table whose numbers have moved
since the freeze, and re-freezing writes a dated entry to a changelog that
ends up in the repository history.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "config"
COSTS_PATH = CONFIG_DIR / "costs.yaml"
SYSTEM_PATH = CONFIG_DIR / "system.yaml"
COSTS_CHANGELOG = CONFIG_DIR / "costs.CHANGELOG.md"

PENDING = "PENDING_INITIAL_FREEZE"


class FrozenConfigError(RuntimeError):
    """Raised when the frozen cost table no longer matches its own hash."""


# --------------------------------------------------------------------------


def _cost_digest(doc: dict[str, Any]) -> str:
    """Hash over exactly the blocks that must not drift: the cost matrix and
    the score fusion. Comments, provenance and the informational
    `expected_thresholds` block are excluded so they can be edited freely."""
    material = {"matrix": doc.get("matrix"), "fusion": doc.get("fusion")}
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CostTable:
    """The frozen cost of each (true class, action) pair (spec §6.5)."""

    matrix: dict[str, dict[str, float]]
    fusion: dict[str, float]
    frozen_on: str
    digest: str

    def cost(self, true_class: str, action: str) -> float:
        return float(self.matrix[true_class][action])

    def expected_cost(self, action: str, p_attack: float) -> float:
        """Expected cost of `action` given hostility probability `p_attack`.

        This is the whole decision rule of spec §6.5: the policy does not
        compare a score against a tuned number, it prices each of the three
        actions and takes the cheapest.
        """
        p = min(max(float(p_attack), 0.0), 1.0)
        return (1.0 - p) * self.cost("benign", action) + p * self.cost("attack", action)

    def derive_thresholds(self, resolution: int = 100_000) -> dict[str, float]:
        """Find where the cheapest action changes as p sweeps 0 -> 1.

        Solved numerically rather than algebraically so that the derivation
        stays correct if the matrix is ever re-frozen with different numbers,
        including shapes where an action is never optimal.
        """
        boundaries: dict[str, float] = {}
        previous = self.best_action(0.0)
        for i in range(1, resolution + 1):
            p = i / resolution
            current = self.best_action(p)
            if current != previous:
                boundaries[f"{previous}_to_{current}"] = round(p, 6)
                previous = current
        return boundaries

    def best_action(self, p_attack: float) -> str:
        costs = {a: self.expected_cost(a, p_attack) for a in ("pass", "bait", "divert")}
        return min(costs, key=costs.get)

    def all_expected_costs(self, p_attack: float) -> dict[str, float]:
        return {a: round(self.expected_cost(a, p_attack), 6) for a in ("pass", "bait", "divert")}


def load_costs(path: Path | None = None, *, allow_unfrozen: bool = False) -> CostTable:
    path = path or COSTS_PATH
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))

    digest = _cost_digest(doc)
    recorded = str(doc.get("integrity_sha256", "")).strip()

    if recorded == PENDING:
        if not allow_unfrozen:
            raise FrozenConfigError(
                f"{path.name} has never been frozen. Run `python -m adf.config --refreeze` "
                "BEFORE generating any traffic (spec §13 Phase 0)."
            )
    elif recorded != digest:
        raise FrozenConfigError(
            f"FROZEN COST TABLE HAS CHANGED.\n"
            f"  recorded : {recorded}\n"
            f"  actual   : {digest}\n\n"
            "The decision thresholds are derived from these numbers, so editing them\n"
            "after data collection invalidates every baseline comparison (spec §6.5, §16).\n"
            "If the change is genuinely intended and no results depend on the old table,\n"
            "run `python -m adf.config --refreeze` to record it in config/costs.CHANGELOG.md."
        )

    return CostTable(
        matrix=doc["matrix"],
        fusion=doc["fusion"],
        frozen_on=str(doc.get("frozen_on", "")),
        digest=digest,
    )


def refreeze_costs(reason: str = "initial freeze", path: Path | None = None) -> str:
    """Record the current cost matrix as the frozen one, leaving an audit trail."""
    path = path or COSTS_PATH
    text = path.read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    new_digest = _cost_digest(doc)
    old_digest = str(doc.get("integrity_sha256", "")).strip()

    if old_digest == new_digest:
        return new_digest

    updated = text.replace(f'integrity_sha256: "{old_digest}"', f'integrity_sha256: "{new_digest}"')
    if updated == text:
        raise FrozenConfigError("could not locate integrity_sha256 line to update")
    path.write_text(updated, encoding="utf-8")

    entry = (
        f"\n## {date.today().isoformat()}\n\n"
        f"- **reason:** {reason}\n"
        f"- **previous digest:** `{old_digest}`\n"
        f"- **new digest:** `{new_digest}`\n"
        f"- **matrix:** `{json.dumps(doc['matrix'], sort_keys=True)}`\n"
        f"- **fusion:** `{json.dumps(doc['fusion'], sort_keys=True)}`\n"
    )
    if not COSTS_CHANGELOG.exists():
        COSTS_CHANGELOG.write_text(
            "# Cost table change log\n\n"
            "Every entry here is a re-freeze of `config/costs.yaml`. Entries dated after\n"
            "the first traffic generation are a methodological red flag and must be\n"
            "justified in the paper's limitations section (spec §6.5, §7.3).\n",
            encoding="utf-8",
        )
    with COSTS_CHANGELOG.open("a", encoding="utf-8") as fh:
        fh.write(entry)
    return new_digest


# --------------------------------------------------------------------------


@dataclass
class SystemConfig:
    """Everything in config/system.yaml, plus environment overrides.

    Environment variables win over the file so containers can be reconfigured
    without rebuilding an image; the prefix is ADF_ and nesting uses __,
    e.g. ADF_NETWORK__TARGET_PORT=9001.
    """

    raw: dict[str, Any]

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.raw
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    # convenience accessors used all over the codebase
    @property
    def mode(self) -> str:
        return str(self.get("mode", "b4_full"))

    @property
    def seed(self) -> int:
        return int(self.get("reproducibility.seed", 0))

    @property
    def log_dir(self) -> Path:
        return REPO_ROOT / str(self.get("logging.log_dir", "data/logs"))

    @property
    def label_dir(self) -> Path:
        return REPO_ROOT / str(self.get("logging.label_dir", "data/labels"))

    #: Modes that run the full three-action pipeline. `b5_fixed` is the
    #: fixed-threshold ablation: identical to `b4_full` in every respect except
    #: that its band edges are hand-set rather than derived, which is the whole
    #: point of the comparison. It therefore has to score, bait and divert like
    #: b4_full -- gating it out of any of those would make the ablation measure
    #: something other than the edges.
    _PROBING_MODES = ("b4_full", "b5_fixed")

    @property
    def bait_enabled(self) -> bool:
        # Mode is authoritative: b0-b3 must not bait regardless of the flag,
        # otherwise the baselines silently stop being baselines (spec §10.1).
        return bool(self.get("bait.enabled", True)) and self.mode in self._PROBING_MODES

    @property
    def decoy_enabled(self) -> bool:
        return bool(self.get("decoy.enabled", True)) and self.mode in (
            ("b3_static",) + self._PROBING_MODES)

    @property
    def scoring_enabled(self) -> bool:
        return self.mode in (("b2_passive", "b3_static") + self._PROBING_MODES)

    @property
    def rules_enabled(self) -> bool:
        # B1 is the rule-based WAF baseline (spec §10.1); it does NOT use the
        # learned meter or the cost policy.
        return self.mode == "b1_rules"


def _apply_env_overrides(doc: dict[str, Any]) -> dict[str, Any]:
    for key, value in os.environ.items():
        if not key.startswith("ADF_"):
            continue
        path = key[4:].lower().split("__")
        node = doc
        for part in path[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                break
        else:
            try:
                node[path[-1]] = yaml.safe_load(value)
            except yaml.YAMLError:
                node[path[-1]] = value
    return doc


def load_system(path: Path | None = None) -> SystemConfig:
    path = path or SYSTEM_PATH
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return SystemConfig(raw=_apply_env_overrides(doc))


# --------------------------------------------------------------------------

_SYSTEM: SystemConfig | None = None
_COSTS: CostTable | None = None


def system() -> SystemConfig:
    global _SYSTEM
    if _SYSTEM is None:
        _SYSTEM = load_system()
    return _SYSTEM


def costs() -> CostTable:
    global _COSTS
    if _COSTS is None:
        _COSTS = load_costs()
    return _COSTS


if __name__ == "__main__":  # pragma: no cover - freeze helper
    import argparse

    ap = argparse.ArgumentParser(description="Inspect or re-freeze the cost table.")
    ap.add_argument("--refreeze", action="store_true", help="record the current matrix as frozen")
    ap.add_argument("--reason", default="initial freeze")
    args = ap.parse_args()

    if args.refreeze:
        digest = refreeze_costs(args.reason)
        print(f"cost table frozen: {digest}")

    table = load_costs()
    print(f"\nfrozen on : {table.frozen_on}")
    print(f"digest    : {table.digest}")
    print(f"matrix    : {json.dumps(table.matrix, sort_keys=True)}")
    print("\nderived thresholds (NOT tuned -- solved from the matrix):")
    for name, value in table.derive_thresholds().items():
        print(f"  {name:24s} p = {value}")
    print("\nexpected cost by action:")
    for p in (0.0, 0.05, 0.1, 0.5, 0.85, 0.9, 1.0):
        row = table.all_expected_costs(p)
        print(f"  p={p:<5} pass={row['pass']:>9.3f}  bait={row['bait']:>9.3f}  "
              f"divert={row['divert']:>9.3f}  -> {table.best_action(p).upper()}")
