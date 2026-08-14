"""
Model freeze (spec §7.2, §13 Phase 6).

Spec §7.2 is the methodological rule the whole evaluation depends on: the model
is fit on round 1 and FROZEN before round 2 (the reported test set) is ever
collected. "Freeze the model before round 2 begins and do not retrain on round 2
data." A comment cannot enforce that; this module does.

`freeze()` records a manifest of every artefact that must be immutable for a
valid evaluation -- the trained meter, the cost table, the record schema, the
feature set, the calibrated bait library, the invisibility certificates -- each
by content hash. `verify()` recomputes those hashes and fails if anything moved
since the freeze. The Phase 7 evaluator calls `verify()` before it runs, so a
meter that was retrained, a cost table that was edited, or a bait library that
was recalibrated after the freeze cannot silently reach a reported result.

This is the same discipline as the cost-table freeze (adf/config), applied to
the whole system state rather than one file.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
FREEZE_PATH = REPO_ROOT / "config" / "model_freeze.json"
DEFAULT_METER = REPO_ROOT / "data" / "models" / "meter.json"


class FreezeError(RuntimeError):
    pass


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _repo_relative(path: Path) -> str:
    """Path relative to the repo, or just the name if it lives elsewhere (e.g. a
    temp file on another drive during tests)."""
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return path.name


def _sha256_obj(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode("utf-8")).hexdigest()


def _collect_state(meter_path: Path) -> dict[str, Any]:
    """Everything that must not drift between freeze and evaluation."""
    from adf.schema import schema_fingerprint, SCHEMA_VERSION
    from adf.config import load_costs
    from adf.features import FEATURE_SET_VERSION, ALL_FEATURES
    from adf.policy.engine import BaitLibrary
    from adf.bait.gate import load_certificates

    if not meter_path.exists():
        raise FreezeError(f"no trained meter at {meter_path}; train it before freezing "
                          "(python -m tools.train_meter).")

    costs = load_costs()
    library = BaitLibrary.load()
    # hash only the research-bearing parts of each bait (id, category, effect),
    # so a comment edit does not trip the freeze but a beta change does.
    bait_effects = {
        bid: {"category": e.get("category"), "effect": e.get("effect")}
        for bid, e in library.entries.items()
    }
    certs = load_certificates()

    return {
        "schema": {"version": SCHEMA_VERSION, "fingerprint": schema_fingerprint()},
        "cost_table": {"digest": costs.digest, "frozen_on": costs.frozen_on},
        "features": {"version": FEATURE_SET_VERSION, "count": len(ALL_FEATURES),
                     "hash": _sha256_obj(ALL_FEATURES)},
        "meter": {"file": _repo_relative(meter_path), "sha256": _sha256_file(meter_path)},
        "bait_library": {"calibrated": library.calibrated, "effects_hash": _sha256_obj(bait_effects)},
        "bait_certificates": {"count": len(certs), "hash": _sha256_obj(certs),
                              "certified": sorted(certs)},
    }


@dataclass
class FreezeManifest:
    frozen_on: str
    seed: int
    mode: str
    state: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"frozen_on": self.frozen_on, "seed": self.seed, "mode": self.mode, "state": self.state}


def freeze(meter_path: Path | None = None, *, require_calibrated: bool = True,
           path: Path | None = None) -> FreezeManifest:
    """Record the current system state as the frozen baseline for evaluation."""
    from adf.config import system

    meter_path = meter_path or DEFAULT_METER
    path = path or FREEZE_PATH
    state = _collect_state(meter_path)

    if require_calibrated and not state["bait_library"]["calibrated"]:
        raise FreezeError(
            "the bait library is not calibrated. Freezing an uncalibrated library would "
            "let Phase 7 report results computed from prior guesses (spec §6.6). Run "
            "python -m tools.calibrate_baits --write first."
        )
    if not state["bait_certificates"]["count"]:
        raise FreezeError("no bait invisibility certificates found; run the gate first (spec §6.7).")

    cfg = system()
    manifest = FreezeManifest(frozen_on=date.today().isoformat(), seed=cfg.seed,
                              mode=cfg.mode, state=state)
    path.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
    return manifest


def load_manifest(path: Path | None = None) -> dict[str, Any] | None:
    path = path or FREEZE_PATH
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def verify(meter_path: Path | None = None, path: Path | None = None) -> tuple[bool, list[str]]:
    """Recompute the frozen state and report any drift. Returns (ok, reasons)."""
    manifest = load_manifest(path)
    if manifest is None:
        return False, ["no freeze manifest found; the model has not been frozen (spec §7.2)"]

    current = _collect_state(meter_path or DEFAULT_METER)
    frozen = manifest["state"]
    reasons: list[str] = []

    checks = [
        ("meter", "sha256", "the trained meter changed since the freeze (retrained?)"),
        ("schema", "fingerprint", "the record schema changed since the freeze"),
        ("cost_table", "digest", "the cost table changed since the freeze"),
        ("features", "hash", "the feature set changed since the freeze"),
        ("bait_library", "effects_hash", "the bait library (betas) changed since the freeze"),
        ("bait_certificates", "hash", "the bait certificates changed since the freeze"),
    ]
    for block, key, message in checks:
        if frozen.get(block, {}).get(key) != current.get(block, {}).get(key):
            reasons.append(message)
    return (not reasons), reasons


def require_frozen(meter_path: Path | None = None) -> None:
    """Raise unless the system matches its freeze manifest. Called by the
    Phase 7 evaluator before it produces any reported number."""
    ok, reasons = verify(meter_path)
    if not ok:
        raise FreezeError(
            "the frozen model no longer matches the running system, so any evaluation "
            "against round-2 data would be invalid (spec §7.2):\n  - " + "\n  - ".join(reasons)
            + "\nRe-freeze deliberately (python -m tools.freeze_model) only if you intend "
            "to discard the previous evaluation."
        )
