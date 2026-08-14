"""
Freeze the model for evaluation (spec §7.2, §13 Phase 6 exit).

This is the last act of Phase 6: it records the trained meter and every artefact
the evaluation depends on, by content hash, so Phase 7 can prove nothing drifted.
After this, retraining the meter, editing the cost table or recalibrating baits
will make `verify` fail and the evaluator will refuse to run.

    python -m tools.freeze_model            # freeze
    python -m tools.freeze_model --verify   # check the running system still matches
"""

from __future__ import annotations

import argparse

from adf.freeze import freeze, verify, load_manifest, FREEZE_PATH


def main() -> None:
    ap = argparse.ArgumentParser(description="Freeze or verify the model (spec §7.2).")
    ap.add_argument("--verify", action="store_true", help="check the running system against the freeze")
    args = ap.parse_args()

    if args.verify:
        ok, reasons = verify()
        if ok:
            m = load_manifest()
            print(f"OK: system matches the freeze from {m['frozen_on']} (seed {m['seed']}).")
        else:
            print("DRIFT DETECTED — evaluation would be invalid (spec §7.2):")
            for r in reasons:
                print(f"  - {r}")
        raise SystemExit(0 if ok else 1)

    manifest = freeze()
    s = manifest.state
    print(f"model frozen on {manifest.frozen_on} (seed {manifest.seed}, mode {manifest.mode})")
    print(f"  meter            : {s['meter']['sha256'][:16]}…  ({s['meter']['file']})")
    print(f"  schema           : v{s['schema']['version']}  {s['schema']['fingerprint'][:16]}…")
    print(f"  cost table       : {s['cost_table']['digest'][:16]}…  (frozen {s['cost_table']['frozen_on']})")
    print(f"  feature set      : v{s['features']['version']}  ({s['features']['count']} features)")
    print(f"  bait library     : calibrated={s['bait_library']['calibrated']}  {s['bait_library']['effects_hash'][:16]}…")
    print(f"  bait certificates: {s['bait_certificates']['count']} certified {s['bait_certificates']['certified']}")
    print(f"\nwritten to {FREEZE_PATH.relative_to(FREEZE_PATH.parent.parent)}")
    print("The model is frozen. Do not retrain or recalibrate before Phase 7 (spec §7.2).")


if __name__ == "__main__":
    main()
