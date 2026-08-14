"""
Build the fake world offline and load it into the Fact Notebook
(spec §6.8, §13 Phase 5).

This is the batch step that spec §6.8 insists happens BEFORE the system runs, so
that no generation ever sits in the request path. Run it once; the decoy then
serves everything from the notebook at the speed of a database read.

    python -m tools.build_decoy_world            # default notebook from config
    python -m tools.build_decoy_world --fresh    # wipe and rebuild
"""

from __future__ import annotations

import argparse
from pathlib import Path

from adf.config import system
from adf.decoy.notebook import FactNotebook
from adf.decoy.world import populate
from adf.decoy.credential import planted_credential


def main() -> None:
    cfg = system()
    ap = argparse.ArgumentParser(description="Populate the Fact Notebook (spec §6.8).")
    ap.add_argument("--dsn", default=cfg.get("databases.fact_notebook_dsn",
                                             "sqlite:///data/decoy/notebook.sqlite3"))
    ap.add_argument("--seed", type=int, default=cfg.seed)
    ap.add_argument("--users", type=int, default=24)
    ap.add_argument("--records", type=int, default=60)
    ap.add_argument("--notices", type=int, default=8)
    ap.add_argument("--fresh", action="store_true", help="delete an existing notebook first")
    args = ap.parse_args()

    if args.fresh and args.dsn.startswith("sqlite:///"):
        path = Path(args.dsn[len("sqlite:///"):])
        if not path.is_absolute():
            path = Path(__file__).resolve().parent.parent / path
        path.unlink(missing_ok=True)
        print(f"removed existing notebook at {path}")

    nb = FactNotebook(args.dsn, seed=args.seed)
    counts = populate(nb, users=args.users, records=args.records,
                      notices=args.notices, seed=args.seed)

    print(f"fake world built in {args.dsn} (seed {args.seed}):")
    for ns, n in counts.items():
        print(f"  {ns:14} {n}")

    cred = planted_credential(args.seed)
    print(f"\nplanted credential: key_id={cred.key_id}")
    print("  (lives in config 'service.ini'; the system watches for its reuse — spec §6.10)")
    print("\noffline generation complete. The decoy serves everything from the notebook,")
    print("so no generation ever sits in the request path (spec §6.8).")


if __name__ == "__main__":
    main()
