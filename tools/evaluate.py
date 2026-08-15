"""
Phase 7 evaluation — one baseline arm (spec §10, §13 Phase 7).

Runs the held-out round-2 attack set and a benign corpus through the proxy AS
IT IS CURRENTLY CONFIGURED (its `mode`), then scores the run against the labels
the generators wrote in advance. Because the generators are seeded, invoking
this with the same `--seed` in each mode replays byte-identical traffic, so the
baselines are compared on exactly the same input (spec §7.3).

The metrics (spec §10.3):
  * precision / recall / F1, and recall per attack category — a session counts
    as detected if it was ever DIVERTED.
  * requests-to-decision — index of the first divert, median over detected
    attacks. This is the primary efficiency claim.
  * benign bait-exposure rate and benign DIVERSION rate (NFR-05, target zero).
  * expected cost per session, from the frozen cost table.
  * holdout arm sizes and the causal effect of bait on requests-to-decision
    (b4 only): baited vs deliberately-withheld sessions at the same belief band.

The model must be frozen (spec §7.2): this refuses to run otherwise.

    python -m tools.evaluate --attack 48 --benign 60 --out data/eval/b4_full.json
"""

from __future__ import annotations

import argparse
import glob
import json
import random
import statistics
import time
from collections import defaultdict

import httpx

from adf.config import system, load_costs
from adf.freeze import require_frozen
from adf.logstore import LabelSidecar


def _run_traffic(proxy_url: str, attack_n: int, benign_n: int, seed: int) -> str:
    """Replay benign + round-2 attack traffic through the proxy. Returns the
    label directory used (a fresh one per run so joins are unambiguous)."""
    from tools.benign_traffic import BenignUser, PERSONA_WEIGHTS
    from tools.attack_traffic_round2 import PROFILES as R2, GENERATOR, VERSION
    from tools.benign_agents import PROFILES as AGENTS

    cfg = system()
    labels = LabelSidecar(str(cfg.label_dir / "eval_labels.jsonl"))
    rng = random.Random(seed)

    # benign: 75% simulated humans, 25% automated-but-harmless agents (monitor,
    # crawler, integration). The agents MUST be in the eval's benign set: the
    # first evaluation was human-only, which is exactly what hid a 100% false
    # positive on the benign JSON-API integration client (docs/DECISIONS.md).
    personas = list(PERSONA_WEIGHTS)
    weights = list(PERSONA_WEIGHTS.values())
    agent_names = list(AGENTS)
    for i in range(benign_n):
        if i % 4 == 0:  # every fourth benign session is an automated agent
            profile = agent_names[(i // 4) % len(agent_names)]
            cls, ua = AGENTS[profile]
            a = cls(base_url=proxy_url, rng=random.Random(rng.random()), dwell=False,
                    profile=profile, user_agent=ua)
            labels.write(session_id=a.session_id, round="eval", **a.label)
            a.run()
            a.close()
        else:
            persona = rng.choices(personas, weights=weights)[0]
            u = BenignUser(proxy_url, random.Random(rng.random()), dwell=False, persona=persona)
            labels.write(session_id=u.session_id, ground_truth="benign", attack_category="none",
                         attack_subcategory="none", automation_label="human",
                         generator="benign_traffic.py", tool_version="1.0", round="eval",
                         notes=f"eval benign {persona}")
            u.run()

    # attack round 2 (held out; genuinely different techniques)
    names = list(R2)
    for i in range(attack_n):
        name = names[i % len(names)]
        cls, kw = R2[name]
        atk = cls(proxy_url, random.Random(rng.random()), dwell=False, **kw)
        labels.write(session_id=atk.session_id, ground_truth="attack",
                     attack_category=atk.category, attack_subcategory=atk.subcategory,
                     automation_label=atk.automation, generator=GENERATOR, tool_version=VERSION,
                     round="eval", notes=f"eval {name}")
        atk.run()
        atk.close()
    return str(cfg.label_dir / "eval_labels.jsonl")


def _sessionise(proxy_glob: str, labels_path: str) -> dict:
    """Join proxy records to labels by provenance id; return per-session facts."""
    labels = {e["session_id"]: e for e in (json.loads(l) for l in open(labels_path, encoding="utf-8") if l.strip())}
    records = []
    for f in glob.glob(proxy_glob):
        records += [json.loads(l) for l in open(f, encoding="utf-8") if l.strip()]

    by_prov = defaultdict(list)
    for r in records:
        prov = r["session"].get("provenance_id", "")
        if prov:
            by_prov[prov].append(r)

    sessions = {}
    for prov, recs in by_prov.items():
        if prov not in labels:
            continue
        recs.sort(key=lambda r: r["seq"])
        actions = [r["decision"].get("action") for r in recs]
        first_divert = next((i for i, a in enumerate(actions) if a == "divert"), None)
        baited = any(r["bait"].get("injected") for r in recs)
        bit = any(r["bite"].get("occurred") for r in recs)
        assignment = next((r["decision"].get("bait_assignment") for r in recs
                           if r["decision"].get("bait_assignment") in ("policy", "holdout")), "none")
        sessions[prov] = {
            "label": labels[prov]["ground_truth"],
            "category": labels[prov]["attack_category"],
            "subcategory": labels[prov].get("attack_subcategory", "none"),
            "diverted": first_divert is not None,
            "reqs_to_divert": (first_divert + 1) if first_divert is not None else None,
            "baited": baited,
            "bit": bit,
            "assignment": assignment,
            "requests": len(recs),
        }
    return sessions


def _metrics(sessions: dict, mode: str) -> dict:
    costs = load_costs()
    atk = [s for s in sessions.values() if s["label"] == "attack"]
    ben = [s for s in sessions.values() if s["label"] == "benign"]

    tp = sum(1 for s in atk if s["diverted"])
    fn = len(atk) - tp
    fp = sum(1 for s in ben if s["diverted"])
    tn = len(ben) - fp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    recall_by_cat = {}
    for cat in ("sqli", "idor", "auth"):
        c = [s for s in atk if s["category"] == cat]
        recall_by_cat[cat] = (sum(1 for s in c if s["diverted"]) / len(c)) if c else None

    r2d = [s["reqs_to_divert"] for s in atk if s["diverted"]]

    def session_cost(s):
        action = "divert" if s["diverted"] else ("bait" if s["baited"] else "pass")
        true_class = "attack" if s["label"] == "attack" else "benign"
        return costs.cost(true_class, action)

    exp_cost = statistics.fmean([session_cost(s) for s in sessions.values()]) if sessions else 0.0

    # per-subcategory: where does B4 differ from B2? (the uncertain-band
    # subcategories are where bait can help; the aggressive ones saturate)
    by_subcat = {}
    subcats = sorted({s["subcategory"] for s in atk})
    for sc in subcats:
        g = [s for s in atk if s["subcategory"] == sc]
        d = [s for s in g if s["diverted"]]
        r = [s["reqs_to_divert"] for s in d]
        by_subcat[sc] = {
            "n": len(g),
            "divert_rate": round(len(d) / len(g), 4) if g else None,
            "median_reqs_to_divert": statistics.median(r) if r else None,
            "bite_rate": round(sum(1 for s in g if s["bit"]) / len(g), 4) if g else None,
        }

    # holdout arm (b4): baited vs withheld among bait-band sessions
    baited_arm = [s for s in atk if s["assignment"] == "policy"]
    holdout_arm = [s for s in atk if s["assignment"] == "holdout"]

    def median_r2d(arm):
        v = [s["reqs_to_divert"] for s in arm if s["diverted"]]
        return statistics.median(v) if v else None

    return {
        "mode": mode,
        "n_attack": len(atk), "n_benign": len(ben),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "recall_by_category": recall_by_cat,
        "by_subcategory": by_subcat,
        "median_requests_to_decision": statistics.median(r2d) if r2d else None,
        "p90_requests_to_decision": sorted(r2d)[int(len(r2d) * 0.9)] if r2d else None,
        "benign_bait_exposure_rate": round(sum(1 for s in ben if s["baited"]) / len(ben), 4) if ben else 0.0,
        "benign_diversion_rate": round(fp / len(ben), 4) if ben else 0.0,
        "expected_cost_per_session": round(exp_cost, 4),
        "holdout": {
            "baited_arm_n": len(baited_arm),
            "holdout_arm_n": len(holdout_arm),
            "baited_median_r2d": median_r2d(baited_arm),
            "holdout_median_r2d": median_r2d(holdout_arm),
            "baited_divert_rate": round(sum(1 for s in baited_arm if s["diverted"]) / len(baited_arm), 4) if baited_arm else None,
            "holdout_divert_rate": round(sum(1 for s in holdout_arm if s["diverted"]) / len(holdout_arm), 4) if holdout_arm else None,
        },
    }


def main() -> None:
    cfg = system()
    ap = argparse.ArgumentParser(description="Phase 7 evaluation — one arm (spec §10).")
    ap.add_argument("--proxy", default=f"http://127.0.0.1:{cfg.get('network.proxy_port', 8000)}")
    ap.add_argument("--attack", type=int, default=48)
    ap.add_argument("--benign", type=int, default=60)
    ap.add_argument("--seed", type=int, default=cfg.seed + 7)
    ap.add_argument("--mode", required=True,
                    help="the mode the proxy was started in (label for this run; "
                         "the driver sets it to the ADF_MODE it launched)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    require_frozen()   # spec §7.2 — refuse to report against an unfrozen model
    httpx.get(args.proxy + "/", timeout=5)   # fail fast if the proxy is not up

    # fresh label + log window for this run: wipe the proxy log so only THIS
    # arm's traffic is measured (each arm is an independent run of the same
    # seeded traffic through a different mode).
    import os
    from pathlib import Path
    Path(cfg.label_dir / "eval_labels.jsonl").unlink(missing_ok=True)
    for f in glob.glob(str(cfg.log_dir / "proxy.*.jsonl")):
        os.remove(f)

    print(f"running eval traffic through {args.proxy} (mode={args.mode}): "
          f"{args.benign} benign + {args.attack} attack, seed {args.seed}")
    labels_path = _run_traffic(args.proxy, args.attack, args.benign, args.seed)
    time.sleep(1.5)

    sessions = _sessionise(str(cfg.log_dir / "proxy.*.jsonl"), labels_path)
    m = _metrics(sessions, args.mode)

    print(json.dumps(m, indent=2))
    out = args.out or f"data/eval/{args.mode}.json"
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(m, indent=2), encoding="utf-8")
    print(f"\nwritten -> {out}")


if __name__ == "__main__":
    main()
