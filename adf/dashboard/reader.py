"""
Data access for the dashboard. READ-ONLY: it opens the append-only proxy log and
the evaluation summaries and never writes, so it is safe to run alongside a live
proxy or an evaluation in progress (it simply reads whatever has been flushed).

Nothing here loads the model or touches the frozen artefacts beyond asking the
policy for its derived bands, which is a pure function of the frozen cost table
and calibrated library.
"""

from __future__ import annotations

import glob
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# decision bands (pure function of the frozen cost table + calibrated library)
# ---------------------------------------------------------------------------


def decision_bands() -> dict[str, float] | None:
    """The live derived bands, or None if the policy cannot be loaded.

    This used to fall back to hardcoded values so the page always rendered. That
    is the wrong trade for a console whose whole point is showing where the real
    boundaries are: after the library was recalibrated the literals were stale, and
    a stale band silently mislabels every session plotted against it. Returning
    None lets the page say "unavailable" instead of quietly lying.
    """
    try:
        from adf.policy.engine import DecisionPolicy
        return DecisionPolicy.from_config().bands()
    except Exception:
        return None


def cost_only_boundary() -> float:
    return 0.8163


# ---------------------------------------------------------------------------
# sessions from the proxy log
# ---------------------------------------------------------------------------


@dataclass
class SessionView:
    session_id: str
    provenance_id: str
    label: str
    n_requests: int
    peak_malice: float
    last_automation: float
    action: str            # final action taken (pass / bait / divert)
    baited: bool
    bitten: bool
    in_decoy: bool
    first_divert_req: int | None
    #: the belief the policy actually acted on when it took `action`. This is NOT
    #: `peak_malice`: belief can rise and fall within a session (error ratio falls
    #: as later requests succeed), so plotting a session at its PEAK while
    #: colouring it by its FINAL action puts dots in bands they were never in --
    #: which reads as a broken policy. Plot this instead.
    decisive_malice: float = 0.0
    #: True when `action` disagrees with the band `decisive_malice` falls in. Any
    #: such session is either a fail-open, a bait-availability effect, or a real
    #: inconsistency -- either way the console should surface it rather than hide
    #: it behind an averaged number.
    band_violation: bool = False
    requests: list[dict] = field(default_factory=list)


def latest_proxy_log() -> Path | None:
    logs = sorted(glob.glob(str(REPO / "data" / "logs" / "proxy.*.jsonl")))
    return Path(logs[-1]) if logs else None


def _label_index() -> dict[str, dict]:
    """session_id -> label row, pooled across every sidecar in data/labels/.

    The proxy log stores only a provenance id (a real client sends no ground
    truth); the generators wrote the truth to a sidecar keyed by that same id, so
    joining the two is what lets the dashboard show attack/benign classes."""
    idx: dict[str, dict] = {}
    for f in glob.glob(str(REPO / "data" / "labels" / "*.jsonl")):
        for line in open(f, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            sid = row.get("session_id")
            if sid:
                idx[sid] = row
    return idx


def _read_records(path: Path) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # a partially-flushed final line, ignore
    return out


def load_sessions(path: Path | None = None) -> list[SessionView]:
    path = path or latest_proxy_log()
    if path is None or not path.exists():
        return []
    by_sid: dict[str, list[dict]] = {}
    for r in _read_records(path):
        by_sid.setdefault(r["session"]["session_id"], []).append(r)

    labels = _label_index()
    bands = decision_bands()
    b2d = bands.get("bait_to_divert", 0.8626)
    cost_only = cost_only_boundary()

    def _is_violation(action: str, p: float) -> bool:
        """Flag only decisions that are wrong under EVERY admissible band.

        The bands are per-session, not global: a request with no applicable bait
        (wrong category, or a response the bait cannot ride) has EVSI = 0, so the
        policy correctly collapses to the two-action rule and diverts at the
        cost-only boundary instead of the wider bait-aware one. Comparing every
        session against the global three-band split therefore manufactures
        'violations' out of correct behaviour -- it flagged 36 of 54 sessions,
        all of them legitimate no-bait passes.

        So only the unambiguous cases are flagged, leaving the interval between
        the two divert edges (where the answer genuinely depends on which baits
        were available) alone:
          * DIVERT below the cost-only boundary -- never optimal, whatever bait exists;
          * PASS/BAIT at or above the widest divert edge -- should have diverted
            under every configuration.
        """
        if action == "divert":
            return p < cost_only
        if action in ("pass", "bait"):
            return p >= b2d
        return False

    views: list[SessionView] = []
    for sid, recs in by_sid.items():
        recs.sort(key=lambda r: r.get("seq", 0))
        actions = [r["decision"].get("action") for r in recs]
        peak = max((r["scores"].get("p_attack", 0.0) for r in recs), default=0.0)
        last_auto = recs[-1]["scores"].get("after", {}).get("automation", 0.0)
        first_div = next((i + 1 for i, a in enumerate(actions) if a == "divert"), None)
        final = next((a for a in reversed(actions) if a), "pass")
        # The decisive record is the one that produced `final`: the first divert if
        # the session was ever diverted (a divert is terminal -- everything after
        # it is routed to the decoy), otherwise the last record carrying an action.
        decisive_rec = None
        if first_div is not None:
            decisive_rec = recs[first_div - 1]
        else:
            decisive_rec = next((r for r in reversed(recs) if r["decision"].get("action")), None)
        decisive_p = float((decisive_rec or {}).get("scores", {}).get("p_attack", 0.0) or 0.0)
        # A fail-open record is a deliberate, logged degradation (NFR-04), not an
        # inconsistency, so it never counts as a band violation.
        failed_open = bool((decisive_rec or {}).get("decision", {}).get("fail_open_triggered"))
        violation = (not failed_open) and _is_violation(final, decisive_p)
        # ground truth: the record's own labels field if present, else the sidecar
        # joined on the provenance id the generator stamped
        prov = recs[0]["session"].get("provenance_id", "")
        lbl = (recs[0].get("labels", {}) or {}).get("ground_truth")
        if lbl not in ("attack", "benign"):   # record has no usable truth -> join sidecar
            lbl = labels.get(prov, {}).get("ground_truth", lbl or "?")
        views.append(SessionView(
            session_id=sid,
            provenance_id=prov,
            label=lbl,
            n_requests=len(recs),
            peak_malice=round(peak, 4),
            last_automation=round(last_auto, 4),
            action=final,
            baited=any(r["bait"].get("injected") for r in recs),
            bitten=any(r["bite"].get("occurred") for r in recs),
            in_decoy=any(r["session"].get("in_decoy") for r in recs),
            first_divert_req=first_div,
            decisive_malice=round(decisive_p, 4),
            band_violation=violation,
            requests=recs,
        ))
    # most interesting first: diverts, then baited, then by request count
    order = {"divert": 0, "bait": 1, "pass": 2}
    views.sort(key=lambda v: (order.get(v.action, 3), -v.n_requests))
    return views


def session_detail(sid: str, path: Path | None = None) -> SessionView | None:
    for v in load_sessions(path):
        if v.session_id == sid:
            return v
    return None


# ---------------------------------------------------------------------------
# evaluation KPIs
# ---------------------------------------------------------------------------


def _load_json(rel: str) -> Any:
    p = REPO / rel
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
    return None


def traffic_stats(path: Path | None = None) -> dict[str, Any]:
    """Aggregate the log into the flows a topology view needs: how many requests
    reached the target vs the decoy, how many baits were shown and bitten, and
    the breakdown by ground-truth class."""
    path = path or latest_proxy_log()
    recs: list[dict] = _read_records(path) if path and path.exists() else []
    sessions = load_sessions(path)

    req_to_target = sum(1 for r in recs if r["decision"].get("action") in ("pass", "bait"))
    req_to_decoy = sum(1 for r in recs if r["decision"].get("action") == "divert")
    baits_injected = sum(1 for r in recs if r["bait"].get("injected"))
    bites = sum(1 for r in recs if r["bite"].get("occurred"))

    by_class = {"attack": {}, "benign": {}, "?": {}}
    for cls in by_class:
        grp = [s for s in sessions if s.label == cls]
        by_class[cls] = {
            "sessions": len(grp),
            "diverted": sum(1 for s in grp if s.action == "divert"),
            "baited": sum(1 for s in grp if s.baited),
            "bitten": sum(1 for s in grp if s.bitten),
        }

    biters = [{"session_id": s.session_id, "label": s.label, "peak": s.peak_malice}
              for s in sessions if s.bitten][:12]

    n = len(sessions) or 1
    return {
        "total_sessions": len(sessions),
        "total_requests": len(recs),
        # Auditability: how many sessions took an action the derived bands do not
        # account for. Should be zero; surfacing it makes a regression in the
        # policy visible on the console instead of hiding inside an average.
        "band_violations": sum(1 for s in sessions if s.band_violation),
        "action_sessions": {
            "pass": sum(1 for s in sessions if s.action == "pass"),
            "bait": sum(1 for s in sessions if s.action == "bait"),
            "divert": sum(1 for s in sessions if s.action == "divert"),
        },
        "flows": {
            "client_to_proxy": len(recs),
            "proxy_to_target": req_to_target,
            "proxy_to_decoy": req_to_decoy,
            "baits_injected": baits_injected,
            "bites": bites,
        },
        "by_class": by_class,
        "biters": biters,
        "divert_share": round(sum(1 for s in sessions if s.action == "divert") / n, 3),
    }


def system_health() -> list[dict[str, Any]]:
    """One row per component: is it present / frozen / reachable. Read-only and
    fast (upstream probes use a short timeout and never block the page)."""
    import httpx

    out: list[dict[str, Any]] = []

    def add(name, status, detail):
        out.append({"component": name, "status": status, "detail": detail})

    # proxy log
    log = latest_proxy_log()
    if log:
        n = len(_read_records(log))
        add("proxy log", "ok", f"{n} records · {log.name}")
    else:
        add("proxy log", "idle", "no log yet")

    # frozen model
    try:
        from adf.freeze import verify as verify_freeze
        ok, problems = verify_freeze()
        add("frozen model", "ok" if ok else "warn",
            "verified · matches manifest" if ok else (problems[0][:60] if problems else "mismatch"))
    except Exception as e:
        add("frozen model", "warn", str(e)[:50])

    # cost table
    try:
        from adf.config import costs as load_cost_table
        t = load_cost_table()
        add("cost table", "ok", f"frozen · digest {getattr(t,'digest','')[:8]}")
    except Exception as e:
        add("cost table", "warn", str(e)[:50])

    # bait library
    try:
        from adf.policy.engine import BaitLibrary
        lib = BaitLibrary.load()
        cal = getattr(lib, "calibrated", None)
        add("bait library", "ok" if cal else "warn",
            f"{len(lib.effects())} baits · calibrated={cal}")
    except Exception as e:
        add("bait library", "warn", str(e)[:50])

    # decoy notebook
    nb = REPO / "data" / "decoy" / "notebook.sqlite3"
    if nb.exists():
        try:
            import sqlite3
            c = sqlite3.connect(nb)
            n = c.execute("SELECT COUNT(*) FROM facts").fetchone()[0]
            c.close()
            add("decoy notebook", "ok", f"{n} facts persisted")
        except Exception:
            add("decoy notebook", "ok", "present")
    else:
        add("decoy notebook", "idle", "not populated")

    # live upstreams (best-effort, short timeout)
    try:
        from adf.config import system
        cfg = system()
        for name, key in (("target app", "network.target_upstream"),
                          ("decoy app", "network.decoy_upstream")):
            url = cfg.get(key, "")
            up = False
            if url:
                try:
                    httpx.get(url.rstrip("/") + "/healthz", timeout=0.4)
                    up = True
                except Exception:
                    up = False
            add(name, "ok" if up else "idle", (url or "—") + (" · up" if up else " · not running"))
    except Exception:
        pass

    return out


def bait_library() -> list[dict[str, Any]]:
    """The calibrated probes the bands are derived from.

    The console showed a single "baits injected / bites" counter, which is the one
    number that cannot be acted on: the bands move because of *per-probe* bite
    rates, and a probe whose measured effectiveness is a retained prior is a much
    weaker claim than one measured over 180 sessions. Surfacing the library makes
    the derived bands auditable from the page itself.
    """
    try:
        from adf.policy.engine import BaitLibrary
        lib = BaitLibrary.load()
        out = []
        for e in lib.effects():
            lr_pos = (e.beta_attack / e.beta_benign) if e.beta_benign else None
            lr_neg = ((1 - e.beta_attack) / (1 - e.beta_benign)) if e.beta_benign < 1 else None
            out.append({
                "bait_id": e.bait_id,
                "category": getattr(e, "category", ""),
                "beta_attack": e.beta_attack,
                "beta_benign": e.beta_benign,
                "lr_bite": lr_pos,
                "lr_no_bite": lr_neg,
            })
        return sorted(out, key=lambda r: r["bait_id"])
    except Exception:
        return []


def kpi_provenance() -> dict[str, Any]:
    """Whether the stored evaluation report still matches the frozen artefacts.

    `report.json` is written under one cost table and one bait library. Re-freezing
    either leaves the file parseable, plausible and wrong -- the exact failure that
    had the figures reporting a superseded library for a day. `make_figures` refuses
    to plot a stale report; the console should not present one as current either.
    """
    ms = _load_json("data/eval/multiseed/report.json")
    prov = ((ms or {}).get("provenance") or {}).get("frozen_artefacts") or {}
    if not prov:
        return {"status": "unknown",
                "detail": "report.json predates artefact provenance — re-run tools.stats_report"}
    stale = []
    try:
        from adf.config import load_costs
        if prov.get("cost_digest") and prov["cost_digest"] != load_costs().digest:
            stale.append("cost table")
    except Exception:
        pass
    lib_path = REPO / "config" / "bait_library.yaml"
    if lib_path.exists() and prov.get("bait_library_sha256"):
        import hashlib
        live = hashlib.sha256(lib_path.read_bytes()).hexdigest()
        if live != prov["bait_library_sha256"]:
            stale.append("bait library")
    if stale:
        return {"status": "stale",
                "detail": f"produced under a different {' and '.join(stale)} — "
                          f"re-run the evaluation, then tools.stats_report"}
    return {"status": "current", "detail": "matches the frozen cost table and bait library"}


def load_kpis() -> dict[str, Any]:
    """Best-effort headline numbers from whatever eval output exists."""
    kpis: dict[str, Any] = {"arms": {}, "multiseed": None, "real_attack": None}

    summary = _load_json("data/eval/summary.json")
    if isinstance(summary, dict):
        for arm in ("b1_rules", "b2_passive", "b4_full"):
            a = summary.get(arm)
            if a:
                kpis["arms"][arm] = {
                    "recall": a.get("recall"),
                    "precision": a.get("precision"),
                    "benign_diversion": a.get("benign_diversion_rate"),
                    "cost": a.get("expected_cost_per_session"),
                }

    ms = _load_json("data/eval/multiseed/report.json")
    if isinstance(ms, dict):
        kpis["multiseed"] = {
            "seeds": ms.get("seeds"),
            "arms": {k: {"recall_pooled": v.get("recall_pooled"),
                         "recall_ci95": v.get("recall_ci95"),
                         # carried through so the safety tile can quote the POOLED
                         # false-positive rate; quoting a single draw underneath a
                         # pooled recall invites the wrong comparison
                         "benign_diversion": v.get("benign_diversion"),
                         "n_attack": v.get("n_attack")}
                     for k, v in ms.get("arms", {}).items()},
            "seeds_per_arm": ms.get("seeds_per_arm"),
            "holdout": ms.get("holdout_fisher"),
            "mcnemar": ms.get("mcnemar_b2_b4_attack"),
        }

    ra = _load_json("data/eval/real_attack.json")
    if isinstance(ra, dict):
        kpis["real_attack"] = ra.get("per_tool")

    return kpis
