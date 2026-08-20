"""
The invisibility gate (spec §6.7, NFR-01) -- the single most important safety
mechanism in the project.

Spec §13.1 is emphatic that this is built BEFORE any bait. A bait that leaks
into normal user experience does not merely weaken the results; it invalidates
the central claim of the research, which is that provoking is safe. So the rule
is strict: every bait must pass this gate before it may enter the library, and
a bait that fails is DELETED, not scheduled for repair (spec §6.7).

The gate asserts the three things §6.7 requires, against a corpus of real
benign responses:

  1. Rendered output is identical -- what a browser paints is unchanged
     (`compare_rendered`, which strips comments/scripts/hidden nodes).
  2. No functional change -- forms still submit, links still resolve, and a
     JSON response still parses with every original field intact.
  3. No timing change -- the injection's added latency is below the noise floor
     of ordinary response timing, so it cannot be used to detect the bait.

A pass produces a CERTIFICATE (id, timestamp, corpus size, measured overhead)
that the bait engine checks at run time before serving the bait -- enforcing
the "verified before use" rule in the running system, not just at build time.
"""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from adf.bait.baits import Bait, build_bait, BAIT_SPECS
from adf.bait.channels import BaitedResponse, compare_rendered, BaitInjectionError

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CERTIFICATE_PATH = REPO_ROOT / "config" / "bait_certificates.json"

# The added latency a bait may introduce, in milliseconds, before it is
# considered detectable. Injection is pure string/dict work; this ceiling is
# far below the millisecond-scale jitter of a real response, so an attacker
# cannot separate a baited response from an unbaited one by timing.
MAX_OVERHEAD_MS = 0.5


@dataclass
class GateResult:
    bait_id: str
    passed: bool
    tested_responses: int
    injected_responses: int          # how many of the corpus responses it applied to
    median_overhead_ms: float
    p95_overhead_ms: float
    failures: list[str] = field(default_factory=list)
    ts: str = ""

    def certificate(self) -> dict:
        return {
            "bait_id": self.bait_id,
            "passed": self.passed,
            "tested_responses": self.tested_responses,
            "injected_responses": self.injected_responses,
            "median_overhead_ms": round(self.median_overhead_ms, 4),
            "p95_overhead_ms": round(self.p95_overhead_ms, 4),
            "ts": self.ts or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }


class InvisibilityGate:
    def __init__(self, *, max_overhead_ms: float = MAX_OVERHEAD_MS) -> None:
        self.max_overhead_ms = max_overhead_ms

    def test(self, bait: Bait, corpus: list[BaitedResponse]) -> GateResult:
        """Run one bait against a corpus of clean benign responses."""
        failures: list[str] = []
        overheads: list[float] = []
        injected = 0

        applicable = [r for r in corpus if bait.applicable(r)]
        if not applicable:
            failures.append(
                "bait applies to none of the corpus responses; it cannot be "
                "verified and therefore must not enter the library"
            )

        for clean in applicable:
            try:
                started = time.perf_counter()
                baited = bait.inject(clean)
                overheads.append((time.perf_counter() - started) * 1000.0)
            except BaitInjectionError as exc:
                failures.append(f"injection refused on a benign response: {exc}")
                continue
            injected += 1

            # 1 + 2: rendered output and functional structure identical
            diff = compare_rendered(clean, baited)
            if not diff.identical:
                failures.append("visible/functional change: " + "; ".join(diff.reasons))

            # 2 (cont.): a JSON response must still parse
            if "json" in (baited.content_type or "").lower() or baited.body.lstrip()[:1] in ("{", "["):
                try:
                    json.loads(baited.body)
                except json.JSONDecodeError:
                    failures.append("baited JSON no longer parses")

        median = statistics.median(overheads) if overheads else 0.0
        p95 = _percentile(overheads, 95) if overheads else 0.0

        # 3: timing indistinguishable
        if median > self.max_overhead_ms:
            failures.append(
                f"added latency {median:.3f}ms exceeds the {self.max_overhead_ms}ms ceiling"
            )

        return GateResult(
            bait_id=bait.bait_id,
            passed=not failures,
            tested_responses=len(corpus),
            injected_responses=injected,
            median_overhead_ms=median,
            p95_overhead_ms=p95,
            failures=_dedupe(failures),
            ts=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * pct / 100.0
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def _dedupe(items: list[str]) -> list[str]:
    seen, out = set(), []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


# ---------------------------------------------------------------------------
# Certificate store -- the run-time enforcement of "verified before use"
# ---------------------------------------------------------------------------


def certify_all(corpus: list[BaitedResponse], *, seed: int = 0,
                path: Path | None = None) -> dict[str, GateResult]:
    """Run every bait through the gate and write certificates for those that
    pass. Failing baits are recorded as failed and are NOT certified, so the
    engine will refuse to serve them (the deletion rule, enforced at run time)."""
    path = path or CERTIFICATE_PATH
    gate = InvisibilityGate()
    results: dict[str, GateResult] = {}
    certificates: dict[str, dict] = {}

    for bait_id in BAIT_SPECS:
        bait = build_bait(bait_id, session_id="gate-certification", seed=seed)
        result = gate.test(bait, corpus)
        results[bait_id] = result
        if result.passed:
            certificates[bait_id] = result.certificate()

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gate_version": 1,
        "max_overhead_ms": MAX_OVERHEAD_MS,
        "certificates": certificates,
    }, indent=2), encoding="utf-8")
    return results


def _load_certificate_doc(path: Path | None = None) -> dict:
    path = path or CERTIFICATE_PATH
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def load_certificates(path: Path | None = None) -> dict[str, dict]:
    return _load_certificate_doc(path).get("certificates", {})


def is_certified(bait_id: str, path: Path | None = None) -> bool:
    return bait_id in load_certificates(path)


def certificate_id(bait_id: str, path: Path | None = None) -> str:
    """Identifier of the gate run that certified this bait; "" if uncertified.

    `adf.schema.BaitBlock.invisibility_certificate` is documented as "id of the
    passing gate run" (spec §6.7) and the README claims a served bait "carries a
    certificate the engine checks at run time". The check was enforced -- but
    nothing ever wrote the id, so every log line showed an empty certificate on
    a served bait. A reviewer reading the logs could not tell an authorised
    injection from an unauthorised one. This closes that gap.
    """
    doc = _load_certificate_doc(path)
    cert = doc.get("certificates", {}).get(bait_id)
    if not cert or not cert.get("passed"):
        return ""
    stamp = cert.get("ts") or doc.get("generated", "")
    return f"gate{doc.get('gate_version', 0)}@{stamp}"
