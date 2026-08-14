"""
The consistency fuzzer (spec §6.9).

It interrogates the decoy for the same information through several different
routes and counts the disagreements. The resulting CONTRADICTION RATE is a
reportable metric and, as spec §6.9 notes, is not something existing decoy work
measures -- it is the evidence for the project's second contribution.

The fuzzer probes each of the four consistency dimensions §6.9 names:

  1. Repetition       -- fetch the same endpoint twice; the bytes must match.
  2. Cross-reference  -- a user seen via /profile/{id} (HTML), /api/profile/{id}
                         (JSON) and the /directory listing must agree on name,
                         email and department.
  3. Write-then-read  -- (covered by the notebook tests; the HTTP decoy has no
                         write surface, so it is checked at the store level.)
  4. Referential integrity -- a record's owner, followed to that owner's
                         profile, must resolve and match.

A "probe" is a single consistency question with two or more observations that
must agree. The contradiction rate is contradicting-probes / total-probes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx


@dataclass
class Contradiction:
    dimension: str
    subject: str
    detail: str


@dataclass
class FuzzResult:
    probes: int = 0
    contradictions: list[Contradiction] = field(default_factory=list)
    by_dimension: dict[str, int] = field(default_factory=dict)

    @property
    def contradiction_rate(self) -> float:
        return len(self.contradictions) / self.probes if self.probes else 0.0

    def record(self, dimension: str, ok: bool, subject: str = "", detail: str = "") -> None:
        self.probes += 1
        self.by_dimension.setdefault(dimension, 0)
        if not ok:
            self.by_dimension[dimension] += 1
            self.contradictions.append(Contradiction(dimension, subject, detail))


_EMAIL = re.compile(r"[\w.]+@[\w.-]+")


def _name_from_profile_html(html: str) -> str | None:
    m = re.search(r"<h1>([^<]+)</h1>", html)
    return m.group(1).strip() if m else None


def _field_from_dl(html: str, label: str) -> str | None:
    m = re.search(rf"<dt>{label}</dt><dd>([^<]+)</dd>", html)
    return m.group(1).strip() if m else None


class ConsistencyFuzzer:
    def __init__(self, base_url: str | None = None, *, timeout: float = 10.0,
                 client: httpx.Client | None = None) -> None:
        # `client` lets tests drive an in-process ASGI decoy without binding a
        # socket; `base_url` is the live path.
        #
        # The fuzzer stands in for a DIVERTED, already-authenticated attacker
        # exploring the decoy, so it presents the proxy's auth vouch. The decoy
        # gates its pages exactly as the target does, so without this the fuzzer
        # would only ever see the login redirect.
        self.client = client or httpx.Client(
            base_url=base_url, follow_redirects=True, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (fuzzer)", "X-ADF-Authenticated": "1"},
        )

    def close(self) -> None:
        self.client.close()

    # -- dimension 1: repetition ------------------------------------------

    def probe_repetition(self, result: FuzzResult, ids: range) -> None:
        for pid in ids:
            a = self.client.get(f"/api/profile/{pid}").text
            b = self.client.get(f"/api/profile/{pid}").text
            result.record("repetition", a == b, subject=f"profile {pid}",
                          detail="two fetches of the same profile disagreed")

    # -- dimension 2: cross-reference -------------------------------------

    def probe_cross_reference(self, result: FuzzResult, ids: range) -> None:
        # directory listing, parsed once
        directory = self.client.get("/directory").text
        for pid in ids:
            html = self.client.get(f"/profile/{pid}").text
            api = self.client.get(f"/api/profile/{pid}").json().get("profile", {})

            html_name = _name_from_profile_html(html)
            html_email = _field_from_dl(html, "Email")
            html_dept = _field_from_dl(html, "Department")

            ok = (html_name == api.get("full_name")
                  and html_email == api.get("email")
                  and html_dept == api.get("department"))
            result.record("cross-reference", ok, subject=f"profile {pid}",
                          detail=f"HTML({html_name},{html_email},{html_dept}) vs "
                                 f"JSON({api.get('full_name')},{api.get('email')},{api.get('department')})")

            # the name shown in the directory must match too, if present there
            if api.get("full_name") and api["full_name"] in directory:
                result.record("cross-reference", True, subject=f"directory {pid}")
            elif api.get("full_name"):
                # only a contradiction if the profile claims a directory listing
                # exists; the directory only lists ids 1..24
                if 1 <= pid <= 24:
                    result.record("cross-reference", False, subject=f"directory {pid}",
                                  detail=f"{api['full_name']} not found in directory listing")

    # -- dimension 4: referential integrity -------------------------------

    def probe_referential_integrity(self, result: FuzzResult, ids: range) -> None:
        for rid in ids:
            rec = self.client.get(f"/api/records/{rid}").json().get("record", {})
            owner_id = rec.get("owner_id")
            owner_name_in_record = rec.get("owner_name")
            if owner_id is None:
                result.record("referential-integrity", False, subject=f"record {rid}",
                              detail="record has no owner_id")
                continue
            owner = self.client.get(f"/api/profile/{owner_id}").json().get("profile", {})
            ok = bool(owner) and owner.get("full_name") == owner_name_in_record
            result.record("referential-integrity", ok, subject=f"record {rid}",
                          detail=f"record.owner_name={owner_name_in_record} but "
                                 f"profile/{owner_id}.full_name={owner.get('full_name')}")

    # -- run everything ---------------------------------------------------

    def run(self, *, profile_ids: range = range(1, 25),
            record_ids: range = range(1, 40),
            probe_ids: range = range(1, 15)) -> FuzzResult:
        result = FuzzResult()
        self.probe_repetition(result, probe_ids)
        self.probe_cross_reference(result, profile_ids)
        self.probe_referential_integrity(result, record_ids)
        return result


def main() -> None:
    import argparse
    from adf.config import system

    cfg = system()
    ap = argparse.ArgumentParser(description="Measure the decoy's contradiction rate (spec §6.9).")
    ap.add_argument("--base-url",
                    default=f"http://{cfg.get('network.bind_host','127.0.0.1')}:{cfg.get('network.decoy_port',8002)}")
    args = ap.parse_args()

    print(f"fuzzing decoy at {args.base_url} ...\n")
    fz = ConsistencyFuzzer(args.base_url)
    try:
        result = fz.run()
    finally:
        fz.close()

    print(f"probes            : {result.probes}")
    print(f"contradictions    : {len(result.contradictions)}")
    print(f"contradiction rate: {result.contradiction_rate:.4%}")
    print("\nby dimension (contradictions / probed):")
    for dim, bad in sorted(result.by_dimension.items()):
        print(f"  {dim:22} {bad}")
    if result.contradictions:
        print("\nexamples:")
        for c in result.contradictions[:8]:
            print(f"  [{c.dimension}] {c.subject}: {c.detail}")

    print("\n" + "=" * 60)
    if result.contradiction_rate < 0.01:
        print(f"PHASE 5 EXIT: decoy survives the fuzzer with contradiction rate "
              f"{result.contradiction_rate:.4%} (< 1%).")
    else:
        print(f"Contradiction rate {result.contradiction_rate:.4%} is high; the decoy "
              "is detectable. Report how and why (spec §16) or fix the notebook.")


if __name__ == "__main__":
    main()
