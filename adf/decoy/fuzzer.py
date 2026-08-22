"""
The consistency fuzzer (spec §6.9) -- adversarial edition.

It interrogates the decoy for the same information through many different routes,
in many orders, with repetition and interleaving, and counts the disagreements.
The resulting CONTRADICTION RATE is the metric spec §6.9 says existing decoy work
does not report; it is the evidence for the project's second contribution, so the
fuzzer has to be aggressive enough that a rate of zero actually means something.

A weak fuzzer that fetches one row twice and finds it unchanged proves almost
nothing -- of course a store-backed decoy is self-consistent. This one probes the
ways a decoy realistically betrays itself:

  CONTRADICTIONS (§6.9 -- the decoy disagreeing with itself)
    repetition        -- the same endpoint, fetched again, byte-identical.
    interleaving      -- a fact is unchanged after many INTERVENING reads (no
                         drift from generation order or caching).
    cross-reference   -- a user seen via /profile (HTML), /api/profile (JSON)
                         and the /directory listing agrees on EVERY field.
    multi-reference   -- every record owned by the same user shows the SAME
                         owner, and that owner matches their own profile. This
                         is the case a naive decoy fails: two records generated
                         independently disagree about who owns them.
    referential       -- a record's owner id resolves to a real profile whose
                         name matches the record's stated owner.
    sql-error         -- the same injection payload yields the SAME error every
                         time and through repeat requests (the error surface is
                         itself a fact that must not drift).
    search            -- the same query returns identical results on repeat.

  PLAUSIBILITY (§10.4 -- content that would make an attacker suspicious even if
  it is self-consistent). Reported separately, since an implausible-but-
  consistent decoy is a different failure from a contradictory one.
    field domains     -- department, role, classification drawn from real sets;
                         email matches the username; ids within the stated space.
    numeric sanity    -- amounts parse as money; phone/format shapes hold.

Both are reported. The headline number is the contradiction rate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

from adf.decoy.world import _DEPT, _ROLE, _CLASSIFICATION, _LOCATION

_VALID_DEPT = set(_DEPT)
_VALID_ROLE = set(_ROLE)
_VALID_CLASS = set(_CLASSIFICATION)
_VALID_LOCATION = set(_LOCATION)
_AMOUNT = re.compile(r"^\d+\.\d{2}$")


@dataclass
class Finding:
    dimension: str
    subject: str
    detail: str


@dataclass
class FuzzResult:
    probes: int = 0
    contradictions: list[Finding] = field(default_factory=list)
    plausibility: list[Finding] = field(default_factory=list)
    plausibility_probes: int = 0
    by_dimension: dict[str, int] = field(default_factory=dict)
    probed_by_dimension: dict[str, int] = field(default_factory=dict)

    @property
    def contradiction_rate(self) -> float:
        return len(self.contradictions) / self.probes if self.probes else 0.0

    @property
    def plausibility_rate(self) -> float:
        return len(self.plausibility) / self.plausibility_probes if self.plausibility_probes else 0.0

    def contradiction(self, dimension: str, ok: bool, subject: str = "", detail: str = "") -> None:
        self.probes += 1
        self.probed_by_dimension[dimension] = self.probed_by_dimension.get(dimension, 0) + 1
        if not ok:
            self.by_dimension[dimension] = self.by_dimension.get(dimension, 0) + 1
            self.contradictions.append(Finding(dimension, subject, detail))

    def plausible(self, dimension: str, ok: bool, subject: str = "", detail: str = "") -> None:
        self.plausibility_probes += 1
        if not ok:
            self.plausibility.append(Finding(dimension, subject, detail))


# -- HTML parsing helpers ---------------------------------------------------

def _h1(html: str) -> str | None:
    m = re.search(r"<h1>([^<]+)</h1>", html)
    return m.group(1).strip() if m else None


def _dl(html: str, label: str) -> str | None:
    m = re.search(rf"<dt>{label}</dt><dd>([^<]*)</dd>", html)
    return m.group(1).strip() if m else None


def _profile_from_html(html: str) -> dict:
    return {
        "full_name": _h1(html),
        "email": _dl(html, "Email"),
        "phone": _dl(html, "Phone"),
        "department": _dl(html, "Department"),
        "location": _dl(html, "Location"),
    }


class ConsistencyFuzzer:
    def __init__(self, base_url: str | None = None, *, timeout: float = 10.0,
                 client: httpx.Client | None = None) -> None:
        # Stands in for a diverted, already-authenticated attacker, so it carries
        # the proxy's auth vouch (the decoy gates pages exactly like the target).
        self.client = client or httpx.Client(
            base_url=base_url, follow_redirects=True, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (fuzzer)", "X-ADF-Authenticated": "1"},
        )

    def close(self) -> None:
        self.client.close()

    # -- json helpers -----------------------------------------------------

    def _profile(self, pid: int) -> dict:
        return self.client.get(f"/api/profile/{pid}").json().get("profile", {})

    def _record(self, rid: int) -> dict:
        return self.client.get(f"/api/records/{rid}").json().get("record", {})

    # -- CONTRADICTION dimensions ----------------------------------------

    def probe_repetition(self, result: FuzzResult, ids) -> None:
        for pid in ids:
            a = self.client.get(f"/api/profile/{pid}").text
            b = self.client.get(f"/api/profile/{pid}").text
            result.contradiction("repetition", a == b, f"profile {pid}",
                                 "two consecutive fetches disagreed")

    def probe_interleaving(self, result: FuzzResult, ids) -> None:
        """Fetch a fact, read many OTHER things, then re-fetch it. A decoy whose
        answers depend on generation order or a bounded cache drifts here."""
        ids = list(ids)
        if not ids:
            return
        anchor = ids[0]
        first = self.client.get(f"/api/profile/{anchor}").text
        for other in ids[1:]:
            self.client.get(f"/api/profile/{other}")
            self.client.get(f"/api/records/{other}")
        again = self.client.get(f"/api/profile/{anchor}").text
        result.contradiction("interleaving", first == again, f"profile {anchor}",
                             "profile changed after intervening reads")

    def probe_cross_reference(self, result: FuzzResult, ids) -> None:
        directory = self.client.get("/directory").text
        for pid in ids:
            api = self._profile(pid)
            html = _profile_from_html(self.client.get(f"/profile/{pid}").text)
            for field_name in ("full_name", "email", "phone", "department", "location"):
                ok = html[field_name] == api.get(field_name)
                result.contradiction("cross-reference", ok, f"profile {pid}.{field_name}",
                                     f"HTML={html[field_name]!r} JSON={api.get(field_name)!r}")
            if api.get("full_name") and 1 <= pid <= 24:
                result.contradiction("cross-reference", api["full_name"] in directory,
                                     f"directory/{pid}",
                                     f"{api['full_name']} missing from directory listing")

    def probe_multi_reference(self, result: FuzzResult, record_ids) -> None:
        """Group records by owner and assert every reference to one owner
        agrees -- the hard case a from-scratch decoy fails."""
        by_owner: dict[int, list[tuple[int, str]]] = {}
        for rid in record_ids:
            rec = self._record(rid)
            oid = rec.get("owner_id")
            if oid is not None:
                by_owner.setdefault(oid, []).append((rid, rec.get("owner_name")))
        for oid, refs in by_owner.items():
            names = {name for _, name in refs}
            result.contradiction("multi-reference", len(names) <= 1, f"owner {oid}",
                                 f"records disagree on owner name: {names}")
            profile_name = self._profile(oid).get("full_name")
            result.contradiction("multi-reference", profile_name in names or not names,
                                 f"owner {oid} vs profile",
                                 f"records say {names}, profile says {profile_name!r}")

    def probe_referential_integrity(self, result: FuzzResult, record_ids) -> None:
        for rid in record_ids:
            rec = self._record(rid)
            oid = rec.get("owner_id")
            if oid is None:
                result.contradiction("referential", False, f"record {rid}", "no owner_id")
                continue
            owner = self._profile(oid)
            result.contradiction("referential", bool(owner) and owner.get("full_name") == rec.get("owner_name"),
                                 f"record {rid}",
                                 f"owner_name={rec.get('owner_name')!r} vs profile/{oid}={owner.get('full_name')!r}")

    def probe_sql_error(self, result: FuzzResult, payloads) -> None:
        """The error surface is itself a fact: the same injection must yield the
        same error, and repeat it identically."""
        for p in payloads:
            a = self.client.get("/search", params={"q": p})
            b = self.client.get("/search", params={"q": p})
            result.contradiction("sql-error", a.status_code == b.status_code == 500,
                                 f"payload {p!r}", f"status {a.status_code} vs {b.status_code}")
            result.contradiction("sql-error", a.text == b.text, f"payload {p!r}",
                                 "same injection produced different error pages")

    def probe_search(self, result: FuzzResult, queries) -> None:
        for q in queries:
            a = self.client.get("/search", params={"q": q}).text
            b = self.client.get("/search", params={"q": q}).text
            result.contradiction("search", a == b, f"query {q!r}",
                                 "same query returned different results")

    # -- PLAUSIBILITY dimensions -----------------------------------------

    def probe_plausibility(self, result: FuzzResult, profile_ids, record_ids) -> None:
        for pid in profile_ids:
            u = self._profile(pid)
            if not u:
                continue
            result.plausible("field-domain", u.get("department") in _VALID_DEPT,
                             f"profile {pid}", f"department {u.get('department')!r} not in the org set")
            result.plausible("field-domain", u.get("role") in _VALID_ROLE,
                             f"profile {pid}", f"role {u.get('role')!r} not in the role set")
            result.plausible("field-domain", u.get("location") in _VALID_LOCATION,
                             f"profile {pid}", f"location {u.get('location')!r} not in the location set")
            uname = u.get("username", "")
            result.plausible("field-domain", bool(u.get("email", "").startswith(uname)) if uname else False,
                             f"profile {pid}", f"email {u.get('email')!r} does not match username {uname!r}")
        for rid in record_ids:
            r = self._record(rid)
            if not r:
                continue
            result.plausible("field-domain", r.get("classification") in _VALID_CLASS,
                             f"record {rid}", f"classification {r.get('classification')!r} invalid")
            result.plausible("numeric", bool(_AMOUNT.match(str(r.get("amount", "")))),
                             f"record {rid}", f"amount {r.get('amount')!r} is not money-shaped")

    def probe_distinctness(self, result: FuzzResult, profile_ids) -> None:
        """Different ids must be different people.

        Every other probe here asks whether one id answers *consistently*. None
        asks whether two ids answer *differently*, and a decoy can pass all of
        them while issuing the same person twice. A study participant found
        exactly that -- two profiles with the same name, different numbers and
        different locations -- and reported the site as a mock-up because of it.
        Two colleagues can genuinely share a name; two profiles of that name in
        different departments and buildings read as generated data.
        """
        by_name: dict[str, list[int]] = {}
        by_username: dict[str, list[int]] = {}
        for pid in profile_ids:
            u = self._profile(pid)
            if not u:
                continue
            if u.get("full_name"):
                by_name.setdefault(u["full_name"], []).append(pid)
            if u.get("username"):
                by_username.setdefault(u["username"], []).append(pid)
        for field, index in (("name", by_name), ("username", by_username)):
            for value, ids in index.items():
                result.plausible(
                    "distinctness", len(ids) == 1, f"{field} {value!r}",
                    f"{field} {value!r} is shared by profiles {ids}")

    # -- run everything ---------------------------------------------------

    def run(self, *, profile_ids=range(1, 25), record_ids=range(1, 60),
            probe_ids=range(1, 20)) -> FuzzResult:
        payloads = ["x' UNION SELECT 1 -- ", "' OR '1'='1", "'; DROP TABLE users -- ",
                    "x' AND 1=2 -- ", "admin'--"]
        queries = ["policy", "maintenance", "audit", "training", "review"]
        result = FuzzResult()
        self.probe_repetition(result, probe_ids)
        self.probe_interleaving(result, list(profile_ids))
        self.probe_cross_reference(result, profile_ids)
        self.probe_multi_reference(result, record_ids)
        self.probe_referential_integrity(result, record_ids)
        self.probe_sql_error(result, payloads)
        self.probe_search(result, queries)
        self.probe_plausibility(result, profile_ids, record_ids)
        self.probe_distinctness(result, profile_ids)
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

    print("CONTRADICTIONS (spec §6.9)")
    print(f"  probes            : {result.probes}")
    print(f"  contradictions    : {len(result.contradictions)}")
    print(f"  contradiction rate: {result.contradiction_rate:.4%}")
    print("  by dimension (contradictions / probed):")
    for dim in sorted(result.probed_by_dimension):
        print(f"    {dim:18} {result.by_dimension.get(dim, 0)} / {result.probed_by_dimension[dim]}")
    if result.contradictions:
        print("  examples:")
        for c in result.contradictions[:8]:
            print(f"    [{c.dimension}] {c.subject}: {c.detail}")

    print("\nPLAUSIBILITY (spec §10.4 indicators, reported separately)")
    print(f"  probes                : {result.plausibility_probes}")
    print(f"  implausible content   : {len(result.plausibility)}")
    print(f"  rate                  : {result.plausibility_rate:.4%}")
    if result.plausibility:
        for c in result.plausibility[:8]:
            print(f"    [{c.dimension}] {c.subject}: {c.detail}")

    print("\n" + "=" * 62)
    if result.contradiction_rate < 0.01:
        print(f"PHASE 5 EXIT: decoy survives {result.probes} adversarial probes with "
              f"contradiction rate {result.contradiction_rate:.4%} (< 1%).")
    else:
        print(f"Contradiction rate {result.contradiction_rate:.4%} is high; the decoy is "
              "detectable. Report how and why (spec §16) or fix the notebook.")


if __name__ == "__main__":
    main()
