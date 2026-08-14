"""
FROZEN RECORD SCHEMA v3  —  Phase 0 artefact (spec §6.11, §11, §13 Phase 0).

Every request, decision, score and label the system ever emits uses this
shape. It is frozen deliberately and early, because the single practical
warning in spec §11 is that deciding the format after collection has begun
means either re-running every experiment or abandoning the dataset release.

The freeze is enforced, not merely documented: SCHEMA_FINGERPRINT is a hash
over the field layout, and tests/test_frozen_artefacts.py fails if the layout
drifts without a version bump. Adding a field is a schema change like any
other -- bump the version and migrate, do not silently extend.

The v1 -> v2 bump happened before any corpus collection, which is the only
time such a change is free. After collection begins it costs a re-run.

This module deliberately depends on nothing outside the standard library so
that it can be imported by the target app, the decoy, the proxy, the traffic
generators and the analysis notebooks alike.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Literal

SCHEMA_VERSION = 3

# v1 -> v2 (2026-08-13, BEFORE any corpus collection -- see
# docs/DECISIONS.md). Three changes, all forced by the value-of-information
# reformulation of the decision policy:
#
#   * `Round` became a named vocabulary and gained `calibrate`. The v1
#     rounds {0,1,2} had nowhere to put bait-effectiveness estimation:
#     round 1 predates the bait library and round 2 is the test set, so the
#     bite parameters had no legitimate source of data at all.
#   * `DecisionBlock` gained `evsi` and `bait_assignment`, so the information
#     value behind each decision, and whether the session was in the
#     randomised no-bait holdout, are both recoverable from the log.
#   * `BiteBlock` gained `cross_session` and `likelihood_ratio`: a token
#     presented by a session other than the one it was issued to is stronger
#     evidence than an ordinary bite, and was previously unrepresentable.
#
# v2 -> v3 (2026-08-13, still before corpus collection). `SessionBlock` gained
# `provenance_id`. Found by checking rather than assuming: labels were keyed by
# the generator's session id and records by the application's cookie, two
# namespaces that never met, so the join produced ZERO matches and the corpus
# was silently unlabelled. Phase 1's exit condition requires a *labelled*
# corpus, so this was a blocking defect rather than an inconvenience.

# --------------------------------------------------------------------------
# Controlled vocabularies. Labels are applied at the point of generation
# (spec §7.3) -- never inferred afterwards by inspecting traffic -- so these
# enumerations are what the generators write, not what a classifier guesses.
# --------------------------------------------------------------------------

GroundTruth = Literal["benign", "attack", "unknown"]

#: Three attack categories, reduced from six by scope discipline (spec §15.1).
#: `auth` spans both credential attack and OTP bypass; the distinction is
#: carried in `attack_subcategory` so it stays recoverable in the dataset.
AttackCategory = Literal["none", "sqli", "idor", "auth", "unknown"]

AttackSubcategory = Literal[
    "none",
    "sqli_union",
    "sqli_boolean",
    "sqli_error",
    "sqli_time",
    "idor_sequential",
    "idor_tamper",
    "auth_credential_stuffing",
    "auth_bruteforce",
    "auth_otp_bypass",
    "auth_otp_reuse",
    "recon",
    "unknown",
]

AutomationLabel = Literal["human", "scripted", "hybrid", "unknown"]

#: The three-outcome decision that is contribution #1 of this project (§4.3).
Action = Literal["pass", "bait", "divert"]

#: Which experimental round produced this record. These are NEVER mixed
#: (spec §7.2): each round has exactly one permitted use.
#:
#:   dev       throwaway smoke traffic; never enters any reported result
#:   train     attack round 1 -- fits the suspicion meter, and nothing else
#:   calibrate attack round 1b -- estimates bait effectiveness ONLY
#:   eval      attack round 2 -- reported results ONLY, model already frozen
#:
#: `calibrate` does not appear in the specification. It exists because the
#: spec's phase order leaves the bait parameters uncalibrated: round 1 runs
#: before the bait library is built (Phase 2 precedes Phase 4) so it contains
#: no bites, and round 2 is the held-out test set. Estimating bait
#: effectiveness on either would be indefensible, so it gets its own round,
#: run after Phase 4 and frozen before Phase 7.
Round = Literal["dev", "train", "calibrate", "eval"]

#: How the BAIT action came about. Sessions in the randomised holdout sit in
#: the bait band but are deliberately not baited, which turns bait into an
#: assigned treatment and lets its effect be estimated causally rather than
#: by comparing two different systems (see docs/NOVELTY.md).
BaitAssignment = Literal["none", "policy", "holdout", "forced"]

RecordSource = Literal["proxy", "target-access", "decoy-access", "fuzzer"]

#: Header carrying the generator's session marker. Synthetic traffic only; a
#: real client never sends it. Recorded into `session.provenance_id`, never
#: into `request.headers`, so it cannot leak into a feature vector.
PROVENANCE_HEADER = "x-adf-session"

#: Fields that are ground truth or provenance, and must never be read by the
#: feature extractor, the meter or the policy. Training on any of these would
#: mean training on the answer key, and the resulting accuracy would be
#: meaningless. `adf.features` asserts against this set.
NEVER_FEATURE_FIELDS = frozenset({
    "labels",                  # the entire label block
    "session.provenance_id",   # join key, uniquely identifies the generator's intent
    "bite.issued_to_session",  # bookkeeping, not evidence
})


def utc_now_iso() -> str:
    """Timestamps are UTC and ISO-8601 with explicit offset, always."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


# --------------------------------------------------------------------------
# Nested blocks
# --------------------------------------------------------------------------


@dataclass
class RunBlock:
    """Which experiment this record belongs to. Carries the seed so any run
    is reproducible from the log alone (NFR-08)."""

    run_id: str = ""
    mode: str = "b4_full"          # see config/system.yaml `mode`
    seed: int = 0
    round: Round = "dev"
    notes: str = ""


@dataclass
class SessionBlock:
    """One continuous run of activity by a single visitor (spec §21)."""

    session_id: str = ""
    fingerprint: str = ""          # fallback identity when no cookie is carried
    request_index: int = 0         # 0-based position of this request in the session
    in_decoy: bool = False

    #: Identifier assigned by whatever GENERATED this traffic, used solely to
    #: join the record to its ground-truth label (spec §7.3).
    #:
    #: This is necessary because the generator names a session before it makes
    #: its first request -- which is what lets the label be written in advance
    #: rather than inferred afterwards -- while the application names the same
    #: session independently, via its own cookie. Without a carried marker the
    #: two namespaces never meet and the corpus cannot be labelled at all.
    #:
    #: *** THIS FIELD IS THE ANSWER KEY AND MUST NEVER BECOME A FEATURE. ***
    #: It is held here, outside `request.headers`, precisely so that anything
    #: reading headers to build a feature vector cannot reach it by accident.
    #: See NEVER_FEATURE_FIELDS below.
    provenance_id: str = ""


@dataclass
class RequestBlock:
    method: str = ""
    path: str = ""
    query: str = ""
    query_params: dict[str, list[str]] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    header_order: list[str] = field(default_factory=list)  # ordering is an automation signal (§6.3)
    body: str = ""
    body_truncated: bool = False
    content_type: str = ""
    remote_addr: str = ""
    user_agent: str = ""


@dataclass
class ResponseBlock:
    status: int = 0
    bytes: int = 0
    elapsed_ms: float = 0.0
    content_type: str = ""


@dataclass
class ScorePair:
    """The two independent scores of spec §6.4. One combined score cannot
    express 'automated but harmless' and 'manual but hostile' at once."""

    automation: float = 0.0
    malice: float = 0.0


@dataclass
class ScoresBlock:
    before: ScorePair = field(default_factory=ScorePair)
    after: ScorePair = field(default_factory=ScorePair)
    p_attack: float = 0.0          # fused hostility probability fed to the policy


@dataclass
class ReasonItem:
    """One feature's contribution to the decision. The presence of this list
    on every record is what satisfies NFR-07 (explainability) and is what
    makes the evaluation defensible months later (spec §6.11)."""

    feature: str = ""
    value: float = 0.0
    weight: float = 0.0
    contribution: float = 0.0


@dataclass
class DecisionBlock:
    action: Action = "pass"
    reason: list[ReasonItem] = field(default_factory=list)
    expected_costs: dict[str, float] = field(default_factory=dict)   # pass/bait/divert
    thresholds: dict[str, float] = field(default_factory=dict)       # derived, not tuned
    policy_version: str = ""
    fail_open_triggered: bool = False

    #: Expected value of the information a bait would buy at this belief,
    #: in the same cost units as `expected_costs`. This is what justifies the
    #: BAIT action; logging it makes the justification auditable per request.
    evsi: float = 0.0

    #: Whether bait was applied by the policy, withheld by the randomised
    #: holdout, or forced (replay and ablation runs).
    bait_assignment: BaitAssignment = "none"


@dataclass
class BaitBlock:
    injected: bool = False
    bait_id: str = ""              # e.g. B-SQL-1 (spec §6.6)
    category: AttackCategory = "none"
    token: str = ""                # session-unique bait content (§16 mitigation)
    location: str = ""             # where it was injected: body_html_comment, json_field, error_text...
    invisibility_certificate: str = ""   # id of the passing gate run (§6.7)


@dataclass
class BiteBlock:
    """A bite is the moment an attacker acts on bait, thereby identifying
    themselves (spec §21). This is the manufactured evidence the whole
    research claim rests on."""

    occurred: bool = False
    bait_id: str = ""
    matched_token: str = ""
    evidence: str = ""             # where the token was seen: param name, path, body

    #: True when the token was presented by a session other than the one it
    #: was issued to. Bait content is unique per session (spec §6.6), so this
    #: means either an attacker rotating identity or a leaked token -- both
    #: more informative than an ordinary bite, and the early warning that a
    #: bait has been published and is burning (spec §16).
    cross_session: bool = False
    issued_to_session: str = ""

    #: P(bite | attacker) / P(bite | benign) for the bait that was taken,
    #: estimated in the `calibrate` round. This is the evidence weight the
    #: meter applies -- derived, never a hand-set "jump sharply" constant.
    likelihood_ratio: float = 0.0


@dataclass
class PlantedCredentialBlock:
    """Spec §6.10 -- proves exploration, harvesting and intent at once."""

    used: bool = False
    key_id: str = ""


@dataclass
class LabelsBlock:
    """Applied at generation time by whatever produced the traffic."""

    ground_truth: GroundTruth = "unknown"
    attack_category: AttackCategory = "unknown"
    attack_subcategory: AttackSubcategory = "unknown"
    automation_label: AutomationLabel = "unknown"
    generator: str = ""            # benign_traffic.py, sqlmap, hydra, manual, ...
    tool_version: str = ""
    notes: str = ""


@dataclass
class IntegrityBlock:
    """Tamper-evidence (NFR-13). Each record chains to the previous one, so
    any retroactive edit or deletion breaks the chain verifiably."""

    prev_hash: str = ""
    hash: str = ""


# --------------------------------------------------------------------------
# The record
# --------------------------------------------------------------------------


@dataclass
class Record:
    """One line of the append-only log, and one row of the released dataset."""

    schema_version: int = SCHEMA_VERSION
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    seq: int = 0
    ts: str = field(default_factory=utc_now_iso)
    source: RecordSource = "proxy"

    run: RunBlock = field(default_factory=RunBlock)
    session: SessionBlock = field(default_factory=SessionBlock)
    request: RequestBlock = field(default_factory=RequestBlock)
    response: ResponseBlock = field(default_factory=ResponseBlock)

    features: dict[str, float] = field(default_factory=dict)
    scores: ScoresBlock = field(default_factory=ScoresBlock)
    decision: DecisionBlock = field(default_factory=DecisionBlock)

    bait: BaitBlock = field(default_factory=BaitBlock)
    bite: BiteBlock = field(default_factory=BiteBlock)
    planted_credential: PlantedCredentialBlock = field(default_factory=PlantedCredentialBlock)

    labels: LabelsBlock = field(default_factory=LabelsBlock)
    integrity: IntegrityBlock = field(default_factory=IntegrityBlock)

    # -- serialisation -----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def canonical_json(self, *, exclude_integrity: bool = True) -> str:
        """Deterministic encoding used for hashing.

        The integrity block is excluded by default because a record cannot
        contain its own hash while that hash is being computed.
        """
        d = self.to_dict()
        if exclude_integrity:
            d.pop("integrity", None)
        return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def content_hash(self, prev_hash: str = "") -> str:
        payload = prev_hash + "\n" + self.canonical_json()
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def hash_raw(raw: dict[str, Any], prev_hash: str = "") -> str:
        """Chain hash computed directly from the STORED dict, without routing
        through from_dict().

        Verification must hash exactly the bytes that were written, not a
        reconstructed record: any imperfection in from_dict() (a dropped or
        renamed field) would otherwise be indistinguishable from tampering.
        Because the writer stored json.dumps(to_dict()), the raw dict read back
        equals that to_dict(), so canonicalising it here reproduces the string
        that was hashed at write time."""
        d = dict(raw)
        d.pop("integrity", None)
        canonical = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256((prev_hash + "\n" + canonical).encode("utf-8")).hexdigest()

    def to_json_line(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Record":
        def build(cls, value):
            if value is None:
                return cls()
            known = {f for f in cls.__dataclass_fields__}
            return cls(**{k: v for k, v in value.items() if k in known})

        rec = Record(
            schema_version=d.get("schema_version", SCHEMA_VERSION),
            record_id=d.get("record_id", ""),
            seq=d.get("seq", 0),
            ts=d.get("ts", ""),
            source=d.get("source", "proxy"),
            features=d.get("features", {}) or {},
        )
        rec.run = build(RunBlock, d.get("run"))
        rec.session = build(SessionBlock, d.get("session"))
        rec.request = build(RequestBlock, d.get("request"))
        rec.response = build(ResponseBlock, d.get("response"))
        rec.bait = build(BaitBlock, d.get("bait"))
        rec.bite = build(BiteBlock, d.get("bite"))
        rec.planted_credential = build(PlantedCredentialBlock, d.get("planted_credential"))
        rec.labels = build(LabelsBlock, d.get("labels"))
        rec.integrity = build(IntegrityBlock, d.get("integrity"))

        scores = d.get("scores") or {}
        rec.scores = ScoresBlock(
            before=build(ScorePair, scores.get("before")),
            after=build(ScorePair, scores.get("after")),
            p_attack=scores.get("p_attack", 0.0),
        )

        # Use build() so every scalar DecisionBlock field is copied and this
        # cannot silently drift when the block gains a field (it did, once:
        # evsi and bait_assignment were dropped here, which made verify()
        # report false tampering -- see docs/DECISIONS.md). `reason` is the one
        # nested list and is rebuilt explicitly afterwards.
        decision = d.get("decision") or {}
        rec.decision = build(DecisionBlock, decision)
        rec.decision.reason = [build(ReasonItem, r) for r in decision.get("reason", []) or []]
        return rec


# --------------------------------------------------------------------------
# Freeze enforcement
# --------------------------------------------------------------------------


def _layout() -> list[str]:
    """Flattened, sorted list of `path:type` for every field in the schema.

    Nested dataclasses are walked recursively so that a change anywhere in
    the tree -- not just at the top level -- moves the fingerprint.
    """
    import typing
    from dataclasses import fields as dc_fields, is_dataclass

    out: list[str] = []
    hints_cache: dict[Any, dict[str, Any]] = {}

    def hints_for(cls):
        # `from __future__ import annotations` makes every annotation a
        # string, so they have to be resolved before they can be inspected.
        if cls not in hints_cache:
            hints_cache[cls] = typing.get_type_hints(cls, globalns=globals())
        return hints_cache[cls]

    def walk(cls, prefix: str) -> None:
        hints = hints_for(cls)
        for f in dc_fields(cls):
            ftype = hints.get(f.name, f.type)
            name = f"{prefix}{f.name}"
            if isinstance(ftype, type) and is_dataclass(ftype):
                walk(ftype, name + ".")
            else:
                out.append(f"{name}:{_typename(ftype)}")

    walk(Record, "")
    return sorted(out)


def _typename(t: Any) -> str:
    if isinstance(t, type):
        return t.__name__
    rendered = str(t).replace("typing.", "")
    # A dataclass inside a generic renders with its defining module, which is
    # `adf.schema` on import but `__main__` under `python -m adf.schema`. The
    # fingerprint must describe the layout, not how the module was invoked, so
    # the module qualification is stripped.
    for prefix in (f"{__name__}.", "adf.schema.", "__main__."):
        rendered = rendered.replace(prefix, "")
    return rendered


def schema_fingerprint() -> str:
    return hashlib.sha256("\n".join(_layout()).encode("utf-8")).hexdigest()


#: Recorded at freeze time. tests/test_schema_frozen.py compares the live
#: fingerprint against this constant; a mismatch means the layout changed and
#: SCHEMA_VERSION must be bumped with a documented migration.
SCHEMA_FINGERPRINT = "4dc46fbc4fadadea963e204a7fd307dcb995c18be391a780060a9420be4b7de9"

#: Field count at freeze time, kept alongside the hash purely so a diff of
#: this file shows a human what changed as well as that something changed.
SCHEMA_FIELD_COUNT = 68


if __name__ == "__main__":  # pragma: no cover - freeze helper
    print(f"schema_version   : {SCHEMA_VERSION}")
    print(f"fingerprint      : {schema_fingerprint()}")
    print(f"recorded         : {SCHEMA_FINGERPRINT}")
    print(f"fields           : {len(_layout())}")
