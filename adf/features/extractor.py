"""
Feature extraction (spec §6.3, FR-03).

Converts each request into a row of numbers, with the features deliberately
split into two groups because the two suspicion scores need different evidence
(spec §6.3, §6.4):

  AUTOMATION features -- is this a script or a person?
  MALICE features     -- is this hostile?

The separation is not cosmetic. A vulnerability scanner is automated AND
hostile; a price-comparison bot is automated and harmless; a careful human
attacker is barely automated and extremely hostile. One combined feature
vector could not keep those apart -- so the vector is partitioned and the two
partitions feed two independent scores.

STREAMING AND ACCUMULATION
--------------------------
Scores accumulate across a session; they do not reset each request (spec
§5.2, §6.4). Features therefore have to be computed from the session so far,
not from the current request in isolation -- "requests per minute", "failed
auth attempts in this session" and "is this id one higher than the last" are
all session-level quantities. So the public object is a per-session
`SessionFeatureExtractor` that is fed requests in order and returns, for each,
the feature vector reflecting everything seen up to and including it.

SINGLE SOURCE OF TRUTH
----------------------
These functions are the ONLY definition of each feature in the project. The
corpus diagnostic (tools/corpus_report.py) imports the same primitives, so the
numbers used to justify Phase 1/2 and the numbers the meter trains on cannot
drift apart. Changing a feature's definition is a deliberate act that bumps
FEATURE_SET_VERSION.

An explicit non-goal: no feature may read `session.provenance_id` or anything
in adf.schema.NEVER_FEATURE_FIELDS. Those carry the ground-truth join key, and
a model that learned from them would be reading the answer sheet. There is a
test that enforces this.
"""

from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from datetime import datetime

from adf.schema import Record

# v1 -> v2: SQL-keyword patterns rewritten to require syntax context, not bare
#           vocabulary (see _DB_KEYWORDS), to stop ordinary English matching.
# v2 -> v3: removed the two id-access malice features, `mal_touched_sensitive`
#           (touched /api) and `mal_seq_id_run` (ascending-id run). BOTH diverted
#           the benign JSON-API integration client -- a false positive on the
#           §6.3 automated-but-harmless class -- because they fire on exactly the
#           behaviour a benign integration and an IDOR sweep SHARE (walking object
#           ids). No passive feature separates those two (§6.3 names the
#           ambiguity), so IDOR detection is delegated entirely to bait, and the
#           passive meter keeps only the features with a genuine benign/attack
#           signal (SQL lexical + auth failure). See the notes below.
# Each bump forces a retrain and makes the model freeze (adf/freeze.py) catch it.
FEATURE_SET_VERSION = 3

STATIC_PREFIX = "/static/"

# Characters that carry SQL / markup meaning. High density in client-controlled
# input is the clearest injection signal (spec §6.3).
_SPECIAL_CHARS = set("'\"();=<>-#%*|/\\`{}")

# SQL injection signatures.
#
# An earlier version matched BARE keywords -- `and`, `or`, `from`, `where`,
# `select`, `update`. Those are ordinary English: "terms and conditions",
# "where is the printer", "notes from the all-hands" all matched, and because
# `mal_db_keyword_any` LATCHES for the rest of the session and carries one of
# the largest malice weights, a single such search would have elevated an
# honest user permanently. The current benign corpus only escaped it by using
# single-word search terms -- which means the false-positive rate was partly an
# artefact of a lexically narrow corpus rather than a property of the detector.
#
# So the patterns now require SQL *syntax context*, not just vocabulary. Every
# payload the attack generators use still matches (quote break-outs,
# tautologies, UNION SELECT, comment terminators, stacked statements), while
# natural-language phrasing does not. Verified in both directions by
# tests/test_features.py.
_DB_KEYWORDS = re.compile(
    "|".join([
        r"\bunion\s+(?:all\s+)?select\b",          # UNION SELECT
        r"\bselect\b[\s\S]{0,80}?\bfrom\b",        # SELECT ... FROM
        r"\binsert\s+into\b",
        r"\bdelete\s+from\b",
        r"\b(?:drop|truncate)\s+(?:table|database)\b",
        r"\border\s+by\s+\d+",                     # ORDER BY 3  (column probing)
        r"\bgroup\s+by\b",
        r"\binformation_schema\b",
        r"\b(?:sleep|benchmark|pg_sleep|waitfor)\s*\(",   # time-based
        # tautology: OR/AND joined to a comparison -- "or 1=1", "and 'a'='a'"
        r"\b(?:or|and)\s+['\"]?[\w.]+['\"]?\s*(?:=|<>|!=|<|>)",
        # quote (optionally closing a paren) followed by a SQL keyword: the
        # classic break-out, e.g.  x' OR   ') AND   1' UNION
        r"['\"]\s*\)?\s*(?:or|and|union|select|;)\b",
        # comment terminators used to swallow the rest of the query
        r"--[\s\-]|--$|/\*|;\s*--",
    ]),
    re.IGNORECASE,
)

# Paths where a 401 means a failed authentication attempt (spec §6.3
# "failed authentication attempts in this session").
_AUTH_PATHS = {"/login", "/otp"}

# Headers a well-behaved browser sends. Their ABSENCE is an automation signal
# (spec §6.3 "header set"); tools frequently omit most of them.
_BROWSER_HEADERS = ("accept", "accept-language", "accept-encoding")


# ---------------------------------------------------------------------------
# Feature names. The vector is these keys, always in this order, so a missing
# feature is a bug rather than a silently shorter row.
# ---------------------------------------------------------------------------

AUTOMATION_FEATURES = [
    "auto_interarrival_last",        # seconds since previous request (0 for first)
    "auto_interarrival_cv",          # coeff. of variation of gaps so far (regularity)
    "auto_requests_per_min",         # rolling request rate
    "auto_asset_fetch_ratio",        # static assets fetched per navigation so far
    "auto_fetched_assets",           # 1 if this session has ever fetched an asset
    "auto_browser_header_ratio",     # fraction of expected browser headers present
    "auto_header_count",             # number of headers on this request
    "auto_ua_is_tool",               # 1 if the UA looks like a tool, not a browser
    "auto_ua_stable",                # 1 if the UA has not changed within the session
    "auto_cookie_carried",           # 1 if a cookie was sent on this request
]

MALICE_FEATURES = [
    "mal_input_length",              # length of client-controlled input
    "mal_special_char_ratio",        # special-character density in that input
    "mal_db_keyword_hits",           # database-keyword matches on this request
    "mal_db_keyword_any",            # 1 if any db keyword has appeared this session
    "mal_failed_auth",               # failed auth attempts so far this session
    "mal_error_ratio",               # 4xx/5xx over all responses so far
    "mal_param_mutation",            # 1 if a param value changed on an otherwise identical request
]
# REMOVED in feature-set v3, both for the same reason: `mal_touched_sensitive`
# (touched /api|/auth|/admin) and `mal_seq_id_run` (length of the ascending-id
# run). Each fired on behaviour a benign JSON-API integration and an IDOR sweep
# SHARE — using the API, and walking object ids — so each diverted benign
# integration clients (10/10 via touched_sensitive; 3/10 via seq_id_run after
# the first removal). Spec §6.3 names this ambiguity outright: the reporting
# integration "walks record ids in ascending order... the request shape of an
# IDOR sweep from a client doing nothing wrong." No passive feature can separate
# them, so IDOR detection is delegated ENTIRELY to bait (an attacker submits
# ref_uid / internal_view; a benign integration never does), and the passive
# meter keeps only features with a real benign/attack signal. This was found by
# auditing the corpus after the eval's human-only benign set had hidden it.

ALL_FEATURES = AUTOMATION_FEATURES + MALICE_FEATURES


# ---------------------------------------------------------------------------
# Shared primitives (imported by tools/corpus_report.py too)
# ---------------------------------------------------------------------------


def client_inputs(record: Record) -> str:
    """The client-controlled input that forms the INJECTION SURFACE: query
    parameter values, plus the body of non-authentication requests.

    Two exclusions, both deliberate:

      * The path is excluded so that legitimately visiting /records/5 does not
        read as special-character-laden. Object-id access is not a lexical
        signal at all -- and, as a behavioural one, it is not passively
        separable from a benign integration either, so it is left to bait
        rather than scored here (see the v3 feature-removal note above).

      * Authentication bodies (/login, /otp) are excluded. A password is
        expected to be long and full of special characters -- "Summer2024!" is
        not an injection payload -- so measuring its length or symbol density
        as malice produces a false positive on every legitimate sign-in. The
        login form is not the injection surface anyway (it uses parameterised
        queries; only /search concatenates), and the credential-attack signal
        is carried by `mal_failed_auth`, not by input content. Query params on
        an auth path are still counted, so /login?x=' UNION is not a blind spot.

    This scoping was added after the end-to-end smoke test diverted a benign
    login POST purely on its body length (see docs/DECISIONS.md).
    """
    parts = [v for values in record.request.query_params.values() for v in values]
    if record.request.body and record.request.path not in _AUTH_PATHS:
        parts.append(record.request.body)
    return " ".join(parts)


def special_char_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(c in _SPECIAL_CHARS for c in text) / len(text)


def db_keyword_hits(text: str) -> int:
    return len(_DB_KEYWORDS.findall(text))


def is_tool_user_agent(ua: str) -> bool:
    """A UA that does not present as a browser. Browsers begin 'Mozilla/'."""
    if not ua:
        return True
    ua_l = ua.lower()
    if ua_l.startswith("mozilla/"):
        return False
    return True


def _parse_ts(value: str) -> float:
    return datetime.fromisoformat(value).timestamp()


# ---------------------------------------------------------------------------
# Per-session streaming extractor
# ---------------------------------------------------------------------------


@dataclass
class SessionFeatureExtractor:
    """Feed it a session's requests in order; get a feature vector for each.

    All accumulated state is per session and lives here. The extractor never
    looks at ground-truth labels or the provenance id -- it sees exactly what
    the live proxy would see, which is the whole point: a feature that cannot
    be computed online cannot be used online.
    """

    # accumulated raw state
    _times: list[float] = field(default_factory=list)
    _nav_count: int = 0
    _asset_count: int = 0
    _user_agents: set[str] = field(default_factory=set)
    _db_keyword_seen: bool = False
    _failed_auth: int = 0
    _responses: int = 0
    _errors: int = 0
    _param_sig_map: dict[str, dict[str, str]] = field(default_factory=dict)
    _count: int = 0

    def observe(self, record: Record) -> dict[str, float]:
        """Update state with `record`, then return its feature vector."""
        self._count += 1
        path = record.request.path
        is_asset = path.startswith(STATIC_PREFIX)

        # --- timing -------------------------------------------------------
        interarrival = 0.0
        if record.ts:
            try:
                now = _parse_ts(record.ts)
                if self._times:
                    interarrival = max(0.0, now - self._times[-1])
                self._times.append(now)
            except ValueError:
                pass

        # --- assets vs navigations ---------------------------------------
        if is_asset:
            self._asset_count += 1
        else:
            self._nav_count += 1

        # --- user agent ---------------------------------------------------
        ua = record.request.user_agent
        if ua:
            self._user_agents.add(ua)

        # --- inputs / malice ---------------------------------------------
        text = client_inputs(record)
        kw = db_keyword_hits(text)
        if kw:
            self._db_keyword_seen = True

        # failed auth
        if (record.request.method == "POST" and path in _AUTH_PATHS
                and record.response.status == 401):
            self._failed_auth += 1

        # error ratio
        if record.response.status:
            self._responses += 1
            if record.response.status >= 400:
                self._errors += 1

        # parameter mutation: same path+method as last, but a param value moved
        mutated = self._update_param_mutation(record)

        # --- assemble -----------------------------------------------------
        vector = {
            # automation
            "auto_interarrival_last": round(interarrival, 4),
            "auto_interarrival_cv": self._interarrival_cv(),
            "auto_requests_per_min": self._requests_per_min(),
            "auto_asset_fetch_ratio": (self._asset_count / self._nav_count) if self._nav_count else 0.0,
            "auto_fetched_assets": 1.0 if self._asset_count > 0 else 0.0,
            "auto_browser_header_ratio": self._browser_header_ratio(record),
            "auto_header_count": float(len(record.request.header_order)),
            "auto_ua_is_tool": 1.0 if is_tool_user_agent(ua) else 0.0,
            "auto_ua_stable": 1.0 if len(self._user_agents) <= 1 else 0.0,
            "auto_cookie_carried": 1.0 if "cookie" in record.request.headers else 0.0,
            # malice
            "mal_input_length": float(len(text)),
            "mal_special_char_ratio": round(special_char_ratio(text), 4),
            "mal_db_keyword_hits": float(kw),
            "mal_db_keyword_any": 1.0 if self._db_keyword_seen else 0.0,
            "mal_failed_auth": float(self._failed_auth),
            "mal_error_ratio": (self._errors / self._responses) if self._responses else 0.0,
            "mal_param_mutation": 1.0 if mutated else 0.0,
        }
        # Guard: the vector must contain exactly the declared features, in a
        # form the meter can consume. A drift here would silently misalign the
        # weights, so it is cheap to assert.
        assert set(vector) == set(ALL_FEATURES), "feature vector drifted from ALL_FEATURES"
        return vector

    # -- helpers -----------------------------------------------------------

    def _interarrival_cv(self) -> float:
        gaps = [b - a for a, b in zip(self._times, self._times[1:], strict=False) if b - a > 0]
        if len(gaps) < 2:
            return 0.0
        mean = statistics.fmean(gaps)
        if mean <= 0:
            return 0.0
        return round(statistics.pstdev(gaps) / mean, 4)

    def _requests_per_min(self) -> float:
        if len(self._times) < 2:
            return 0.0
        span = self._times[-1] - self._times[0]
        if span <= 0:
            return 0.0
        return round(self._count / (span / 60.0), 3)

    def _browser_header_ratio(self, record: Record) -> float:
        present = sum(1 for h in _BROWSER_HEADERS if h in record.request.headers)
        return round(present / len(_BROWSER_HEADERS), 4)

    def _update_param_mutation(self, record: Record) -> bool:
        sig_key = f"{record.request.method} {record.request.path}"
        current = {k: ",".join(v) for k, v in record.request.query_params.items()}
        mutated = False
        if sig_key in self._param_sig_map:
            prev = self._param_sig_map[sig_key]
            # same endpoint, same set of param names, at least one value changed
            if set(prev) == set(current) and prev != current and current:
                mutated = True
        self._param_sig_map[sig_key] = current
        return mutated


def extract_session(records: list[Record]) -> list[dict[str, float]]:
    """Convenience: feature vectors for an entire session, in order."""
    extractor = SessionFeatureExtractor()
    return [extractor.observe(r) for r in records]
