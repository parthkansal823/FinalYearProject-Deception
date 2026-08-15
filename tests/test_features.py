"""
Tests for the feature extractor (spec §6.3, FR-03).

The extractor is deterministic and streaming, so it is tested on hand-built
records rather than on a corpus: each test constructs exactly the request
pattern a feature is meant to detect and asserts that the feature -- and
ideally only that feature -- moves.

The most important test in this file is the last one. A feature that read the
provenance id or the label block would be reading the answer key, and the
resulting accuracy would be a fiction. That must be impossible, not merely
avoided by convention.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from adf.features import (
    ALL_FEATURES,
    AUTOMATION_FEATURES,
    MALICE_FEATURES,
    SessionFeatureExtractor,
)
from adf.features.extractor import is_tool_user_agent, special_char_ratio, db_keyword_hits
from adf.schema import Record, NEVER_FEATURE_FIELDS


BASE = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)


def _req(
    *,
    t: float = 0.0,
    method: str = "GET",
    path: str = "/",
    query: dict[str, list[str]] | None = None,
    ua: str = "Mozilla/5.0 (browser)",
    headers: dict[str, str] | None = None,
    status: int = 200,
    body: str = "",
    session_id: str = "s1",
    provenance: str = "benign-SECRET",
    ground_truth: str = "benign",
) -> Record:
    r = Record()
    r.ts = (BASE + timedelta(seconds=t)).isoformat(timespec="microseconds")
    r.session.session_id = session_id
    r.session.provenance_id = provenance          # the answer key -- must never be read
    r.request.method = method
    r.request.path = path
    r.request.query_params = query or {}
    r.request.user_agent = ua
    default_headers = {"user-agent": ua}
    if ua.lower().startswith("mozilla"):
        default_headers.update({"accept": "text/html", "accept-language": "en", "accept-encoding": "gzip"})
    r.request.headers = {**default_headers, **(headers or {})}
    r.request.header_order = list(r.request.headers)
    r.request.body = body
    r.response.status = status
    r.labels.ground_truth = ground_truth          # also the answer key
    return r


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------


def test_vector_has_exactly_the_declared_features():
    ex = SessionFeatureExtractor()
    vec = ex.observe(_req())
    assert set(vec) == set(ALL_FEATURES)
    assert len(ALL_FEATURES) == len(AUTOMATION_FEATURES) + len(MALICE_FEATURES)
    assert set(AUTOMATION_FEATURES).isdisjoint(MALICE_FEATURES), "a feature is in both partitions"


def test_every_feature_is_a_finite_number():
    ex = SessionFeatureExtractor()
    vec = ex.observe(_req(query={"q": ["hello"]}))
    for name, value in vec.items():
        assert isinstance(value, float), name
        assert value == value, f"{name} is NaN"  # NaN != NaN


# ---------------------------------------------------------------------------
# Automation features
# ---------------------------------------------------------------------------


def test_tool_user_agent_is_detected():
    assert is_tool_user_agent("sqlmap/1.8") is True
    assert is_tool_user_agent("python-requests/2.32") is True
    assert is_tool_user_agent("") is True
    assert is_tool_user_agent("Mozilla/5.0 (Windows NT 10.0)") is False


def test_asset_fetching_raises_the_asset_ratio_and_flag():
    ex = SessionFeatureExtractor()
    ex.observe(_req(path="/dashboard"))
    v_css = ex.observe(_req(path="/static/app.css", t=0.1))
    assert v_css["auto_fetched_assets"] == 1.0
    assert v_css["auto_asset_fetch_ratio"] > 0.0


def test_metronomic_timing_has_low_cv_and_irregular_has_high():
    regular = SessionFeatureExtractor()
    v = {}
    for i in range(8):
        v = regular.observe(_req(t=i * 1.0))            # exactly 1s apart
    low = v["auto_interarrival_cv"]

    irregular = SessionFeatureExtractor()
    for t in (0.0, 0.3, 2.5, 2.7, 6.0, 6.1, 12.0):      # bursty, uneven
        v = irregular.observe(_req(t=t))
    high = v["auto_interarrival_cv"]

    assert low < high, f"regular CV {low} should be below irregular CV {high}"
    assert low < 0.1, "perfectly periodic timing should have near-zero CV"


def test_requests_per_minute_reflects_rate():
    fast = SessionFeatureExtractor()
    v = {}
    for i in range(10):
        v = fast.observe(_req(t=i * 0.05))              # 20 req/s
    assert v["auto_requests_per_min"] > 100


def test_missing_browser_headers_lower_the_ratio():
    ex = SessionFeatureExtractor()
    # a tool sending only a UA
    v = ex.observe(_req(ua="curl/8", headers={"accept": "", "accept-language": "", "accept-encoding": ""}))
    # header dict still has the keys but as empty; simulate a bare tool instead
    bare = SessionFeatureExtractor()
    r = _req(ua="curl/8")
    r.request.headers = {"user-agent": "curl/8"}
    r.request.header_order = ["user-agent"]
    v = bare.observe(r)
    assert v["auto_browser_header_ratio"] == 0.0
    assert v["auto_ua_is_tool"] == 1.0


# ---------------------------------------------------------------------------
# Malice features
# ---------------------------------------------------------------------------


def test_special_characters_and_db_keywords_fire_on_injection():
    assert special_char_ratio("O'Brien") > 0
    assert db_keyword_hits("x' UNION SELECT password FROM users -- ") >= 2

    # A UNION payload is keyword-heavy but not punctuation-heavy, so its signal
    # lives in db_keyword_hits, not in special-char density.
    ex = SessionFeatureExtractor()
    v = ex.observe(_req(path="/search", query={"q": ["x' UNION SELECT a,b FROM users -- "]}))
    assert v["mal_db_keyword_hits"] >= 2
    assert v["mal_db_keyword_any"] == 1.0

    # A quote-bunched payload is the opposite: high special-char density.
    ex2 = SessionFeatureExtractor()
    v2 = ex2.observe(_req(path="/search", query={"q": ["');--"]}))
    assert v2["mal_special_char_ratio"] > 0.5


# Ordinary phrasing a staff search box genuinely receives. None of these is an
# injection attempt, and none may register as one -- `mal_db_keyword_any` latches
# for the whole session and carries one of the largest malice weights, so a
# single false hit would elevate an honest user permanently.
BENIGN_PHRASES = [
    "terms and conditions", "where is the printer", "parking or transport",
    "select a training course", "notes from the all-hands", "update on the office move",
    "policy for new starters", "maintenance window", "group meeting", "order form",
    "O'Connell", "Maeve O'Connell", "d'Angelo", "O'Brien travel", "Dell'Aquila",
]

# Every payload the attack generators actually send. All must still register.
ATTACK_PAYLOADS = [
    "') OR ('1'='1", "1' OR '1", "x' AND '1'='2", "x' OR '1'='1", "x' OR 1=1 -- ",
    "x' UNION SELECT 1,2,3,4 -- ",
    "x' UNION SELECT id, username, password_hash, role FROM users -- ",
    "x' UNION SELECT id, username, password_hash, role FROM users WHERE role='admin' -- ",
    "1; DROP TABLE users", "admin'--", "x' AND 1=2 -- ", "' OR '1'='1",
    "1 ORDER BY 3--", "' UNION SELECT NULL,NULL--", "1' AND SLEEP(5)--",
]


@pytest.mark.parametrize("phrase", BENIGN_PHRASES)
def test_ordinary_english_is_not_a_sql_keyword_hit(phrase):
    """Regression: the patterns used to match bare `and`/`or`/`from`/`where`,
    so "terms and conditions" scored as an injection probe. The corpus only
    escaped it by using single-word search terms — meaning the false-positive
    rate was an artefact of a narrow corpus, not a property of the detector."""
    assert db_keyword_hits(phrase) == 0, f"{phrase!r} falsely read as SQL"


@pytest.mark.parametrize("payload", ATTACK_PAYLOADS)
def test_real_injection_payloads_are_still_detected(payload):
    """The other half: tightening the patterns must not lose a single real
    payload the attack generators send."""
    assert db_keyword_hits(payload) >= 1, f"{payload!r} no longer detected"


def test_a_legitimate_login_body_is_not_read_as_malice():
    """Regression (see docs/DECISIONS.md): the end-to-end smoke diverted a
    benign login POST because its body length drove malice up. A password is
    expected to be long and full of symbols and is NOT an injection payload, so
    the auth-path body must be excluded from the content features."""
    ex = SessionFeatureExtractor()
    v = ex.observe(_req(method="POST", path="/login",
                        body="username=a.mirza&password=Summer2024!"))
    assert v["mal_input_length"] == 0.0, "login credentials must not count as input length"
    assert v["mal_special_char_ratio"] == 0.0, "the '!' in a password is not an injection symbol"
    assert v["mal_db_keyword_hits"] == 0.0


def test_query_params_on_an_auth_path_are_still_inspected():
    """Excluding the auth BODY must not create a blind spot: an injection in a
    query parameter on /login is still the injection surface and must register."""
    ex = SessionFeatureExtractor()
    v = ex.observe(_req(method="POST", path="/login",
                        query={"next": ["x' UNION SELECT a,b -- "]},
                        body="username=a.mirza&password=Summer2024!"))
    assert v["mal_db_keyword_hits"] >= 2, "a query-param payload on /login must still be seen"


def test_db_keyword_any_latches_for_the_rest_of_the_session():
    ex = SessionFeatureExtractor()
    ex.observe(_req(path="/search", query={"q": ["' OR 1=1 -- "]}))
    v = ex.observe(_req(path="/dashboard"))     # innocent follow-up
    assert v["mal_db_keyword_any"] == 1.0, "session-level malice memory must persist"


def test_object_id_access_is_not_a_malice_feature():
    """Object-id access (sequential OR scattered) must NOT register as malice:
    a benign JSON-API integration walks ids exactly like an IDOR sweep, so any
    id-based malice feature diverts benign integrations (it did — 10/10 via
    touched_sensitive, 3/10 via seq_id_run). Removed in feature-set v3; IDOR is
    delegated to bait. This asserts neither removed feature has crept back."""
    ex = SessionFeatureExtractor()
    last = {}
    for pid in range(1, 6):
        last = ex.observe(_req(path=f"/api/profile/{pid}"))
    assert "mal_seq_id_run" not in last
    assert "mal_touched_sensitive" not in last
    # and API access alone contributes nothing lexical
    assert last["mal_db_keyword_hits"] == 0.0 and last["mal_special_char_ratio"] == 0.0


def test_failed_auth_accumulates_only_on_401_login():
    ex = SessionFeatureExtractor()
    for _ in range(3):
        v = ex.observe(_req(method="POST", path="/login", status=401))
    assert v["mal_failed_auth"] == 3.0
    v = ex.observe(_req(method="POST", path="/login", status=303))  # success
    assert v["mal_failed_auth"] == 3.0, "a successful login must not increment the counter"


def test_error_ratio_tracks_4xx_5xx():
    ex = SessionFeatureExtractor()
    ex.observe(_req(status=200))
    ex.observe(_req(status=200))
    v = ex.observe(_req(status=500))
    assert abs(v["mal_error_ratio"] - 1 / 3) < 1e-6


def test_param_mutation_detects_a_changed_value_on_the_same_endpoint():
    ex = SessionFeatureExtractor()
    ex.observe(_req(path="/search", query={"q": ["a"]}))
    v = ex.observe(_req(path="/search", query={"q": ["b"]}, t=1))
    assert v["mal_param_mutation"] == 1.0
    # a different endpoint is not a mutation
    v2 = ex.observe(_req(path="/records", query={"id": ["5"]}, t=2))
    assert v2["mal_param_mutation"] == 0.0


# ---------------------------------------------------------------------------
# THE SAFETY TEST: the extractor must not read the answer key
# ---------------------------------------------------------------------------


def test_features_are_identical_regardless_of_the_ground_truth_label():
    """If any feature depended on the label or provenance id, changing them
    while holding the observable request fixed would change the vector. It
    must not. This is what makes the eventual accuracy trustworthy."""
    def run(gt: str, prov: str) -> dict:
        ex = SessionFeatureExtractor()
        out = {}
        for pid in range(1, 4):
            out = ex.observe(_req(
                path=f"/api/profile/{pid}",
                query={"q": ["x' OR 1=1 -- "]},
                ground_truth=gt,
                provenance=prov,
                session_id="same",
            ))
        return out

    as_benign = run("benign", "benign-AAA")
    as_attack = run("attack", "attack-ZZZ")
    assert as_benign == as_attack, "a feature is leaking the ground-truth label or provenance id"


def test_never_feature_fields_are_declared():
    """A guard on the guard: the fields the extractor promises never to read
    must actually be the sensitive ones."""
    assert "labels" in NEVER_FEATURE_FIELDS
    assert "session.provenance_id" in NEVER_FEATURE_FIELDS


# ---------------------------------------------------------------------------
# mal_distinct_usernames (feature-set v4) -- retiring the forgetful-login FP
# ---------------------------------------------------------------------------


def _login(username: str, *, status: int, t: float = 0.0) -> Record:
    """An auth POST as the log actually stores it: username in the form body,
    credential already redacted at capture (target_app._capture_body)."""
    return _req(
        t=t, method="POST", path="/login", status=status,
        body=f"username={username}&password=%5BREDACTED%5D",
    )


def test_forgetful_user_and_credential_spray_are_separable():
    """The whole point of the feature. On mal_failed_auth these two are nearly
    identical -- which is exactly why the forgetful persona was diverted 3/5 of
    the time and the false positive was reported as inherent. They differ on how
    many DIFFERENT accounts were tried, and that is what this measures."""
    forgetful = SessionFeatureExtractor()
    for i in range(5):                                    # one account, five failures
        v_forgetful = forgetful.observe(_login("rmehta", status=401, t=i * 9.0))
    v_forgetful = forgetful.observe(_login("rmehta", status=303, t=54.0))  # then succeeds

    spray = SessionFeatureExtractor()
    for i, user in enumerate(["ajain", "rmehta", "skhan", "pdas", "troy", "nkap"]):
        v_spray = spray.observe(_login(user, status=401, t=i * 9.0))

    # indistinguishable on the v3 feature ...
    assert abs(v_forgetful["mal_failed_auth"] - v_spray["mal_failed_auth"]) <= 1.0
    # ... and cleanly separated on the v4 one
    assert v_forgetful["mal_distinct_usernames"] == 1.0
    assert v_spray["mal_distinct_usernames"] == 6.0


def test_distinct_usernames_counts_accounts_not_attempts():
    """Retrying the same account must never inflate the count, or the feature
    degenerates into a second copy of mal_failed_auth."""
    ex = SessionFeatureExtractor()
    for i in range(8):
        vec = ex.observe(_login("rmehta", status=401, t=i * 3.0))
    assert vec["mal_distinct_usernames"] == 1.0
    assert vec["mal_failed_auth"] == 8.0


def test_distinct_usernames_is_case_insensitive():
    """`RMehta` and `rmehta` are one account. Without this an attacker could
    inflate nothing, but a benign user with a capitalised autofill would look
    like two accounts."""
    ex = SessionFeatureExtractor()
    for name in ["rmehta", "RMehta", "  rmehta  "]:
        vec = ex.observe(_login(name, status=401))
    assert vec["mal_distinct_usernames"] == 1.0


def test_distinct_usernames_ignores_non_auth_requests():
    """A `username` parameter on an ordinary page is not an auth attempt."""
    ex = SessionFeatureExtractor()
    vec = ex.observe(_req(path="/records", query={"username": ["rmehta"]}))
    assert vec["mal_distinct_usernames"] == 0.0


def test_the_credential_is_never_readable_from_the_body():
    """The feature needs the account name and nothing else. If a real password
    ever reaches the extractor, capture-time redaction has regressed."""
    from adf.features.extractor import auth_username
    rec = _login("rmehta", status=401)
    assert auth_username(rec) == "rmehta"
    assert "REDACTED" in rec.request.body
    assert "Summer2024" not in rec.request.body
