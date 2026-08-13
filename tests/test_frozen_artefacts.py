"""
Guards on the two Phase 0 freezes.

Spec §13.1 is blunt that Phase 0 looks like preparation and is not: fixing
the cost table and the label schema before any data exists is what makes the
evaluation possible at all. These tests are how that intention survives
contact with a future self who is three weeks from a deadline and just wants
one more field in the log.

If a test here fails, the correct response is almost never to update the
constant. It is to ask whether the change is worth invalidating collected
data over, and if so, to bump a version and write a migration.
"""

from __future__ import annotations

import json

import pytest

from adf import schema
from adf.config import CostTable, load_costs, _cost_digest, COSTS_PATH
import yaml


# ---------------------------------------------------------------------------
# Label schema (spec §11)
# ---------------------------------------------------------------------------


def test_schema_layout_matches_recorded_fingerprint():
    live = schema.schema_fingerprint()
    assert live == schema.SCHEMA_FINGERPRINT, (
        "The record layout has changed since it was frozen.\n"
        f"  recorded : {schema.SCHEMA_FINGERPRINT}\n"
        f"  live     : {live}\n\n"
        "Spec §11: deciding the label format after collection begins means either\n"
        "re-running every experiment or abandoning the dataset release. Bump\n"
        "SCHEMA_VERSION, write a migration, then update the fingerprint."
    )


def test_schema_version_is_current():
    """v2 added the `calibrate` round and the EVSI/holdout fields; v3 added
    `session.provenance_id`, without which labels and traffic were two
    namespaces that never met. Both bumped before any corpus existed — the
    only time a schema change is free."""
    assert schema.SCHEMA_VERSION == 3


def test_calibrate_round_exists_and_is_distinct():
    """The bait effectiveness parameters need a data source that is neither
    the training set nor the test set (see docs/SPEC_REVIEW.md finding 1).
    Losing this round would leave them uncalibratable again."""
    import typing

    rounds = set(typing.get_args(schema.Round))
    assert rounds == {"dev", "train", "calibrate", "eval"}


def test_record_round_trips_through_json():
    rec = schema.Record()
    rec.session.session_id = "s-1"
    rec.request.path = "/search"
    rec.request.query_params = {"q": ["maintenance"]}
    rec.features = {"payload_length": 11.0}
    rec.scores.after.malice = 0.42
    rec.decision.action = "bait"
    rec.decision.reason = [schema.ReasonItem(feature="sql_keywords", value=2.0, weight=1.3, contribution=2.6)]
    rec.labels.ground_truth = "attack"

    restored = schema.Record.from_dict(json.loads(rec.to_json_line()))

    assert restored.session.session_id == "s-1"
    assert restored.request.query_params == {"q": ["maintenance"]}
    assert restored.scores.after.malice == pytest.approx(0.42)
    assert restored.decision.action == "bait"
    assert restored.decision.reason[0].feature == "sql_keywords"
    assert restored.labels.ground_truth == "attack"


def test_three_actions_exactly():
    """Contribution #1 is that there are three outcomes, not two (spec §4.3)."""
    import typing

    assert set(typing.get_args(schema.Action)) == {"pass", "bait", "divert"}


def test_attack_categories_match_the_reduced_scope():
    """Scope was cut from six categories to three (spec §15.1). A fourth
    appearing here is the single most likely form of scope creep (§15.2)."""
    import typing

    assert set(typing.get_args(schema.AttackCategory)) == {"none", "sqli", "idor", "auth", "unknown"}


# ---------------------------------------------------------------------------
# Cost table (spec §6.5)
# ---------------------------------------------------------------------------


def test_cost_table_integrity_hash_is_current():
    doc = yaml.safe_load(COSTS_PATH.read_text(encoding="utf-8"))
    assert doc["integrity_sha256"] == _cost_digest(doc), (
        "config/costs.yaml has been edited since it was frozen. Spec §6.5: changing\n"
        "the cost table after seeing results invalidates every baseline comparison."
    )


def test_cost_table_loads():
    table = load_costs()
    assert table.frozen_on
    assert set(table.matrix) == {"benign", "attack"}


def test_cost_ordering_reflects_the_stated_priorities():
    """The numbers may be re-frozen, but these relationships are what spec
    §6.5 actually asserts, so they are the part worth pinning."""
    t = load_costs()

    # Wrongly diverting a real user is the outcome that must almost never occur.
    assert t.cost("benign", "divert") > t.cost("attack", "pass"), \
        "a wrongly diverted user must cost more than a missed attacker"

    # Wasted bait on a normal user is near zero -- this is what buys the
    # third action its wide band, and it is the central claim of the research.
    assert t.cost("benign", "bait") < t.cost("attack", "pass") / 10

    # Correctly diverting an attacker is the win, so it is negative.
    assert t.cost("attack", "divert") < 0

    # Baiting an attacker is NOT immediately cheaper than passing them: the
    # request still reaches the real application, so the exposure is the same.
    #
    # The first freeze had this at 8.0 vs 25.0, following spec §6.5's
    # instruction to discount bait "to reflect that purchased information".
    # That discount double counted, because the value of the information is
    # now computed explicitly by adf.policy.voi and subtracted at decision
    # time. Re-introducing a discount here would count the same benefit twice
    # and make the bait band an artefact of an arbitrary constant.
    assert t.cost("attack", "bait") >= t.cost("attack", "pass"), \
        "the information discount has crept back into the cost table"


def test_cost_accounting_alone_does_not_justify_bait():
    """The third action is bought by information, not by accounting.

    This is the sharpest statement of the contribution, so it is worth
    pinning as a test. On immediate expected cost alone the policy degenerates
    to the ordinary two-outcome rule — PASS or DIVERT, with a single boundary
    and no middle band at all. BAIT only becomes optimal once the expected
    value of the information it buys is subtracted (tests/test_policy.py).

    A reviewer asking "isn't the third option just a tuned threshold?" is
    answered by this test: without the information term there is no third
    option to tune.
    """
    t = load_costs()
    boundaries = t.derive_thresholds()

    assert set(boundaries) == {"pass_to_divert"}, (
        f"expected the cost table alone to yield a single PASS/DIVERT boundary, got {boundaries}. "
        "A bait band appearing here means bait has been made immediately cheap again, "
        "which double counts the information value."
    )
    assert t.best_action(0.0) == "pass"
    assert t.best_action(1.0) == "divert"
    assert "bait" not in {t.best_action(i / 100) for i in range(101)}


def test_expected_cost_is_linear_in_p():
    t = load_costs()
    for action in ("pass", "bait", "divert"):
        at_0 = t.expected_cost(action, 0.0)
        at_1 = t.expected_cost(action, 1.0)
        assert t.expected_cost(action, 0.5) == pytest.approx((at_0 + at_1) / 2)
        assert at_0 == pytest.approx(t.cost("benign", action))
        assert at_1 == pytest.approx(t.cost("attack", action))


def test_divert_requires_overwhelming_evidence():
    """NFR-05 targets an effectively zero benign diversion rate. That is a
    property of the cost table before it is a property of the classifier."""
    t = load_costs()
    assert t.derive_thresholds()["pass_to_divert"] > 0.75


def test_a_modified_cost_table_is_rejected(tmp_path):
    """The freeze must be enforced, not merely documented."""
    doc = yaml.safe_load(COSTS_PATH.read_text(encoding="utf-8"))
    doc["matrix"]["benign"]["divert"] = 1.0          # make diverting users cheap
    path = tmp_path / "costs.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    with pytest.raises(Exception) as exc:
        load_costs(path)
    assert "CHANGED" in str(exc.value).upper() or "FROZEN" in str(exc.value).upper()
