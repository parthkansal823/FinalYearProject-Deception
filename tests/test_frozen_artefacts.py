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


def test_schema_version_is_one():
    assert schema.SCHEMA_VERSION == 1


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

    # Baiting an attacker beats letting them straight through.
    assert t.cost("attack", "bait") < t.cost("attack", "pass")


def test_thresholds_are_derived_not_tuned():
    """The policy must produce all three actions across p, in the right order.

    A table that never chooses `bait` would quietly reduce the system to the
    two-outcome design it is supposed to improve on.
    """
    t = load_costs()
    boundaries = t.derive_thresholds()

    assert "pass_to_bait" in boundaries, "the cost table never selects BAIT -- there is no third action"
    assert "bait_to_divert" in boundaries, "the cost table never selects DIVERT"
    assert 0.0 < boundaries["pass_to_bait"] < boundaries["bait_to_divert"] < 1.0

    assert t.best_action(0.0) == "pass"
    assert t.best_action(1.0) == "divert"
    assert t.best_action((boundaries["pass_to_bait"] + boundaries["bait_to_divert"]) / 2) == "bait"


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
    assert t.derive_thresholds()["bait_to_divert"] > 0.75


def test_a_modified_cost_table_is_rejected(tmp_path):
    """The freeze must be enforced, not merely documented."""
    doc = yaml.safe_load(COSTS_PATH.read_text(encoding="utf-8"))
    doc["matrix"]["benign"]["divert"] = 1.0          # make diverting users cheap
    path = tmp_path / "costs.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    with pytest.raises(Exception) as exc:
        load_costs(path)
    assert "CHANGED" in str(exc.value).upper() or "FROZEN" in str(exc.value).upper()
