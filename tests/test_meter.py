"""
Tests for the dual suspicion meter (spec §6.4).

The meter is trained on the corpus, but its *behaviour* can be pinned down on
small synthetic data that this test builds deterministically: two separable
clouds per axis, so a correct logistic head must learn the obvious boundary.
The properties under test are the ones the paper claims -- two independent
axes, explainable contributions, and a frozen model that round-trips -- not
the eventual accuracy, which belongs to the evaluation.
"""

from __future__ import annotations

import random

import numpy as np
import pytest

from adf.features import ALL_FEATURES, AUTOMATION_FEATURES, MALICE_FEATURES
from adf.meter import DualMeter


def _vector(**overrides) -> dict[str, float]:
    v = {f: 0.0 for f in ALL_FEATURES}
    v.update(overrides)
    return v


def _synthetic_corpus(n: int = 200, seed: int = 0):
    """Four clouds mapping onto the 2x2 of spec §6.3, so automation and malice
    are deliberately UNCORRELATED: each is driven by its own feature."""
    rng = random.Random(seed)
    vectors, autos, malices = [], [], []
    for _ in range(n):
        scripted = rng.random() < 0.5
        attack = rng.random() < 0.5
        v = _vector(
            # automation is driven by ua_is_tool + low CV; malice by db keywords
            auto_ua_is_tool=1.0 if scripted else 0.0,
            auto_interarrival_cv=rng.uniform(0.0, 0.2) if scripted else rng.uniform(0.6, 1.2),
            auto_fetched_assets=0.0 if scripted else 1.0,
            mal_db_keyword_hits=rng.uniform(2, 6) if attack else 0.0,
            mal_failed_auth=rng.uniform(3, 8) if attack else rng.uniform(0, 1),
            mal_special_char_ratio=rng.uniform(0.2, 0.5) if attack else 0.0,
        )
        vectors.append(v)
        autos.append(1 if scripted else 0)
        malices.append(1 if attack else 0)
    return vectors, autos, malices


@pytest.fixture(scope="module")
def trained_meter() -> DualMeter:
    vectors, autos, malices = _synthetic_corpus()
    meter = DualMeter()
    meter.fit(vectors, autos, malices, seed=0)
    return meter


# ---------------------------------------------------------------------------
# Two independent axes (spec §6.3 contribution #2)
# ---------------------------------------------------------------------------


def test_scores_are_in_range_and_start_low_for_a_blank_request(trained_meter):
    scores = trained_meter.score(_vector())
    assert 0.0 <= scores.automation <= 1.0
    assert 0.0 <= scores.malice <= 1.0
    # a featureless request should not look hostile
    assert scores.malice < 0.5


def test_automation_axis_responds_to_automation_features_only(trained_meter):
    """A price-comparison bot: fully automated, entirely harmless. Automation
    high, malice low. If malice also rises, the axes are not independent."""
    bot = _vector(auto_ua_is_tool=1.0, auto_interarrival_cv=0.05, auto_fetched_assets=0.0)
    s = trained_meter.score(bot)
    assert s.automation > 0.6, "a scripted client should score high on automation"
    assert s.malice < 0.5, "a harmless bot must NOT score high on malice"


def test_malice_axis_responds_to_malice_features_only(trained_meter):
    """A careful human attacker: barely automated, extremely hostile. Malice
    high, automation low -- the cell a single combined score cannot express."""
    manual = _vector(mal_db_keyword_hits=5.0, mal_failed_auth=6.0, mal_special_char_ratio=0.4,
                     auto_ua_is_tool=0.0, auto_interarrival_cv=0.9, auto_fetched_assets=1.0)
    s = trained_meter.score(manual)
    assert s.malice > 0.6, "an injection-laden session should score high on malice"
    assert s.automation < 0.5, "a human-paced attacker must NOT score high on automation"


# ---------------------------------------------------------------------------
# Accumulation (spec §5.2, §6.4)
# ---------------------------------------------------------------------------


def test_malice_rises_as_evidence_accumulates(trained_meter):
    """A series of individually mild requests should add up. Modelled here by
    the cumulative db-keyword count growing across the session."""
    scores = [trained_meter.score(_vector(mal_db_keyword_hits=float(k))).malice
              for k in (0, 1, 2, 4, 6)]
    assert scores == sorted(scores), f"malice should be monotone in accumulated evidence: {scores}"
    assert scores[-1] > scores[0] + 0.2


# ---------------------------------------------------------------------------
# Explainability (NFR-07)
# ---------------------------------------------------------------------------


def test_explanation_lists_the_feature_that_drove_the_score(trained_meter):
    manual = _vector(mal_db_keyword_hits=6.0, mal_failed_auth=7.0)
    expl = trained_meter.score(manual).malice_expl
    top = expl.top(3)
    names = {c.feature for c in top}
    assert names & {"mal_db_keyword_hits", "mal_failed_auth"}, \
        "the driving malice features must appear among the top contributions"
    # the reconstructed logit must match the sum of contributions + bias
    total = expl.bias + sum(c.contribution for c in expl.contributions)
    assert abs(total - expl.logit) < 1e-9


def test_every_axis_only_sees_its_own_partition():
    meter = DualMeter()
    assert meter.automation.feature_names == AUTOMATION_FEATURES
    assert meter.malice.feature_names == MALICE_FEATURES
    assert set(AUTOMATION_FEATURES).isdisjoint(MALICE_FEATURES)


# ---------------------------------------------------------------------------
# Freeze / persistence (spec §7.2: the model is frozen before evaluation)
# ---------------------------------------------------------------------------


def test_meter_round_trips_through_disk_identically(trained_meter, tmp_path):
    path = tmp_path / "meter.json"
    trained_meter.save(path)
    reloaded = DualMeter.load(path)

    probe = _vector(mal_db_keyword_hits=4.0, auto_ua_is_tool=1.0, auto_interarrival_cv=0.05)
    a = trained_meter.score(probe)
    b = reloaded.score(probe)
    assert abs(a.automation - b.automation) < 1e-12
    assert abs(a.malice - b.malice) < 1e-12


def test_load_rejects_a_mismatched_feature_set(trained_meter, tmp_path):
    path = tmp_path / "meter.json"
    trained_meter.save(path)
    import json
    doc = json.loads(path.read_text())
    doc["feature_set_version"] = 999
    path.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="feature set"):
        DualMeter.load(path)


def test_degenerate_single_class_does_not_crash():
    """A tiny smoke corpus can contain only one class on an axis. The head
    must fall back to an uninformative prior rather than raising."""
    vectors = [_vector(mal_db_keyword_hits=1.0) for _ in range(10)]
    meter = DualMeter()
    meter.fit(vectors, [0] * 10, [0] * 10)   # all benign, all human
    s = meter.score(_vector())
    assert 0.0 <= s.malice <= 1.0
    assert not meter.fitted   # honest: it learned nothing on a one-class axis
