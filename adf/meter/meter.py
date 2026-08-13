"""
Dual suspicion meter (spec §6.4, FR-04).

Each session carries TWO scores in [0, 1], both starting low: `automation`
(is this a script?) and `malice` (is this hostile?). Every request nudges them.
The two are kept independent because one combined score cannot express the
three situations spec §6.3 names -- automated+hostile, automated+harmless,
manual+hostile -- and separating them is contribution #2 of the project.

MECHANISM (spec §6.4)
---------------------
The score is a running total of weighted evidence. Two design commitments the
paper has to defend, both honoured here:

  * Explainable. For any decision, the exact features that pushed the score
    can be listed (NFR-07). A logistic model gives this for free: the score is
    sigmoid(bias + Σ wᵢxᵢ), and each wᵢxᵢ is that feature's signed
    contribution in log-odds. `explain()` returns them sorted.

  * Works on small data. A single-person campaign yields thousands of
    requests, not millions. Logistic regression is the right tool at that
    scale; a deep model would overfit and could not be defended in a viva.
    Spec §6.4 names logistic regression first for exactly this reason, and it
    is the default here.

ACCUMULATION
------------
Spec §5.2/§6.4 require the score to accumulate across the session rather than
reset each request. That accumulation lives in the FEATURES, which are already
session-cumulative (failed-auth count, longest sequential-id run, db-keyword
latch, rolling rate). Feeding the model the cumulative feature vector makes the
score a monotone-ish function of accumulated evidence without any hand-tuned
decay constant -- a series of individually unremarkable requests can still add
up to a confident conclusion, which is the property §6.4 asks for.

TRAINING SEPARATION
-------------------
Two independent classifiers over two feature partitions:
  * automation head trains on the AUTOMATION features against the
    automation label (scripted vs human);
  * malice head trains on the MALICE features against ground truth
    (attack vs benign).
Neither ever sees `labels` or `provenance_id` as an input -- the feature
extractor cannot emit them (see adf.schema.NEVER_FEATURE_FIELDS). The heads
are fit ONLY on round-1 `train` data and frozen before evaluation (spec §7.2).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import numpy as np

from adf.features import ALL_FEATURES, AUTOMATION_FEATURES, MALICE_FEATURES, FEATURE_SET_VERSION

METER_VERSION = "meter-1"

AxisName = Literal["automation", "malice"]


@dataclass
class Contribution:
    """One feature's signed push on an axis, in log-odds (NFR-07)."""

    feature: str
    value: float
    weight: float
    contribution: float          # weight * standardised(value)


@dataclass
class AxisExplanation:
    score: float                 # sigmoid(logit), in [0, 1]
    logit: float
    bias: float
    contributions: list[Contribution] = field(default_factory=list)

    def top(self, k: int = 5) -> list[Contribution]:
        return sorted(self.contributions, key=lambda c: abs(c.contribution), reverse=True)[:k]


@dataclass
class MeterScores:
    automation: float
    malice: float
    automation_expl: AxisExplanation
    malice_expl: AxisExplanation


def _sigmoid(z: float) -> float:
    # numerically stable
    if z >= 0:
        return 1.0 / (1.0 + np.exp(-z))
    ez = np.exp(z)
    return ez / (1.0 + ez)


class _LogisticHead:
    """A tiny, self-contained logistic-regression head.

    Deliberately not sklearn at inference time: the live proxy scores one
    feature vector at a time and must not pay an import or allocation cost per
    request, and persisting three numpy arrays as JSON keeps the frozen model
    diffable and inspectable. Training (offline) DOES use sklearn -- see
    `fit` -- which is where spec §12's choice of scikit-learn applies.
    """

    def __init__(self, feature_names: list[str]) -> None:
        self.feature_names = list(feature_names)
        self.mean = np.zeros(len(feature_names))
        self.scale = np.ones(len(feature_names))
        self.weights = np.zeros(len(feature_names))
        self.bias = 0.0
        self.fitted = False

    # -- training (offline only) ------------------------------------------

    def fit(self, X: np.ndarray, y: np.ndarray, *, C: float = 1.0, seed: int = 0) -> None:
        from sklearn.linear_model import LogisticRegression

        # Standardise so the weights are comparable as evidence strengths and
        # so regularisation treats every feature on the same footing. The
        # standardiser is stored and reapplied at inference.
        self.mean = X.mean(axis=0)
        self.scale = X.std(axis=0)
        self.scale[self.scale == 0] = 1.0
        Xs = (X - self.mean) / self.scale

        if len(np.unique(y)) < 2:
            # Degenerate class (can happen on a tiny smoke corpus). Leave the
            # head at its zero prior rather than raising: a meter that predicts
            # 0.5 everywhere is honest about having learned nothing.
            self.weights = np.zeros(X.shape[1])
            self.bias = 0.0
            self.fitted = False
            return

        model = LogisticRegression(C=C, max_iter=2000, random_state=seed, class_weight="balanced")
        model.fit(Xs, y)
        self.weights = model.coef_[0].astype(float)
        self.bias = float(model.intercept_[0])
        self.fitted = True

    # -- inference (online) -----------------------------------------------

    def _standardise(self, x: np.ndarray) -> np.ndarray:
        return (x - self.mean) / self.scale

    def logit(self, x: np.ndarray) -> float:
        return float(self.bias + self._standardise(x) @ self.weights)

    def score(self, x: np.ndarray) -> float:
        return _sigmoid(self.logit(x))

    def explain(self, x: np.ndarray) -> AxisExplanation:
        xs = self._standardise(x)
        contribs = [
            Contribution(
                feature=name,
                value=float(x[i]),
                weight=float(self.weights[i]),
                contribution=float(self.weights[i] * xs[i]),
            )
            for i, name in enumerate(self.feature_names)
        ]
        logit = float(self.bias + xs @ self.weights)
        return AxisExplanation(score=_sigmoid(logit), logit=logit, bias=float(self.bias),
                               contributions=contribs)

    # -- persistence ------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "feature_names": self.feature_names,
            "mean": self.mean.tolist(),
            "scale": self.scale.tolist(),
            "weights": self.weights.tolist(),
            "bias": self.bias,
            "fitted": self.fitted,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "_LogisticHead":
        head = cls(d["feature_names"])
        head.mean = np.array(d["mean"], dtype=float)
        head.scale = np.array(d["scale"], dtype=float)
        head.weights = np.array(d["weights"], dtype=float)
        head.bias = float(d["bias"])
        head.fitted = bool(d.get("fitted", True))
        return head


class DualMeter:
    """Two heads, two axes. The public surface the proxy uses is `score()`."""

    def __init__(self) -> None:
        self.automation = _LogisticHead(AUTOMATION_FEATURES)
        self.malice = _LogisticHead(MALICE_FEATURES)
        self.feature_set_version = FEATURE_SET_VERSION

    # -- scoring -----------------------------------------------------------

    def _split(self, vector: dict[str, float]) -> tuple[np.ndarray, np.ndarray]:
        missing = set(ALL_FEATURES) - set(vector)
        if missing:
            raise ValueError(f"feature vector missing {sorted(missing)}")
        auto = np.array([vector[f] for f in AUTOMATION_FEATURES], dtype=float)
        mal = np.array([vector[f] for f in MALICE_FEATURES], dtype=float)
        return auto, mal

    def score(self, vector: dict[str, float]) -> MeterScores:
        auto_x, mal_x = self._split(vector)
        a_expl = self.automation.explain(auto_x)
        m_expl = self.malice.explain(mal_x)
        return MeterScores(
            automation=a_expl.score,
            malice=m_expl.score,
            automation_expl=a_expl,
            malice_expl=m_expl,
        )

    # -- training (offline) ------------------------------------------------

    def fit(
        self,
        vectors: list[dict[str, float]],
        automation_labels: list[int],
        malice_labels: list[int],
        *,
        C: float = 1.0,
        seed: int = 0,
    ) -> None:
        """Fit both heads. `vectors` are per-request cumulative feature vectors;
        the labels are 1/0 for scripted/human and attack/benign respectively.

        Both label lists are session-level truth broadcast to every request of
        the session by the caller -- the meter does not join labels itself, so
        it can never accidentally read them as features."""
        auto_X = np.array([[v[f] for f in AUTOMATION_FEATURES] for v in vectors], dtype=float)
        mal_X = np.array([[v[f] for f in MALICE_FEATURES] for v in vectors], dtype=float)
        self.automation.fit(auto_X, np.array(automation_labels), C=C, seed=seed)
        self.malice.fit(mal_X, np.array(malice_labels), C=C, seed=seed)

    @property
    def fitted(self) -> bool:
        return self.automation.fitted and self.malice.fitted

    # -- persistence ------------------------------------------------------

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "meter_version": METER_VERSION,
            "feature_set_version": self.feature_set_version,
            "automation": self.automation.to_dict(),
            "malice": self.malice.to_dict(),
        }
        path.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "DualMeter":
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        if doc.get("feature_set_version") != FEATURE_SET_VERSION:
            raise ValueError(
                f"meter was trained on feature set v{doc.get('feature_set_version')}, "
                f"but the code is on v{FEATURE_SET_VERSION}. Retrain before use."
            )
        meter = cls()
        meter.automation = _LogisticHead.from_dict(doc["automation"])
        meter.malice = _LogisticHead.from_dict(doc["malice"])
        return meter
