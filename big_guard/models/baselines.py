"""Working, testable baseline detectors."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ..config import DetectionConfig
from ..detection.scoring import score_events
from ..features.behavioral import FEATURE_COLUMNS
from .base import BaseDetector


class HeuristicEngineModel(BaseDetector):
    """Adapter exposing the weighted heuristic engine through the model interface."""

    name = "Heuristic engine"
    description = "Configurable weighted rules (heuristic 0-100 score scaled to 0-1; not a probability)."

    def __init__(self, cfg: DetectionConfig | None = None):
        self.cfg = cfg or DetectionConfig()
        self.default_threshold = self.cfg.alert_threshold / 100.0

    def score(self, X):
        return score_events(X, self.cfg)["risk_score"].to_numpy() / 100.0


class RuleBaselineModel(BaseDetector):
    """Transparent baseline: fraction of five fixed, human-readable rules that fire."""

    name = "Rule-based baseline"
    default_threshold = 0.2
    description = "Five fixed boolean rules; score = fraction fired. Flags when any rule fires."
    RULES = {
        "reactivated identity touches a sensitive resource": lambda X: (X["in_reactivation_window"] > 0) & (X["is_sensitive"] > 0),
        "unfamiliar admin tool on a sensitive resource": lambda X: (X["admin_tool_unfamiliar"] > 0) & (X["is_sensitive"] > 0),
        "4+ failed logins within the window": lambda X: X["failures_in_window"] >= 4,
        "3+ devices within the window": lambda X: X["distinct_devices_window"] >= 3,
        "3+ distinct sensitive resources in a session": lambda X: X["session_sensitive_distinct"] >= 3,
    }

    def score(self, X):
        fired = np.column_stack([np.asarray(rule(X)) for rule in self.RULES.values()])
        return fired.mean(axis=1)


class IsolationForestModel(BaseDetector):
    """Unsupervised anomaly detector. Trained without labels; score is a normalised anomaly score."""

    name = "Isolation Forest"
    description = "Unsupervised. Score = min-max-normalised anomaly score (not a probability)."

    def __init__(self, contamination: float = 0.02, n_estimators: int = 200, seed: int = 42):
        self.contamination = contamination
        self.model = IsolationForest(n_estimators=n_estimators, contamination="auto", random_state=seed, n_jobs=1)
        self._lo = self._hi = None

    def fit(self, X, y=None):
        data = X[FEATURE_COLUMNS].astype(float).to_numpy()
        self.model.fit(data)
        raw = -self.model.score_samples(data)
        self._lo, self._hi = float(raw.min()), float(raw.max())
        self.default_threshold = float(np.quantile(self._scale(raw), 1 - self.contamination))
        return self

    def _scale(self, raw):
        span = (self._hi - self._lo) or 1.0
        return np.clip((raw - self._lo) / span, 0.0, 1.0)

    def score(self, X):
        if self._lo is None:
            raise RuntimeError("IsolationForestModel must be fitted first.")
        return self._scale(-self.model.score_samples(X[FEATURE_COLUMNS].astype(float).to_numpy()))


class LogisticRegressionModel(BaseDetector):
    """Supervised baseline; requires labelled data with both classes."""

    name = "Logistic Regression"
    supervised = True
    score_is_probability = False  # class_weight='balanced' makes outputs uncalibrated
    description = "Supervised, class-balanced. Output is a model score, not a calibrated probability."

    def __init__(self, seed: int = 42):
        self.pipe = Pipeline([("scale", StandardScaler()),
                              ("clf", LogisticRegression(class_weight="balanced", max_iter=2000, random_state=seed))])

    def fit(self, X, y=None):
        if y is None or len(set(np.asarray(y).tolist())) < 2:
            raise ValueError("LogisticRegressionModel needs labelled data containing both classes.")
        self.pipe.fit(X[FEATURE_COLUMNS].astype(float).to_numpy(), np.asarray(y).astype(int))
        return self

    def score(self, X):
        return self.pipe.predict_proba(X[FEATURE_COLUMNS].astype(float).to_numpy())[:, 1]

    def coefficients(self) -> pd.DataFrame:
        coef = self.pipe.named_steps["clf"].coef_[0]
        return (pd.DataFrame({"feature": FEATURE_COLUMNS, "coefficient": coef})
                .sort_values("coefficient", key=np.abs, ascending=False).reset_index(drop=True))
