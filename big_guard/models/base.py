"""Model interface. Every detector consumes the causal feature table and returns a score in [0, 1]."""
from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np
import pandas as pd


class BaseDetector(ABC):
    """Common interface. ``X`` is the feature DataFrame produced by ``compute_event_features``."""

    name = "base"
    supervised = False
    implemented = True
    score_is_probability = False
    default_threshold = 0.5
    description = ""

    def fit(self, X: pd.DataFrame, y: np.ndarray | None = None) -> "BaseDetector":
        return self

    @abstractmethod
    def score(self, X: pd.DataFrame) -> np.ndarray:
        """Higher = more suspicious. Values lie in [0, 1]."""

    def predict(self, X: pd.DataFrame, threshold: float | None = None) -> np.ndarray:
        thr = self.default_threshold if threshold is None else threshold
        return (self.score(X) >= thr).astype(int)


class TemporalGraphDetector(BaseDetector):
    """PLACEHOLDER for the proposed Temporal Graph Neural Network (NOT IMPLEMENTED).

    A future implementation should consume the temporal edge table from
    ``big_guard.graph.temporal_edge_table`` plus node/edge features from
    ``big_guard.graph.schema`` and expose the same ``fit`` / ``score`` contract so it can be
    benchmarked side by side with the baselines. See docs/RESEARCH_METHODOLOGY.md.
    """

    name = "Temporal Graph NN (future work)"
    supervised = True
    implemented = False
    description = "Not implemented. No predictions are produced and none are displayed."

    def fit(self, X, y=None):
        raise NotImplementedError("The Temporal GNN is proposed future work and is not implemented.")

    def score(self, X):
        raise NotImplementedError("The Temporal GNN is proposed future work and is not implemented.")
