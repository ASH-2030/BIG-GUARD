"""Benchmark all implemented detectors on a held-out identity split."""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from ..config import DetectionConfig
from ..models import (HeuristicEngineModel, IsolationForestModel, LogisticRegressionModel,
                      RuleBaselineModel, TemporalGraphDetector)
from .metrics import classification_metrics, curves, measure_latency
from .splits import identity_grouped_split


@dataclass
class BenchmarkResult:
    mode: str                                   # "labelled" | "unlabelled"
    metrics: pd.DataFrame = field(default_factory=pd.DataFrame)
    confusion: dict = field(default_factory=dict)
    curves: dict = field(default_factory=dict)
    scores: pd.DataFrame = field(default_factory=pd.DataFrame)   # event_id, split, <model scores>
    notes: list = field(default_factory=list)
    split_info: dict = field(default_factory=dict)
    lr_coefficients: pd.DataFrame = field(default_factory=pd.DataFrame)
    unavailable: list = field(default_factory=list)


def run_benchmark(features: pd.DataFrame, cfg: DetectionConfig | None = None, seed: int = 42,
                  synthetic: bool = True) -> BenchmarkResult:
    cfg = cfg or DetectionConfig()
    labelled = ("label" in features.columns and features["label"].notna().any()
                and features["label"].dropna().nunique() == 2 and int(features["label"].sum()) >= 5)
    res = BenchmarkResult(mode="labelled" if labelled else "unlabelled")
    res.unavailable = [TemporalGraphDetector().name]
    heur, rules, iso = HeuristicEngineModel(cfg), RuleBaselineModel(), IsolationForestModel(seed=seed)

    scores = pd.DataFrame({"event_id": features["event_id"].to_numpy()})
    if not labelled:
        iso.fit(features)
        scores["split"] = "all"
        scores["Heuristic engine"] = heur.score(features)
        scores["Rule-based baseline"] = rules.score(features)
        scores[iso.name] = iso.score(features)
        res.scores = scores
        res.notes.append("No usable ground-truth labels (need a 0/1 'label' column with both classes and at least "
                         "5 positives). Performance metrics, ROC/PR and the supervised model are unavailable; "
                         "unsupervised scores are shown for exploration only.")
        return res

    train_ids, test_ids = identity_grouped_split(features, seed=seed)
    is_test = features["identity"].isin(test_ids).to_numpy()
    known = features["label"].notna().to_numpy()
    train = features[~is_test & known]
    test = features[is_test & known]
    res.split_info = {
        "train_identities": len(train_ids), "test_identities": len(test_ids),
        "train_events": int(len(train)), "test_events": int(len(test)),
        "train_positives": int(train["label"].sum()), "test_positives": int(test["label"].sum()),
        "overlap": len(set(train_ids) & set(test_ids)),
    }
    iso.fit(train)
    models = [heur, rules, iso]
    lr = None
    if train["label"].nunique() == 2:
        lr = LogisticRegressionModel(seed=seed).fit(train, train["label"].to_numpy())
        models.append(lr)
        res.lr_coefficients = lr.coefficients()
    else:
        res.notes.append("Training split has a single class; Logistic Regression was skipped.")

    y_test = test["label"].astype(int).to_numpy()
    rows = []
    for m in models:
        s = m.score(test)
        met = classification_metrics(y_test, s, m.default_threshold)
        lat = measure_latency(m.score, test)
        rows.append({"model": m.name, "type": "supervised" if m.supervised else
                     ("unsupervised" if m.name == iso.name else "rule-based"), **met, **lat})
        res.confusion[m.name] = np.array([[met["tn"], met["fp"]], [met["fn"], met["tp"]]])
        res.curves[m.name] = curves(y_test, s)
    res.metrics = pd.DataFrame(rows)

    scores["split"] = np.where(is_test, "test", "train")
    for m in models:
        scores[m.name] = m.score(features)
    res.scores = scores
    res.notes.append("Metrics are computed on held-out TEST identities only; train identities are never scored for evaluation.")
    if synthetic:
        res.notes.append("SYNTHETIC DEMONSTRATION: the labels come from the same generator that authored the scenarios "
                         "the rules look for. Results show the pipeline works, not real-world detection performance.")
    return res
