import numpy as np
import pytest

from big_guard.config import DetectionConfig
from big_guard.data import generate_events
from big_guard.detection import score_events
from big_guard.evaluation import classification_metrics, curves, identity_grouped_split, measure_latency, run_benchmark
from big_guard.features import FEATURE_COLUMNS, compute_event_features
from big_guard.models import (HeuristicEngineModel, IsolationForestModel, LogisticRegressionModel, RuleBaselineModel,
                              TemporalGraphDetector)


def _feats():
    return compute_event_features(generate_events(42))


def test_metrics_exact_values():
    y = [1, 1, 1, 0, 0, 0, 0, 0]
    s = [0.9, 0.8, 0.2, 0.7, 0.1, 0.1, 0.1, 0.1]
    m = classification_metrics(y, s, 0.5)
    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (2, 1, 4, 1)
    assert m["precision"] == pytest.approx(2 / 3) and m["recall"] == pytest.approx(2 / 3)
    assert m["f1"] == pytest.approx(2 / 3) and m["false_positive_rate"] == pytest.approx(0.2)
    assert 0.8 < m["roc_auc"] <= 1 and 0.5 < m["pr_auc"] <= 1


def test_metrics_handle_degenerate_inputs():
    m = classification_metrics([0, 0, 0], [0.1, 0.2, 0.3], 0.5)
    assert m["roc_auc"] is None and m["pr_auc"] is None and m["precision"] == 0.0 and m["recall"] == 0.0
    assert curves([0, 0], [0.1, 0.2]) == {}


def test_latency_is_positive_and_scales_fields():
    lat = measure_latency(lambda X: sum(range(1000)), list(range(100)), repeats=3)
    assert lat["total_ms"] >= 0 and lat["ms_per_1000_events"] >= 0


def test_all_models_share_interface_and_return_unit_scores():
    f = _feats()
    models = [HeuristicEngineModel(), RuleBaselineModel(), IsolationForestModel().fit(f),
              LogisticRegressionModel().fit(f, f["label"].to_numpy())]
    for m in models:
        s = m.score(f.head(300))
        assert s.shape == (300,) and np.isfinite(s).all() and s.min() >= 0 and s.max() <= 1, m.name
        assert set(np.unique(m.predict(f.head(300)))) <= {0, 1}


def test_isolation_forest_needs_fit_and_is_deterministic():
    f = _feats()
    with pytest.raises(RuntimeError):
        IsolationForestModel().score(f.head(10))
    a = IsolationForestModel(seed=1).fit(f).score(f.head(200))
    b = IsolationForestModel(seed=1).fit(f).score(f.head(200))
    assert np.allclose(a, b)


def test_logistic_regression_requires_two_classes_and_never_sees_labels_as_features():
    f = _feats()
    with pytest.raises(ValueError):
        LogisticRegressionModel().fit(f, np.zeros(len(f)))
    assert "label" not in FEATURE_COLUMNS and "scenario" not in FEATURE_COLUMNS
    lr = LogisticRegressionModel().fit(f, f["label"].to_numpy())
    assert len(lr.coefficients()) == len(FEATURE_COLUMNS)


def test_temporal_gnn_is_an_honest_placeholder():
    t = TemporalGraphDetector()
    assert t.implemented is False
    with pytest.raises(NotImplementedError):
        t.fit(None)
    with pytest.raises(NotImplementedError):
        t.score(None)


def test_split_has_no_identity_leakage_and_is_stratified():
    f = _feats()
    tr, te = identity_grouped_split(f, seed=3)
    assert not set(tr) & set(te) and set(tr) | set(te) == set(f["identity"])
    pos = set(f.loc[f["label"] == 1, "identity"])
    assert pos & set(tr) and pos & set(te)
    assert identity_grouped_split(f, seed=3) == (tr, te)


def test_benchmark_on_labelled_data_uses_only_heldout_events():
    f = score_events(_feats())
    b = run_benchmark(f, DetectionConfig(), synthetic=True)
    assert b.mode == "labelled" and b.split_info["overlap"] == 0
    assert set(b.metrics["model"]) == {"Heuristic engine", "Rule-based baseline", "Isolation Forest", "Logistic Regression"}
    assert (b.metrics["n_events"] == b.split_info["test_events"]).all()
    assert b.metrics["ms_per_1000_events"].gt(0).all() and any("SYNTHETIC" in n for n in b.notes)
    assert set(b.scores["split"]) == {"train", "test"}


def test_benchmark_without_labels_reports_no_metrics():
    f = score_events(_feats().drop(columns=["label", "scenario"]))
    b = run_benchmark(f, DetectionConfig())
    assert b.mode == "unlabelled" and b.metrics.empty and "Isolation Forest" in b.scores.columns
    assert any("No usable ground-truth labels" in n for n in b.notes)
