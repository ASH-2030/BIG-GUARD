"""Evaluation metrics. All values are computed from real model outputs on labelled data."""
from __future__ import annotations

import time

import numpy as np
from sklearn.metrics import (average_precision_score, confusion_matrix, precision_recall_curve,
                             roc_auc_score, roc_curve)


def classification_metrics(y_true, y_score, threshold: float) -> dict:
    y_true = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score, dtype=float)
    y_pred = (y_score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    both = len(np.unique(y_true)) == 2
    return {
        "threshold": float(threshold), "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "precision": float(precision), "recall": float(recall), "f1": float(f1),
        "false_positive_rate": float(fpr),
        "roc_auc": float(roc_auc_score(y_true, y_score)) if both else None,
        "pr_auc": float(average_precision_score(y_true, y_score)) if both else None,
        "n_events": int(len(y_true)), "n_positive": int(y_true.sum()),
    }


def curves(y_true, y_score) -> dict:
    y_true = np.asarray(y_true).astype(int)
    if len(np.unique(y_true)) < 2:
        return {}
    fpr, tpr, _ = roc_curve(y_true, y_score)
    prec, rec, _ = precision_recall_curve(y_true, y_score)
    return {"roc": (fpr, tpr), "pr": (prec, rec)}


def measure_latency(fn, X, repeats: int = 5) -> dict:
    """Median wall-clock time of ``fn(X)`` (scoring only; feature extraction excluded)."""
    times = []
    for _ in range(max(1, repeats)):
        t0 = time.perf_counter()
        fn(X)
        times.append(time.perf_counter() - t0)
    med = float(np.median(times))
    n = max(len(X), 1)
    return {"total_ms": med * 1000, "ms_per_1000_events": med * 1000 * 1000 / n, "us_per_event": med * 1e6 / n}
