"""Configurable, explainable heuristic scoring.

risk_score = min(100, sum(weight of every signal that fired)). It is a HEURISTIC score, not a probability.
New-entity signals are suppressed until an identity has ``min_history_events`` of history (cold start).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from ..config import DetectionConfig

# signal -> (label, category)
SIGNAL_INFO = {
    "dormant_reactivation": ("Activity after long inactivity", "Dormant Identity Activity"),
    "new_device": ("Device never seen for this identity", "Unusual Source / Device"),
    "new_source_ip": ("Source IP never seen for this identity", "Unusual Source / Device"),
    "off_hours": ("Activity outside business hours", "Anomalous Behavior"),
    "first_sensitive_access": ("First access to a sensitive resource", "Unusual Access Pattern"),
    "new_resource": ("Resource never accessed before", "Unusual Access Pattern"),
    "new_process": ("Process never used by this identity", "Unexpected Process Activity"),
    "unfamiliar_admin_tool": ("Administrative tool outside this identity's baseline", "Living-off-the-Land Context"),
    "lotl_context_combo": ("Unfamiliar admin tool touching a sensitive resource", "Living-off-the-Land Context"),
    "failure_burst": ("Burst of failed logins", "Unusual Authentication"),
    "success_after_failures": ("Successful login right after a failure burst", "Unusual Authentication"),
    "multi_device_burst": ("Many devices used within a short window", "Multi-Device Activity"),
    "sensitive_sweep": ("Several distinct sensitive resources in one session", "Unusual Access Pattern"),
    "novel_transition": ("Process sequence not seen before for this identity", "Unusual Activity Sequence"),
}


def _flags(f: pd.DataFrame, cfg: DetectionConfig) -> dict[str, np.ndarray]:
    base = f["has_baseline"].to_numpy() > 0
    b = lambda col: f[col].to_numpy() > 0  # noqa: E731
    unfamiliar = b("admin_tool_unfamiliar") & base
    return {
        "dormant_reactivation": b("in_reactivation_window") & base,
        "new_device": b("new_device") & base,
        "new_source_ip": b("new_source_ip") & base,
        "off_hours": b("is_off_hours") & base,
        "first_sensitive_access": b("first_sensitive_access") & base,
        "new_resource": b("new_resource") & base,
        "new_process": b("new_process") & base,
        "unfamiliar_admin_tool": unfamiliar,
        "lotl_context_combo": unfamiliar & b("is_sensitive"),
        "failure_burst": b("is_login_failure") & (f["failures_in_window"].to_numpy() >= cfg.failure_burst_count),
        "success_after_failures": (f["event_type"].to_numpy() == "login_success") & (f["failures_in_window"].to_numpy() >= cfg.failure_burst_count),
        "multi_device_burst": f["distinct_devices_window"].to_numpy() >= cfg.multi_device_count,
        "sensitive_sweep": f["session_sensitive_distinct"].to_numpy() >= cfg.sweep_distinct_sensitive,
        "novel_transition": b("novel_transition") & base,
    }


def severity_from_score(score: float, cfg: DetectionConfig) -> str:
    if score >= cfg.critical_threshold:
        return "Critical"
    if score >= cfg.high_threshold:
        return "High"
    if score >= cfg.medium_threshold:
        return "Medium"
    if score >= cfg.alert_threshold:
        return "Low"
    return "Info"


def score_events(features: pd.DataFrame, cfg: DetectionConfig | None = None) -> pd.DataFrame:
    """Append sig_* flags, ``risk_score`` (heuristic 0-100), ``signals`` text and ``severity``."""
    cfg = cfg or DetectionConfig()
    flags = _flags(features, cfg)
    total = np.zeros(len(features))
    parts: list[list[str]] = [[] for _ in range(len(features))]
    out = features.copy()
    for name, mask in flags.items():
        w = cfg.weights.get(name, 0)
        out[f"sig_{name}"] = mask
        total += mask * w
        for i in np.flatnonzero(mask):
            parts[i].append(f"{name}(+{w})")
    out["risk_score"] = np.clip(total, 0, 100).round(0).astype(int)
    out["signals"] = [", ".join(p) for p in parts]
    out["severity"] = [severity_from_score(s, cfg) for s in out["risk_score"]]
    out["flagged"] = out["risk_score"] >= cfg.alert_threshold
    return out
