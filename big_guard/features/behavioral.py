"""Causal behavioural / temporal feature engineering.

Every feature of an event is computed ONLY from that identity's earlier events (plus the event
itself). Nothing looks into the future, so features are safe for time-ordered evaluation.
"""
from __future__ import annotations

from collections import deque

import numpy as np
import pandas as pd

from ..config import ADMIN_TOOLS, NONE_TOKEN, SENSITIVE_RESOURCES, DetectionConfig

FEATURE_COLUMNS = [
    "gap_days", "hour", "is_off_hours", "is_weekend", "new_device", "new_source_ip", "new_resource",
    "new_process", "is_sensitive", "is_admin_tool", "admin_tool_unfamiliar", "in_reactivation_window",
    "failures_in_window", "distinct_devices_window", "session_sensitive_distinct", "novel_transition",
    "is_login_failure", "has_baseline", "log_prior_events",
]


def compute_event_features(events: pd.DataFrame, cfg: DetectionConfig | None = None) -> pd.DataFrame:
    """Return the events (sorted by time) with causal feature columns appended."""
    cfg = cfg or DetectionConfig()
    df = events.sort_values(["timestamp", "event_id"], kind="stable").reset_index(drop=True)
    n = len(df)

    # robust epoch-seconds regardless of datetime unit (ns/us)
    ts = ((df["timestamp"] - pd.Timestamp("1970-01-01", tz="UTC")) // pd.Timedelta(seconds=1)).to_numpy(dtype=np.int64)
    devices = df["device"].tolist()
    ips = df["source_ip"].tolist()
    resources = df["resource"].tolist()
    procs = df["process"].tolist()
    etypes = df["event_type"].tolist()
    sessions = df["session_id"].tolist()

    out = {k: np.zeros(n, dtype=float) for k in (
        "gap_days", "new_device", "new_source_ip", "new_resource", "new_process", "is_sensitive",
        "is_admin_tool", "admin_tool_unfamiliar", "in_reactivation_window", "failures_in_window",
        "distinct_devices_window", "session_sensitive_distinct", "novel_transition", "is_login_failure",
        "has_baseline", "log_prior_events", "first_sensitive_access")}

    fail_win = cfg.failure_window_minutes * 60
    dev_win = cfg.multi_device_window_minutes * 60
    react_win = cfg.reactivation_window_hours * 3600
    new_win = cfg.new_entity_window_hours * 3600
    dormant_sec = cfg.dormant_days * 86400

    for _, idx in df.groupby("identity", sort=False).indices.items():
        dev_first: dict = {}
        ip_first: dict = {}
        seen_res, seen_proc, seen_pairs = set(), set(), set()
        admin_days: set = set()
        last_ts = None
        react_ts = None
        fails: deque = deque()
        devwin: deque = deque()
        sess_sens: dict[str, set] = {}
        sess_prev: dict[str, str] = {}
        for k, i in enumerate(idx):
            t = ts[i]
            dev, ip, res, proc, et, ses = devices[i], ips[i], resources[i], procs[i], etypes[i], sessions[i]
            has_hist = k > 0
            out["log_prior_events"][i] = np.log1p(k)
            out["has_baseline"][i] = float(k >= cfg.min_history_events)

            if last_ts is not None:
                gap = t - last_ts
                out["gap_days"][i] = gap / 86400.0
                if gap > dormant_sec:
                    react_ts = t
            out["in_reactivation_window"][i] = float(react_ts is not None and (t - react_ts) <= react_win)

            # a device/IP counts as "new" while it is younger than new_entity_window_hours for this identity
            out["new_device"][i] = float(has_hist and (dev not in dev_first or t - dev_first[dev] <= new_win))
            out["new_source_ip"][i] = float(has_hist and (ip not in ip_first or t - ip_first[ip] <= new_win))
            sensitive = res in SENSITIVE_RESOURCES
            out["is_sensitive"][i] = float(sensitive)
            out["new_resource"][i] = float(has_hist and res != NONE_TOKEN and not sensitive and res not in seen_res)
            out["new_process"][i] = float(has_hist and proc != NONE_TOKEN and proc not in seen_proc)
            out["is_login_failure"][i] = float(et == "login_failure")

            # first-ever access to a sensitive resource is tracked via a separate column below
            first_sens = has_hist and sensitive and res not in seen_res
            out["first_sensitive_access"][i] = float(first_sens)

            is_admin = proc in ADMIN_TOOLS
            out["is_admin_tool"][i] = float(is_admin)
            if is_admin:
                # familiar = identity has used administrative tools on >= tool_familiar_days distinct days
                out["admin_tool_unfamiliar"][i] = float(len(admin_days) < cfg.tool_familiar_days)

            # failed-login window (count includes the current failure; for a success it is prior failures)
            while fails and t - fails[0] > fail_win:
                fails.popleft()
            if et == "login_failure":
                fails.append(t)
            out["failures_in_window"][i] = len(fails)
            if et == "login_success":
                fails.clear()

            # distinct devices within the multi-device window
            devwin.append((t, dev))
            while devwin and t - devwin[0][0] > dev_win:
                devwin.popleft()
            out["distinct_devices_window"][i] = len({d for _, d in devwin})

            # per-session sensitive sweep and transition novelty
            if sensitive:
                sess_sens.setdefault(ses, set()).add(res)
            out["session_sensitive_distinct"][i] = len(sess_sens.get(ses, ()))
            prev = sess_prev.get(ses)
            if has_hist and prev is not None and proc != NONE_TOKEN and prev != NONE_TOKEN:
                out["novel_transition"][i] = float((prev, proc) not in seen_pairs)
            if proc != NONE_TOKEN:
                if prev is not None and prev != NONE_TOKEN:
                    seen_pairs.add((prev, proc))
                sess_prev[ses] = proc

            # state updates (after feature capture)
            dev_first.setdefault(dev, t); ip_first.setdefault(ip, t); seen_proc.add(proc)
            if res != NONE_TOKEN:
                seen_res.add(res)
            if is_admin:
                admin_days.add(t // 86400)
            last_ts = t

    feats = pd.DataFrame(out)
    hour = df["timestamp"].dt.hour
    weekday = df["timestamp"].dt.weekday
    feats["hour"] = hour.to_numpy(dtype=float)
    feats["is_weekend"] = (weekday >= 5).to_numpy(dtype=float)
    feats["is_off_hours"] = (((hour < cfg.business_start_hour) | (hour >= cfg.business_end_hour)) | (weekday >= 5)).to_numpy(dtype=float)
    return pd.concat([df, feats], axis=1)


def feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Numeric model input. Never includes ground-truth columns (label / scenario)."""
    return df[FEATURE_COLUMNS].astype(float)


def identity_summary(df: pd.DataFrame, alerts: pd.DataFrame | None = None, score_col: str = "risk_score") -> pd.DataFrame:
    """One row per identity: activity, diversity, temporal gaps and detection results."""
    g = df.groupby("identity")
    s = pd.DataFrame({
        "events": g.size(),
        "active_days": g["timestamp"].apply(lambda x: x.dt.date.nunique()),
        "first_seen": g["timestamp"].min(),
        "last_seen": g["timestamp"].max(),
        "devices": g["device"].nunique(),
        "source_ips": g["source_ip"].nunique(),
        "resources": g["resource"].apply(lambda x: x[x != NONE_TOKEN].nunique()),
        "sensitive_events": g["is_sensitive"].sum().astype(int) if "is_sensitive" in df else 0,
        "admin_tool_events": g["is_admin_tool"].sum().astype(int) if "is_admin_tool" in df else 0,
        "login_failures": g["event_type"].apply(lambda x: int((x == "login_failure").sum())),
        "max_gap_days": g["gap_days"].max() if "gap_days" in df else 0.0,
    })
    if score_col in df:
        s["max_risk_score"] = g[score_col].max()
        s["flagged_events"] = g[score_col].apply(lambda x: int((x > 0).sum()))
    if alerts is not None and len(alerts):
        ac = alerts.groupby("identity").size().rename("alerts")
        s = s.join(ac)
    s["alerts"] = s["alerts"].fillna(0).astype(int) if "alerts" in s else 0
    return s.reset_index().sort_values(["max_risk_score" if "max_risk_score" in s else "events"], ascending=False)
