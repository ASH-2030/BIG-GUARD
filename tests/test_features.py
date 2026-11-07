from datetime import timedelta

import pandas as pd

from big_guard.config import DetectionConfig
from big_guard.data import generate_events
from big_guard.features import FEATURE_COLUMNS, compute_event_features, feature_matrix
from helpers import T0, history, make_events


def _row(f, event_id):
    return f[f["event_id"] == event_id].iloc[0]


def test_feature_columns_exist_and_exclude_ground_truth():
    f = compute_event_features(generate_events(42).head(500))
    assert set(FEATURE_COLUMNS) <= set(f.columns)
    assert "label" not in FEATURE_COLUMNS and "scenario" not in FEATURE_COLUMNS
    assert feature_matrix(f).shape == (500, len(FEATURE_COLUMNS))


def test_features_are_causal_future_events_do_not_change_past_features():
    df = generate_events(42)
    cut = len(df) // 2
    full = compute_event_features(df).head(cut)
    part = compute_event_features(df.head(cut))
    assert (full[FEATURE_COLUMNS].to_numpy() == part[FEATURE_COLUMNS].to_numpy()).all()


def test_reactivation_after_long_gap():
    rows = history(days=10) + [{"ts": T0 + timedelta(days=50), "event_id": "R"}, {"ts": T0 + timedelta(days=50, hours=1), "event_id": "R2"},
                               {"ts": T0 + timedelta(days=53), "event_id": "LATE"}]
    f = compute_event_features(make_events(rows), DetectionConfig(dormant_days=30))
    assert _row(f, "R")["in_reactivation_window"] == 1 and _row(f, "R")["gap_days"] > 30
    assert _row(f, "R2")["in_reactivation_window"] == 1
    assert _row(f, "LATE")["in_reactivation_window"] == 0


def test_new_device_window_and_cold_start():
    rows = history(days=10) + [{"ts": T0, "event_id": "N", "device": "WX-9", "source_ip": "203.0.113.5"},
                               {"ts": T0 + timedelta(hours=2), "event_id": "N2", "device": "WX-9", "source_ip": "203.0.113.5"},
                               {"ts": T0 + timedelta(days=3), "event_id": "N3", "device": "WX-9", "source_ip": "203.0.113.5"}]
    f = compute_event_features(make_events(rows), DetectionConfig(min_history_events=40))
    assert _row(f, "N")["new_device"] == 1 and _row(f, "N")["new_source_ip"] == 1
    assert _row(f, "N2")["new_device"] == 1          # still inside the 24h novelty window
    assert _row(f, "N3")["new_device"] == 0
    assert _row(f, "N")["has_baseline"] == 1
    assert f.iloc[0]["has_baseline"] == 0             # first event of an identity has no baseline


def test_failed_login_burst_counts_and_resets_on_success():
    rows = [{"minutes": i, "event_type": "login_failure", "event_id": f"F{i}", "process": "none", "resource": "none",
             "auth_status": "failure"} for i in range(5)]
    rows.append({"minutes": 6, "event_type": "login_success", "event_id": "OK", "process": "none", "resource": "none"})
    rows.append({"minutes": 7, "event_type": "login_success", "event_id": "OK2", "process": "none", "resource": "none"})
    f = compute_event_features(make_events(rows), DetectionConfig(failure_window_minutes=15))
    assert _row(f, "F4")["failures_in_window"] == 5
    assert _row(f, "OK")["failures_in_window"] == 5      # failures preceding the success
    assert _row(f, "OK2")["failures_in_window"] == 0


def test_multi_device_and_sensitive_sweep():
    rows = [{"minutes": i * 5, "device": f"D{i}", "event_id": f"M{i}", "session_id": f"S{i}"} for i in range(4)]
    rows += [{"minutes": 60 + i, "resource": r, "event_id": f"X{i}", "session_id": "SW", "device": "D0"}
             for i, r in enumerate(["finance_vault", "customer_records", "hr_records"])]
    f = compute_event_features(make_events(rows), DetectionConfig())
    assert _row(f, "M3")["distinct_devices_window"] == 4
    assert _row(f, "X2")["session_sensitive_distinct"] == 3 and _row(f, "X1")["session_sensitive_distinct"] == 2


def test_admin_tool_familiarity_depends_on_identity_history():
    admin = make_events(history("admin1", days=6, admin_tool=True) + [{"ts": T0, "identity": "admin1", "process": "powershell", "event_id": "A"}])
    user = make_events(history("bob", days=6) + [{"ts": T0, "identity": "bob", "process": "powershell", "event_id": "B"}])
    f = compute_event_features(pd.concat([admin, user], ignore_index=True), DetectionConfig())
    assert _row(f, "A")["admin_tool_unfamiliar"] == 0
    assert _row(f, "B")["admin_tool_unfamiliar"] == 1
