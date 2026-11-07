from datetime import timedelta

import pandas as pd

from big_guard.config import DEFAULT_WEIGHTS, DetectionConfig
from big_guard.data import generate_events
from big_guard.detection import build_alerts, score_events, severity_from_score
from big_guard.features import compute_event_features
from helpers import T0, history, make_events


def _run(rows, cfg=None):
    cfg = cfg or DetectionConfig()
    s = score_events(compute_event_features(make_events(rows), cfg), cfg)
    return s, build_alerts(s, cfg)


def test_dormant_identity_misuse_raises_explained_alert():
    rows = history(days=12) + [
        {"ts": T0 + timedelta(days=60, hours=-6), "event_type": "login_success", "process": "none", "resource": "none",
         "device": "WX-9", "source_ip": "203.0.113.9", "session_id": "ATK", "event_id": "A0"},
        {"ts": T0 + timedelta(days=60, hours=-5, minutes=50), "process": "powershell", "resource": "finance_vault",
         "device": "WX-9", "source_ip": "203.0.113.9", "session_id": "ATK", "event_id": "A1", "label": 1}]
    s, alerts = _run(rows)
    assert len(alerts) == 1
    a = alerts.iloc[0]
    assert a["identity"] == "alice" and a["severity"] in ("High", "Critical") and a["category"] == "Dormant Identity Activity"
    for text in ("alice", "inactivity", "finance_vault", "HEURISTIC", "not probabilities", "Why generated"):
        assert text in a["explanation"], text
    assert "dormant_reactivation" in a["signals"] and a["recommended_steps"]
    assert a["score_type"].startswith("heuristic")


def test_legitimate_admin_tool_use_is_not_flagged():
    rows = history("adm", days=10, admin_tool=True) + [
        {"ts": T0, "identity": "adm", "process": "powershell", "resource": "backup_archive", "event_id": "L1"},
        {"ts": T0 + timedelta(minutes=5), "identity": "adm", "process": "schtasks", "resource": "config_repo", "event_id": "L2"}]
    s, alerts = _run(rows)
    assert alerts.empty and s["risk_score"].max() < DetectionConfig().alert_threshold
    assert not s["sig_unfamiliar_admin_tool"].any()


def test_same_tool_on_non_admin_identity_in_sensitive_context_is_flagged():
    rows = history("bob", days=10) + [{"ts": T0, "identity": "bob", "process": "powershell", "resource": "customer_records", "event_id": "X"}]
    s, alerts = _run(rows)
    assert len(alerts) == 1 and alerts.iloc[0]["category"] == "Living-off-the-Land Context"
    assert s.loc[s["event_id"] == "X", "sig_lotl_context_combo"].iloc[0]


def test_returning_from_leave_alone_does_not_alert():
    rows = history(days=10) + [{"ts": T0 + timedelta(days=50), "event_id": "R"}]
    s, alerts = _run(rows)
    assert s.loc[s["event_id"] == "R", "sig_dormant_reactivation"].iloc[0]
    assert alerts.empty


def test_cold_start_identity_is_not_flagged_for_novelty():
    rows = [{"minutes": 0, "device": "WX-1", "process": "powershell", "resource": "finance_vault", "identity": "newbie"}]
    s, alerts = _run(rows)
    assert alerts.empty and s["risk_score"].iloc[0] == 0


def test_scores_bounded_integer_and_severity_monotonic():
    s = score_events(compute_event_features(generate_events(42)))
    assert s["risk_score"].between(0, 100).all()
    cfg = DetectionConfig()
    order = ["Info", "Low", "Medium", "High", "Critical"]
    sevs = [order.index(severity_from_score(x, cfg)) for x in range(0, 101)]
    assert sevs == sorted(sevs)


def test_configuration_changes_behaviour():
    f = compute_event_features(generate_events(42))
    loose = build_alerts(score_events(f, DetectionConfig(alert_threshold=30)), DetectionConfig(alert_threshold=30))
    strict = build_alerts(score_events(f, DetectionConfig(alert_threshold=90)), DetectionConfig(alert_threshold=90))
    assert len(loose) >= len(strict)
    zero = DetectionConfig(weights={k: 0 for k in DEFAULT_WEIGHTS})
    assert score_events(f, zero)["risk_score"].max() == 0


def test_alert_schema_and_ids():
    s = score_events(compute_event_features(generate_events(42)))
    alerts = build_alerts(s)
    need = {"alert_id", "timestamp", "identity", "severity", "category", "risk_score", "signals", "explanation",
            "recommended_steps", "status"}
    assert need <= set(alerts.columns) and alerts["alert_id"].is_unique
    assert (alerts["status"] == "New").all() and alerts["explanation"].str.len().min() > 100
    assert alerts.groupby(["identity", "session_id"]).size().max() == 1
