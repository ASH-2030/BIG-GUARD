"""Test helpers: build tiny hand-made event tables."""
from datetime import datetime, timedelta, timezone

import pandas as pd

T0 = datetime(2026, 3, 2, 9, 0, tzinfo=timezone.utc)  # a Monday, 09:00 UTC


def make_events(rows):
    """rows: dicts with minutes (offset from T0 or datetime) and optional overrides."""
    out = []
    for i, r in enumerate(rows):
        ts = r.get("ts") or (T0 + timedelta(minutes=r.get("minutes", i)))
        out.append({
            "event_id": r.get("event_id", f"E{i:04d}"), "timestamp": ts, "identity": r.get("identity", "alice"),
            "device": r.get("device", "WS-1"), "source_ip": r.get("source_ip", "192.0.2.10"),
            "event_type": r.get("event_type", "resource_access"), "process": r.get("process", "browser"),
            "resource": r.get("resource", "wiki"), "session_id": r.get("session_id", "S1"),
            "auth_status": r.get("auth_status", "not_applicable"), "event_context": r.get("event_context", "routine_work"),
            "is_synthetic": True, "label": r.get("label", 0), "scenario": r.get("scenario", "normal"),
        })
    df = pd.DataFrame(out)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


def history(identity="alice", days=10, per_day=6, device="WS-1", ip="192.0.2.10", admin_tool=False):
    """Ordinary history: `days` workdays of normal activity ending before T0."""
    rows = []
    for d in range(days, 0, -1):
        base = T0 - timedelta(days=d)
        for k in range(per_day):
            proc = "powershell" if (admin_tool and k == 0) else "browser"
            rows.append({"ts": base + timedelta(minutes=10 * k), "identity": identity, "device": device,
                         "source_ip": ip, "process": proc, "resource": "wiki", "session_id": f"H{d}"})
    return rows
