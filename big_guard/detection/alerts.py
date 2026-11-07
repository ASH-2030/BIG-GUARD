"""Alert construction: one alert per (identity, session) with a full explanation."""
from __future__ import annotations

import pandas as pd

from ..config import ADMIN_TOOLS, NONE_TOKEN, SCORE_NOTICE, DetectionConfig
from .scoring import SIGNAL_INFO, severity_from_score

CATEGORY_PRIORITY = [
    ("dormant_reactivation", "Dormant Identity Activity"),
    ("multi_device_burst", "Multi-Device Activity"),
    ("success_after_failures", "Unusual Authentication"),
    ("failure_burst", "Unusual Authentication"),
    ("lotl_context_combo", "Living-off-the-Land Context"),
    ("unfamiliar_admin_tool", "Living-off-the-Land Context"),
    ("sensitive_sweep", "Unusual Access Pattern"),
    ("first_sensitive_access", "Unusual Access Pattern"),
    ("new_device", "Unusual Source / Device"),
]

RECOMMENDED_STEPS = {
    "Dormant Identity Activity": [
        "Confirm with the account owner or HR/IT whether this identity is expected to be active again.",
        "Review the authentication source (device, IP, remote vs interactive) against the identity's history.",
        "Check for recent credential resets, MFA enrolment or device registration changes for the identity.",
        "Review every resource touched after reactivation, prioritising sensitive resources.",
        "If unexpected, follow your authorised incident-response process (e.g. require re-verification).",
    ],
    "Multi-Device Activity": [
        "Verify whether the user legitimately uses several devices (shared workstations, VDI, kiosks).",
        "Compare device identifiers and source IPs for each session in the time window.",
        "Check whether the sessions are concurrent and whether any device is unmanaged or unregistered.",
    ],
    "Unusual Authentication": [
        "Review the failed-login source IP/device and whether it matches the user's normal locations.",
        "Check lockout and MFA logs around the successful login.",
        "Ask the user whether they mistyped their password; if not, treat the credentials as at risk per policy.",
    ],
    "Living-off-the-Land Context": [
        "Do not assume the tool is malicious: confirm whether the identity has a legitimate administrative need.",
        "Review parent process, command-line arguments and change tickets for the activity (if your EDR provides them).",
        "Compare against the maintenance schedule and the identity's role.",
        "Review which sensitive resources the tool touched and whether access was authorised.",
    ],
    "Unusual Access Pattern": [
        "Confirm with the resource owner whether this identity should access these resources.",
        "Review the volume and sequence of accesses within the session.",
        "Check for recent role or permission changes for the identity.",
    ],
    "Unusual Source / Device": [
        "Check whether the device or IP is newly provisioned (hardware refresh, travel, VPN change).",
        "Verify device registration and compliance status.",
    ],
    "Anomalous Behavior": [
        "Review the flagged events in context with the account owner.",
        "Compare the activity against the identity's baseline before taking action.",
    ],
}


def _category(signals: set[str]) -> str:
    for sig, cat in CATEGORY_PRIORITY:
        if sig in signals:
            return cat
    return SIGNAL_INFO[next(iter(signals))][1] if signals else "Anomalous Behavior"


def _behaviours(grp: pd.DataFrame, signals: set[str], cfg: DetectionConfig) -> list[str]:
    out = []
    flagged = grp[grp["flagged"]]
    if "dormant_reactivation" in signals:
        out.append(f"activity resumed after about {grp['gap_days'].max():.0f} days of inactivity "
                   f"(dormancy threshold {cfg.dormant_days} days)")
    if "success_after_failures" in signals or "failure_burst" in signals:
        out.append(f"{int(grp['failures_in_window'].max())} failed logins within {cfg.failure_window_minutes} minutes"
                   " before/around a login")
    if "multi_device_burst" in signals:
        out.append(f"{int(grp['distinct_devices_window'].max())} distinct devices used within {cfg.multi_device_window_minutes} minutes")
    if "new_device" in signals or "new_source_ip" in signals:
        devs = sorted(set(grp.loc[grp["sig_new_device"], "device"]))[:4]
        out.append("activity from a device/IP not previously associated with the identity"
                   + (f" ({', '.join(devs)})" if devs else ""))
    tools = sorted(set(grp.loc[grp["sig_unfamiliar_admin_tool"], "process"]))
    if tools:
        out.append(f"administrative utilit{'y' if len(tools) == 1 else 'ies'} ({', '.join(tools)}) outside the identity's baseline")
    sens = sorted(set(flagged.loc[flagged["is_sensitive"] > 0, "resource"]) - {NONE_TOKEN})
    if sens:
        out.append(f"access to sensitive resource(s): {', '.join(sens)}")
    if "sensitive_sweep" in signals:
        out.append(f"{int(grp['session_sensitive_distinct'].max())} distinct sensitive resources in one session")
    if "off_hours" in signals:
        out.append("activity outside configured business hours")
    if "new_process" in signals or "novel_transition" in signals:
        out.append("process usage or sequence not seen before for this identity")
    return out or ["combination of weak behavioural deviations"]


def build_alerts(scored: pd.DataFrame, cfg: DetectionConfig | None = None) -> pd.DataFrame:
    """Aggregate flagged events into alerts (one per identity+session)."""
    cfg = cfg or DetectionConfig()
    flagged = scored[scored["flagged"]]
    cols = ["alert_id", "timestamp", "last_timestamp", "identity", "severity", "category", "risk_score",
            "score_type", "signals", "explanation", "recommended_steps", "status", "flagged_events",
            "session_id", "event_ids", "devices", "resources"]
    if flagged.empty:
        return pd.DataFrame(columns=cols)

    sig_cols = [c for c in scored.columns if c.startswith("sig_")]
    rows = []
    for (identity, session), g in flagged.groupby(["identity", "session_id"], sort=False):
        grp = scored[(scored["identity"] == identity) & (scored["session_id"] == session)]
        fired = {c[4:] for c in sig_cols if g[c].any()}
        top = g.loc[g["risk_score"].idxmax()]
        score = int(top["risk_score"])
        sev = severity_from_score(score, cfg)
        cat = _category(fired)
        contrib = "; ".join(f"{s} +{cfg.weights.get(s, 0)} ({SIGNAL_INFO[s][0]})"
                            for s in sorted(fired, key=lambda x: -cfg.weights.get(x, 0)))
        familiar = grp[(grp["process"].isin(ADMIN_TOOLS)) & (~grp["sig_unfamiliar_admin_tool"])]
        context = ""
        if len(familiar):
            context = (f" Context considered: {len(familiar)} administrative-tool event(s) in this session match the "
                       "identity's historical baseline and were NOT scored as suspicious.")
        behaviours = _behaviours(grp, fired, cfg)
        explanation = (
            f"Identity '{identity}' triggered a {sev} alert in session {session}. "
            f"Unusual behavior: {'; '.join(behaviours)}. "
            f"Contributing signals (highest-scoring event): {top['signals'] or 'n/a'}. "
            f"All signals fired in this session: {contrib}. "
            f"Why generated: the highest event score ({score}/100) reached the alert threshold ({cfg.alert_threshold}). "
            f"{SCORE_NOTICE}{context}"
        )
        rows.append({
            "timestamp": g["timestamp"].min(), "last_timestamp": g["timestamp"].max(), "identity": identity,
            "severity": sev, "category": cat, "risk_score": score, "score_type": "heuristic (0-100, not a probability)",
            "signals": contrib, "explanation": explanation,
            "recommended_steps": " | ".join(RECOMMENDED_STEPS[cat]), "status": "New",
            "flagged_events": int(len(g)), "session_id": session, "event_ids": ",".join(g["event_id"]),
            "devices": ", ".join(sorted(set(g["device"]))), "resources": ", ".join(sorted(set(g["resource"]) - {NONE_TOKEN})),
        })
    alerts = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    alerts.insert(0, "alert_id", [f"ALR-{i + 1:04d}" for i in range(len(alerts))])
    if "label" in scored.columns:
        lab = scored.dropna(subset=["label"]).set_index("event_id")["label"]
        alerts["contains_labelled_positive"] = [
            bool(lab.reindex(ids.split(",")).fillna(0).max() > 0) for ids in alerts["event_ids"]]
    return alerts
