"""Reproducible SYNTHETIC event generator.

Everything produced here is fabricated. IP addresses come from the RFC 5737
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

Ground-truth columns (``label``, ``scenario``) exist only so the evaluation module has
labelled data; they must never be used as model inputs.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

from ..config import NONE_TOKEN

BASE_DATE = datetime(2026, 1, 5, tzinfo=timezone.utc)  # a Monday
N_DAYS = 90

NORMAL = "normal"
BENIGN_SCENARIOS = (
    "benign_admin_maintenance", "benign_new_device", "benign_leave_return", "benign_failed_logins",
)
ATTACK_SCENARIOS = (
    "dormant_misuse", "lotl_context", "unusual_login", "multi_device_access", "unusual_access_sweep",
)
SCENARIOS = (NORMAL,) + BENIGN_SCENARIOS + ATTACK_SCENARIOS

STANDARD_RESOURCES = ["project_docs", "team_calendar", "public_share", "wiki", "timesheet", "mail_gateway", "crm_dashboard"]
APPS = ["browser", "office", "mail_client", "ide", "python"]
USER_TOOLS = ["python", "ide", "office"]
ADMIN_TOOL_LIST = ["powershell", "cmd", "wmic", "schtasks"]


class _Builder:
    """Accumulates rows; deterministic given the RNG seed."""

    def __init__(self, rng: np.random.Generator):
        self.rng = rng
        self.rows: list[dict] = []
        self._session = 0

    def new_session(self) -> str:
        self._session += 1
        return f"SES-{self._session:06d}"

    def emit(self, ts, identity, device, ip, etype, process, resource, session, auth, context, label, scenario):
        self.rows.append({
            "timestamp": ts, "identity": identity, "device": device, "source_ip": ip,
            "event_type": etype, "process": process, "resource": resource, "session_id": session,
            "auth_status": auth, "event_context": context, "is_synthetic": True,
            "label": int(label), "scenario": scenario,
        })


def _day_ts(day: int, hour: float) -> datetime:
    return BASE_DATE + timedelta(days=day, hours=float(hour))


def _is_workday(day: int) -> bool:
    return (day % 7) < 5


def _normal_session(b: _Builder, ident, dev, ip, ts, n_events, resources, tools, context="routine_work",
                    label=0, scenario=NORMAL, login_ctx="interactive_logon", tool_prob=0.22):
    s = b.new_session()
    b.emit(ts, ident, dev, ip, "login_success", NONE_TOKEN, NONE_TOKEN, s, "success", login_ctx, 0, scenario)
    t = ts
    for _ in range(n_events):
        t = t + timedelta(minutes=float(b.rng.uniform(4, 35)))
        if b.rng.random() < tool_prob:
            proc = str(b.rng.choice(tools))
            res = str(b.rng.choice(resources)) if b.rng.random() < 0.4 else NONE_TOKEN
            b.emit(t, ident, dev, ip, "process_exec", proc, res, s, "not_applicable", context, label, scenario)
        else:
            b.emit(t, ident, dev, ip, "resource_access", str(b.rng.choice(APPS)),
                   str(b.rng.choice(resources)), s, "not_applicable", context, label, scenario)
    return s


def _ip(prefix: str, rng: np.random.Generator) -> str:
    return f"{prefix}.{int(rng.integers(10, 240))}"


def _workday_sessions(b, ident, dev, ip, days, resources, tools, attendance=0.88, scenario=NORMAL, **kw):
    for d in days:
        if not _is_workday(d) or b.rng.random() > attendance:
            continue
        start = float(np.clip(b.rng.normal(9.0, 0.7), 7.2, 11.0))
        _normal_session(b, ident, dev, ip, _day_ts(d, start), int(b.rng.integers(3, 9)),
                        resources, tools, scenario=scenario, **kw)


def generate_events(seed: int = 42) -> pd.DataFrame:
    """Return a labelled synthetic event table (~19k rows, 90 days, 54 identities)."""
    rng = np.random.default_rng(seed)
    b = _Builder(rng)
    all_days = list(range(N_DAYS))
    counters = {"n": 0}

    def std_profile():
        res = list(rng.choice(STANDARD_RESOURCES, size=4, replace=False))
        return res, USER_TOOLS

    def new_identity(prefix):
        counters["n"] += 1
        i = counters["n"]
        return f"{prefix}_{i:03d}", f"WS-{i:03d}", _ip("192.0.2", rng)

    # ---- benign population -------------------------------------------------
    for _ in range(26):                                   # standard users
        ident, dev, ip = new_identity("user")
        res, tools = std_profile()
        _workday_sessions(b, ident, dev, ip, all_days, res, tools)

    for _ in range(6):                                    # finance users (legit sensitive access)
        ident, dev, ip = new_identity("fin")
        res = list(rng.choice(STANDARD_RESOURCES, size=3, replace=False)) + ["finance_vault", "customer_records"]
        _workday_sessions(b, ident, dev, ip, all_days, res, USER_TOOLS)

    for k in range(4):                                    # administrators (legit admin tools)
        counters["n"] += 1
        ident, dev, ip = f"adm_{k + 1:03d}", f"ADM-{k + 1:03d}", _ip("198.51.100", rng)
        res = list(rng.choice(STANDARD_RESOURCES, size=3, replace=False)) + ["ad_directory", "backup_archive", "config_repo"]
        tools = USER_TOOLS + ADMIN_TOOL_LIST
        _workday_sessions(b, ident, dev, ip, all_days, res, tools, tool_prob=0.4)
        for d in all_days:                                # weekly night change window (benign)
            if d % 7 == 2:
                _normal_session(b, ident, dev, ip, _day_ts(d, float(rng.uniform(0.8, 2.5))), int(rng.integers(4, 8)),
                                ["ad_directory", "backup_archive", "config_repo"], ADMIN_TOOL_LIST,
                                context="admin_change_window", scenario="benign_admin_maintenance", tool_prob=0.7)

    # benign: replaced laptop -> new device + new IP from day 50
    for _ in range(2):
        ident, dev, ip = new_identity("user")
        res, tools = std_profile()
        _workday_sessions(b, ident, dev, ip, range(0, 50), res, tools)
        _workday_sessions(b, ident, dev.replace("WS", "WN"), _ip("192.0.2", rng), range(50, N_DAYS), res, tools,
                          scenario="benign_new_device")

    # benign: long leave (35 days) then ordinary return
    ident, dev, ip = new_identity("user")
    res, tools = std_profile()
    _workday_sessions(b, ident, dev, ip, range(0, 21), res, tools)
    _workday_sessions(b, ident, dev, ip, range(56, 59), res, tools, scenario="benign_leave_return")
    _workday_sessions(b, ident, dev, ip, range(59, N_DAYS), res, tools)

    # benign: forgotten password (failures then success, home device, business hours)
    ident, dev, ip = new_identity("user")
    res, tools = std_profile()
    _workday_sessions(b, ident, dev, ip, all_days, res, tools)
    t0 = _day_ts(42, 9.4)
    s = b.new_session()
    for i in range(5):
        b.emit(t0 + timedelta(seconds=40 * i), ident, dev, ip, "login_failure", NONE_TOKEN, NONE_TOKEN, s,
               "failure", "interactive_logon", 0, "benign_failed_logins")
    b.emit(t0 + timedelta(seconds=260), ident, dev, ip, "login_success", NONE_TOKEN, NONE_TOKEN, s,
           "success", "interactive_logon", 0, "benign_failed_logins")

    # ---- suspicious scenarios (labelled) -----------------------------------
    sens_targets = ["finance_vault", "customer_records", "hr_records", "backup_archive"]

    for _ in range(4):                                    # 1. dormant identity misuse
        ident, dev, ip = new_identity("user")
        res, tools = std_profile()
        _workday_sessions(b, ident, dev, ip, range(0, 25), res, tools)
        adev, aip = f"WX-{counters['n']:03d}", _ip("203.0.113", rng)
        for d in (76, 81):
            s = b.new_session()
            t = _day_ts(d, float(rng.uniform(1.0, 4.0)))
            b.emit(t, ident, adev, aip, "login_success", NONE_TOKEN, NONE_TOKEN, s, "success", "remote_logon", 1, "dormant_misuse")
            for _ in range(int(rng.integers(5, 9))):
                t += timedelta(minutes=float(rng.uniform(2, 12)))
                if rng.random() < 0.55:
                    b.emit(t, ident, adev, aip, "process_exec", str(rng.choice(["powershell", "cmd"])),
                           str(rng.choice(sens_targets)), s, "not_applicable", "routine_work", 1, "dormant_misuse")
                else:
                    b.emit(t, ident, adev, aip, "resource_access", "browser", str(rng.choice(sens_targets)),
                           s, "not_applicable", "routine_work", 1, "dormant_misuse")

    for _ in range(3):                                    # 2. contextual LotL on an active non-admin identity
        ident, dev, ip = new_identity("user")
        res, tools = std_profile()
        _workday_sessions(b, ident, dev, ip, all_days, res, tools)
        d = int(rng.choice([66, 69, 72, 75]))
        t = _day_ts(d, float(rng.uniform(13.0, 15.0)))
        s = b.new_session()
        b.emit(t - timedelta(minutes=30), ident, dev, ip, "login_success", NONE_TOKEN, NONE_TOKEN, s, "success", "interactive_logon", 0, "lotl_context")
        for _ in range(int(rng.integers(5, 8))):
            t += timedelta(minutes=float(rng.uniform(1, 6)))
            b.emit(t, ident, dev, ip, "process_exec", str(rng.choice(["powershell", "wmic", "cmd"])),
                   str(rng.choice(["customer_records", "hr_records", "backup_archive"])), s, "not_applicable",
                   "routine_work", 1, "lotl_context")

    for _ in range(3):                                    # 3. unusual login (failures from new source, then success)
        ident, dev, ip = new_identity("user")
        res, tools = std_profile()
        _workday_sessions(b, ident, dev, ip, all_days, res, tools)
        adev, aip = f"WX-{counters['n']:03d}", _ip("203.0.113", rng)
        t = _day_ts(int(rng.choice([70, 74, 78])), float(rng.uniform(2.0, 4.0)))
        s = b.new_session()
        for _ in range(int(rng.integers(6, 10))):
            t += timedelta(seconds=float(rng.uniform(30, 90)))
            b.emit(t, ident, adev, aip, "login_failure", NONE_TOKEN, NONE_TOKEN, s, "failure", "remote_logon", 1, "unusual_login")
        t += timedelta(seconds=45)
        b.emit(t, ident, adev, aip, "login_success", NONE_TOKEN, NONE_TOKEN, s, "success", "remote_logon", 1, "unusual_login")
        for r in list(rng.choice(res, size=3, replace=False)) + [str(rng.choice(sens_targets))]:
            t += timedelta(minutes=float(rng.uniform(2, 8)))
            b.emit(t, ident, adev, aip, "resource_access", "browser", r, s, "not_applicable", "routine_work", 1, "unusual_login")

    for _ in range(2):                                    # 4. one identity authenticating from many devices at once
        ident, dev, ip = new_identity("user")
        res, tools = std_profile()
        _workday_sessions(b, ident, dev, ip, all_days, res, tools)
        t = _day_ts(int(rng.choice([68, 73])), float(rng.uniform(10.0, 14.0)))
        for k in range(5):
            s = b.new_session()
            d2, i2 = f"WZ-{counters['n']:03d}-{k}", _ip("198.51.100", rng)
            t += timedelta(minutes=float(rng.uniform(3, 9)))
            b.emit(t, ident, d2, i2, "login_success", NONE_TOKEN, NONE_TOKEN, s, "success", "remote_logon", 1, "multi_device_access")
            for _ in range(2):
                t += timedelta(minutes=float(rng.uniform(1, 3)))
                b.emit(t, ident, d2, i2, "resource_access", "browser", str(rng.choice(res)), s,
                       "not_applicable", "routine_work", 1, "multi_device_access")

    for _ in range(2):                                    # 5. sweep of sensitive resources, never accessed before
        ident, dev, ip = new_identity("user")
        res, tools = std_profile()
        _workday_sessions(b, ident, dev, ip, all_days, res, tools)
        t = _day_ts(int(rng.choice([71, 77])), float(rng.uniform(9.5, 11.5)))
        s = b.new_session()
        b.emit(t - timedelta(minutes=10), ident, dev, ip, "login_success", NONE_TOKEN, NONE_TOKEN, s, "success", "interactive_logon", 0, "unusual_access_sweep")
        for r in sens_targets:
            t += timedelta(minutes=float(rng.uniform(1, 3)))
            b.emit(t, ident, dev, ip, "process_exec", "archive_utility", r, s, "not_applicable", "routine_work", 1, "unusual_access_sweep")

    df = pd.DataFrame(b.rows).sort_values(["timestamp", "identity"], kind="stable").reset_index(drop=True)
    df.insert(0, "event_id", [f"EVT-{i + 1:06d}" for i in range(len(df))])
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df
