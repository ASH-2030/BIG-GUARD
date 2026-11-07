"""Central configuration: schema constants and detection settings."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields

SYNTHETIC_NOTICE = (
    "All generated records are SYNTHETIC. They contain no real credentials, "
    "organizational logs or personal information. IPs use RFC 5737 documentation ranges."
)
SCORE_NOTICE = (
    "Risk scores are HEURISTIC scores (a capped sum of rule weights, 0-100). "
    "They are not probabilities and are not calibrated."
)

REQUIRED_COLUMNS = [
    "event_id", "timestamp", "identity", "device", "source_ip", "event_type",
    "process", "resource", "session_id", "auth_status", "event_context",
]
OPTIONAL_COLUMNS = ["is_synthetic", "label", "scenario"]
NONE_TOKEN = "none"          # sentinel for "no process / no resource on this event"
UNKNOWN_TOKEN = "unknown"    # sentinel for missing categorical values
AUTH_STATUSES = ("success", "failure", "not_applicable")
EVENT_TYPES = ("login_success", "login_failure", "process_exec", "resource_access")
MAX_UPLOAD_ROWS = 100_000

SENSITIVE_RESOURCES = frozenset(
    {"finance_vault", "customer_records", "backup_archive", "ad_directory", "hr_records"}
)
# Dual-use administrative utilities. Presence alone is NOT malicious; the engine
# scores them only in context (identity baseline, resource sensitivity).
ADMIN_TOOLS = frozenset({"powershell", "cmd", "wmic", "schtasks", "certutil"})

SEVERITIES = ("Critical", "High", "Medium", "Low")
STATUSES = ("New", "Investigating", "Escalated", "Resolved", "False Positive")

DEFAULT_WEIGHTS = {
    "dormant_reactivation": 30,
    "new_device": 15,
    "new_source_ip": 10,
    "off_hours": 10,
    "first_sensitive_access": 20,
    "new_resource": 4,
    "new_process": 6,
    "unfamiliar_admin_tool": 25,
    "lotl_context_combo": 15,
    "failure_burst": 15,
    "success_after_failures": 30,
    "multi_device_burst": 25,
    "sensitive_sweep": 25,
    "novel_transition": 6,
}


@dataclass
class DetectionConfig:
    """All tunable heuristic parameters. Every field is surfaced in the dashboard sidebar."""

    alert_threshold: int = 45
    medium_threshold: int = 60
    high_threshold: int = 75
    critical_threshold: int = 90
    dormant_days: int = 30
    reactivation_window_hours: int = 24
    min_history_events: int = 40
    new_entity_window_hours: int = 24
    failure_burst_count: int = 4
    failure_window_minutes: int = 15
    multi_device_count: int = 3
    multi_device_window_minutes: int = 60
    sweep_distinct_sensitive: int = 3
    business_start_hour: int = 6
    business_end_hour: int = 20
    tool_familiar_days: int = 3
    weights: dict = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "DetectionConfig":
        raw = json.loads(text)
        known = {f.name for f in fields(cls)}
        cfg = cls(**{k: v for k, v in raw.items() if k in known})
        cfg.weights = {**DEFAULT_WEIGHTS, **cfg.weights}
        return cfg
