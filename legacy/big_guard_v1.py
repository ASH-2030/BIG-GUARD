"""Core defensive detection logic for the BIG-Guard demonstration."""
from __future__ import annotations
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import random
import uuid

SENSITIVE_RESOURCES = {"finance_vault", "customer_records", "backup_archive"}
ADMIN_TOOLS = {"powershell", "cmd", "wmi"}
NORMAL_USERS = [f"user_{i:02d}" for i in range(1, 9)]

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def generate_event():
    """Generate a benign event most of the time and occasional safe test anomalies."""
    if random.random() < 0.16:
        return {
            "event_id": str(uuid.uuid4())[:8],
            "timestamp": now_iso(),
            "user": "dormant_user",
            "process": random.choice(["powershell", "cmd"]),
            "resource": random.choice(["finance_vault", "customer_records"]),
            "source": "SIMULATOR",
            "note": "Synthetic dormant-account scenario"
        }
    return {
        "event_id": str(uuid.uuid4())[:8],
        "timestamp": now_iso(),
        "user": random.choice(NORMAL_USERS),
        "process": random.choice(["browser", "office", "python", "backup_agent"]),
        "resource": random.choice(["public_share", "project_docs", "team_calendar"]),
        "source": "SIMULATOR",
        "note": "Synthetic routine activity"
    }

class EventDetector:
    """Transparent heuristic detector with an in-memory identity activity graph."""
    def __init__(self):
        self.last_seen = {}
        self.relationships = deque(maxlen=500)
        self.alerted_keys = set()

    def process(self, event):
        user = event["user"]
        process = event["process"]
        resource = event["resource"]
        timestamp = datetime.fromisoformat(event["timestamp"])
        previous = self.last_seen.get(user)
        self.last_seen[user] = timestamp
        self.relationships.append((user, process, resource, event["timestamp"]))

        score = 0
        reasons = []
        rule = "Contextual activity"

        # A controlled demo identity is initialized as dormant so the scenario
        # can be demonstrated immediately without waiting weeks for history.
        if user == "dormant_user" and resource in SENSITIVE_RESOURCES:
            score += 65
            reasons.append("Dormant demo identity accessed a sensitive resource.")
            rule = "Sleeper-account behavior"

        if process in ADMIN_TOOLS and resource in SENSITIVE_RESOURCES:
            score += 25
            reasons.append("Administrative utility used in a sensitive-resource access context.")
            if rule == "Contextual activity":
                rule = "Living-off-the-Land context"

        if previous and timestamp - previous > timedelta(days=30) and resource in SENSITIVE_RESOURCES:
            score += 20
            reasons.append("More than 30 days since the identity's previous observed event.")
            rule = "Long-inactivity access"

        if score < 50:
            return None

        key = (user, rule, resource)
        if key in self.alerted_keys:
            return None
        self.alerted_keys.add(key)

        return {
            "alert_id": str(uuid.uuid4())[:8],
            "timestamp": event["timestamp"],
            "user": user,
            "rule": rule,
            "severity": "HIGH" if score >= 70 else "MEDIUM",
            "risk_score": min(score, 100),
            "resource": resource,
            "process": process,
            "explanation": " ".join(reasons),
            "event_id": event["event_id"]
        }

def demo_batch(count=20, seed=7):
    random.seed(seed)
    detector = EventDetector()
    events, alerts = [], []
    for _ in range(count):
        event = generate_event()
        events.append(event)
        alert = detector.process(event)
        if alert:
            alerts.append(alert)
    return events, alerts
