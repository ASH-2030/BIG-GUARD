"""Temporal graph data schema (documented contract for the proposed Temporal GNN).

Only the NetworkX representation and the temporal edge table are implemented. The feature
definitions below describe what a learning model would consume; no GNN is trained here.
"""
NODE_TYPES = ("Identity", "Device", "Process", "Resource", "Session")

# relation -> (source node type, destination node type)
RELATIONS = {
    "authenticated_from": ("Identity", "Device"),
    "executed": ("Identity", "Process"),
    "accessed": ("Identity", "Resource"),
    "initiated_session": ("Identity", "Session"),
    "associated_with": ("Session", "Device"),
}
RELATION_LABELS = {
    "authenticated_from": "Authenticated From", "executed": "Executed", "accessed": "Accessed",
    "initiated_session": "Initiated Session", "associated_with": "Associated With",
}

NODE_FEATURES = {
    "Identity": ["event_count", "active_days", "distinct_devices", "distinct_resources", "sensitive_access_ratio",
                 "admin_tool_ratio", "login_failure_ratio", "max_gap_days", "off_hours_ratio"],
    "Device": ["event_count", "distinct_identities", "first_seen_age_days"],
    "Process": ["event_count", "is_admin_tool", "distinct_identities"],
    "Resource": ["event_count", "is_sensitive", "distinct_identities"],
    "Session": ["duration_minutes", "event_count", "sensitive_events", "distinct_resources"],
}
EDGE_FEATURES = ["timestamp", "relation_type", "dt_since_prev_edge_of_source", "is_first_occurrence",
                 "event_type", "auth_status", "hour_sin", "hour_cos", "weekday"]
