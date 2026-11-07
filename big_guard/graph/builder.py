"""NetworkX identity graph with temporal edge attributes, plus identity-centric views."""
from __future__ import annotations

import networkx as nx
import pandas as pd

from ..config import ADMIN_TOOLS, NONE_TOKEN, SENSITIVE_RESOURCES, UNKNOWN_TOKEN
from .schema import RELATIONS

_EMPTY = {NONE_TOKEN, UNKNOWN_TOKEN}


def nid(kind: str, name: str) -> str:
    return f"{kind}:{name}"


def _aggregate(df: pd.DataFrame, src_col: str, dst_col: str, src_t: str, dst_t: str, relation: str, G: nx.MultiDiGraph):
    sub = df[~df[dst_col].isin(_EMPTY)]
    if sub.empty:
        return
    agg = sub.groupby([src_col, dst_col]).agg(
        first_seen=("timestamp", "min"), last_seen=("timestamp", "max"), count=("event_id", "size"),
        flagged_count=("flagged", "sum"), max_score=("risk_score", "max")).reset_index()
    for r in agg.itertuples(index=False):
        s, d = nid(src_t, r[0]), nid(dst_t, r[1])
        for n, t, name in ((s, src_t, r[0]), (d, dst_t, r[1])):
            if n not in G:
                G.add_node(n, node_type=t, label=str(name))
        G.add_edge(s, d, key=relation, relation=relation, first_seen=r.first_seen, last_seen=r.last_seen,
                   count=int(r.count), flagged_count=int(r.flagged_count), max_score=int(r.max_score),
                   suspicious=bool(r.flagged_count > 0))


def build_graph(scored: pd.DataFrame) -> nx.MultiDiGraph:
    """Build the identity graph from a scored event table (needs ``flagged`` and ``risk_score``)."""
    df = scored
    if "flagged" not in df:
        df = df.assign(flagged=False, risk_score=0)
    G = nx.MultiDiGraph()
    _aggregate(df, "identity", "device", "Identity", "Device", "authenticated_from", G)
    _aggregate(df, "identity", "process", "Identity", "Process", "executed", G)
    _aggregate(df, "identity", "resource", "Identity", "Resource", "accessed", G)
    _aggregate(df, "identity", "session_id", "Identity", "Session", "initiated_session", G)
    # session -> device (each session is tied to the device(s) it ran on)
    sd = df[~df["device"].isin(_EMPTY) & ~df["session_id"].isin(_EMPTY)]
    agg = sd.groupby(["session_id", "device"]).agg(first_seen=("timestamp", "min"), last_seen=("timestamp", "max"),
                                                    count=("event_id", "size"), flagged_count=("flagged", "sum"),
                                                    max_score=("risk_score", "max")).reset_index()
    for r in agg.itertuples(index=False):
        s, d = nid("Session", r.session_id), nid("Device", r.device)
        G.add_edge(s, d, key="associated_with", relation="associated_with", first_seen=r.first_seen,
                   last_seen=r.last_seen, count=int(r.count), flagged_count=int(r.flagged_count),
                   max_score=int(r.max_score), suspicious=bool(r.flagged_count > 0))
    # node-level attributes
    for n, data in G.nodes(data=True):
        name = data["label"]
        data["sensitive"] = data["node_type"] == "Resource" and name in SENSITIVE_RESOURCES
        data["admin_tool"] = data["node_type"] == "Process" and name in ADMIN_TOOLS
        data["suspicious"] = any(e.get("suspicious") for _, _, e in G.edges(n, data=True)) if G.degree(n) else False
    return G


def temporal_edge_table(scored: pd.DataFrame) -> pd.DataFrame:
    """Event-level temporal edge list (the proposed input table for temporal graph learning)."""
    rows = []
    for rel, (_, _) in RELATIONS.items():
        if rel == "authenticated_from":
            cols, mask = ("identity", "device"), scored["device"].notna()
        elif rel == "executed":
            cols, mask = ("identity", "process"), ~scored["process"].isin(_EMPTY)
        elif rel == "accessed":
            cols, mask = ("identity", "resource"), ~scored["resource"].isin(_EMPTY)
        elif rel == "initiated_session":
            cols, mask = ("identity", "session_id"), scored["event_type"] == "login_success"
        else:
            cols, mask = ("session_id", "device"), scored["session_id"].notna()
        sub = scored[mask]
        rows.append(pd.DataFrame({
            "src": sub[cols[0]].to_numpy(), "dst": sub[cols[1]].to_numpy(), "relation": rel,
            "timestamp": sub["timestamp"].to_numpy(), "event_id": sub["event_id"].to_numpy(),
            "event_type": sub["event_type"].to_numpy(), "auth_status": sub["auth_status"].to_numpy(),
            "flagged": sub["flagged"].to_numpy() if "flagged" in sub else False,
        }))
    return pd.concat(rows, ignore_index=True).sort_values("timestamp", kind="stable").reset_index(drop=True)


def neighborhood(G: nx.MultiDiGraph, identity: str, include_sessions: bool = False, include_related: bool = False,
                 suspicious_only: bool = False, max_sessions: int = 10) -> nx.MultiDiGraph:
    """Identity-centred subgraph (kept small so it stays readable)."""
    center = nid("Identity", identity)
    if center not in G:
        return nx.MultiDiGraph()
    keep = {center}
    sessions = []
    for _, dst, e in G.out_edges(center, data=True):
        t = G.nodes[dst]["node_type"]
        if suspicious_only and not e.get("suspicious"):
            continue
        if t == "Session":
            sessions.append((e["last_seen"], dst, e.get("suspicious")))
        else:
            keep.add(dst)
    if include_sessions:
        sessions.sort(key=lambda x: (not x[2], x[0]), reverse=False)
        flagged = [s for s in sessions if s[2]]
        recent = sorted([s for s in sessions if not s[2]], key=lambda x: x[0], reverse=True)
        for _, s, _ in (flagged + recent)[:max_sessions]:
            keep.add(s)
            for _, dev, _e in G.out_edges(s, data=True):
                keep.add(dev)
    if include_related:
        for n in list(keep):
            nt = G.nodes[n]["node_type"]
            if nt == "Device" or (nt == "Resource" and G.nodes[n].get("sensitive")):
                for src, _, e in G.in_edges(n, data=True):
                    if G.nodes[src]["node_type"] == "Identity" and src != center:
                        keep.add(src)
    return G.subgraph(keep).copy()


def identity_behavior_summary(scored: pd.DataFrame, identity: str) -> dict:
    d = scored[scored["identity"] == identity]
    if d.empty:
        return {}
    res = d.loc[~d["resource"].isin(_EMPTY), "resource"]
    return {
        "identity": identity, "events": int(len(d)), "sessions": int(d["session_id"].nunique()),
        "active_days": int(d["timestamp"].dt.date.nunique()), "first_seen": d["timestamp"].min(),
        "last_seen": d["timestamp"].max(), "devices": sorted(d["device"].unique().tolist()),
        "source_ips": sorted(d["source_ip"].unique().tolist()),
        "top_resources": res.value_counts().head(5).to_dict(),
        "top_processes": d.loc[~d["process"].isin(_EMPTY), "process"].value_counts().head(5).to_dict(),
        "sensitive_events": int((d["resource"].isin(SENSITIVE_RESOURCES)).sum()),
        "admin_tool_events": int(d["process"].isin(ADMIN_TOOLS).sum()),
        "login_failures": int((d["event_type"] == "login_failure").sum()),
        "max_gap_days": float(d["gap_days"].max()) if "gap_days" in d else 0.0,
        "max_risk_score": int(d["risk_score"].max()) if "risk_score" in d else 0,
        "flagged_events": int(d["flagged"].sum()) if "flagged" in d else 0,
    }


def session_sequence(scored: pd.DataFrame, session_id: str) -> pd.DataFrame:
    cols = ["timestamp", "identity", "device", "source_ip", "event_type", "process", "resource", "auth_status",
            "event_context", "risk_score", "signals"]
    d = scored[scored["session_id"] == session_id]
    return d[[c for c in cols if c in d.columns]].sort_values("timestamp").reset_index(drop=True)
