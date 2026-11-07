"""The nine dashboard pages. Each takes a ``Context`` and renders with Streamlit."""
from __future__ import annotations

import importlib.metadata as md
import json
import platform
from dataclasses import dataclass

import pandas as pd
import streamlit as st

from ..config import (ADMIN_TOOLS, OPTIONAL_COLUMNS, REQUIRED_COLUMNS, SCORE_NOTICE, SENSITIVE_RESOURCES, SEVERITIES,
                      STATUSES, SYNTHETIC_NOTICE)
from ..data import sample_csv_bytes
from ..detection import SIGNAL_INFO
from ..evaluation import BenchmarkResult
from ..graph import (EDGE_FEATURES, NODE_FEATURES, RELATIONS, build_graph, identity_behavior_summary, neighborhood,
                     session_sequence, temporal_edge_table)
from ..graph.schema import RELATION_LABELS
from ..models import TemporalGraphDetector
from ..pipeline import PipelineResult
from ..utils.helpers import SEVERITY_COLORS, to_csv_bytes
from . import charts
from .components import (alert_card, badge, callout, esc, hero, metric_card, section, severity_badge, show_df,
                         show_plot)

PAGES = [
    "Security Overview", "Identity Behavior Analytics", "Event Explorer", "Temporal Activity Analysis",
    "Identity Relationship Graph", "Threat & Alert Center", "AI/ML Detection Results",
    "Model Performance & Evaluation", "System Information",
]


@dataclass
class Context:
    result: PipelineResult
    bench: BenchmarkResult
    data_key: str


def _banner(ctx: Context):
    if ctx.result.synthetic:
        callout("SYNTHETIC DEMONSTRATION DATA. " + SYNTHETIC_NOTICE, "warn")
    else:
        callout(f"Uploaded dataset: {ctx.result.source_name}. Scores are heuristic and are not probabilities.", "info")


# --------------------------------------------------------------------------- 1
def page_overview(ctx: Context):
    r = ctx.result
    ev, al = r.events, r.alerts
    hero("Security Operations Center · Defensive Analytics", "Security Overview",
         "Identity behavior, temporal patterns and explainable alerts at a glance.")
    _banner(ctx)
    crit_high = int(al["severity"].isin(["Critical", "High"]).sum()) if len(al) else 0
    cols = st.columns(5)
    cards = [
        ("Events analysed", f"{len(ev):,}", f"{ev['timestamp'].min():%Y-%m-%d} → {ev['timestamp'].max():%Y-%m-%d}", "#3b82f6"),
        ("Identities", f"{ev['identity'].nunique():,}", f"{ev['device'].nunique():,} devices", "#2dd4bf"),
        ("Alerts", f"{len(al):,}", f"threshold {r.config.alert_threshold}/100 (heuristic)", "#a78bfa"),
        ("Critical / High", f"{crit_high:,}", "needs prioritised review", "#fb7185"),
        ("Flagged events", f"{int(ev['flagged'].sum()):,}", f"{ev['flagged'].mean() * 100:.2f}% of all events", "#fbbf24"),
    ]
    for col, (a, b, c, d) in zip(cols, cards):
        with col:
            metric_card(a, b, c, d)
    a, b = st.columns([2, 1])
    with a, st.container(border=True):
        show_plot(charts.daily_activity(ev), key="ov_daily")
    with b, st.container(border=True):
        show_plot(charts.severity_donut(al), key="ov_sev")
    a, b = st.columns(2)
    with a, st.container(border=True):
        show_plot(charts.top_risk_identities(r.identities), key="ov_top")
    with b, st.container(border=True):
        show_plot(charts.category_bar(al), key="ov_cat")
    section("Highest-priority alerts")
    if al.empty:
        callout("No alerts at the current threshold.", "ok")
    else:
        for _, row in al.sort_values("risk_score", ascending=False).head(5).iterrows():
            alert_card(row)
        st.caption("Open 'Threat & Alert Center' for explanations and recommended investigation steps.")


# --------------------------------------------------------------------------- 2
def page_identities(ctx: Context):
    r = ctx.result
    hero("Behavioral analytics", "Identity Behavior Analytics", "Per-identity baselines, diversity of devices/resources and risk.")
    _banner(ctx)
    ids = r.identities["identity"].tolist()
    a, b = st.columns([1, 2])
    with a, st.container(border=True):
        ident = st.selectbox("Identity (sorted by highest risk score)", ids, key="ia_identity")
        s = identity_behavior_summary(r.events, ident)
        st.markdown(
            f'<div class="small-muted">First seen</div>{esc(str(s["first_seen"])[:16])} UTC'
            f'<div class="small-muted" style="margin-top:6px">Last seen</div>{esc(str(s["last_seen"])[:16])} UTC'
            f'<div class="small-muted" style="margin-top:6px">Devices</div>{esc(", ".join(s["devices"][:6]))}'
            f'<div class="small-muted" style="margin-top:6px">Source IPs</div>{esc(", ".join(s["source_ips"][:6]))}'
            f'<div class="small-muted" style="margin-top:6px">Top resources</div>{esc(", ".join(s["top_resources"]) or "-")}'
            f'<div class="small-muted" style="margin-top:6px">Top processes</div>{esc(", ".join(s["top_processes"]) or "-")}',
            unsafe_allow_html=True)
    with b:
        c = st.columns(4)
        vals = [("Events", f"{s['events']:,}", f"{s['sessions']} sessions", "#3b82f6"),
                ("Max risk score", s["max_risk_score"], f"{s['flagged_events']} flagged events (heuristic)", "#fb7185"),
                ("Sensitive events", s["sensitive_events"], f"{s['admin_tool_events']} admin-tool events", "#fbbf24"),
                ("Longest gap", f"{s['max_gap_days']:.0f} d", f"{s['login_failures']} login failures", "#2dd4bf")]
        for col, v in zip(c, vals):
            with col:
                metric_card(*v)
        with st.container(border=True):
            show_plot(charts.identity_timeline(r.events, ident), key="ia_timeline")
    a, b = st.columns([1, 1])
    with a, st.container(border=True):
        show_plot(charts.identity_daily(r.events, ident), key="ia_daily")
    with b, st.container(border=True):
        show_plot(charts.risk_scatter(r.identities), key="ia_scatter")
    section("All identities")
    show_df(r.identities, hide_index=True, column_config={
        "max_risk_score": st.column_config.ProgressColumn("Max risk score", min_value=0, max_value=100, format="%d"),
        "first_seen": st.column_config.DatetimeColumn("First seen", format="YYYY-MM-DD HH:mm"),
        "last_seen": st.column_config.DatetimeColumn("Last seen", format="YYYY-MM-DD HH:mm"),
        "max_gap_days": st.column_config.NumberColumn("Max gap (days)", format="%.1f")})
    st.download_button("⬇ Download identity summary CSV", to_csv_bytes(r.identities), "big_guard_identities.csv", "text/csv")


# --------------------------------------------------------------------------- 3
def page_events(ctx: Context):
    r = ctx.result
    ev = r.events
    hero("Telemetry", "Event Explorer", "Filter, search and export the normalised event table.")
    _banner(ctx)
    with st.container(border=True):
        c = st.columns([2, 2, 2, 2])
        text = c[0].text_input("Search identity / device / process / resource", key="ee_text")
        etypes = c[1].multiselect("Event type", sorted(ev["event_type"].unique()), key="ee_etype")
        auth = c[2].multiselect("Auth status", sorted(ev["auth_status"].unique()), key="ee_auth")
        only_flagged = c[3].checkbox("Flagged events only", key="ee_flag")
        d0, d1 = ev["timestamp"].min().date(), ev["timestamp"].max().date()
        rng = st.date_input("Date range (UTC)", value=(d0, d1), min_value=d0, max_value=d1, key="ee_dates")
    f = ev
    if text:
        t = text.lower()
        f = f[f[["identity", "device", "process", "resource", "source_ip"]].apply(
            lambda col: col.astype(str).str.lower().str.contains(t, regex=False)).any(axis=1)]
    if etypes:
        f = f[f["event_type"].isin(etypes)]
    if auth:
        f = f[f["auth_status"].isin(auth)]
    if only_flagged:
        f = f[f["flagged"]]
    if isinstance(rng, (tuple, list)) and len(rng) == 2:
        f = f[(f["timestamp"].dt.date >= rng[0]) & (f["timestamp"].dt.date <= rng[1])]
    st.caption(f"{len(f):,} of {len(ev):,} events match. Showing the first 2,000 rows.")
    cols = ["timestamp", "event_id", "identity", "device", "source_ip", "event_type", "process", "resource", "session_id",
            "auth_status", "event_context", "risk_score", "signals"]
    show_df(f[cols].head(2000), hide_index=True, column_config={
        "timestamp": st.column_config.DatetimeColumn("Timestamp (UTC)", format="YYYY-MM-DD HH:mm:ss"),
        "risk_score": st.column_config.ProgressColumn("Heuristic score", min_value=0, max_value=100, format="%d")})
    st.download_button("⬇ Download filtered events CSV", to_csv_bytes(f[cols]), "big_guard_events.csv", "text/csv")


# --------------------------------------------------------------------------- 4
def page_temporal(ctx: Context):
    r = ctx.result
    ev = r.events
    hero("Time-based behavior", "Temporal Activity Analysis", "Activity rhythm, off-hours behavior and dormant-identity reactivation.")
    _banner(ctx)
    a, b = st.columns(2)
    with a, st.container(border=True):
        show_plot(charts.hour_weekday_heatmap(ev), key="ta_heat")
    with b, st.container(border=True):
        show_plot(charts.hourly_flagged(ev), key="ta_hourly")
    a, b = st.columns([3, 2])
    with a, st.container(border=True):
        show_plot(charts.gap_chart(r.identities, r.config.dormant_days), key="ta_gap")
    with b:
        section("Reactivation events")
        st.caption(f"First events after an inactivity gap longer than {r.config.dormant_days} days.")
        react = ev[(ev["gap_days"] > r.config.dormant_days)][["timestamp", "identity", "gap_days", "device", "resource", "risk_score"]]
        if react.empty:
            callout("No identity was reactivated after the dormancy threshold.", "ok")
        else:
            show_df(react.sort_values("gap_days", ascending=False), hide_index=True, column_config={
                "gap_days": st.column_config.NumberColumn("Gap (days)", format="%.1f"),
                "timestamp": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm")})
    callout("A long gap alone is NOT treated as malicious: returning from leave produces the dormant signal "
            "(+" + str(r.config.weights["dormant_reactivation"]) + ") but stays below the alert threshold unless combined with other deviations.", "info")


# --------------------------------------------------------------------------- 5
def page_graph(ctx: Context):
    r = ctx.result
    hero("Behavioral Identity Graph", "Identity Relationship Graph",
         "Identity ↔ Device ↔ Process ↔ Resource ↔ Session relationships with first/last-seen timestamps.")
    _banner(ctx)
    callout("This is a NetworkX graph built from events, with temporal attributes on every relationship. "
            "It is NOT a trained Temporal Graph Neural Network (see AI/ML pages and docs).", "warn")
    ids = r.identities["identity"].tolist()
    with st.container(border=True):
        c = st.columns([2, 1, 1, 1])
        ident = c[0].selectbox("Identity", ids, key="g_ident")
        sessions = c[1].checkbox("Show sessions", value=False, key="g_sess")
        related = c[2].checkbox("Show related identities", value=False, key="g_rel",
                                help="Other identities sharing a device or a sensitive resource.")
        susp = c[3].checkbox("Suspicious relationships only", value=False, key="g_susp")
    sub = neighborhood(r.graph, ident, include_sessions=sessions, include_related=related, suspicious_only=susp)
    cols = st.columns(4)
    for col, (a, b, c_, d) in zip(cols, [
        ("Nodes shown", sub.number_of_nodes(), f"of {r.graph.number_of_nodes():,} total", "#3b82f6"),
        ("Relationships shown", sub.number_of_edges(), f"of {r.graph.number_of_edges():,} total", "#2dd4bf"),
        ("Suspicious relationships", sum(1 for *_, e in sub.edges(data=True) if e["suspicious"]), "edges with flagged events", "#fb7185"),
        ("Node types", len({d["node_type"] for _, d in sub.nodes(data=True)}), "of 5 defined", "#a78bfa")]):
        with col:
            metric_card(a, b, c_, d)
    with st.container(border=True):
        show_plot(charts.graph_figure(sub), key="g_fig")
    t1, t2, t3, t4 = st.tabs(["Relationships", "Identity summary", "Event sequence inspector", "Temporal graph schema"])
    with t1:
        rows = [{"relation": RELATION_LABELS[e["relation"]], "source": sub.nodes[u]["label"], "target": sub.nodes[v]["label"],
                 "first_seen": e["first_seen"], "last_seen": e["last_seen"], "events": e["count"],
                 "flagged_events": e["flagged_count"], "max_score": e["max_score"], "suspicious": e["suspicious"]}
                for u, v, e in sub.edges(data=True)]
        df = pd.DataFrame(rows)
        if df.empty:
            st.info("No relationships for this selection.")
        else:
            show_df(df.sort_values(["suspicious", "max_score"], ascending=False), hide_index=True)
            st.download_button("⬇ Download shown relationships CSV", to_csv_bytes(df), "big_guard_graph_edges.csv", "text/csv")
    with t2:
        s = identity_behavior_summary(r.events, ident)
        st.json({k: (str(v) if not isinstance(v, (int, float, list, dict)) else v) for k, v in s.items()})
    with t3:
        sess_ids = (r.events[r.events["identity"] == ident].groupby("session_id")["risk_score"].max()
                    .sort_values(ascending=False).index.tolist())
        sid = st.selectbox("Session (highest score first)", sess_ids, key="g_session")
        seq = session_sequence(r.events, sid)
        show_df(seq, hide_index=True, column_config={
            "risk_score": st.column_config.ProgressColumn("Heuristic score", min_value=0, max_value=100, format="%d")})
    with t4:
        st.markdown("**Node types:** " + ", ".join(RELATIONS_NODE_TYPES))
        st.table(pd.DataFrame([{"relation": RELATION_LABELS[k], "source": v[0], "target": v[1]} for k, v in RELATIONS.items()]))
        st.markdown("**Proposed node features (for future graph learning):**")
        st.table(pd.DataFrame({"node type": list(NODE_FEATURES), "features": [", ".join(v) for v in NODE_FEATURES.values()]}))
        st.markdown("**Proposed edge features:** " + ", ".join(EDGE_FEATURES))
        te = temporal_edge_table(r.events)
        st.caption(f"Temporal edge table (event-level, input for temporal learning): {len(te):,} rows.")
        st.download_button("⬇ Download temporal edge table CSV", to_csv_bytes(te), "big_guard_temporal_edges.csv", "text/csv")


RELATIONS_NODE_TYPES = ["Identity", "Device", "Process", "Resource", "Session"]


# --------------------------------------------------------------------------- 6
def page_alerts(ctx: Context):
    r = ctx.result
    hero("Alert management", "Threat & Alert Center", "Explainable alerts with contributing signals and recommended investigation steps.")
    _banner(ctx)
    callout(SCORE_NOTICE, "info")
    al = r.alerts.copy()
    if al.empty:
        callout("No alerts at the current threshold. Lower the alert threshold in the sidebar to see weaker signals.", "ok")
        return
    store = st.session_state.setdefault("alert_status", {})
    if store.get("_key") != ctx.data_key:
        store.clear()
        store["_key"] = ctx.data_key
    al["status"] = [store.get(a, s) for a, s in zip(al["alert_id"], al["status"])]

    with st.container(border=True):
        c = st.columns([2, 2, 2, 2, 2])
        sev = c[0].multiselect("Severity", [s for s in SEVERITIES if s in set(al["severity"])], key="ac_sev")
        cat = c[1].multiselect("Category", sorted(al["category"].unique()), key="ac_cat")
        stat = c[2].multiselect("Status", list(STATUSES), key="ac_stat")
        ident = c[3].text_input("Identity contains", key="ac_ident")
        sort = c[4].selectbox("Sort by", ["Risk score (high → low)", "Time (newest first)", "Time (oldest first)", "Severity"], key="ac_sort")
        min_score = st.slider("Minimum heuristic score", 0, 100, 0, key="ac_min")
    f = al
    if sev:
        f = f[f["severity"].isin(sev)]
    if cat:
        f = f[f["category"].isin(cat)]
    if stat:
        f = f[f["status"].isin(stat)]
    if ident:
        f = f[f["identity"].str.contains(ident, case=False, regex=False)]
    f = f[f["risk_score"] >= min_score]
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    if sort.startswith("Risk"):
        f = f.sort_values(["risk_score", "timestamp"], ascending=[False, True])
    elif "newest" in sort:
        f = f.sort_values("timestamp", ascending=False)
    elif "oldest" in sort:
        f = f.sort_values("timestamp")
    else:
        f = f.assign(_o=f["severity"].map(order)).sort_values(["_o", "risk_score"], ascending=[True, False]).drop(columns="_o")

    st.caption(f"{len(f)} of {len(al)} alerts. Investigation status is editable in the table and kept for this session.")
    table_cols = ["alert_id", "timestamp", "severity", "category", "identity", "risk_score", "status", "flagged_events", "resources"]
    edited = st.data_editor(
        f[table_cols], hide_index=True, key="ac_editor", disabled=[c for c in table_cols if c != "status"],
        column_config={
            "status": st.column_config.SelectboxColumn("Status", options=list(STATUSES), required=True),
            "risk_score": st.column_config.ProgressColumn("Heuristic score", min_value=0, max_value=100, format="%d"),
            "timestamp": st.column_config.DatetimeColumn("First flagged (UTC)", format="YYYY-MM-DD HH:mm")})
    for aid, s in zip(edited["alert_id"], edited["status"]):
        store[aid] = s

    section("Alert details")
    if f.empty:
        st.info("No alert matches the filters.")
    else:
        pick = st.selectbox("Select an alert", f["alert_id"].tolist(), key="ac_pick")
        a = f[f["alert_id"] == pick].iloc[0]
        c1, c2 = st.columns([3, 2])
        with c1, st.container(border=True):
            st.markdown(f'{severity_badge(a["severity"])} &nbsp; <b>{esc(a["category"])}</b> &nbsp; '
                        f'{badge("heuristic " + str(int(a["risk_score"])) + "/100", "#a78bfa")}', unsafe_allow_html=True)
            st.markdown("**Identity:** " + esc(a["identity"]) + " · **Session:** " + esc(a["session_id"]))
            st.markdown("**Why this alert was generated**")
            st.write(a["explanation"])
            st.markdown("**Signals contributing to the score**")
            for part in a["signals"].split("; "):
                st.markdown("- " + part)
        with c2, st.container(border=True):
            st.markdown("**Recommended investigation steps**")
            for step in a["recommended_steps"].split(" | "):
                st.markdown("- " + step)
            st.caption("Steps are defensive suggestions; follow your organisation's authorised incident-response process.")
        with st.expander("Events in this session"):
            show_df(session_sequence(r.events, a["session_id"]), hide_index=True)
    out = f.copy()
    out["status"] = [store.get(x, s) for x, s in zip(out["alert_id"], out["status"])]
    st.download_button("⬇ Download alerts CSV (current filters)", to_csv_bytes(out), "big_guard_alerts.csv", "text/csv")


# --------------------------------------------------------------------------- 7
def page_ml(ctx: Context):
    b = ctx.bench
    r = ctx.result
    hero("Machine learning", "AI/ML Detection Results", "Baseline models, their scores and what they can (and cannot) tell you.")
    _banner(ctx)
    t = TemporalGraphDetector()
    c = st.columns(4)
    with c[0]:
        metric_card("Heuristic engine", "Implemented", "weighted explainable rules", "#2dd4bf")
    with c[1]:
        metric_card("Isolation Forest", "Implemented", "unsupervised anomaly score", "#3b82f6")
    with c[2]:
        metric_card("Logistic Regression", "Implemented" if b.mode == "labelled" else "Needs labels",
                    "supervised baseline", "#a78bfa" if b.mode == "labelled" else "#64748b")
    with c[3]:
        metric_card("Temporal GNN", "Not implemented", "proposed future work", "#fb7185")
    st.markdown(f'<div class="small-muted">{esc(t.name)}: {esc(t.description)}</div>', unsafe_allow_html=True)
    for n in b.notes:
        callout(n, "warn" if "SYNTHETIC" in n else "info")
    models = [m for m in b.scores.columns if m not in ("event_id", "split")]
    pick = st.selectbox("Model", models, key="ml_pick")
    merged = r.events[["event_id", "timestamp", "identity", "device", "event_type", "process", "resource", "risk_score"]].merge(
        b.scores[["event_id", "split", pick]], on="event_id")
    thr = None
    if not b.metrics.empty and pick in set(b.metrics["model"]):
        thr = float(b.metrics.loc[b.metrics["model"] == pick, "threshold"].iloc[0])
    a, c2 = st.columns([1, 1])
    with a, st.container(border=True):
        show_plot(charts.score_distribution(merged[pick], thr if thr is not None else 0.5, pick), key="ml_dist")
    with c2, st.container(border=True):
        st.markdown("**Model description**")
        descr = {"Heuristic engine": "Weighted, configurable rules; every score is explained by named signals.",
                 "Rule-based baseline": "Five transparent boolean rules; score is the fraction that fire.",
                 "Isolation Forest": "Unsupervised; flags events whose features are easy to isolate. Fitted without labels.",
                 "Logistic Regression": "Supervised, class-balanced linear model; coefficients below show feature influence."}
        st.write(descr.get(pick, ""))
        st.caption("Scores are model outputs in [0, 1]. They are not calibrated probabilities. "
                   + ("Operating threshold used for evaluation: " + f"{thr:.3f}." if thr is not None else ""))
        if pick == "Logistic Regression" and not b.lr_coefficients.empty:
            show_df(b.lr_coefficients.head(10), hide_index=True)
    section("Highest-scoring events")
    top = merged.sort_values(pick, ascending=False).head(25)
    show_df(top, hide_index=True, column_config={
        pick: st.column_config.ProgressColumn("Model score", min_value=0.0, max_value=1.0, format="%.3f"),
        "risk_score": st.column_config.NumberColumn("Heuristic score")})
    st.download_button("⬇ Download model scores CSV", to_csv_bytes(merged), "big_guard_model_scores.csv", "text/csv")


# --------------------------------------------------------------------------- 8
def page_performance(ctx: Context):
    b = ctx.bench
    r = ctx.result
    hero("Evaluation", "Model Performance & Evaluation", "Precision, recall, F1, confusion matrices, ROC/PR curves and latency on held-out data.")
    _banner(ctx)
    for n in b.notes:
        callout(n, "warn" if "SYNTHETIC" in n else "info")
    if b.mode != "labelled":
        callout("No labelled data available, so no performance metrics are shown. Upload a CSV with a 0/1 'label' column "
                "(and at least 5 positives) to evaluate the models.", "info")
        return
    si = b.split_info
    c = st.columns(4)
    for col, v in zip(c, [("Train identities", si["train_identities"], f"{si['train_events']:,} events", "#3b82f6"),
                          ("Test identities", si["test_identities"], f"{si['test_events']:,} events", "#2dd4bf"),
                          ("Test positives", si["test_positives"], "labelled suspicious events", "#fb7185"),
                          ("Train/test overlap", si["overlap"], "identities (must be 0)", "#a78bfa")]):
        with col:
            metric_card(*v)
    m = b.metrics
    section("Metrics on the held-out test identities")
    show_df(m[["model", "type", "precision", "recall", "f1", "false_positive_rate", "roc_auc", "pr_auc", "tp", "fp", "tn", "fn",
               "threshold", "ms_per_1000_events"]], hide_index=True, column_config={
        k: st.column_config.NumberColumn(k.replace("_", " "), format="%.3f") for k in
        ["precision", "recall", "f1", "false_positive_rate", "roc_auc", "pr_auc", "threshold", "ms_per_1000_events"]})
    a, c2 = st.columns(2)
    with a, st.container(border=True):
        show_plot(charts.metrics_bar(m), key="pf_bar")
    with c2, st.container(border=True):
        show_plot(charts.latency_bar(m), key="pf_lat")
    a, c2 = st.columns(2)
    with a, st.container(border=True):
        show_plot(charts.roc_figure(b.curves), key="pf_roc")
    with c2, st.container(border=True):
        show_plot(charts.pr_figure(b.curves), key="pf_pr")
    section("Confusion matrices")
    names = list(b.confusion)
    for i in range(0, len(names), 2):
        cols = st.columns(2)
        for col, n in zip(cols, names[i:i + 2]):
            with col, st.container(border=True):
                show_plot(charts.confusion_heatmap(b.confusion[n], n), key=f"pf_cm_{n}")
    st.caption("Precision/recall/F1 use each model's stated operating threshold; ROC-AUC and PR-AUC are threshold-free. "
               "Latency covers scoring only (feature extraction: "
               f"{r.timings['feature_ms_per_1000_events']:.0f} ms per 1,000 events). Event-level labels; rare positives make PR-AUC "
               "more informative than ROC-AUC.")
    st.download_button("⬇ Download evaluation results CSV", to_csv_bytes(m), "big_guard_evaluation.csv", "text/csv")


# --------------------------------------------------------------------------- 9
def _ver(pkg: str) -> str:
    try:
        return md.version(pkg)
    except md.PackageNotFoundError:
        return "not installed"


def page_system(ctx: Context):
    r = ctx.result
    hero("Platform", "System Information", "Versions, dataset schema, configuration, scope and limitations.")
    _banner(ctx)
    t1, t2, t3, t4 = st.tabs(["Environment & data", "Configuration", "Scope: implemented vs future", "Schema & CSV template"])
    with t1:
        c = st.columns(2)
        with c[0], st.container(border=True):
            st.markdown("**Environment**")
            st.table(pd.DataFrame({"component": ["Python", "Streamlit", "Plotly", "pandas", "scikit-learn", "NetworkX", "BIG-Guard"],
                                   "version": [platform.python_version(), _ver("streamlit"), _ver("plotly"), _ver("pandas"),
                                               _ver("scikit-learn"), _ver("networkx"), _ver("big-guard") if _ver("big-guard") != "not installed" else "2.0.0"]}))
        with c[1], st.container(border=True):
            st.markdown("**Dataset & pipeline timings**")
            ev = r.events
            st.table(pd.DataFrame({"item": ["Source", "Events", "Identities", "Alerts", "Graph nodes / edges", "Labelled", "Feature extraction", "Scoring"],
                                   "value": [r.source_name, f"{len(ev):,}", f"{ev['identity'].nunique():,}", f"{len(r.alerts):,}",
                                             f"{r.graph.number_of_nodes():,} / {r.graph.number_of_edges():,}",
                                             "yes" if "label" in ev and ev["label"].notna().any() else "no",
                                             f"{r.timings['feature_extraction_s']:.2f} s", f"{r.timings['scoring_s']:.2f} s"]}))
    with t2:
        st.markdown("**Active detection configuration**")
        st.json(json.loads(r.config.to_json()))
        st.markdown("**Signals**")
        st.table(pd.DataFrame([{"signal": k, "weight": r.config.weights.get(k, 0), "meaning": v[0], "category": v[1]}
                               for k, v in SIGNAL_INFO.items()]))
        st.caption("Sensitive resources: " + ", ".join(sorted(SENSITIVE_RESOURCES)) + " · Administrative tools "
                   "(dual-use, scored only in context): " + ", ".join(sorted(ADMIN_TOOLS)))
    with t3:
        st.table(pd.DataFrame([
            ("Synthetic data generator (seeded, labelled)", "Implemented"), ("CSV upload, validation, preprocessing", "Implemented"),
            ("Causal behavioral/temporal features", "Implemented"), ("Identity graph (NetworkX, temporal edge attributes)", "Implemented"),
            ("Explainable heuristic detection + alerts", "Implemented"), ("Isolation Forest / Logistic Regression / rule baseline", "Implemented"),
            ("Evaluation (P/R/F1, CM, FPR, ROC/PR-AUC, latency)", "Implemented"),
            ("Temporal Graph Neural Network", "Future work (not implemented)"), ("Real SIEM / AD / EDR integration", "Future work (not implemented)"),
            ("Validation on real, authorised, labelled data", "Future work (not done)")], columns=["Capability", "Status"]))
        st.markdown("**Limitations:** synthetic labels come from the same author as the rules (results are optimistic and not evidence of real-world "
                    "performance); event-level labels; heuristic scores are not probabilities; business hours are assumed UTC; no real infrastructure is "
                    "contacted; nothing here performs or enables offensive activity.")
    with t4:
        st.markdown("**Required columns:** " + ", ".join(REQUIRED_COLUMNS))
        st.markdown("**Optional columns:** " + ", ".join(OPTIONAL_COLUMNS) + " (`label` must be 0/1 to enable evaluation)")
        st.download_button("⬇ Download sample CSV template (synthetic)", sample_csv_bytes(), "big_guard_sample_template.csv", "text/csv")
        st.caption("Do not upload real credentials or personal data. Process only data you are authorised to analyse.")


RENDERERS = {
    "Security Overview": page_overview, "Identity Behavior Analytics": page_identities, "Event Explorer": page_events,
    "Temporal Activity Analysis": page_temporal, "Identity Relationship Graph": page_graph, "Threat & Alert Center": page_alerts,
    "AI/ML Detection Results": page_ml, "Model Performance & Evaluation": page_performance, "System Information": page_system,
}
