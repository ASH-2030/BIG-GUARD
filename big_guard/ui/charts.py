"""Plotly figures (dark theme). Each function returns a plotly Figure; no Streamlit calls here."""
from __future__ import annotations

import networkx as nx
import numpy as np
import pandas as pd
import plotly.graph_objects as go

from ..graph.schema import RELATION_LABELS
from ..utils.helpers import SEVERITY_COLORS
from .theme import COLORS as C

NODE_STYLE = {"Identity": (C["teal"], "circle", 22), "Device": (C["blue"], "square", 16),
              "Process": (C["violet"], "diamond", 14), "Resource": (C["amber"], "hexagon", 15),
              "Session": ("#94a3b8", "circle", 8)}


def _style(fig: go.Figure, height: int = 320, legend: bool = True) -> go.Figure:
    fig.update_layout(
        height=height, margin=dict(l=10, r=10, t=36, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color=C["text"], size=12), showlegend=legend,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, bgcolor="rgba(0,0,0,0)"),
        title=dict(font=dict(size=14), x=0.01),
    )
    fig.update_xaxes(gridcolor=C["grid"], zerolinecolor=C["grid"])
    fig.update_yaxes(gridcolor=C["grid"], zerolinecolor=C["grid"])
    return fig


def empty_figure(message: str, height: int = 280) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(text=message, showarrow=False, font=dict(color=C["muted"], size=14))
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return _style(fig, height, legend=False)


def daily_activity(events: pd.DataFrame) -> go.Figure:
    day = events["timestamp"].dt.floor("D")
    total = events.groupby(day).size()
    flagged = events[events["flagged"]].groupby(day[events["flagged"]]).size().reindex(total.index, fill_value=0)
    fig = go.Figure()
    fig.add_bar(x=total.index, y=total.values, name="Events", marker_color="#1f4e79")
    fig.add_scatter(x=flagged.index, y=flagged.values, name="Flagged events", mode="lines+markers",
                    line=dict(color=C["red"], width=2), yaxis="y2")
    fig.update_layout(yaxis2=dict(overlaying="y", side="right", showgrid=False, title="Flagged"), title="Daily event volume")
    return _style(fig, 320)


def severity_donut(alerts: pd.DataFrame) -> go.Figure:
    if alerts.empty:
        return empty_figure("No alerts")
    counts = alerts["severity"].value_counts()
    fig = go.Figure(go.Pie(labels=counts.index.tolist(), values=counts.values.tolist(), hole=0.62,
                           marker=dict(colors=[SEVERITY_COLORS.get(s, "#64748b") for s in counts.index]),
                           textinfo="label+value", sort=False))
    fig.update_layout(title="Alerts by severity")
    return _style(fig, 320, legend=False)


def category_bar(alerts: pd.DataFrame) -> go.Figure:
    if alerts.empty:
        return empty_figure("No alerts")
    c = alerts["category"].value_counts().sort_values()
    fig = go.Figure(go.Bar(x=c.values, y=c.index, orientation="h", marker_color=C["violet"]))
    fig.update_layout(title="Alerts by detection category")
    return _style(fig, 320, legend=False)


def top_risk_identities(identities: pd.DataFrame, n: int = 10) -> go.Figure:
    d = identities.sort_values("max_risk_score", ascending=False).head(n).iloc[::-1]
    colors = [C["red"] if v >= 75 else C["amber"] if v >= 45 else "#3b6ea5" for v in d["max_risk_score"]]
    fig = go.Figure(go.Bar(x=d["max_risk_score"], y=d["identity"], orientation="h", marker_color=colors))
    fig.update_layout(title="Highest heuristic risk score by identity", xaxis=dict(range=[0, 100]))
    return _style(fig, 320, legend=False)


def event_type_mix(events: pd.DataFrame) -> go.Figure:
    c = events["event_type"].value_counts()
    fig = go.Figure(go.Pie(labels=c.index.tolist(), values=c.values.tolist(), hole=0.55, textinfo="label+percent"))
    fig.update_layout(title="Event type mix")
    return _style(fig, 300, legend=False)


def hour_weekday_heatmap(events: pd.DataFrame) -> go.Figure:
    pivot = (events.assign(hour=events["timestamp"].dt.hour, wd=events["timestamp"].dt.weekday)
             .pivot_table(index="wd", columns="hour", values="event_id", aggfunc="count", fill_value=0)
             .reindex(index=range(7), columns=range(24), fill_value=0))
    fig = go.Figure(go.Heatmap(z=pivot.values, x=list(range(24)), y=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
                               colorscale=[[0, "#0b1220"], [0.3, "#16436b"], [1, C["teal"]]], colorbar=dict(title="Events")))
    fig.update_layout(title="Activity by hour of day (UTC) and weekday", xaxis_title="Hour", yaxis=dict(autorange="reversed"))
    return _style(fig, 320, legend=False)


def hourly_flagged(events: pd.DataFrame) -> go.Figure:
    h = events.assign(hour=events["timestamp"].dt.hour)
    allc = h.groupby("hour").size().reindex(range(24), fill_value=0)
    flg = h[h["flagged"]].groupby("hour").size().reindex(range(24), fill_value=0)
    fig = go.Figure()
    fig.add_bar(x=allc.index, y=allc.values, name="All events", marker_color="#1f4e79")
    fig.add_bar(x=flg.index, y=flg.values, name="Flagged events", marker_color=C["red"])
    fig.update_layout(barmode="overlay", title="Events vs flagged events by hour", xaxis_title="Hour (UTC)")
    return _style(fig, 300)


def gap_chart(identities: pd.DataFrame, dormant_days: int, n: int = 15) -> go.Figure:
    d = identities.sort_values("max_gap_days", ascending=False).head(n).iloc[::-1]
    fig = go.Figure(go.Bar(x=d["max_gap_days"], y=d["identity"], orientation="h",
                           marker_color=[C["amber"] if v > dormant_days else "#3b6ea5" for v in d["max_gap_days"]]))
    fig.add_vline(x=dormant_days, line_dash="dash", line_color=C["red"], annotation_text=f"dormancy threshold {dormant_days}d")
    fig.update_layout(title="Longest inactivity gap per identity (days)")
    return _style(fig, 380, legend=False)


def identity_timeline(events: pd.DataFrame, identity: str) -> go.Figure:
    d = events[events["identity"] == identity]
    if d.empty:
        return empty_figure("No events")
    fig = go.Figure()
    for flagged, color, name in ((False, "#3b6ea5", "Normal range"), (True, C["red"], "Flagged")):
        s = d[d["flagged"] == flagged]
        fig.add_scatter(x=s["timestamp"], y=s["event_type"], mode="markers", name=name,
                        marker=dict(color=color, size=9 if flagged else 6, opacity=0.85),
                        text=s["resource"] + " / " + s["process"] + " · score " + s["risk_score"].astype(str),
                        hovertemplate="%{x}<br>%{y}<br>%{text}<extra></extra>")
    fig.update_layout(title=f"Event timeline - {identity}")
    return _style(fig, 300)


def identity_daily(events: pd.DataFrame, identity: str) -> go.Figure:
    d = events[events["identity"] == identity]
    c = d.groupby(d["timestamp"].dt.floor("D")).size()
    fig = go.Figure(go.Bar(x=c.index, y=c.values, marker_color=C["blue"]))
    fig.update_layout(title=f"Daily activity - {identity}")
    return _style(fig, 260, legend=False)


def risk_scatter(identities: pd.DataFrame) -> go.Figure:
    fig = go.Figure(go.Scatter(x=identities["events"], y=identities["max_risk_score"], mode="markers", text=identities["identity"],
                               marker=dict(size=9, color=identities["max_risk_score"], colorscale=[[0, "#3b6ea5"], [0.45, C["amber"]], [1, C["red"]]],
                                           cmin=0, cmax=100, showscale=True, colorbar=dict(title="Score")),
                               hovertemplate="%{text}<br>events %{x}<br>max score %{y}<extra></extra>"))
    fig.update_layout(title="Identity activity volume vs highest heuristic score", xaxis_title="Events", yaxis_title="Max risk score")
    return _style(fig, 320, legend=False)


def score_distribution(scores: pd.Series, threshold: float, name: str) -> go.Figure:
    fig = go.Figure(go.Histogram(x=scores, nbinsx=40, marker_color=C["teal"]))
    fig.add_vline(x=threshold, line_dash="dash", line_color=C["red"], annotation_text="operating threshold")
    fig.update_yaxes(type="log")
    fig.update_layout(title=f"{name} - score distribution (log count)", xaxis_title="Score (0-1)")
    return _style(fig, 300, legend=False)


def roc_figure(curves: dict) -> go.Figure:
    fig = go.Figure()
    fig.add_scatter(x=[0, 1], y=[0, 1], mode="lines", line=dict(dash="dot", color="#64748b"), name="Chance", showlegend=False)
    for name, c in curves.items():
        if c:
            fig.add_scatter(x=c["roc"][0], y=c["roc"][1], mode="lines", name=name)
    fig.update_layout(title="ROC curves (held-out test)", xaxis_title="False positive rate", yaxis_title="True positive rate")
    return _style(fig, 340)


def pr_figure(curves: dict) -> go.Figure:
    fig = go.Figure()
    for name, c in curves.items():
        if c:
            fig.add_scatter(x=c["pr"][1], y=c["pr"][0], mode="lines", name=name)
    fig.update_layout(title="Precision-recall curves (held-out test)", xaxis_title="Recall", yaxis_title="Precision")
    return _style(fig, 340)


def confusion_heatmap(cm: np.ndarray, title: str) -> go.Figure:
    labels = [["TN", "FP"], ["FN", "TP"]]
    text = [[f"{labels[i][j]}<br>{int(cm[i][j]):,}" for j in range(2)] for i in range(2)]
    fig = go.Figure(go.Heatmap(z=np.log1p(cm), x=["Pred normal", "Pred suspicious"], y=["Actual normal", "Actual suspicious"],
                               text=text, texttemplate="%{text}", colorscale=[[0, "#0b1220"], [1, "#1d6fa5"]], showscale=False))
    fig.update_layout(title=title, yaxis=dict(autorange="reversed"))
    return _style(fig, 250, legend=False)


def metrics_bar(metrics: pd.DataFrame) -> go.Figure:
    fig = go.Figure()
    for col, color in (("precision", C["teal"]), ("recall", C["blue"]), ("f1", C["violet"])):
        fig.add_bar(x=metrics["model"], y=metrics[col], name=col.upper() if col == "f1" else col.capitalize(), marker_color=color)
    fig.update_layout(barmode="group", title="Precision / recall / F1 at each model's operating threshold", yaxis=dict(range=[0, 1.05]))
    return _style(fig, 340)


def latency_bar(metrics: pd.DataFrame) -> go.Figure:
    fig = go.Figure(go.Bar(x=metrics["model"], y=metrics["ms_per_1000_events"], marker_color=C["amber"]))
    fig.update_layout(title="Inference latency (ms per 1,000 events, scoring only)")
    return _style(fig, 300, legend=False)


def graph_figure(G: nx.MultiDiGraph, height: int = 640) -> go.Figure:
    if G.number_of_nodes() == 0:
        return empty_figure("No graph data for this selection", height)
    pos = nx.spring_layout(G, seed=42, k=1.4 / np.sqrt(max(G.number_of_nodes(), 1)), iterations=100)
    fig = go.Figure()
    for suspicious, color, width, name in ((False, "rgba(120,140,170,0.45)", 1, "Relationship"),
                                           (True, C["red"], 2.6, "Suspicious relationship")):
        xs, ys = [], []
        for u, v, e in G.edges(data=True):
            if bool(e.get("suspicious")) == suspicious:
                xs += [pos[u][0], pos[v][0], None]
                ys += [pos[u][1], pos[v][1], None]
        if xs:
            fig.add_scatter(x=xs, y=ys, mode="lines", line=dict(color=color, width=width), hoverinfo="skip", name=name)
    mx, my, mt = [], [], []
    for u, v, e in G.edges(data=True):
        mx.append((pos[u][0] + pos[v][0]) / 2)
        my.append((pos[u][1] + pos[v][1]) / 2)
        mt.append(f"{RELATION_LABELS[e['relation']]}<br>{G.nodes[u]['label']} → {G.nodes[v]['label']}<br>"
                  f"first {str(e['first_seen'])[:16]} · last {str(e['last_seen'])[:16]}<br>"
                  f"events {e['count']} · flagged {e['flagged_count']} · max score {e['max_score']}")
    fig.add_scatter(x=mx, y=my, mode="markers", marker=dict(size=7, opacity=0), text=mt, hoverinfo="text", showlegend=False)
    for ntype, (color, symbol, size) in NODE_STYLE.items():
        nodes = [n for n, d in G.nodes(data=True) if d["node_type"] == ntype]
        if not nodes:
            continue
        fig.add_scatter(
            x=[pos[n][0] for n in nodes], y=[pos[n][1] for n in nodes], mode="markers+text" if ntype != "Session" else "markers",
            name=ntype, text=[G.nodes[n]["label"] for n in nodes], textposition="top center", textfont=dict(size=10, color=C["muted"]),
            marker=dict(color=color, symbol=symbol, size=size,
                        line=dict(width=[3 if G.nodes[n].get("suspicious") else 0.5 for n in nodes],
                                  color=[C["red"] if G.nodes[n].get("suspicious") else "#0b1220" for n in nodes])),
            hovertext=[f"{ntype}: {G.nodes[n]['label']}" + (" (sensitive)" if G.nodes[n].get("sensitive") else "")
                       + (" (admin tool)" if G.nodes[n].get("admin_tool") else "") for n in nodes], hoverinfo="text")
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return _style(fig, height)
