"""Reusable UI building blocks. All dynamic text is HTML-escaped (uploaded CSVs are untrusted)."""
from __future__ import annotations

import html

import streamlit as st

from ..utils.helpers import SEVERITY_COLORS


def esc(x) -> str:
    return html.escape(str(x))


def _stretch(fn, *args, **kwargs):
    """Call a Streamlit widget with full width, supporting both new (width) and old (use_container_width) APIs."""
    try:
        return fn(*args, width="stretch", **kwargs)
    except Exception:  # older Streamlit without width="stretch"
        return fn(*args, use_container_width=True, **kwargs)


def show_df(df, **kwargs):
    return _stretch(st.dataframe, df, **kwargs)


def show_plot(fig, key: str | None = None):
    return _stretch(st.plotly_chart, fig, key=key)


def hero(kicker: str, title: str, subtitle: str):
    st.markdown(f'<div class="hero"><div class="hero-kicker">{esc(kicker)}</div><h1>{esc(title)}</h1>'
                f'<p>{esc(subtitle)}</p></div>', unsafe_allow_html=True)


def section(title: str):
    st.markdown(f'<div class="section-title">{esc(title)}</div>', unsafe_allow_html=True)


def metric_card(label: str, value, note: str = "", accent: str = "#2dd4bf"):
    st.markdown(f'<div class="metric-card" style="--accent:{accent}"><div class="metric-label">{esc(label)}</div>'
                f'<div class="metric-value">{esc(value)}</div><div class="metric-note">{esc(note)}</div></div>',
                unsafe_allow_html=True)


def callout(text: str, kind: str = "info"):
    st.markdown(f'<div class="callout {kind}">{esc(text)}</div>', unsafe_allow_html=True)


def badge(text: str, color: str) -> str:
    return (f'<span class="badge" style="color:{color};border-color:{color};background:{color}22">{esc(text)}</span>')


def severity_badge(sev: str) -> str:
    return badge(sev, SEVERITY_COLORS.get(sev, "#64748b"))


def alert_card(row) -> None:
    color = SEVERITY_COLORS.get(row["severity"], "#64748b")
    st.markdown(
        f'<div class="alert-card" style="--sev:{color}">{severity_badge(row["severity"])} '
        f'<b>&nbsp;{esc(row["category"])}</b>'
        f'<div class="meta">{esc(row["alert_id"])} · identity <b>{esc(row["identity"])}</b> · '
        f'heuristic score {int(row["risk_score"])}/100 · {esc(str(row["timestamp"])[:16])} UTC · status {esc(row["status"])}</div>'
        f'<div style="font-size:13px;margin-top:4px">{esc(row["resources"] or "no sensitive resource")} · '
        f'devices: {esc(row["devices"])}</div></div>', unsafe_allow_html=True)
