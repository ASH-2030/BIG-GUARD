"""BIG-Guard - Behavioral Identity Graph. Run with:  streamlit run app.py"""
from __future__ import annotations

import hashlib

import pandas as pd
import streamlit as st

st.set_page_config(page_title="BIG-Guard | Security Operations", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="expanded")

from big_guard.config import DEFAULT_WEIGHTS, DetectionConfig  # noqa: E402
from big_guard.data import DataValidationError, generate_events, read_events_csv, sample_csv_bytes  # noqa: E402
from big_guard.evaluation import run_benchmark  # noqa: E402
from big_guard.pipeline import run_pipeline  # noqa: E402
from big_guard.ui.pages import PAGES, RENDERERS, Context  # noqa: E402
from big_guard.ui.theme import CSS  # noqa: E402
from big_guard.utils.helpers import dataframe_key  # noqa: E402

st.markdown(CSS, unsafe_allow_html=True)


@st.cache_data(show_spinner="Generating synthetic events…")
def synthetic_events(seed: int) -> pd.DataFrame:
    return generate_events(seed)


@st.cache_resource(show_spinner="Analysing events…", max_entries=4)
def analyse(data_key: str, cfg_json: str, source: str, synthetic: bool, _events: pd.DataFrame):
    cfg = DetectionConfig.from_json(cfg_json)
    result = run_pipeline(_events, cfg, synthetic=synthetic, source_name=source)
    bench = run_benchmark(result.events, cfg, synthetic=synthetic)
    return result, bench


def sidebar_config() -> DetectionConfig:
    with st.expander("Detection settings", expanded=False):
        cfg = DetectionConfig()
        cfg.alert_threshold = st.slider("Alert threshold (heuristic score)", 10, 95, cfg.alert_threshold,
                                        help="Events scoring at or above this value are flagged and grouped into alerts.")
        cfg.dormant_days = st.slider("Dormancy threshold (days)", 7, 90, cfg.dormant_days)
        cfg.failure_burst_count = st.slider("Failed-login burst (count)", 2, 10, cfg.failure_burst_count)
        cfg.multi_device_count = st.slider("Multi-device burst (devices)", 2, 8, cfg.multi_device_count)
        cfg.sweep_distinct_sensitive = st.slider("Sensitive-resource sweep (distinct)", 2, 6, cfg.sweep_distinct_sensitive)
        cfg.business_start_hour, cfg.business_end_hour = st.slider("Business hours (UTC)", 0, 24, (cfg.business_start_hour, cfg.business_end_hour))
        cfg.min_history_events = st.slider("Baseline history required (events)", 5, 150, cfg.min_history_events,
                                           help="New-entity signals are suppressed until an identity has this much history.")
    with st.expander("Signal weights", expanded=False):
        weights = {}
        for k, v in DEFAULT_WEIGHTS.items():
            weights[k] = st.number_input(k, min_value=0, max_value=60, value=int(v), step=1, key=f"w_{k}")
        cfg.weights = weights
    return cfg


def load_data():
    """Returns (events, source_name, synthetic_flag)."""
    with st.expander("Data source", expanded=True):
        choice = st.radio("Dataset", ["Synthetic demonstration data", "Uploaded CSV"], key="data_choice")
        seed = st.number_input("Synthetic seed", min_value=0, max_value=99999, value=42, step=1)
        up = st.file_uploader("Upload normalized CSV", type=["csv"], help="See 'System Information → Schema & CSV template'.")
        st.download_button("⬇ Sample CSV template", sample_csv_bytes(), "big_guard_sample_template.csv", "text/csv")

        uploaded = None
        if up is not None:
            key = f"{up.name}:{up.size}"
            cache = st.session_state.setdefault("upload_cache", {})
            if key not in cache:
                try:
                    df, report = read_events_csv(up.getvalue())
                    cache[key] = ("ok", df, report)
                except DataValidationError as exc:
                    cache[key] = ("error", exc.errors, None)
            status, payload, report = cache[key]
            if status == "error":
                for msg in payload:
                    st.error(msg)
            else:
                st.success(f"Loaded {report['rows_out']:,} of {report['rows_in']:,} rows from {up.name}.")
                for w in report["warnings"]:
                    st.warning(w)
                uploaded = (payload, up.name)
        if choice == "Uploaded CSV" and uploaded is None:
            st.info("No valid uploaded CSV yet - showing synthetic demonstration data.")
    if choice == "Uploaded CSV" and uploaded is not None:
        return uploaded[0], uploaded[1], False
    return synthetic_events(int(seed)), f"synthetic (seed {int(seed)})", True


def main():
    with st.sidebar:
        st.markdown('<div class="brand">🛡️ BIG-Guard</div><div class="brand-sub">BEHAVIORAL IDENTITY GRAPH</div>', unsafe_allow_html=True)
        page = st.radio("Navigation", PAGES, label_visibility="collapsed", key="nav")
        st.divider()
        events, source, synthetic = load_data()
        cfg = sidebar_config()
        st.divider()
        st.caption("v2.0 · defensive research prototype")
        st.caption("Heuristic scores are not probabilities.")

    data_key = dataframe_key(events)
    result, bench = analyse(data_key, cfg.to_json(), source, synthetic, events)
    ctx = Context(result=result, bench=bench, data_key=data_key + "-" + hashlib.sha1(cfg.to_json().encode()).hexdigest()[:8])
    RENDERERS[page](ctx)
    st.markdown("---")
    st.markdown('<div class="small-muted">BIG-GUARD · DEFENSIVE RESEARCH PROTOTYPE · '
                + ("SYNTHETIC DATA" if synthetic else "USER-SUPPLIED DATA") + '</div>', unsafe_allow_html=True)


main()
