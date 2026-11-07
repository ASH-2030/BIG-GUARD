"""End-to-end analysis: features -> heuristic scoring -> alerts -> graph -> identity summary."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import networkx as nx
import pandas as pd

from .config import DetectionConfig
from .detection import build_alerts, score_events
from .features import compute_event_features, identity_summary
from .graph import build_graph


@dataclass
class PipelineResult:
    events: pd.DataFrame            # scored event table (features + signals + risk_score)
    alerts: pd.DataFrame
    graph: nx.MultiDiGraph
    identities: pd.DataFrame
    config: DetectionConfig
    timings: dict = field(default_factory=dict)
    synthetic: bool = True
    source_name: str = "synthetic"


def run_pipeline(events: pd.DataFrame, cfg: DetectionConfig | None = None, synthetic: bool = True,
                 source_name: str = "synthetic") -> PipelineResult:
    cfg = cfg or DetectionConfig()
    t0 = time.perf_counter()
    feats = compute_event_features(events, cfg)
    t1 = time.perf_counter()
    scored = score_events(feats, cfg)
    t2 = time.perf_counter()
    alerts = build_alerts(scored, cfg)
    graph = build_graph(scored)
    summary = identity_summary(scored, alerts)
    t3 = time.perf_counter()
    n = max(len(scored), 1)
    timings = {"feature_extraction_s": t1 - t0, "scoring_s": t2 - t1, "alerts_graph_s": t3 - t2,
               "feature_ms_per_1000_events": (t1 - t0) * 1e6 / n, "scoring_ms_per_1000_events": (t2 - t1) * 1e6 / n}
    return PipelineResult(scored, alerts, graph, summary, cfg, timings, synthetic, source_name)
