# Architecture

```
CSV upload / synthetic generator
        │  big_guard/data      generator.py, preprocessing.py (validation, cleaning)
        ▼
 normalised event table
        │  big_guard/features  behavioral.py (causal per-identity features)
        ▼
 feature table ──► big_guard/detection  scoring.py (14 weighted signals) → alerts.py (explained alerts)
        │                   │
        │                   └─► big_guard/graph  builder.py (NetworkX, temporal edges), schema.py
        ▼
 big_guard/models  base.py (interface), baselines.py (heuristic adapter, rule baseline, IsolationForest, LogisticRegression)
        ▼
 big_guard/evaluation  splits.py (identity-grouped), metrics.py, benchmark.py
        ▼
 big_guard/ui + app.py  Streamlit + Plotly dashboard (9 pages)
```

`big_guard/pipeline.py` wires features → scoring → alerts → graph → identity summary. `app.py` caches the result per
(dataset hash, detection config).

## Design decisions
- **Causal features.** Each event's features use only earlier events of the same identity. A test proves that removing future events does not change past features.
- **Explainability first.** Every score is a sum of named signals with configurable weights; alerts list them.
- **Context-aware admin tools.** `powershell`, `cmd`, `wmic`, `schtasks`, `certutil` are dual-use. They score only when the identity has no history of administrative tool use (< 3 distinct days) and gain extra weight only on sensitive resources.
- **Cold start.** New-entity signals are suppressed until an identity has `min_history_events` (default 40) events.
- **Alert grouping.** One alert per (identity, session); alert score = highest event score in the session.
- **Model interface.** `BaseDetector.fit(X, y)` / `score(X) -> [0,1]` where `X` is the feature table. `TemporalGraphDetector` is a documented placeholder that raises `NotImplementedError`.
- **Safety.** Self-contained, no network calls, no credentials, CSV export neutralises spreadsheet formula injection, UI escapes untrusted text.

## Status
| Component | Status |
|---|---|
| Generator, CSV validation, features, graph, heuristic engine, baselines, evaluation, dashboard | Implemented |
| Temporal GNN, real SIEM/AD/EDR connectors | Not implemented (see ROADMAP) |
