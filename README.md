# BIG-Guard - Behavioral Identity Graph

A **defensive, research-oriented** cybersecurity prototype that analyses identity behavior, temporal patterns and
relationships between identities, devices, processes, resources and sessions to surface suspicious activity, with an
SOC-style Streamlit + Plotly dashboard.

> Research direction: *Explainable Temporal Graph Learning for Detecting Long-Term Dormant Identity Misuse and Contextual Living-off-the-Land Activities.*
> This repository contains the **foundation** (data, features, graph, explainable detection, baselines, evaluation). A Temporal GNN is **proposed future work and not implemented**. No novelty or real-world accuracy claim is made.

## Problem statement
Compromised or misused identities (especially long-dormant accounts) and abuse of legitimate admin tools blend into normal activity. Single-event rules produce noise; behavior over time and identity relationships carry more signal.

## Objectives
Explainable per-identity detection with context-aware handling of admin tools; a temporal identity graph; honest, reproducible evaluation; a clean model interface for later graph learning.

## Research motivation
See [docs/RESEARCH_METHODOLOGY.md](docs/RESEARCH_METHODOLOGY.md) (implemented methods, validity threats, proposed temporal-graph architecture).

## Architecture
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Layers: `big_guard/data` → `features` → `detection` / `graph` → `models` → `evaluation` → `ui` (+ `app.py`).

## Technology stack
Python 3.10+, Streamlit, Plotly, pandas, NumPy, scikit-learn, NetworkX, pytest.

## Installation
```bash
python -m venv .venv
# Windows PowerShell:  .venv\Scripts\Activate.ps1      macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
```

## Run
```bash
streamlit run app.py        # dashboard (Windows alternative: py -m streamlit run app.py)
python run_demo.py          # CLI demo, no Streamlit needed
pytest                      # automated tests
python scripts/generate_sample_data.py   # regenerate data/*.csv
```

## Dashboard pages
Security Overview · Identity Behavior Analytics · Event Explorer · Temporal Activity Analysis · Identity Relationship Graph ·
Threat & Alert Center · AI/ML Detection Results · Model Performance & Evaluation · System Information.
Detection thresholds and signal weights are adjustable in the sidebar. CSV upload (with validation messages) and a sample template are in the sidebar; CSV export is available for events, alerts, identities, graph edges, model scores and evaluation results.

## Screenshots
_Not included in this package (the build environment could not launch a browser). After running the app, add images to `docs/screenshots/` and link them here._

## Dataset
Seeded synthetic data (19,445 events, 54 identities, 90 days). All records are fabricated; IPs use RFC 5737 documentation ranges. Normal behavior, benign hard negatives (admin maintenance window, laptop replacement, return from leave, mistyped password) and five labelled suspicious scenarios. Schema: [docs/DATASET_SCHEMA.md](docs/DATASET_SCHEMA.md).

## Detection methodology
14 named signals with configurable weights (dormant reactivation, new device/IP, off-hours, first sensitive access, unfamiliar admin tool in sensitive context, failed-login burst, success after failures, multi-device burst, sensitive sweep, novel process sequence…). `risk_score = min(100, Σ weights)` is a **heuristic score, not a probability**. Admin tools are scored only when outside the identity's own baseline. Alerts (one per identity+session) state the identity, unusual behavior, contributing signals, why they were generated and recommended defensive investigation steps.

## AI/ML methodology
Baselines behind a common `BaseDetector` interface: heuristic engine, five-rule baseline, Isolation Forest (unsupervised), Logistic Regression (supervised, needs labels). Features are causal and never include `label`/`scenario`.

## Evaluation methodology
Identity-grouped, stratified 60/40 split (no identity overlap); precision, recall, F1, confusion matrix, FPR, ROC-AUC, PR-AUC and scoring latency on the held-out identities only.

Result of the verification run (**SYNTHETIC DEMONSTRATION, seed 42, 22 test identities, 57 test positives; may differ slightly across library versions**):

| Model | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|
| Heuristic engine | 1.000 | 0.702 | 0.825 | 0.0000 | 1.000 | 0.993 |
| Rule-based baseline | 0.929 | 0.684 | 0.788 | 0.0004 | 0.842 | 0.654 |
| Isolation Forest | 0.237 | 0.491 | 0.320 | 0.0112 | 0.990 | 0.360 |
| Logistic Regression | 0.891 | 1.000 | 0.942 | 0.0009 | 1.000 | 0.997 |

These numbers only show the pipeline works. The synthetic labels and the rules were written by the same author, so they are optimistic and are **not** evidence of real-world performance.

## Limitations
Synthetic data only; circular validation; event-level labels; single seed; business hours assumed UTC; heuristic weights hand-set; no Temporal GNN; no real-infrastructure integration; the dashboard rendering was not verified in a browser in the build environment (see below).

## Future enhancements
See [docs/ROADMAP.md](docs/ROADMAP.md).

## Safety
Defensive only. Runs locally, makes no network calls, contains no credential theft, exploitation, persistence or destructive code. Only analyse data you are authorised to use; do not upload real credentials or personal data.

## Legacy
The original v1.1 single-file prototype is preserved in `legacy/`.
