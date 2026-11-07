# Roadmap

## Done (v2.0)
Synthetic generator, CSV import/validation, causal features, NetworkX identity graph, explainable heuristic engine with configurable weights, alert center with status workflow, Isolation Forest / Logistic Regression / rule baselines, evaluation module, 9-page dashboard, tests, docs.

## Next (proposed)
1. Validate on authorised, labelled real or public datasets; report confidence intervals over multiple seeds.
2. Session- and identity-level evaluation and time-to-detect.
3. Persistent alert storage and analyst-feedback loop.
4. Temporal graph model (TGN/TGAT) behind `BaseDetector`; explanation methods for it.
5. Separately configured, explicitly authorised connectors (SIEM/EDR/AD exports).
6. Learned per-role baselines and weight calibration; precision-oriented tuning on a validation split.
7. Containerisation and CI.
