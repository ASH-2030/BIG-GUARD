# Research methodology

Direction: *Explainable Temporal Graph Learning for Detecting Long-Term Dormant Identity Misuse and Contextual Living-off-the-Land Activities.*
No novelty or real-world performance claim is made.

## Implemented (this repository)
1. **Synthetic labelled data** with benign hard negatives.
2. **Causal features** (reactivation after inactivity, device/IP novelty window, resource/process novelty, admin-tool familiarity, failed-login bursts, multi-device bursts, per-session sensitive sweeps, process-transition novelty).
3. **Heuristic scoring**: `risk_score = min(100, Σ weights of fired signals)`. Heuristic, not a probability.
4. **Baselines**: heuristic engine, five-rule baseline, Isolation Forest (unsupervised), Logistic Regression (supervised, class-balanced).
5. **Evaluation**: identity-grouped stratified split (40% test identities, no overlap), threshold metrics at each model's stated operating point, ROC-AUC/PR-AUC, confusion matrices, scoring latency.

## Known validity threats
- **Circularity:** the same author wrote the generator and the rules, so heuristic results are optimistic.
- Event-level labels; early events of an attack session are structurally harder to flag.
- Few positive identities in the test split (single seed, no confidence intervals).
- Isolation Forest is fit on unlabelled training events that include some attacks.
- Operating thresholds were set a priori, not tuned on the test set; weights were adjusted while developing on the same synthetic data.

## Proposed (NOT implemented): temporal graph learning
- **Data:** the event-level temporal edge table from `graph.temporal_edge_table` (`src, dst, relation, timestamp, event_id, ...`); node and edge feature definitions in `graph/schema.py`.
- **Architecture sketch:** a temporal-graph encoder (e.g. TGN/TGAT-style memory + attention over timestamped neighbours, or a relational GNN over time-window snapshots) producing identity/edge embeddings; a classification head for edge- or session-level suspicion; an attention/feature-attribution layer to keep explanations.
- **Training/validation/testing:** chronological split (train earliest, validate next, test latest) *and* identity-held-out evaluation; negative sampling for link-prediction pre-training; class-imbalance handling (weighted loss/focal); early stopping on validation PR-AUC; report PR-AUC, precision@k, time-to-detect, with multiple seeds and confidence intervals.
- **Data requirement:** a genuine labelled corpus (authorised real logs or an established public benchmark). Training a GNN on this repository's synthetic data would only reproduce the generator.
- **Candidate implementations:** TGN, TGAT, JODIE-style memory models, R-GCN/HGT on snapshots (PyTorch Geometric / DGL), compared against the baselines here via the `BaseDetector` interface.
