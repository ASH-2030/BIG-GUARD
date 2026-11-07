"""CLI demo (no Streamlit needed): synthetic data -> detection -> alerts -> baseline evaluation."""
import argparse

import pandas as pd

from big_guard.data import generate_events
from big_guard.evaluation import run_benchmark
from big_guard.pipeline import run_pipeline


def main():
    ap = argparse.ArgumentParser(description="BIG-Guard CLI demo (SYNTHETIC data only)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--top", type=int, default=5, help="number of alerts to print in full")
    args = ap.parse_args()

    pd.set_option("display.width", 200)
    events = generate_events(args.seed)
    r = run_pipeline(events)
    print(f"BIG-Guard demo | SYNTHETIC data, seed {args.seed}")
    print(f"events={len(r.events):,} identities={r.events['identity'].nunique()} alerts={len(r.alerts)} "
          f"graph={r.graph.number_of_nodes():,} nodes / {r.graph.number_of_edges():,} edges")
    print("\nAlerts by severity:\n", r.alerts["severity"].value_counts().to_string())
    for _, a in r.alerts.sort_values("risk_score", ascending=False).head(args.top).iterrows():
        print(f"\n[{a['alert_id']}] {a['severity']} | {a['category']} | identity={a['identity']} | heuristic score {a['risk_score']}/100")
        print("  " + a["explanation"])
        print("  First step: " + a["recommended_steps"].split(" | ")[0])
    b = run_benchmark(r.events, r.config)
    print("\nHeld-out evaluation (SYNTHETIC demonstration, not real-world performance):")
    cols = ["model", "precision", "recall", "f1", "false_positive_rate", "roc_auc", "pr_auc", "ms_per_1000_events"]
    print(b.metrics[cols].round(3).to_string(index=False))


if __name__ == "__main__":
    main()
