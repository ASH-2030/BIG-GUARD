"""Regenerate the sample datasets in data/ (deterministic)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from big_guard.data import generate_events, sample_csv_bytes  # noqa: E402

out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
df = generate_events(42)
df.to_csv(os.path.join(out, "synthetic_events.csv"), index=False)
with open(os.path.join(out, "sample_upload_template.csv"), "wb") as f:
    f.write(sample_csv_bytes(200))
print(f"wrote {len(df):,} rows to data/synthetic_events.csv and a 200-row template")
