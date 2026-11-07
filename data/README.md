# Sample data (SYNTHETIC)

- `synthetic_events.csv` - full seeded (seed 42) synthetic dataset, ~19k events, 54 fabricated identities, 90 days.
- `sample_upload_template.csv` - 200-row subset in the exact upload format.

Everything here is fabricated. No real credentials, logs or personal information. IPs are RFC 5737 documentation
addresses. `label` and `scenario` are ground truth for evaluation only - never model inputs.
Regenerate with `python scripts/generate_sample_data.py`.
