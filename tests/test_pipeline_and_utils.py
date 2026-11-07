from big_guard.data import generate_events
from big_guard.pipeline import run_pipeline
from big_guard.utils.helpers import dataframe_key, to_csv_bytes
import pandas as pd


def test_pipeline_end_to_end_outputs_are_consistent():
    r = run_pipeline(generate_events(42))
    assert len(r.events) == len(generate_events(42)) and len(r.alerts) > 0
    assert r.graph.number_of_nodes() > 0 and set(r.alerts["identity"]) <= set(r.identities["identity"])
    assert r.timings["scoring_s"] >= 0 and r.synthetic


def test_csv_export_neutralises_formula_injection():
    df = pd.DataFrame({"identity": ["=cmd()", "+x", "@y", "-z", "ok"], "n": [1, 2, 3, 4, 5]})
    text = to_csv_bytes(df).decode()
    lines = text.strip().splitlines()
    assert lines[1].startswith("'=cmd()") and lines[2].startswith("'+x") and lines[3].startswith("'@y") and lines[4].startswith("'-z")
    assert lines[5] == "ok,5"


def test_dataframe_key_is_stable_and_content_sensitive():
    a = generate_events(1).head(50)
    assert dataframe_key(a) == dataframe_key(a.copy())
    b = a.copy(); b.loc[0, "identity"] = "changed"
    assert dataframe_key(a) != dataframe_key(b)
