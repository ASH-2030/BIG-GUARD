import io

import pandas as pd
import pytest

from big_guard.config import REQUIRED_COLUMNS
from big_guard.data import (DataValidationError, generate_events, preprocess_events, read_events_csv,
                            sample_csv_bytes, validate_columns)


def _valid_df(n=20):
    return generate_events(42).head(n).drop(columns=["is_synthetic", "label", "scenario"]).astype(str)


def test_sample_csv_round_trips_through_reader():
    df, report = read_events_csv(sample_csv_bytes(200))
    assert len(df) == 200 and report["has_labels"]
    assert set(REQUIRED_COLUMNS) <= set(df.columns)
    assert str(df["timestamp"].dtype).startswith("datetime64")


def test_missing_required_column_is_reported():
    errs = validate_columns(_valid_df().drop(columns=["identity", "device"]))
    assert errs and "identity" in errs[0] and "device" in errs[0]
    with pytest.raises(DataValidationError):
        preprocess_events(_valid_df().drop(columns=["identity"]))


def test_bad_timestamps_are_dropped_and_counted():
    df = _valid_df()
    df.loc[0, "timestamp"] = "not-a-date"
    df.loc[1, "timestamp"] = ""
    out, rep = preprocess_events(df)
    assert len(out) == len(df) - 2
    assert any("timestamp" in w for w in rep["warnings"])


def test_missing_values_are_filled_not_fatal():
    df = _valid_df()
    df.loc[2, "process"] = ""
    df.loc[3, "device"] = ""
    out, rep = preprocess_events(df.replace({"": pd.NA}))
    assert (out["process"] == "none").any() and (out["device"] == "unknown").any()
    assert len(rep["warnings"]) >= 2


def test_duplicate_ids_and_bad_auth_status_and_labels():
    df = _valid_df(10)
    df.loc[1, "event_id"] = df.loc[0, "event_id"]
    df.loc[2, "auth_status"] = "weird"
    df["label"] = ["0", "1", "x", "0", "0", "1", "0", "0", "0", "0"]
    out, rep = preprocess_events(df)
    assert out["event_id"].is_unique and len(out) == 9
    assert (out["auth_status"].isin(["success", "failure", "not_applicable"])).all()
    assert out["label"].isna().sum() == 1 and rep["has_labels"]


def test_empty_and_garbage_files_give_clear_errors():
    with pytest.raises(DataValidationError):
        read_events_csv(b"")
    with pytest.raises(DataValidationError) as e:
        read_events_csv(b"a,b\n1,2\n")
    assert "Missing required" in str(e.value)
    with pytest.raises(DataValidationError):
        read_events_csv(b"\xff\xfe\x00bad")


def test_row_limit_enforced():
    with pytest.raises(DataValidationError):
        preprocess_events(_valid_df(30), max_rows=10)
