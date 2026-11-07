"""CSV validation and preprocessing for normalized event datasets."""
from __future__ import annotations

import io
import ipaddress

import pandas as pd

from ..config import (AUTH_STATUSES, MAX_UPLOAD_ROWS, NONE_TOKEN, OPTIONAL_COLUMNS, REQUIRED_COLUMNS,
                      UNKNOWN_TOKEN)


class DataValidationError(ValueError):
    """Raised when a dataset cannot be used. ``errors`` holds user-readable messages."""

    def __init__(self, errors):
        self.errors = [errors] if isinstance(errors, str) else list(errors)
        super().__init__("; ".join(self.errors))


def validate_columns(df: pd.DataFrame) -> list[str]:
    """Return a list of error messages (empty list = columns are valid)."""
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        return [f"Missing required column(s): {', '.join(missing)}. "
                f"Required: {', '.join(REQUIRED_COLUMNS)}."]
    return []


def preprocess_events(df: pd.DataFrame, max_rows: int = MAX_UPLOAD_ROWS):
    """Validate and clean an event table.

    Returns ``(clean_df, report)``. ``report`` has ``warnings`` (list[str]) and counters.
    Raises DataValidationError for fatal problems.
    """
    errors = validate_columns(df)
    if errors:
        raise DataValidationError(errors)
    if df.empty:
        raise DataValidationError("The dataset contains no rows.")
    if len(df) > max_rows:
        raise DataValidationError(f"Dataset has {len(df):,} rows; the limit for this build is {max_rows:,}.")

    warnings: list[str] = []
    report = {"rows_in": int(len(df)), "warnings": warnings}
    out = df.copy()

    for col in REQUIRED_COLUMNS + [c for c in ("scenario",) if c in out.columns]:
        out[col] = out[col].astype("string").str.strip()
        out.loc[out[col] == "", col] = pd.NA

    # timestamps: invalid or missing rows are dropped (and counted) rather than guessed
    ts = pd.to_datetime(out["timestamp"], errors="coerce", utc=True, format="mixed")
    bad_ts = int(ts.isna().sum())
    if bad_ts:
        warnings.append(f"Dropped {bad_ts} row(s) with a missing or unparseable timestamp.")
    out["timestamp"] = ts
    out = out[out["timestamp"].notna()]

    # identity and event_type are essential
    essential_missing = out["identity"].isna() | out["event_type"].isna()
    if essential_missing.any():
        warnings.append(f"Dropped {int(essential_missing.sum())} row(s) missing identity or event_type.")
        out = out[~essential_missing]

    # fill remaining categoricals
    for col in ("process", "resource"):
        n = int(out[col].isna().sum())
        if n:
            warnings.append(f"Filled {n} missing '{col}' value(s) with '{NONE_TOKEN}'.")
        out[col] = out[col].fillna(NONE_TOKEN)
    for col in ("device", "source_ip", "session_id", "event_context"):
        n = int(out[col].isna().sum())
        if n:
            warnings.append(f"Filled {n} missing '{col}' value(s) with '{UNKNOWN_TOKEN}'.")
        out[col] = out[col].fillna(UNKNOWN_TOKEN)
    out["event_type"] = out["event_type"].str.lower()
    out["identity"] = out["identity"].astype(str)

    # auth status normalisation
    status = out["auth_status"].fillna("not_applicable").str.lower()
    status = status.replace({"succeeded": "success", "ok": "success", "failed": "failure", "fail": "failure",
                             "n/a": "not_applicable", "na": "not_applicable"})
    unexpected = ~status.isin(AUTH_STATUSES)
    if unexpected.any():
        warnings.append(f"{int(unexpected.sum())} row(s) had an unrecognised auth_status; set to 'not_applicable'.")
        status[unexpected] = "not_applicable"
    out["auth_status"] = status

    # event ids
    out["event_id"] = out["event_id"].fillna("").astype(str)
    blank = out["event_id"] == ""
    if blank.any():
        out.loc[blank, "event_id"] = [f"GEN-{i:06d}" for i in range(int(blank.sum()))]
        warnings.append(f"Generated {int(blank.sum())} missing event_id value(s).")
    dups = out["event_id"].duplicated()
    if dups.any():
        warnings.append(f"Dropped {int(dups.sum())} duplicate event_id row(s) (first occurrence kept).")
        out = out[~dups]

    # IP sanity (warn only; values are kept as given)
    def _valid_ip(v):
        try:
            ipaddress.ip_address(str(v))
            return True
        except ValueError:
            return str(v) == UNKNOWN_TOKEN
    bad_ip = ~out["source_ip"].map(_valid_ip)
    if bad_ip.any():
        warnings.append(f"{int(bad_ip.sum())} row(s) have a source_ip that is not a valid IP address (kept as-is).")

    # optional ground-truth label
    if "label" in out.columns:
        lab = pd.to_numeric(out["label"], errors="coerce")
        invalid = lab.notna() & ~lab.isin([0, 1])
        lab[invalid] = pd.NA
        if lab.isna().any():
            warnings.append(f"{int(lab.isna().sum())} row(s) have an empty/invalid label (must be 0 or 1); "
                            "they are excluded from evaluation.")
        out["label"] = lab.astype("Int64")
    out["is_synthetic"] = out["is_synthetic"].astype(str).str.lower().isin(["true", "1"]) if "is_synthetic" in out.columns else False

    out = out.sort_values(["timestamp", "event_id"], kind="stable").reset_index(drop=True)
    if out.empty:
        raise DataValidationError("No valid rows remain after cleaning. " + " ".join(warnings))
    for col in REQUIRED_COLUMNS:
        if col != "timestamp":
            out[col] = out[col].astype(object)
    report["rows_out"] = int(len(out))
    report["has_labels"] = bool("label" in out.columns and out["label"].notna().any())
    return out, report


def read_events_csv(source, max_rows: int = MAX_UPLOAD_ROWS):
    """Read a CSV path/bytes/file-like object and preprocess it. Raises DataValidationError."""
    try:
        if isinstance(source, (bytes, bytearray)):
            source = io.BytesIO(source)
        raw = pd.read_csv(source, dtype=str, keep_default_na=False, na_values=[""])
    except pd.errors.EmptyDataError:
        raise DataValidationError("The file is empty.")
    except UnicodeDecodeError:
        raise DataValidationError("The file is not valid UTF-8 text. Export it as UTF-8 CSV.")
    except pd.errors.ParserError as exc:
        raise DataValidationError(f"The file could not be parsed as CSV: {exc}")
    return preprocess_events(raw, max_rows=max_rows)


def sample_csv_bytes(n_rows: int = 200, seed: int = 42) -> bytes:
    """A small, synthetic, correctly formatted CSV to use as an upload template."""
    from .generator import generate_events
    df = generate_events(seed)
    # include some suspicious rows so the template demonstrates the schema end to end
    pos = df[df["label"] == 1].head(max(10, n_rows // 10))
    rest = df[df["label"] == 0].sample(n=n_rows - len(pos), random_state=seed)
    sample = pd.concat([pos, rest]).sort_values("timestamp")
    return sample.to_csv(index=False).encode("utf-8")
