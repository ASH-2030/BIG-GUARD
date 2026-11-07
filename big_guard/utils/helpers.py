"""Small shared helpers."""
from __future__ import annotations

import hashlib

import pandas as pd

SEVERITY_COLORS = {"Critical": "#f43f5e", "High": "#fb923c", "Medium": "#fbbf24", "Low": "#38bdf8", "Info": "#64748b"}


def to_csv_bytes(df: pd.DataFrame) -> bytes:
    """CSV export that neutralises spreadsheet-formula injection in text cells (=, +, -, @ prefixes)."""
    safe = df.copy()
    for col in safe.columns:
        if safe[col].dtype == object or str(safe[col].dtype) in ("string", "str"):
            safe[col] = safe[col].map(lambda v: "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v)
    return safe.to_csv(index=False).encode("utf-8")


def dataframe_key(df: pd.DataFrame) -> str:
    """Stable short hash of a DataFrame's contents (used as a cache key)."""
    h = pd.util.hash_pandas_object(df.astype(str), index=False).to_numpy().tobytes()
    return hashlib.sha1(h + str(df.shape).encode()).hexdigest()[:16]


def fmt_ts(ts) -> str:
    return pd.Timestamp(ts).strftime("%Y-%m-%d %H:%M")
