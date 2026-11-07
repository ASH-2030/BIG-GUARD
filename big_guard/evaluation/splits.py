"""Identity-grouped, stratified train/test split (no identity appears in both sets)."""
from __future__ import annotations

import numpy as np
import pandas as pd


def identity_grouped_split(df: pd.DataFrame, test_size: float = 0.4, seed: int = 42):
    """Return (train_identities, test_identities). Stratified on 'identity has any positive label'."""
    lab = df.dropna(subset=["label"])
    has_pos = lab.groupby("identity")["label"].max().astype(int)
    rng = np.random.default_rng(seed)
    test = []
    for flag in (0, 1):
        ids = np.array(sorted(has_pos[has_pos == flag].index))
        if len(ids) == 0:
            continue
        rng.shuffle(ids)
        k = max(1, int(round(len(ids) * test_size))) if len(ids) > 1 else 0
        test.extend(ids[:k].tolist())
    train = [i for i in has_pos.index if i not in set(test)]
    return sorted(train), sorted(test)
