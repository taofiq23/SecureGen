"""Bootstrap confidence intervals, same percentile-bootstrap pattern used in the SentinelShield
and DetectorMutation projects."""

from typing import Optional, Tuple

import numpy as np


def rate_bootstrap_ci(flags, n_resamples: int = 2000, seed: int = 0, confidence: float = 0.95):
    flags = np.asarray(flags, dtype=bool)
    n = len(flags)
    if n == 0:
        return None, None, None
    rng = np.random.default_rng(seed)
    values = np.empty(n_resamples)
    for i in range(n_resamples):
        values[i] = flags[rng.integers(0, n, n)].mean()
    lo, hi = np.percentile(values, [(1 - confidence) / 2 * 100, (1 + confidence) / 2 * 100])
    return float(flags.mean()), float(lo), float(hi)


def paired_rate_difference_ci(a_flags, b_flags, n_resamples: int = 2000, seed: int = 0, confidence: float = 0.95):
    """mean(a) - mean(b) on the same paired samples, with a paired bootstrap interval."""
    a = np.asarray(a_flags, dtype=bool)
    b = np.asarray(b_flags, dtype=bool)
    assert len(a) == len(b)
    n = len(a)
    if n == 0:
        return None, None, None
    rng = np.random.default_rng(seed)
    diffs = np.empty(n_resamples)
    for i in range(n_resamples):
        idx = rng.integers(0, n, n)
        diffs[i] = a[idx].mean() - b[idx].mean()
    lo, hi = np.percentile(diffs, [(1 - confidence) / 2 * 100, (1 + confidence) / 2 * 100])
    return float(a.mean() - b.mean()), float(lo), float(hi)
