"""
=============================================================================
LAYER 1: TELEMETRY & ATTACK DOMAIN SHARDING
Module: domain_sql_injection.py
-----------------------------------------------------------------------------
Problem Solved:
  Extracts and partitions SQL Injection attack telemetry for localized
  IoT Edge node training (Domain SQL Injection Attack).

Inputs:  Raw Edge-IIoTset telemetry data.
Outputs: Feature matrix (X) and binary attack labels (y).
=============================================================================
"""

import numpy as np
import pandas as pd
from typing import Tuple, Dict

from layer1_telemetry.data_loader import load_edge_iiot_dataset


def get_sql_injection_domain_data(sample_size: int = 5000, seed: int = 43) -> Tuple[np.ndarray, np.ndarray, Dict]:
    """
    Extracts Domain SQL Injection Attack telemetry shard.
    """
    X, y, df, meta = load_edge_iiot_dataset(sample_size=sample_size * 2, seed=seed)
    if len(y) == 0:
        return X, y, {"domain": "Domain SQL Injection Attack", "samples": 0}

    if "Attack_type" in df.columns:
        mask = df["Attack_type"].isin(["Normal", "SQL_injection", "Uploading", "XSS"])
        indices = np.where(mask)[0]
    else:
        indices = np.arange(len(y))

    if len(indices) > sample_size:
        rng = np.random.default_rng(seed)
        indices = rng.choice(indices, size=sample_size, replace=False)

    X_domain = X[indices]
    y_domain = y[indices]

    meta_domain = {
        "domain": "Domain SQL Injection Attack",
        "samples": len(y_domain),
        "attack_rate": float(y_domain.mean()) if len(y_domain) > 0 else 0.0,
        "attack_name": "SQL Injection",
    }
    return X_domain, y_domain, meta_domain
