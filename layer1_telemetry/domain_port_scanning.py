"""
=============================================================================
LAYER 1: TELEMETRY & ATTACK DOMAIN SHARDING
Module: domain_port_scanning.py
-----------------------------------------------------------------------------
Problem Solved:
  Extracts and partitions Port Scanning attack telemetry for localized
  IoT Edge node training (Domain Port Scanning Attack).

Inputs:  Raw Edge-IIoTset telemetry data.
Outputs: Feature matrix (X) and binary attack labels (y).
=============================================================================
"""

import numpy as np
import pandas as pd
from typing import Tuple, Dict

from layer1_telemetry.data_loader import load_edge_iiot_dataset


def get_port_scanning_domain_data(sample_size: int = 5000, seed: int = 44) -> Tuple[np.ndarray, np.ndarray, Dict]:
    """
    Extracts Domain Port Scanning Attack telemetry shard.
    """
    X, y, df, meta = load_edge_iiot_dataset(sample_size=sample_size * 2, seed=seed)
    if len(y) == 0:
        return X, y, {"domain": "Domain Port Scanning Attack", "samples": 0}

    if "Attack_type" in df.columns:
        mask = df["Attack_type"].isin(["Normal", "Port_Scanning", "Vulnerability_scanner", "Password"])
        indices = np.where(mask)[0]
    else:
        indices = np.arange(len(y))

    if len(indices) > sample_size:
        rng = np.random.default_rng(seed)
        indices = rng.choice(indices, size=sample_size, replace=False)

    X_domain = X[indices]
    y_domain = y[indices]

    meta_domain = {
        "domain": "Domain Port Scanning Attack",
        "samples": len(y_domain),
        "attack_rate": float(y_domain.mean()) if len(y_domain) > 0 else 0.0,
        "attack_name": "Port Scanning",
    }
    return X_domain, y_domain, meta_domain
