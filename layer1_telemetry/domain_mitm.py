"""
=============================================================================
LAYER 1: TELEMETRY & ATTACK DOMAIN SHARDING
Module: domain_mitm.py
-----------------------------------------------------------------------------
Problem Solved:
  Extracts and partitions Man-in-the-Middle (MITM) attack telemetry for
  localized IoT Edge node training (Domain MITM Attack).
  Covers ARP spoofing and DNS-based interception attacks.

Inputs:  Raw Edge-IIoTset telemetry data.
Outputs: Feature matrix (X) and binary attack labels (y).
=============================================================================
"""

import numpy as np
import pandas as pd
from typing import Tuple, Dict

from layer1_telemetry.data_loader import load_edge_iiot_dataset


def get_mitm_domain_data(sample_size: int = 5000, seed: int = 48) -> Tuple[np.ndarray, np.ndarray, Dict]:
    """
    Extracts Domain MITM (Man-in-the-Middle) Attack telemetry shard.
    Covers ARP spoofing and DNS interception attack patterns.
    """
    X, y, df, meta = load_edge_iiot_dataset(sample_size=sample_size * 2, seed=seed)
    if len(y) == 0:
        return X, y, {"domain": "Domain MITM Attack", "samples": 0}

    if "Attack_type" in df.columns:
        mask = df["Attack_type"].isin(["Normal", "MITM"])
        indices = np.where(mask)[0]
    else:
        indices = np.arange(len(y))

    if len(indices) > sample_size:
        rng = np.random.default_rng(seed)
        indices = rng.choice(indices, size=sample_size, replace=False)

    X_domain = X[indices]
    y_domain = y[indices]

    meta_domain = {
        "domain": "Domain MITM Attack",
        "samples": len(y_domain),
        "attack_rate": float(y_domain.mean()) if len(y_domain) > 0 else 0.0,
        "attack_name": "MITM (ARP Spoofing + DNS)",
    }
    return X_domain, y_domain, meta_domain
