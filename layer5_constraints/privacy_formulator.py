"""
=============================================================================
LAYER 5: PRIVACY-PRESERVING DECISION FORMULATION & METRIC FORMALIZATION
Module: privacy_formulator.py
-----------------------------------------------------------------------------
Problem Solved:
  Formalizes post-FL operational metadata leakage reduction using Shannon Entropy
  and Information Disclosure Ratio (IDR) metrics, while transforming raw continuous
  threat probabilities into discretized operational tiers and anonymous tokens.

Mathematical Definitions:
  1. Information Disclosure Ratio (IDR):
       IDR = Bytes(D_priv) / Bytes(D_raw)

  2. Metadata Leakage Reduction (MLR):
       MLR = (1 - IDR) * 100%

  3. Shannon Entropy Reduction (SER):
       H(D) = - Σ p_x * log2(p_x)
       SER = (1 - H(D_priv) / H(D_raw)) * 100%
=============================================================================
"""

import hashlib
import math
import json
from dataclasses import dataclass
from typing import Dict, List, Tuple, Any

from layer3_context.context_aggregator import AggregatedContext
from layer4_confidence.confidence_evaluator import ConfidenceScores


@dataclass
class AnonymizedAssetToken:
    original_id: str
    token_id: str          # e.g. "Asset-TK-73AF"
    asset_tier: str        # e.g. "TIER_A" (Critical), "TIER_B" (High), "TIER_C" (Standard)
    sanitized_type: str    # e.g. "ComputeNode", "DataStore", "ControlDevice"


@dataclass
class DiscretizedContextPayload:
    token_id: str
    threat_tier: str       # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    confidence_tier: str   # "HIGH", "MODERATE", "LOW"
    asset_tier: str        # "TIER_A", "TIER_B", "TIER_C"
    discretized_threat: float
    discretized_confidence: float
    allowed_actions: List[str]


def anonymize_asset(resource_id: str, resource_type: str, seed: int = 42) -> AnonymizedAssetToken:
    """Generates a deterministic anonymous token for a resource ID to prevent infrastructure mapping."""
    digest = hashlib.sha256(f"{resource_id}-{seed}-privacy".encode()).hexdigest()[:6].upper()
    token_id = f"Asset-TK-{digest}"

    if resource_type in {"rds_database", "medical_device", "plc_controller"}:
        asset_tier = "TIER_A"
        sanitized_type = "DataStore/ControlDevice"
    elif resource_type in {"server", "ec2_instance", "iam_role"}:
        asset_tier = "TIER_B"
        sanitized_type = "ComputeNode/IdentityToken"
    else:
        asset_tier = "TIER_C"
        sanitized_type = "EdgeSensor"

    return AnonymizedAssetToken(
        original_id=resource_id,
        token_id=token_id,
        asset_tier=asset_tier,
        sanitized_type=sanitized_type,
    )


def discretize_threat_score(score: float) -> Tuple[str, float]:
    """
    Converts continuous threat score float into calibrated discrete operational tiers.
    Quantile Thresholds: CRITICAL (>=0.85), HIGH (>=0.60), MEDIUM (>=0.30), LOW (<0.30).
    """
    if score >= 0.85:
        return "CRITICAL", 0.90
    elif score >= 0.60:
        return "HIGH", 0.70
    elif score >= 0.30:
        return "MEDIUM", 0.45
    else:
        return "LOW", 0.15


def discretize_confidence_score(score: float) -> Tuple[str, float]:
    """Converts continuous confidence float into discrete confidence tiers."""
    if score >= 0.80:
        return "HIGH", 0.90
    elif score >= 0.50:
        return "MODERATE", 0.65
    else:
        return "LOW", 0.35


def compute_shannon_entropy(data_str: str) -> float:
    """Computes Shannon Entropy H(D) in bits for a given string representation."""
    if not data_str:
        return 0.0
    prob_dict = {}
    for char in data_str:
        prob_dict[char] = prob_dict.get(char, 0) + 1
    length = len(data_str)
    entropy = 0.0
    for count in prob_dict.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def transform_to_privacy_preserving_payload(
    scenario: dict,
    threat_scores: Dict[str, float],
    contexts: Dict[str, AggregatedContext],
    confidences: Dict[str, ConfidenceScores],
) -> Dict[str, DiscretizedContextPayload]:
    """
    Transforms raw incident metadata into a minimal, anonymized, discretized payload.
    Exposes 0 exact floating-point metrics or real asset names to downstream optimizers.
    """
    payloads = {}
    for r in scenario.get("resources", []):
        rid = r["id"]
        rtype = r["type"]
        score = threat_scores.get(rid, 0.5)
        conf = confidences[rid]

        anon = anonymize_asset(rid, rtype)
        th_tier, th_val = discretize_threat_score(score)
        cf_tier, cf_val = discretize_confidence_score(conf.overall_confidence)

        payloads[rid] = DiscretizedContextPayload(
            token_id=anon.token_id,
            threat_tier=th_tier,
            confidence_tier=cf_tier,
            asset_tier=anon.asset_tier,
            discretized_threat=th_val,
            discretized_confidence=cf_val,
            allowed_actions=conf.allowed_actions,
        )
    return payloads


def calculate_formal_privacy_metrics(
    raw_payload_str: str,
    privacy_payload_str: str
) -> Dict[str, float]:
    """
    Calculates formal information theory metrics:
      - Information Disclosure Ratio (IDR)
      - Metadata Leakage Reduction (MLR %)
      - Shannon Entropy Reduction (SER %)
    """
    raw_bytes = len(raw_payload_str.encode("utf-8"))
    priv_bytes = len(privacy_payload_str.encode("utf-8"))

    idr = (priv_bytes / raw_bytes) if raw_bytes > 0 else 1.0
    mlr = (1.0 - idr) * 100.0

    h_raw = compute_shannon_entropy(raw_payload_str)
    h_priv = compute_shannon_entropy(privacy_payload_str)
    ser = (1.0 - (h_priv / h_raw)) * 100.0 if h_raw > 0 else 0.0

    return {
        "raw_payload_bytes": raw_bytes,
        "privacy_payload_bytes": priv_bytes,
        "information_disclosure_ratio": round(idr, 4),
        "metadata_leakage_reduction_pct": round(mlr, 2),
        "shannon_entropy_raw_bits": round(h_raw, 4),
        "shannon_entropy_priv_bits": round(h_priv, 4),
        "shannon_entropy_reduction_pct": round(ser, 2),
    }


def calculate_information_leakage_reduction(
    raw_payload_bytes: int,
    privacy_payload_bytes: int
) -> float:
    """Calculates percentage reduction in exposed metadata information."""
    if raw_payload_bytes == 0:
        return 0.0
    return round((1.0 - (privacy_payload_bytes / raw_payload_bytes)) * 100.0, 2)
