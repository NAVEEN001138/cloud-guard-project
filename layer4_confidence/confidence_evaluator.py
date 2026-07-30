"""
=============================================================================
LAYER 4: CONFIDENCE EVALUATION
Module: confidence_evaluator.py
-----------------------------------------------------------------------------
Problem Solved:
  Evaluates detection confidence, sensor reliability, and evidence quality
  per resource. Solves model uncertainty by discounting threat scores when
  telemetry noise or sensor dropouts are present.

  Confidence-Controlled Action Eligibility (Improvement 1):
    Confidence directly controls the allowed action space per resource:
      - High confidence (>= 0.8): All actions allowed (including high-disruption isolation).
      - Moderate confidence (0.5 <= conf < 0.8): Medium-disruption allowed (block_ip, rotate_credentials).
      - Low confidence (< 0.5): Only low-disruption actions allowed (monitor, increase_logging, snapshot_backup).

Inputs:  Scenario telemetry signals & threat scores.
Outputs: ConfidenceScores dataclass with overall confidence metrics and allowed action sets.
=============================================================================
"""

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

# High-disruption actions that require strong confidence
HIGH_DISRUPTION_ACTIONS: Set[str] = {"isolate", "disable_user"}
MEDIUM_DISRUPTION_ACTIONS: Set[str] = {"block_ip", "rotate_credentials"}
LOW_DISRUPTION_ACTIONS: Set[str] = {"monitor", "increase_logging", "snapshot_backup"}


def _deterministic_float(seed_key: str, low: float, high: float) -> float:
    digest = hashlib.md5(seed_key.encode()).hexdigest()
    ratio = int(digest[:8], 16) / 0xFFFFFFFF
    return low + ratio * (high - low)


@dataclass
class ConfidenceScores:
    resource_id: str
    detection_confidence: float
    sensor_confidence: float
    evidence_quality: float
    overall_confidence: float
    allowed_actions: List[str]
    confidence_tier: str  # "HIGH", "MODERATE", "LOW"


def get_confidence_allowed_actions(overall_confidence: float) -> Tuple[List[str], str]:
    """
    Returns the list of allowed actions and the confidence tier based on overall_confidence.
    Prevents highly uncertain threat signals from triggering catastrophic isolation.
    """
    if overall_confidence >= 0.80:
        tier = "HIGH"
        allowed = list(LOW_DISRUPTION_ACTIONS | MEDIUM_DISRUPTION_ACTIONS | HIGH_DISRUPTION_ACTIONS)
    elif overall_confidence >= 0.50:
        tier = "MODERATE"
        allowed = list(LOW_DISRUPTION_ACTIONS | MEDIUM_DISRUPTION_ACTIONS)
    else:
        tier = "LOW"
        allowed = list(LOW_DISRUPTION_ACTIONS)
    return allowed, tier


def evaluate_resource_confidence(
    resource: dict, threat_score: float, seed: int = 42
) -> ConfidenceScores:
    rid = resource.get("id", "unknown")
    key = f"{rid}-{seed}-conf"

    # Detection confidence is higher for extreme threat scores (near 0 or near 1)
    det_conf = 0.5 + 0.5 * abs(threat_score - 0.5) * 2.0
    det_conf = min(0.99, max(0.4, det_conf))

    # Sensor confidence based on raw signal presence
    raw = resource.get("raw_signal", {})
    non_zero = sum(1 for v in raw.values() if v > 0)
    sensor_conf = 0.7 + 0.1 * non_zero + _deterministic_float(f"{key}-sens", -0.05, 0.05)
    sensor_conf = min(0.99, max(0.5, sensor_conf))

    # Evidence quality
    ev_qual = 0.8 + _deterministic_float(f"{key}-ev", -0.1, 0.15)
    ev_qual = min(0.99, max(0.5, ev_qual))

    overall = 0.5 * det_conf + 0.3 * sensor_conf + 0.2 * ev_qual
    allowed_actions, tier = get_confidence_allowed_actions(overall)

    return ConfidenceScores(
        resource_id=rid,
        detection_confidence=round(det_conf, 4),
        sensor_confidence=round(sensor_conf, 4),
        evidence_quality=round(ev_qual, 4),
        overall_confidence=round(overall, 4),
        allowed_actions=allowed_actions,
        confidence_tier=tier,
    )


def evaluate_confidence(
    scenario: dict, threat_scores: Dict[str, float], seed: int = 42
) -> Dict[str, ConfidenceScores]:
    confidences = {}
    for r in scenario.get("resources", []):
        rid = r.get("id")
        score = threat_scores.get(rid, 0.5)
        confidences[rid] = evaluate_resource_confidence(r, score, seed=seed)
    return confidences
