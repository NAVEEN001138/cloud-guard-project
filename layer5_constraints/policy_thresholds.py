"""
=============================================================================
LAYER 5: POLICY THRESHOLDS & POLICY REVISION (SINGLE SOURCE OF TRUTH)
Module: policy_thresholds.py
-----------------------------------------------------------------------------
Problem Solved:
  Centralizes all quantitative admissibility, budget-scaling, and compliance
  decision thresholds into a single immutable specification.
  Prevents threshold drift and magic numbers across modules.
  The POLICY_REVISION digest cryptographically commits to these thresholds.
=============================================================================
"""

import hashlib
import json

# Canonical threshold values
THRESHOLD_THREAT_HIGH = 0.70
THRESHOLD_HIPAA_MANDATE = 0.60
THRESHOLD_LOW_CONFIDENCE = 0.50
THRESHOLD_THREAT_LOW = 0.40  # SLA Critical restriction & low-threat budget ceiling

# Default fallback values and weight factors associated with policy tiers
DEFAULT_THREAT_SCORE = 0.50
DEFAULT_BUSINESS_IMPACT_NORMAL = 0.50
DEFAULT_BUSINESS_IMPACT_LOW = 0.40
OFF_HOURS_DOWNTIME_FACTOR = 0.70
CONFIDENCE_ADAPTATION_THRESHOLD = 0.60
CONFIDENCE_PENALTY_CONTAINMENT = 0.75

ALL_THREAT_THRESHOLDS = sorted([THRESHOLD_THREAT_LOW, THRESHOLD_HIPAA_MANDATE, THRESHOLD_THREAT_HIGH])

# Cyber-physical PLC operational mode constants
PLC_MODE_RUN = "RUN"
PLC_MODE_MAINTENANCE = "MAINTENANCE"


def get_effective_plc_mode(resource: Any) -> str:
    """
    Returns the effective operating mode for a PLC controller (defaulting to PLC_MODE_RUN == 'RUN').
    If resource has a physical_state dict or attribute, extracts 'mode'.
    Absent, empty, or None -> returns PLC_MODE_RUN ('RUN').
    """
    if isinstance(resource, dict):
        phys = resource.get("physical_state")
        if isinstance(phys, dict):
            mode = phys.get("mode")
            if mode:
                return str(mode)
        elif hasattr(phys, "mode"):
            mode = getattr(phys, "mode")
            if mode:
                return str(mode)
    elif hasattr(resource, "physical_state"):
        phys = getattr(resource, "physical_state", None)
        if isinstance(phys, dict):
            mode = phys.get("mode")
            if mode:
                return str(mode)
        elif hasattr(phys, "mode"):
            mode = getattr(phys, "mode")
            if mode:
                return str(mode)
    return PLC_MODE_RUN

POLICY_THRESHOLDS_DICT = {
    "THRESHOLD_THREAT_HIGH": THRESHOLD_THREAT_HIGH,
    "THRESHOLD_HIPAA_MANDATE": THRESHOLD_HIPAA_MANDATE,
    "THRESHOLD_LOW_CONFIDENCE": THRESHOLD_LOW_CONFIDENCE,
    "THRESHOLD_THREAT_LOW": THRESHOLD_THREAT_LOW,
}

# 16-character canonical hex digest identifying this policy threshold revision
POLICY_REVISION = hashlib.sha256(
    json.dumps(POLICY_THRESHOLDS_DICT, sort_keys=True).encode("utf-8")
).hexdigest()[:16]
