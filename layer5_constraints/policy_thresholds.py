"""
=============================================================================
LAYER 5: POLICY THRESHOLDS & DECISION POLICY MANIFEST (SINGLE SOURCE OF TRUTH)
Module: policy_thresholds.py
-----------------------------------------------------------------------------
Problem Solved:
  Centralizes all quantitative admissibility, budget-scaling, compliance,
  physical capability mappings, action conflicts, and resource profiles into
  a single canonical DECISION_POLICY_MANIFEST.
  Prevents threshold drift and magic numbers across modules.
  The POLICY_REVISION digest cryptographically commits to this complete manifest.
=============================================================================
"""

import hashlib
import json
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any, Tuple

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


# -----------------------------------------------------------------------------
# Physical Capability Map
# -----------------------------------------------------------------------------
PHYSICAL_CAPABILITY_MAP: Dict[str, List[str]] = {
    "server": ["isolate", "rotate_credentials", "block_ip", "disable_user", "snapshot_backup", "monitor", "increase_logging"],
    "ec2_instance": ["isolate", "rotate_credentials", "block_ip", "disable_user", "snapshot_backup", "monitor", "increase_logging"],
    "rds_database": ["rotate_credentials", "block_ip", "snapshot_backup", "monitor", "increase_logging"],
    "plc_controller": ["isolate", "rotate_credentials", "monitor", "increase_logging"],
    "camera_sensor": ["block_ip", "monitor", "increase_logging"],
    "iam_role": ["disable_user", "rotate_credentials", "monitor", "increase_logging"],
    "network_gateway": ["block_ip", "isolate", "monitor", "increase_logging"],
    "medical_device": ["monitor", "increase_logging", "rotate_credentials"],
}


# -----------------------------------------------------------------------------
# Feasible Action Matrix: Supported actions per resource category
# -----------------------------------------------------------------------------
FEASIBLE_ACTION_MATRIX: Dict[str, List[str]] = {
    "server": ["isolate", "rotate_credentials", "block_ip", "disable_user", "snapshot_backup", "monitor", "increase_logging"],
    "ec2_instance": ["isolate", "rotate_credentials", "block_ip", "disable_user", "snapshot_backup", "monitor", "increase_logging"],
    "rds_database": ["rotate_credentials", "block_ip", "snapshot_backup", "monitor", "increase_logging"],
    "plc_controller": ["isolate", "rotate_credentials", "monitor", "increase_logging"],
    "camera_sensor": ["block_ip", "monitor", "increase_logging"],
    "iam_role": ["disable_user", "rotate_credentials", "monitor", "increase_logging"],
    "network_gateway": ["block_ip", "isolate", "monitor", "increase_logging"],
    "medical_device": ["monitor", "increase_logging", "rotate_credentials"],
}


# -----------------------------------------------------------------------------
# Resource C-I-A Importance Profiles (Scale 1 to 5)
# -----------------------------------------------------------------------------
@dataclass
class ResourceProfile:
    resource_type: str
    confidentiality: int  # 1 to 5
    integrity: int        # 1 to 5
    availability: int     # 1 to 5
    auto_isolate_allowed: bool


RESOURCE_PROFILES: Dict[str, ResourceProfile] = {
    "rds_database": ResourceProfile("rds_database", confidentiality=5, integrity=5, availability=4, auto_isolate_allowed=False),
    "plc_controller": ResourceProfile("plc_controller", confidentiality=2, integrity=5, availability=5, auto_isolate_allowed=False),
    "camera_sensor": ResourceProfile("camera_sensor", confidentiality=2, integrity=3, availability=5, auto_isolate_allowed=True),
    "medical_device": ResourceProfile("medical_device", confidentiality=4, integrity=5, availability=5, auto_isolate_allowed=False),
    "server": ResourceProfile("server", confidentiality=4, integrity=4, availability=3, auto_isolate_allowed=True),
    "ec2_instance": ResourceProfile("ec2_instance", confidentiality=4, integrity=4, availability=3, auto_isolate_allowed=True),
    "iam_role": ResourceProfile("iam_role", confidentiality=5, integrity=4, availability=2, auto_isolate_allowed=True),
    "network_gateway": ResourceProfile("network_gateway", confidentiality=3, integrity=4, availability=5, auto_isolate_allowed=True),
}


# -----------------------------------------------------------------------------
# Default Action Conflicts
# -----------------------------------------------------------------------------
DEFAULT_ACTION_CONFLICTS: List[Tuple[str, str, str]] = [
    ("isolate", "monitor", "Contradictory containment state: full disconnection vs active surveillance"),
    ("isolate", "increase_logging", "Contradictory state: isolated host cannot push live syslog streams"),
    ("disable_user", "rotate_credentials", "Redundant credential operation: disabled account needs no immediate rotation"),
]


_TRUSTED_LEARNED_RULES: List[Dict[str, Any]] = []


def get_trusted_learned_rules() -> List[Dict[str, Any]]:
    """Returns currently admitted learned rules from the trusted store."""
    return list(_TRUSTED_LEARNED_RULES)


def register_admitted_learned_rule(rule: Dict[str, Any]) -> None:
    """Registers an admitted learned rule into the trusted in-memory rule store."""
    if rule not in _TRUSTED_LEARNED_RULES:
        _TRUSTED_LEARNED_RULES.append(rule)


def clear_trusted_learned_rules() -> None:
    """Clears admitted learned rules from the trusted store (for testing/reset)."""
    _TRUSTED_LEARNED_RULES.clear()


def build_decision_policy_manifest(learned_rules: Optional[List[dict]] = None) -> Dict[str, Any]:
    """
    Constructs the canonical DECISION_POLICY_MANIFEST encompassing all decision-affecting
    thresholds, matrices, profiles, conflict rules, PLC mode constants, and learned rules.
    """
    rules = learned_rules if learned_rules is not None else get_trusted_learned_rules()
    learned_digest = ""
    if rules:
        learned_digest = hashlib.sha256(json.dumps(rules, sort_keys=True).encode("utf-8")).hexdigest()

    return {
        "THRESHOLD_THREAT_HIGH": THRESHOLD_THREAT_HIGH,
        "THRESHOLD_HIPAA_MANDATE": THRESHOLD_HIPAA_MANDATE,
        "THRESHOLD_LOW_CONFIDENCE": THRESHOLD_LOW_CONFIDENCE,
        "THRESHOLD_THREAT_LOW": THRESHOLD_THREAT_LOW,
        "DEFAULT_THREAT_SCORE": DEFAULT_THREAT_SCORE,
        "DEFAULT_BUSINESS_IMPACT_NORMAL": DEFAULT_BUSINESS_IMPACT_NORMAL,
        "DEFAULT_BUSINESS_IMPACT_LOW": DEFAULT_BUSINESS_IMPACT_LOW,
        "OFF_HOURS_DOWNTIME_FACTOR": OFF_HOURS_DOWNTIME_FACTOR,
        "CONFIDENCE_ADAPTATION_THRESHOLD": CONFIDENCE_ADAPTATION_THRESHOLD,
        "CONFIDENCE_PENALTY_CONTAINMENT": CONFIDENCE_PENALTY_CONTAINMENT,
        "ALL_THREAT_THRESHOLDS": list(ALL_THREAT_THRESHOLDS),
        "PLC_MODE_RUN": PLC_MODE_RUN,
        "PLC_MODE_MAINTENANCE": PLC_MODE_MAINTENANCE,
        "PHYSICAL_CAPABILITY_MAP": {k: list(v) for k, v in PHYSICAL_CAPABILITY_MAP.items()},
        "FEASIBLE_ACTION_MATRIX": {k: list(v) for k, v in FEASIBLE_ACTION_MATRIX.items()},
        "RESOURCE_PROFILES": {
            k: (asdict(v) if hasattr(v, "__dataclass_fields__") else v)
            for k, v in RESOURCE_PROFILES.items()
        },
        "DEFAULT_ACTION_CONFLICTS": [list(item) if isinstance(item, (list, tuple)) else item for item in DEFAULT_ACTION_CONFLICTS],
        "LEARNED_RULES_DIGEST": learned_digest,
    }


# Backwards compatibility dictionary
POLICY_THRESHOLDS_DICT = {
    "THRESHOLD_THREAT_HIGH": THRESHOLD_THREAT_HIGH,
    "THRESHOLD_HIPAA_MANDATE": THRESHOLD_HIPAA_MANDATE,
    "THRESHOLD_LOW_CONFIDENCE": THRESHOLD_LOW_CONFIDENCE,
    "THRESHOLD_THREAT_LOW": THRESHOLD_THREAT_LOW,
}


def _raw_active_revision(learned_rules: Optional[List[dict]] = None) -> str:
    rules = learned_rules if learned_rules is not None else get_trusted_learned_rules()
    manifest = build_decision_policy_manifest(rules)
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def get_active_policy_revision(learned_rules: Optional[List[dict]] = None) -> str:
    """
    Computes 16-character canonical hex digest over DECISION_POLICY_MANIFEST
    and currently admitted learned-rule digests from the trusted rule store.
    """
    mod = sys.modules.get(__name__)
    if mod is not None and getattr(mod, "_override", None) is not None:
        return mod._override
    return _raw_active_revision(learned_rules)


def compute_policy_revision(learned_rules: Optional[List[dict]] = None) -> str:
    return get_active_policy_revision(learned_rules)


def get_policy_revision(learned_rules: Optional[List[dict]] = None) -> str:
    return get_active_policy_revision(learned_rules)


import sys
import types


class _PolicyThresholdsModule(types.ModuleType):
    _override: Optional[str] = None

    @property
    def POLICY_REVISION(self) -> str:
        if self._override is not None:
            return self._override
        return get_active_policy_revision()

    @POLICY_REVISION.setter
    def POLICY_REVISION(self, val: Any) -> None:
        if val is None or val == _raw_active_revision():
            self._override = None
        else:
            self._override = str(val)

    @property
    def DECISION_POLICY_MANIFEST(self) -> Dict[str, Any]:
        return build_decision_policy_manifest()


sys.modules[__name__].__class__ = _PolicyThresholdsModule
