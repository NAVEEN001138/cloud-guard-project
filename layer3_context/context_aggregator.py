"""
=============================================================================
LAYER 3: CONTEXT AGGREGATION
Module: context_aggregator.py
-----------------------------------------------------------------------------
Problem Solved:
  Aggregates multi-dimensional asset context (criticality, sensitivity, recovery
  costs, SLA priority) and compliance constraints (GDPR, HIPAA, PCI-DSS).
  Solves contextual risk modeling beyond simple raw threat scores.

Inputs:  Scenario dictionary & threat scores.
Outputs: AggregatedContext objects mapping threat, asset, business, and compliance metrics per resource.
=============================================================================
"""

import hashlib
from dataclasses import dataclass, field
from typing import Dict


def _deterministic_float(seed_key: str, low: float, high: float) -> float:
    """Deterministic DEMONSTRATION fallback: a reproducible pseudo-value in
    [low, high] derived from a seed string. Used ONLY when a resource does not
    supply a real, measured context field. Not a security primitive."""
    digest = hashlib.md5(seed_key.encode()).hexdigest()
    ratio = int(digest[:8], 16) / 0xFFFFFFFF
    return low + ratio * (high - low)


@dataclass
class ThreatContext:
    threat_score: float
    severity: float
    attack_velocity: float


@dataclass
class AssetContext:
    business_criticality: float
    data_sensitivity: float
    workload_type: str
    resource_type: str = ""


@dataclass
class BusinessContext:
    sla_priority: str
    downtime_cost_per_min: float
    recovery_cost_estimate: float


@dataclass
class ComplianceContext:
    gdpr_applicable: bool
    hipaa_applicable: bool
    pci_dss_applicable: bool


@dataclass
class AggregatedContext:
    resource_id: str
    threat: ThreatContext
    asset: AssetContext
    business: BusinessContext
    compliance: ComplianceContext


def aggregate_context_for_resource(
    resource: dict, threat_score: float, seed: int = 42
) -> AggregatedContext:
    rid = resource.get("id", "unknown")
    rtype = resource.get("type", "generic")
    key = f"{rid}-{seed}"

    # Threat dimensions
    severity = min(1.0, threat_score * _deterministic_float(f"{key}-sev", 0.9, 1.2))
    velocity = _deterministic_float(f"{key}-vel", 0.2, 1.0)
    threat = ThreatContext(threat_score, severity, velocity)

    # Asset dimensions (canonical asset-type tiers; see ASSET_TYPES in config)
    if rtype in {"rds_database", "iam_role", "medical_device"}:
        # High-value data / healthcare assets: elevated criticality and sensitivity
        criticality = _deterministic_float(f"{key}-crit", 0.8, 1.0)
        sensitivity = _deterministic_float(f"{key}-sens", 0.8, 1.0)
    elif rtype == "plc_controller":
        # Cyber-physical controllers: maximal availability criticality
        criticality = _deterministic_float(f"{key}-crit", 0.9, 1.0)
        sensitivity = _deterministic_float(f"{key}-sens", 0.5, 0.8)
    elif rtype == "ec2_instance":
        criticality = _deterministic_float(f"{key}-crit", 0.4, 0.8)
        sensitivity = _deterministic_float(f"{key}-sens", 0.3, 0.7)
    elif rtype in {"camera_sensor", "network_gateway"}:
        criticality = _deterministic_float(f"{key}-crit", 0.5, 0.8)
        sensitivity = _deterministic_float(f"{key}-sens", 0.3, 0.6)
    else:
        criticality = _deterministic_float(f"{key}-crit", 0.5, 0.9)
        sensitivity = _deterministic_float(f"{key}-sens", 0.4, 0.8)

    # Real-context override: prefer measured / inventory-provided asset attributes
    # (e.g. from a CMDB) over the deterministic demonstration fallback above.
    if resource.get("business_criticality") is not None:
        criticality = float(resource["business_criticality"])
    if resource.get("data_sensitivity") is not None:
        sensitivity = float(resource["data_sensitivity"])
    asset = AssetContext(criticality, sensitivity, rtype, resource_type=rtype)

    # Business dimensions
    if criticality > 0.8:
        sla = "CRITICAL"
        downtime_cost = _deterministic_float(f"{key}-dt", 500.0, 2000.0)
    elif criticality > 0.5:
        sla = "HIGH"
        downtime_cost = _deterministic_float(f"{key}-dt", 100.0, 500.0)
    else:
        sla = "MEDIUM"
        downtime_cost = _deterministic_float(f"{key}-dt", 20.0, 100.0)

    # Real-context override for business attributes when supplied.
    if resource.get("sla_priority") is not None:
        sla = str(resource["sla_priority"])
    if resource.get("downtime_cost_per_min") is not None:
        downtime_cost = float(resource["downtime_cost_per_min"])

    rec_cost = downtime_cost * _deterministic_float(f"{key}-rec", 2.0, 5.0)
    business = BusinessContext(sla, downtime_cost, rec_cost)

    # Compliance dimensions (canonical asset-type domains)
    HEALTHCARE_TYPES = {"rds_database", "medical_device"}
    PCI_TYPES = {"ec2_instance", "network_gateway"}
    gdpr = sensitivity > 0.6
    hipaa = rtype in HEALTHCARE_TYPES and sensitivity > 0.7
    pci = rtype in PCI_TYPES and criticality > 0.7

    # Real-context override: explicit compliance flags from the asset inventory
    # take precedence over type-derived defaults.
    explicit = resource.get("compliance") or {}
    gdpr = bool(explicit.get("gdpr", gdpr))
    hipaa = bool(explicit.get("hipaa", hipaa))
    pci = bool(explicit.get("pci", pci))
    compliance = ComplianceContext(gdpr, hipaa, pci)

    return AggregatedContext(rid, threat, asset, business, compliance)


def aggregate_context(
    scenario: dict, threat_scores: Dict[str, float], seed: int = 42
) -> Dict[str, AggregatedContext]:
    contexts = {}
    for r in scenario.get("resources", []):
        rid = r.get("id")
        score = threat_scores.get(rid, 0.5)
        contexts[rid] = aggregate_context_for_resource(r, score, seed=seed)
    return contexts
