"""
=============================================================================
LAYER 5: ADAPTIVE CONSTRAINTS & POLICY PROVENANCE MATRIX ENGINE
Module: adaptive_constraints.py
-----------------------------------------------------------------------------
Problem Solved:
  Synthesizes context, confidence, compliance policies, asset C-I-A profiles,
  and resource capabilities into a mathematical constraint model for Layer 6.

  Policy Provenance Engine (Weakness 3 Solution):
    Every generated required or forbidden constraint carries explicit legal,
    physical, or historical provenance (Rule ID, Origin, Justification), ensuring
    100% auditability and compliance traceability for patents and SOC audits.

  Outputs generated:
    1. Constraint Matrix (Required & Forbidden actions per resource)
    2. Policy Provenance Matrix (Traceable Rule ID, Origin, Justification)
    3. Dynamic Objective Weights (Context-driven weight adaptation)
    4. Feasible Action Matrix (Per-resource-type physical capability filtering)
    5. Action Conflict Matrix (Incompatible action pairs)
    6. Resource C-I-A Importance Profiles (Confidentiality, Integrity, Availability ratings)
    7. Decision Stability Penalty (Prevents action oscillation across rounds)
=============================================================================
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple

from config import UTILITY_WEIGHTS, MAX_BUDGET
from layer3_context.context_aggregator import AggregatedContext
from layer4_confidence.confidence_evaluator import ConfidenceScores
from layer5_constraints.constraint_ir import (
    SecurityConstraintIR,
    VariableDomain,
    ConflictHyperedge,
    InvarianceConstraint,
    HardBudgetConstraint,
    TopologyMetadata,
)
from layer5_constraints.dependency_graph import ConstraintDependencyGraph
from layer5_constraints.safety_certifier import PreSolveSafetyCertifier, ConstraintSafetyCertificate
from layer5_constraints.formulation_compiler import FormulationCompiler


# -----------------------------------------------------------------------------
# Policy Provenance Dataclass
# -----------------------------------------------------------------------------
@dataclass
class ConstraintProvenance:
    resource_id: str
    action: str
    constraint_type: str    # "REQUIRED" or "FORBIDDEN"
    origin: str             # "HIPAA_COMPLIANCE", "PHYSICAL_CAPABILITY", "SLA_SERVICE_LEVEL", "HISTORICAL_EMA_RELIABILITY", "CONFIDENCE_TIER"
    rule_id: str            # e.g. "HIPAA_SEC_164", "PHYS_CAP_PLC", "SLA_CRIT_01", "CONF_TIER_LOW"
    justification: str      # Human-readable legal/technical justification string


# -----------------------------------------------------------------------------
# Feasible Action Matrix: Supported actions per resource category
# -----------------------------------------------------------------------------
FEASIBLE_ACTION_MATRIX: Dict[str, List[str]] = {
    "server": ["isolate", "rotate_credentials", "block_ip", "disable_user", "snapshot_backup", "monitor", "increase_logging"],
    "ec2_instance": ["isolate", "rotate_credentials", "block_ip", "disable_user", "snapshot_backup", "monitor", "increase_logging"],
    "rds_database": ["rotate_credentials", "block_ip", "snapshot_backup", "monitor", "increase_logging"],
    "plc_controller": ["rotate_credentials", "monitor", "increase_logging"],
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


@dataclass
class OptimizationConstraints:
    max_budget: float
    utility_weights: Dict[str, float]
    required_actions: Dict[str, str] = field(default_factory=dict)
    forbidden_actions: Dict[str, Dict[str, str]] = field(default_factory=dict)
    feasible_actions: Dict[str, List[str]] = field(default_factory=dict)
    resource_profiles: Dict[str, ResourceProfile] = field(default_factory=dict)
    provenance_matrix: Dict[str, List[ConstraintProvenance]] = field(default_factory=dict)
    switching_penalty: float = 0.15
    previous_plan: Dict[str, str] = field(default_factory=dict)
    constraint_ir: Optional[SecurityConstraintIR] = None
    safety_certificate: Optional[ConstraintSafetyCertificate] = None


def generate_adaptive_constraints(
    contexts: Dict[str, AggregatedContext],
    confidences: Dict[str, ConfidenceScores],
    base_max_budget: float = MAX_BUDGET,
    base_weights: Optional[Dict[str, float]] = None,
    previous_plan: Optional[Dict[str, str]] = None,
    time_of_day: str = "business_hours",
    scenario: Optional[dict] = None,
    threat_scores: Optional[Dict[str, float]] = None,
    learned_rules: Optional[List[dict]] = None,
) -> OptimizationConstraints:
    """
    Synthesizes context, confidence, C-I-A profiles, and policy rules into Layer 5 constraints
    with complete Policy Provenance tracing.
    """
    weights = (base_weights or UTILITY_WEIGHTS).copy()

    avg_threat = sum(ctx.threat.threat_score for ctx in contexts.values()) / max(1, len(contexts))
    avg_conf = sum(conf.overall_confidence for conf in confidences.values()) / max(1, len(confidences))

    # --- 1. Budget Scaling ---
    if avg_threat > 0.7:
        budget_multiplier = 1.3
    elif avg_threat > 0.4:
        budget_multiplier = 1.0
    else:
        budget_multiplier = 0.8
    adjusted_budget = base_max_budget * budget_multiplier

    # --- 2. Dynamic Weight Adaptation ---
    if time_of_day == "business_hours":
        weights["business_impact"] *= 1.3
        weights["downtime"] *= 1.2
    else:
        weights["containment_effectiveness"] *= 1.3
        weights["downtime"] *= 0.7

    if avg_conf < 0.6:
        weights["containment_effectiveness"] *= 0.75
        weights["business_impact"] *= 1.25

    # --- 3. Feasible Action Matrix, Profiles & Provenance Matrix ---
    feasible = {}
    profiles = {}
    required = {}
    forbidden = {}
    provenance = {}

    for rid, ctx in contexts.items():
        conf = confidences[rid]
        rtype = getattr(ctx.asset, "resource_type", getattr(ctx.asset, "workload_type", "generic"))
        prof = RESOURCE_PROFILES.get(rtype, ResourceProfile(rtype, 3, 3, 3, True))
        profiles[rid] = prof

        physically_allowed = FEASIBLE_ACTION_MATRIX.get(rtype, FEASIBLE_ACTION_MATRIX["server"])
        conf_allowed = conf.allowed_actions
        effective_feasible = [a for a in physically_allowed if a in conf_allowed]
        if not effective_feasible:
            effective_feasible = ["monitor"]

        feasible[rid] = effective_feasible
        forbidden[rid] = {}
        provenance[rid] = []

        # Physical capability provenance
        for act in FEASIBLE_ACTION_MATRIX.get("server", []):
            if act not in physically_allowed:
                provenance[rid].append(ConstraintProvenance(
                    resource_id=rid,
                    action=act,
                    constraint_type="FORBIDDEN",
                    origin="PHYSICAL_CAPABILITY",
                    rule_id=f"PHYS_CAP_{rtype.upper()}",
                    justification=f"Resource category '{rtype}' physically lacks capability for {act}",
                ))

        # Compliance provenance
        if ctx.compliance.hipaa_applicable and ctx.threat.threat_score > 0.6:
            target_act = "isolate" if "isolate" in effective_feasible else "rotate_credentials"
            required[rid] = target_act
            provenance[rid].append(ConstraintProvenance(
                resource_id=rid,
                action=target_act,
                constraint_type="REQUIRED",
                origin="HIPAA_COMPLIANCE",
                rule_id="45_CFR_164_312_A1",
                justification=(
                    "45 CFR § 164.312(a)(1) (Technical Safeguards - Access Control) requires implementation "
                    "of technical mechanisms to restrict access to ePHI. Under system policy, threat score > 0.60 "
                    "triggers mandatory isolation or credential rotation to comply with statutory access controls."
                ),
            ))

        # SLA Critical provenance
        if ctx.business.sla_priority == "CRITICAL" and ctx.threat.threat_score < 0.4:
            forbidden[rid]["isolate"] = "Forbidden by SLA Critical policy when threat score < 0.4"
            provenance[rid].append(ConstraintProvenance(
                resource_id=rid,
                action="isolate",
                constraint_type="FORBIDDEN",
                origin="SLA_SERVICE_LEVEL",
                rule_id="SLA_CRIT_AVAILABILITY_01",
                justification="SLA Priority CRITICAL prohibits automated isolation when threat score < 0.40",
            ))

        # Profile safety provenance (PLC / Medical Device)
        if not prof.auto_isolate_allowed and "isolate" in physically_allowed:
            reason_str = f"Forbidden: {rtype} profile prohibits automated isolation"
            forbidden[rid]["isolate"] = reason_str
            provenance[rid].append(ConstraintProvenance(
                resource_id=rid,
                action="isolate",
                constraint_type="FORBIDDEN",
                origin="PHYSICAL_SAFETY_PROFILE",
                rule_id=f"SAFETY_PROFILE_{rtype.upper()}",
                justification=f"Safety Profile for '{rtype}' prohibits automated network isolation to protect physical processes",
            ))

        # Low Confidence provenance
        if conf.overall_confidence < 0.5:
            forbidden[rid]["isolate"] = "Forbidden: Low detection confidence (< 0.50)"
            forbidden[rid]["disable_user"] = "Forbidden: Low detection confidence (< 0.50)"
            provenance[rid].append(ConstraintProvenance(
                resource_id=rid,
                action="isolate",
                constraint_type="FORBIDDEN",
                origin="CONFIDENCE_TIER",
                rule_id="CONF_TIER_LOW_GATE",
                justification=f"Detection Confidence ({conf.overall_confidence:.2f}) is in LOW tier (<0.50); High-disruption isolation restricted",
            ))
            provenance[rid].append(ConstraintProvenance(
                resource_id=rid,
                action="disable_user",
                constraint_type="FORBIDDEN",
                origin="CONFIDENCE_TIER",
                rule_id="CONF_TIER_LOW_GATE",
                justification=f"Detection Confidence ({conf.overall_confidence:.2f}) is in LOW tier (<0.50); Account disabling restricted",
            ))

    # Build scenario structure if not provided
    eff_scenario = scenario or {
        "scenario": "adaptive_incident",
        "resources": [
            {
                "id": rid,
                "type": getattr(ctx.asset, "resource_type", getattr(ctx.asset, "workload_type", "server")),
            }
            for rid, ctx in contexts.items()
        ]
    }
    eff_scores = threat_scores or {rid: ctx.threat.threat_score for rid, ctx in contexts.items()}

    # Resolve DAG into SecurityConstraintIR
    dag = ConstraintDependencyGraph(incident_id=eff_scenario.get("scenario", "incident"))
    sc_ir = dag.resolve(
        scenario=eff_scenario,
        threat_scores=eff_scores,
        contexts=contexts,
        confidences=confidences,
        base_budget=adjusted_budget,
        switching_penalty=0.15,
        previous_plan=previous_plan,
        learned_rules=learned_rules,
    )

    # Execute Pre-Solve Formal Safety Certification
    cert = PreSolveSafetyCertifier.certify(sc_ir)

    return OptimizationConstraints(
        max_budget=round(adjusted_budget, 2),
        utility_weights=weights,
        required_actions=required,
        forbidden_actions=forbidden,
        feasible_actions=feasible,
        resource_profiles=profiles,
        provenance_matrix=provenance,
        switching_penalty=0.15,
        previous_plan=previous_plan or {},
        constraint_ir=sc_ir,
        safety_certificate=cert,
    )

