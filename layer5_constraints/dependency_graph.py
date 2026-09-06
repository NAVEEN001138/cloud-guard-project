"""
=============================================================================
LAYER 5: CONSTRAINT DEPENDENCY GRAPH (DAG) RESOLVER
Module: dependency_graph.py
-----------------------------------------------------------------------------
Problem Solved:
  Replaces flat independent if-statements with an explicit Directed Acyclic Graph
  (DAG) of constraint derivations.

  Resolves dependencies in topological order:
    1. Physical Capability Evaluation (Asset hardware capabilities)
    2. Cascaded Infeasibility Pruning (Prunes downstream conflicts & variables)
    3. Regulatory & SLA Policy Enforcement (HIPAA, DPDP, SLA, Experience Rules)
    4. Conflict Hyperedge Synthesis (Incompatible action pairs)
    5. Adaptive Budget & Dynamic Objective Synthesis
=============================================================================
"""

from typing import Dict, List, Tuple, Set, Optional, Any
from dataclasses import dataclass, field

from config import ACTIONS, COST_WEIGHTS
from layer3_context.context_aggregator import AggregatedContext
from layer4_confidence.confidence_evaluator import ConfidenceScores
from layer5_constraints.constraint_ir import (
    SecurityConstraintIR,
    VariableDomain,
    InvarianceConstraint,
    ConflictHyperedge,
    HardBudgetConstraint,
    ObjectiveLinearTerm,
    IRProvenanceRecord,
    TopologyMetadata,
    ConstraintRecord,
    ConstraintHardness,
)

# Known conflict pairs (within or across resource categories)
DEFAULT_ACTION_CONFLICTS = [
    ("isolate", "monitor", "Contradictory containment state: full disconnection vs active surveillance"),
    ("isolate", "increase_logging", "Contradictory state: isolated host cannot push live syslog streams"),
    ("disable_user", "rotate_credentials", "Redundant credential operation: disabled account needs no immediate rotation"),
]

# Physical capability map
PHYSICAL_CAPABILITY_MAP: Dict[str, List[str]] = {
    "server": ["isolate", "rotate_credentials", "block_ip", "disable_user", "snapshot_backup", "monitor", "increase_logging"],
    "ec2_instance": ["isolate", "rotate_credentials", "block_ip", "disable_user", "snapshot_backup", "monitor", "increase_logging"],
    "rds_database": ["rotate_credentials", "block_ip", "snapshot_backup", "monitor", "increase_logging"],
    "plc_controller": ["rotate_credentials", "monitor", "increase_logging"],
    "camera_sensor": ["block_ip", "monitor", "increase_logging"],
    "iam_role": ["disable_user", "rotate_credentials", "monitor", "increase_logging"],
    "network_gateway": ["block_ip", "isolate", "monitor", "increase_logging"],
    "medical_device": ["monitor", "increase_logging", "rotate_credentials"],
}


def calculate_action_cost(resource_type: str, action: str, cost_weights=COST_WEIGHTS) -> float:
    """Calculates operational cost for action on specific resource type."""
    w1, w2, w3 = cost_weights
    if action == "isolate":
        business_impact = 0.9 if resource_type in ("rds_database", "plc_controller", "medical_device") else 0.5
        compliance_impact = 0.1
        downtime = 0.8
    elif action == "rotate_credentials":
        business_impact = 0.2
        compliance_impact = 0.1
        downtime = 0.1
    elif action == "block_ip":
        business_impact = 0.3
        compliance_impact = 0.2
        downtime = 0.05
    elif action == "disable_user":
        business_impact = 0.4
        compliance_impact = 0.3
        downtime = 0.2
    elif action == "snapshot_backup":
        business_impact = 0.1
        compliance_impact = 0.05
        downtime = 0.1
    elif action == "monitor":
        business_impact = 0.01
        compliance_impact = 0.0
        downtime = 0.0
    elif action == "increase_logging":
        business_impact = 0.05
        compliance_impact = 0.0
        downtime = 0.0
    else:
        business_impact = 0.2
        compliance_impact = 0.1
        downtime = 0.1

    return round(w1 * business_impact + w2 * compliance_impact + w3 * downtime, 4)


class ConstraintDependencyGraph:
    """
    Executes staged DAG derivation from security runtime context into SecurityConstraintIR.
    """

    def __init__(self, incident_id: str = "incident_001"):
        self.incident_id = incident_id

    def resolve(
        self,
        scenario: dict,
        threat_scores: Dict[str, float],
        contexts: Dict[str, AggregatedContext],
        confidences: Dict[str, ConfidenceScores],
        base_budget: float = 15.0,
        switching_penalty: float = 0.15,
        previous_plan: Optional[Dict[str, str]] = None,
        learned_rules: Optional[List[dict]] = None,
    ) -> SecurityConstraintIR:
        """
        Topological execution of the constraint dependency graph.
        """
        ir = SecurityConstraintIR(incident_id=self.incident_id)
        prev_plan = previous_plan or {}
        resources = scenario.get("resources", [])

        # =========================================================================
        # STAGE 1: Physical Capability Evaluation
        # =========================================================================
        stage1_candidates: Dict[str, Set[str]] = {}
        for r in resources:
            rid = r["id"]
            rtype = r.get("type", "server")
            physically_allowed = set(PHYSICAL_CAPABILITY_MAP.get(rtype, PHYSICAL_CAPABILITY_MAP["server"]))
            all_possible = set(ACTIONS.keys())

            # Identify pruned actions
            pruned_phys = all_possible - physically_allowed
            for act in pruned_phys:
                ir.provenance_records.append(IRProvenanceRecord(
                    target_resource=rid,
                    target_action=act,
                    constraint_type="PRUNED",
                    origin="PHYSICAL_CAPABILITY",
                    rule_id=f"PHYS_CAP_{rtype.upper()}",
                    rationale=f"Hardware/firmware for '{rtype}' does not support action '{act}'",
                ))

            stage1_candidates[rid] = physically_allowed

        # =========================================================================
        # STAGE 2: Detection Confidence Gating
        # =========================================================================
        stage2_candidates: Dict[str, Set[str]] = {}
        for r in resources:
            rid = r["id"]
            conf = confidences.get(rid)
            allowed = set(stage1_candidates[rid])

            if conf and conf.overall_confidence < 0.50:
                # Restrict high-disruption actions
                high_disruption = {"isolate", "disable_user"} & allowed
                for act in high_disruption:
                    allowed.discard(act)
                    ir.provenance_records.append(IRProvenanceRecord(
                        target_resource=rid,
                        target_action=act,
                        constraint_type="PRUNED",
                        origin="CONFIDENCE_TIER",
                        rule_id="CONF_TIER_LOW_GATE",
                        rationale=f"Confidence {conf.overall_confidence:.2f} is in LOW tier; high-disruption '{act}' pruned",
                    ))

            stage2_candidates[rid] = allowed

        # =========================================================================
        # STAGE 3: Statutory & SLA Policy Resolution
        # =========================================================================
        stage3_candidates: Dict[str, Set[str]] = {}
        for r in resources:
            rid = r["id"]
            rtype = r.get("type", "server")
            ctx = contexts.get(rid)
            s_i = threat_scores.get(rid, 0.5)
            allowed = set(stage2_candidates[rid])

            # HIPAA 45 CFR § 164.312(a)(1) Access Control Mandate
            if ctx and ctx.compliance.hipaa_applicable and s_i > 0.60:
                # Mandatory strong containment: isolate if available, else rotate credentials
                if "isolate" in allowed:
                    allowed = {"isolate"}
                    mandated_act = "isolate"
                elif "rotate_credentials" in allowed:
                    allowed = {"rotate_credentials"}
                    mandated_act = "rotate_credentials"
                else:
                    mandated_act = "monitor"

                ir.provenance_records.append(IRProvenanceRecord(
                    target_resource=rid,
                    target_action=mandated_act,
                    constraint_type="MANDATED",
                    origin="HIPAA_45_CFR_164",
                    rule_id="45_CFR_164_312_A1",
                    rationale="Statutory Technical Safeguards mandate access restriction on ePHI when threat > 0.60",
                ))

            # SLA Critical Prohibition (protect 99.99% availability)
            if ctx and ctx.business.sla_priority == "CRITICAL" and s_i < 0.40:
                if "isolate" in allowed:
                    allowed.discard("isolate")
                    ir.provenance_records.append(IRProvenanceRecord(
                        target_resource=rid,
                        target_action="isolate",
                        constraint_type="PRUNED",
                        origin="SLA_TIER",
                        rule_id="SLA_CRIT_AVAILABILITY_01",
                        rationale="SLA CRITICAL forbids automated network isolation when threat < 0.40",
                    ))

            # Industrial Safety Profile (PLC and Medical Devices never automated isolation)
            if rtype in ("plc_controller", "medical_device") and "isolate" in allowed:
                allowed.discard("isolate")
                ir.provenance_records.append(IRProvenanceRecord(
                    target_resource=rid,
                    target_action="isolate",
                    constraint_type="PRUNED",
                    origin="PHYSICAL_SAFETY_PROFILE",
                    rule_id=f"SAFETY_PROFILE_{rtype.upper()}",
                    rationale=f"Cyber-physical safety rules prohibit automated isolation on {rtype}",
                ))

            # System B Experience Rules (Learned from past incidents)
            if learned_rules:
                for rule in learned_rules:
                    target_rt = rule.get("target_resource_type", "all")
                    matches = (
                        target_rt in (rtype, "all", "*")
                        or (target_rt == "server" and rtype in ("server", "ec2_instance"))
                        or rule.get("target_resource_id") == rid
                    )
                    if matches:
                        action_to_prune = rule.get("restrict_action")
                        if action_to_prune in allowed:
                            allowed.discard(action_to_prune)
                            ir.provenance_records.append(IRProvenanceRecord(
                                target_resource=rid,
                                target_action=action_to_prune,
                                constraint_type="EXPERIENCE",
                                origin="EXPERIENCE_MEMORY",
                                rule_id=rule.get("rule_id", "EXP_LEARNED_01"),
                                rationale=rule.get("rationale", "Pruned based on historical negative incident outcome"),
                            ))

            # Guarantee non-empty decision space
            if not allowed:
                allowed = {"monitor"}

            stage3_candidates[rid] = allowed

        # =========================================================================
        # STAGE 4: Variable Domain & Invariance Constraint Construction
        # =========================================================================
        for r in resources:
            rid = r["id"]
            rtype = r.get("type", "server")
            admissible = sorted(list(stage3_candidates[rid]))
            pruned = sorted(list(set(ACTIONS.keys()) - set(admissible)))

            ir.variable_domains[rid] = VariableDomain(
                resource_id=rid,
                resource_type=rtype,
                admissible_actions=admissible,
                pruned_actions=pruned,
            )
            # Invariance: Exactly one action chosen per asset
            ir.invariance_constraints.append(InvarianceConstraint(
                resource_id=rid,
                actions=admissible,
                target_value=1,
            ))

        # =========================================================================
        # STAGE 5: Cascaded Conflict Hyperedge Synthesis
        # =========================================================================
        for r in resources:
            rid = r["id"]
            domain = ir.variable_domains[rid].admissible_actions
            for a1, a2, reason in DEFAULT_ACTION_CONFLICTS:
                if a1 in domain and a2 in domain:
                    # Within-resource mutually exclusive conflict
                    ir.conflict_hyperedges.append(ConflictHyperedge(
                        resource_1=rid,
                        action_1=a1,
                        resource_2=rid,
                        action_2=a2,
                        reason=reason,
                        rule_id="WITHIN_RES_CONFLICT",
                    ))

        # =========================================================================
        # STAGE 6: Objective Terms & Budget Rescaling Synthesis
        # =========================================================================
        cost_map: Dict[Tuple[str, str], float] = {}
        total_possible_cost = 0.0

        for r in resources:
            rid = r["id"]
            rtype = r.get("type", "server")
            s_i = threat_scores.get(rid, 0.5)
            c_i = confidences[rid].overall_confidence if rid in confidences else 1.0
            effective_threat = s_i * c_i
            domain = ir.variable_domains[rid].admissible_actions

            for act in domain:
                cost = calculate_action_cost(rtype, act)
                cost_map[(rid, act)] = cost
                total_possible_cost += cost

                beta_k = ACTIONS.get(act, 0.1)
                containment_term = -beta_k * effective_threat
                cost_term = cost
                switch_term = 0.0

                if prev_plan and rid in prev_plan and prev_plan[rid] != act:
                    switch_term = switching_penalty

                net_coeff = containment_term + cost_term + switch_term

                ir.objective_terms[(rid, act)] = ObjectiveLinearTerm(
                    resource_id=rid,
                    action=act,
                    coefficient=round(net_coeff, 4),
                    containment_component=round(containment_term, 4),
                    cost_component=round(cost_term, 4),
                    switching_penalty_component=round(switch_term, 4),
                )

        # Dynamic budget scaling based on active threat tier
        avg_threat = sum(threat_scores.values()) / max(1, len(threat_scores))
        if avg_threat > 0.70:
            b_mult = 1.3
        elif avg_threat > 0.40:
            b_mult = 1.0
        else:
            b_mult = 0.8
        effective_budget = round(base_budget * b_mult, 2)

        ir.budget_constraint = HardBudgetConstraint(
            max_budget=effective_budget,
            cost_map=cost_map,
        )

        # =========================================================================
        # STAGE 7: Explicit Hard vs Soft Constraint Separation
        # =========================================================================
        # Hard Constraints: Invariants that CANNOT be violated under any trade-off
        for rid, domain in ir.variable_domains.items():
            for pruned in domain.pruned_actions:
                ir.hard_constraints.append(ConstraintRecord(
                    constraint_id=f"HARD_CAP_{rid}_{pruned}",
                    target_resource=rid,
                    target_action=pruned,
                    hardness="HARD",
                    category="CAPABILITY_OR_SAFETY",
                    mathematical_form=f"x_{rid}_{pruned} = 0",
                    provenance_rule_id=f"INVARIANT_{domain.resource_type.upper()}",
                ))
            ir.hard_constraints.append(ConstraintRecord(
                constraint_id=f"HARD_INVAR_{rid}",
                target_resource=rid,
                target_action="*",
                hardness="HARD",
                category="EXACTLY_ONE_INVARIANCE",
                mathematical_form=f"sum_{{a}} x_{rid},a = 1",
                provenance_rule_id="INVARIANCE_POSTULATE",
            ))

        for idx, conf in enumerate(ir.conflict_hyperedges):
            ir.hard_constraints.append(ConstraintRecord(
                constraint_id=f"HARD_CONFLICT_{idx}",
                target_resource=conf.resource_1,
                target_action=f"{conf.action_1}+{conf.action_2}",
                hardness="HARD",
                category="CONFLICT_MUTUAL_EXCLUSION",
                mathematical_form=f"x_{conf.resource_1}_{conf.action_1} + x_{conf.resource_2}_{conf.action_2} <= 1",
                provenance_rule_id=conf.rule_id,
            ))

        # Soft Constraints: Multi-attribute trade-off preferences
        for (rid, act), term in ir.objective_terms.items():
            ir.soft_constraints.append(ConstraintRecord(
                constraint_id=f"SOFT_OBJ_{rid}_{act}",
                target_resource=rid,
                target_action=act,
                hardness="SOFT",
                category="COST_CONTAINMENT_TRADEOFF",
                mathematical_form=f"min coeff * x_{rid}_{act}",
                coefficient_weight=term.coefficient,
                provenance_rule_id="UTILITY_OBJECTIVE",
            ))

        # =========================================================================
        # STAGE 8: Topology Metadata Extraction
        # =========================================================================
        total_vars = len(ir.get_all_variables())
        total_invariants = len(ir.invariance_constraints)
        total_conflicts = len(ir.conflict_hyperedges)
        total_pruned = sum(len(d.pruned_actions) for d in ir.variable_domains.values())

        # Density = Active constraints / (Vars * (Vars - 1) / 2)
        max_possible_edges = max(1, (total_vars * (total_vars - 1)) // 2)
        density = round(total_conflicts / max_possible_edges, 4)

        # Model Family Fingerprint
        rtype_set = {r.get("type", "server") for r in resources}
        if "plc_controller" in rtype_set:
            family = "SCADA_CYBER_PHYSICAL"
        elif any(ctx.compliance.hipaa_applicable for ctx in contexts.values() if ctx):
            family = "HEALTHCARE_EPHI"
        elif "network_gateway" in rtype_set:
            family = "ENTERPRISE_NETWORK"
        else:
            family = "CLOUD_COMPUTE"

        ir.topology = TopologyMetadata(
            num_variables=total_vars,
            num_invariance_constraints=total_invariants,
            num_conflict_hyperedges=total_conflicts,
            has_budget_constraint=True,
            graph_density=density,
            pruned_variable_count=total_pruned,
            environment_fingerprint=f"{family}_V{total_vars}_C{total_conflicts}",
            model_family=family,
            num_hard_constraints=len(ir.hard_constraints),
            num_soft_constraints=len(ir.soft_constraints),
        )

        ir.compute_sha256()
        return ir
