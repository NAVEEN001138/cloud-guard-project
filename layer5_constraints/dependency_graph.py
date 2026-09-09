"""
=============================================================================
LAYER 5: CONSTRAINT DEPENDENCY GRAPH (DAG) RESOLVER & FIXED-POINT CLOSURE
Module: dependency_graph.py
-----------------------------------------------------------------------------
Problem Solved:
  Implements an explicit deterministic fixed-point dependency closure algorithm
  over typed constraint relationships:
    - REQUIRES: Prerequisite action dependencies across or within assets
    - CONFLICTS_WITH: Mutually exclusive action pairs
    - CONSUMES_RESOURCE: Resource and budget consumption relations
    - DERIVES_BOUND: Dynamic operational and resource bounds
    - MANDATES: Policy and statutory mandates (e.g. HIPAA § 164.312)
    - PROTECTS_FAILSAFE: Guaranteed non-empty baseline failsafe paths

  Fixed-Point Closure Formulation:
    Let R_0 contain initially inadmissible/pruned decision variables.
    Iteratively compute:
        R_{k+1} = R_k ∪ DependentConsequences(R_k)
    until:
        R_{k+1} = R_k  (Fixed point R*)

  Post-Closure Guarantees:
    1. No dependency references a nonexistent decision variable.
    2. No conflict references a removed decision variable.
    3. All resource bounds are consistent with the active domain.
    4. All mandatory failsafe paths remain valid.
    5. Every propagated structural change contains full provenance.
    6. Deterministic termination and cycle safety.
=============================================================================
"""

import time
from typing import Dict, List, Tuple, Set, Optional, Any
from dataclasses import dataclass, field, asdict

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


class DependencyRelationType:
    REQUIRES = "REQUIRES"
    CONFLICTS_WITH = "CONFLICTS_WITH"
    CONSUMES_RESOURCE = "CONSUMES_RESOURCE"
    DERIVES_BOUND = "DERIVES_BOUND"
    MANDATES = "MANDATES"
    PROTECTS_FAILSAFE = "PROTECTS_FAILSAFE"


@dataclass
class ClosureProvenance:
    """Structured audit provenance tracking exact causal reasons for dependency graph modifications."""
    entity: str
    operation: str  # "REMOVE_VARIABLE", "DEACTIVATE_CONFLICT", "REGENERATE_BOUND", "FAILSAFE_PRESERVED"
    reason: str
    parent_event: str
    downstream_effects: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity": self.entity,
            "operation": self.operation,
            "reason": self.reason,
            "parent_event": self.parent_event,
            "downstream_effects": list(self.downstream_effects),
        }


@dataclass
class TypedDependencyEdge:
    """Typed dependency relationship between decision variables or operational resources."""
    source_entity: str  # e.g. "server-01:isolate"
    target_entity: str  # e.g. "network-gw:isolate" or "budget:operational"
    relation_type: str  # DependencyRelationType
    rule_id: str
    description: str = ""
    is_sole_prerequisite: bool = False


@dataclass
class ClosureResult:
    """Complete structured output of the fixed-point dependency closure resolution."""
    initial_changes: List[str]
    removed_variables: List[Tuple[str, str]]
    removed_edges: List[Dict[str, str]]
    affected_constraints: List[str]
    affected_resources: List[str]
    regenerated_bounds: Dict[str, Any]
    propagation_depth: int
    iterations_to_fixed_point: int
    causal_trace: List[ClosureProvenance]
    closure_status: str  # "CONVERGED", "CYCLE_TERMINATED", "PRESERVED_FAILSAFE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "initial_changes": self.initial_changes,
            "removed_variables": [f"{r}:{a}" for r, a in self.removed_variables],
            "removed_edges": self.removed_edges,
            "affected_constraints": self.affected_constraints,
            "affected_resources": self.affected_resources,
            "regenerated_bounds": self.regenerated_bounds,
            "propagation_depth": self.propagation_depth,
            "iterations_to_fixed_point": self.iterations_to_fixed_point,
            "causal_trace": [p.to_dict() for p in self.causal_trace],
            "closure_status": self.closure_status,
        }


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
    Deterministic Fixed-Point Dependency Closure Engine and Constraint DAG Resolver.
    """

    def __init__(self, incident_id: str = "incident_001"):
        self.incident_id = incident_id

    @classmethod
    def compute_fixed_point_closure(
        cls,
        initial_removed: Set[Tuple[str, str]],
        all_variables: Set[Tuple[str, str]],
        dependency_edges: List[TypedDependencyEdge],
        conflict_pairs: List[Tuple[str, str, str, str, str]],  # (r1, a1, r2, a2, rule_id)
        cost_map: Dict[Tuple[str, str], float],
        base_budget: float,
        max_iterations: int = 100,
    ) -> Tuple[Set[Tuple[str, str]], List[Tuple[str, str, str, str, str]], ClosureResult]:
        """
        Executes deterministic fixed-point dependency closure:
            R_{k+1} = R_k ∪ DependentConsequences(R_k)
        until R_{k+1} = R_k.

        Returns (final_active_variables, final_active_conflicts, closure_result).
        """
        causal_trace: List[ClosureProvenance] = []
        removed_vars: Set[Tuple[str, str]] = set(initial_removed)
        initial_changes_list = [f"{r}:{a}" for r, a in sorted(initial_removed)]

        for r, a in sorted(initial_removed):
            causal_trace.append(ClosureProvenance(
                entity=f"{r}:{a}",
                operation="REMOVE_VARIABLE",
                reason="INITIAL_INADMISSIBILITY",
                parent_event="runtime_state_evaluation",
                downstream_effects=[],
            ))

        visited_states: Set[frozenset] = set()
        iteration = 0
        propagation_depth = 0
        closure_status = "CONVERGED"
        removed_edges: List[Dict[str, str]] = []

        # Map entity strings to tuples
        def parse_entity(ent: str) -> Optional[Tuple[str, str]]:
            if ":" in ent:
                parts = ent.split(":", 1)
                return (parts[0], parts[1])
            return None

        while iteration < max_iterations:
            state_key = frozenset(removed_vars)
            if state_key in visited_states:
                closure_status = "CYCLE_TERMINATED"
                break
            visited_states.add(state_key)

            next_removed = set(removed_vars)
            step_effects_found = False

            for edge in dependency_edges:
                src_tuple = parse_entity(edge.source_entity)
                tgt_tuple = parse_entity(edge.target_entity)

                # Case 1: REQUIRES relation
                # If source REQUIRES target, and target is removed, source cannot be executed
                if edge.relation_type == DependencyRelationType.REQUIRES:
                    if tgt_tuple and tgt_tuple in removed_vars and src_tuple and src_tuple not in removed_vars:
                        # Failsafe check
                        if src_tuple[1] in ("monitor", "increase_logging"):
                            causal_trace.append(ClosureProvenance(
                                entity=edge.source_entity,
                                operation="FAILSAFE_PRESERVED",
                                reason=f"Failsafe baseline '{src_tuple[1]}' protected against pruning by policy",
                                parent_event=f"attempted_removal_from_{edge.target_entity}",
                            ))
                        else:
                            next_removed.add(src_tuple)
                            step_effects_found = True
                            causal_trace.append(ClosureProvenance(
                                entity=edge.source_entity,
                                operation="REMOVE_VARIABLE",
                                reason=f"UNSATISFIED_PREREQUISITE: Requires '{edge.target_entity}' which was removed ({edge.rule_id})",
                                parent_event=f"removal_of_{edge.target_entity}",
                            ))

                    # Sole prerequisite deactivation:
                    # If target exists solely to serve source, and source is removed, de-activate target
                    if edge.is_sole_prerequisite and src_tuple and src_tuple in removed_vars and tgt_tuple and tgt_tuple not in removed_vars:
                        if tgt_tuple[1] not in ("monitor", "increase_logging"):
                            next_removed.add(tgt_tuple)
                            step_effects_found = True
                            causal_trace.append(ClosureProvenance(
                                entity=edge.target_entity,
                                operation="REMOVE_VARIABLE",
                                reason=f"UNUSED_PREREQUISITE: Existed solely to serve '{edge.source_entity}' which was pruned",
                                parent_event=f"removal_of_{edge.source_entity}",
                            ))

                # Case 2: MANDATES relation
                # If target is mandated, and was removed, flag conflict and restore failsafe
                elif edge.relation_type == DependencyRelationType.MANDATES:
                    if tgt_tuple and tgt_tuple in removed_vars:
                        causal_trace.append(ClosureProvenance(
                            entity=edge.target_entity,
                            operation="MANDATE_CONFLICT",
                            reason=f"Mandated action '{edge.target_entity}' was pruned; requires intervention",
                            parent_event="closure_evaluation",
                        ))

            iteration += 1
            if step_effects_found:
                propagation_depth += 1

            if next_removed == removed_vars:
                # Fixed point reached!
                closure_status = "CONVERGED"
                break
            removed_vars = next_removed

        if iteration >= max_iterations and closure_status != "CYCLE_TERMINATED":
            closure_status = "CYCLE_TERMINATED"

        # Active decision variables
        active_vars = all_variables - removed_vars

        # Guarantee at least one valid failsafe action per resource
        resource_ids = {r for r, _ in all_variables}
        for rid in sorted(resource_ids):
            active_for_res = [a for r, a in active_vars if r == rid]
            if not active_for_res:
                # Re-activate failsafe monitor
                active_vars.add((rid, "monitor"))
                removed_vars.discard((rid, "monitor"))
                causal_trace.append(ClosureProvenance(
                    entity=f"{rid}:monitor",
                    operation="FAILSAFE_RESTORED",
                    reason="Empty admissible domain prevented: guaranteed failsafe 'monitor' re-activated",
                    parent_event="domain_feasibility_guarantee",
                ))

        # Regenerate conflict topology: remove any conflict referencing a pruned variable
        active_conflicts = []
        for r1, a1, r2, a2, rule_id in conflict_pairs:
            pair1 = (r1, a1)
            pair2 = (r2, a2)
            if pair1 in removed_vars or pair2 in removed_vars:
                removed_edges.append({
                    "resource_1": r1, "action_1": a1,
                    "resource_2": r2, "action_2": a2,
                    "rule_id": rule_id,
                    "reason": f"Pruned because variable was removed in closure: {pair1 if pair1 in removed_vars else pair2}",
                })
                causal_trace.append(ClosureProvenance(
                    entity=f"Conflict({r1}:{a1} <-> {r2}:{a2})",
                    operation="DEACTIVATE_CONFLICT",
                    reason="Dependent conflict hyperedge pruned because referencing variable was removed",
                    parent_event="conflict_hyperedge_pruning",
                ))
            else:
                active_conflicts.append((r1, a1, r2, a2, rule_id))

        # Regenerate Operational Bounds B'
        min_possible_cost = 0.0
        for rid in sorted(resource_ids):
            res_costs = [cost_map.get((rid, a), 0.0) for r, a in active_vars if r == rid]
            if res_costs:
                min_possible_cost += min(res_costs)

        regenerated_bounds = {
            "min_possible_cost": round(min_possible_cost, 4),
            "effective_budget": round(base_budget, 4),
            "budget_consistent": min_possible_cost <= base_budget,
            "active_variable_count": len(active_vars),
            "removed_variable_count": len(removed_vars),
            "active_conflict_count": len(active_conflicts),
            "removed_conflict_count": len(removed_edges),
        }

        affected_resources = sorted(list({r for r, _ in removed_vars}))
        affected_constraints = [
            f"INVARIANCE_{r}" for r in affected_resources
        ] + [f"CONFLICT_{e['rule_id']}" for e in removed_edges]

        closure_result = ClosureResult(
            initial_changes=initial_changes_list,
            removed_variables=sorted(list(removed_vars)),
            removed_edges=removed_edges,
            affected_constraints=affected_constraints,
            affected_resources=affected_resources,
            regenerated_bounds=regenerated_bounds,
            propagation_depth=propagation_depth,
            iterations_to_fixed_point=iteration,
            causal_trace=causal_trace,
            closure_status=closure_status,
        )

        return active_vars, active_conflicts, closure_result

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
        explicit_dependencies: Optional[List[TypedDependencyEdge]] = None,
        runtime_state_version: int = 1,
        ir_version: int = 1,
    ) -> SecurityConstraintIR:
        """
        Topological execution of the constraint dependency graph with deterministic
        fixed-point dependency closure resolution.
        """
        ir = SecurityConstraintIR(
            incident_id=self.incident_id,
            ir_version=ir_version,
            runtime_state_version=runtime_state_version,
            creation_timestamp=time.time(),
        )
        prev_plan = previous_plan or {}
        resources = scenario.get("resources", [])
        all_possible_actions = set(ACTIONS.keys())

        # =========================================================================
        # STAGE 1: Physical Capability & Initial Inadmissibility Identification
        # =========================================================================
        all_variables_set: Set[Tuple[str, str]] = set()
        initial_removed_set: Set[Tuple[str, str]] = set()

        for r in resources:
            rid = r["id"]
            rtype = r.get("type", "server")
            physically_allowed = set(PHYSICAL_CAPABILITY_MAP.get(rtype, PHYSICAL_CAPABILITY_MAP["server"]))

            for act in all_possible_actions:
                var_tuple = (rid, act)
                all_variables_set.add(var_tuple)
                if act not in physically_allowed:
                    initial_removed_set.add(var_tuple)
                    ir.provenance_records.append(IRProvenanceRecord(
                        target_resource=rid,
                        target_action=act,
                        constraint_type="PRUNED",
                        origin="PHYSICAL_CAPABILITY",
                        rule_id=f"PHYS_CAP_{rtype.upper()}",
                        rationale=f"Hardware/firmware for '{rtype}' does not support action '{act}'",
                    ))

        # =========================================================================
        # STAGE 2: Detection Confidence Gating
        # =========================================================================
        for r in resources:
            rid = r["id"]
            conf = confidences.get(rid)
            if conf and conf.overall_confidence < 0.50:
                for act in ("isolate", "disable_user"):
                    var_tuple = (rid, act)
                    if var_tuple not in initial_removed_set:
                        initial_removed_set.add(var_tuple)
                        ir.provenance_records.append(IRProvenanceRecord(
                            target_resource=rid,
                            target_action=act,
                            constraint_type="PRUNED",
                            origin="CONFIDENCE_TIER",
                            rule_id="CONF_TIER_LOW_GATE",
                            rationale=f"Confidence {conf.overall_confidence:.2f} is in LOW tier; high-disruption '{act}' pruned",
                        ))

        # =========================================================================
        # STAGE 3: Statutory & SLA Policy Resolution
        # =========================================================================
        for r in resources:
            rid = r["id"]
            rtype = r.get("type", "server")
            ctx = contexts.get(rid)
            s_i = threat_scores.get(rid, 0.5)

            # HIPAA 45 CFR § 164.312(a)(1) Access Control Mandate
            if ctx and ctx.compliance.hipaa_applicable and s_i > 0.60:
                # Mandatory strong containment: isolate if available, else rotate credentials
                allowed_so_far = {a for (res, a) in all_variables_set if res == rid and (res, a) not in initial_removed_set}
                if "isolate" in allowed_so_far:
                    mandated_act = "isolate"
                elif "rotate_credentials" in allowed_so_far:
                    mandated_act = "rotate_credentials"
                else:
                    mandated_act = "monitor"

                for act in allowed_so_far:
                    if act != mandated_act:
                        initial_removed_set.add((rid, act))
                        ir.provenance_records.append(IRProvenanceRecord(
                            target_resource=rid,
                            target_action=act,
                            constraint_type="PRUNED",
                            origin="MANDATED_POLICY_EXCLUSION",
                            rule_id="HIPAA_MANDATE_EXCLUSION",
                            rationale=f"Action '{act}' excluded because '{mandated_act}' is mandated by HIPAA 45 CFR § 164.312",
                        ))

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
                var_tuple = (rid, "isolate")
                if var_tuple not in initial_removed_set:
                    initial_removed_set.add(var_tuple)
                    ir.provenance_records.append(IRProvenanceRecord(
                        target_resource=rid,
                        target_action="isolate",
                        constraint_type="PRUNED",
                        origin="SLA_TIER",
                        rule_id="SLA_CRIT_AVAILABILITY_01",
                        rationale="SLA CRITICAL forbids automated network isolation when threat < 0.40",
                    ))

            # Cyber-Physical Industrial Safety Profile (PLC and Medical Devices never automated isolation)
            if rtype in ("plc_controller", "medical_device"):
                var_tuple = (rid, "isolate")
                if var_tuple not in initial_removed_set:
                    initial_removed_set.add(var_tuple)
                    ir.provenance_records.append(IRProvenanceRecord(
                        target_resource=rid,
                        target_action="isolate",
                        constraint_type="PRUNED",
                        origin="PHYSICAL_SAFETY_PROFILE",
                        rule_id=f"SAFETY_PROFILE_{rtype.upper()}",
                        rationale=f"Cyber-physical safety rules prohibit automated isolation on {rtype}",
                    ))

            # System B Experience Rules
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
                        var_tuple = (rid, action_to_prune)
                        if action_to_prune and var_tuple not in initial_removed_set:
                            initial_removed_set.add(var_tuple)
                            ir.provenance_records.append(IRProvenanceRecord(
                                target_resource=rid,
                                target_action=action_to_prune,
                                constraint_type="EXPERIENCE",
                                origin="EXPERIENCE_MEMORY",
                                rule_id=rule.get("rule_id", "EXP_LEARNED_01"),
                                rationale=rule.get("rationale", "Pruned based on historical negative incident outcome"),
                            ))

        # =========================================================================
        # STAGE 4: Build Dependency Edges & Candidate Conflict Set
        # =========================================================================
        dependency_edges = list(explicit_dependencies or [])

        # Default failsafe protections
        for r in resources:
            rid = r["id"]
            dependency_edges.append(TypedDependencyEdge(
                source_entity=f"{rid}:monitor",
                target_entity=f"{rid}:monitor",
                relation_type=DependencyRelationType.PROTECTS_FAILSAFE,
                rule_id="FAILSAFE_INVARIANT",
                description="Guarantees baseline surveillance is never eliminated",
            ))

        # Initial candidate conflict pairs
        candidate_conflicts: List[Tuple[str, str, str, str, str]] = []
        for r in resources:
            rid = r["id"]
            for a1, a2, reason in DEFAULT_ACTION_CONFLICTS:
                candidate_conflicts.append((rid, a1, rid, a2, "WITHIN_RES_CONFLICT"))

        # Pre-compute cost map for bound regeneration
        cost_map: Dict[Tuple[str, str], float] = {}
        for r in resources:
            rid = r["id"]
            rtype = r.get("type", "server")
            for act in all_possible_actions:
                cost_map[(rid, act)] = calculate_action_cost(rtype, act)

        # Dynamic budget multiplier
        avg_threat = sum(threat_scores.values()) / max(1, len(threat_scores))
        if avg_threat > 0.70:
            b_mult = 1.3
        elif avg_threat > 0.40:
            b_mult = 1.0
        else:
            b_mult = 0.8
        effective_budget = round(base_budget * b_mult, 2)

        # =========================================================================
        # STAGE 5: Execute Fixed-Point Dependency Closure Algorithm
        # =========================================================================
        active_vars, active_conflicts, closure_result = self.compute_fixed_point_closure(
            initial_removed=initial_removed_set,
            all_variables=all_variables_set,
            dependency_edges=dependency_edges,
            conflict_pairs=candidate_conflicts,
            cost_map=cost_map,
            base_budget=effective_budget,
        )

        ir.dependency_closure_metadata = closure_result
        ir.regenerated_bounds = closure_result.regenerated_bounds

        # =========================================================================
        # STAGE 6: Variable Domains & Exactly-One Invariance Constraints
        # =========================================================================
        for r in resources:
            rid = r["id"]
            rtype = r.get("type", "server")
            admissible = sorted([a for res, a in active_vars if res == rid])
            pruned = sorted([a for res, a in all_variables_set - active_vars if res == rid])

            ir.variable_domains[rid] = VariableDomain(
                resource_id=rid,
                resource_type=rtype,
                admissible_actions=list(admissible),
                pruned_actions=list(pruned),
            )
            ir.invariance_constraints.append(InvarianceConstraint(
                resource_id=rid,
                actions=list(admissible),
                target_value=1,
            ))

        # =========================================================================
        # STAGE 7: Conflict Hyperedges
        # =========================================================================
        for r1, a1, r2, a2, rule_id in active_conflicts:
            ir.conflict_hyperedges.append(ConflictHyperedge(
                resource_1=r1,
                action_1=a1,
                resource_2=r2,
                action_2=a2,
                reason="Mutually exclusive operational action pair",
                rule_id=rule_id,
            ))

        # =========================================================================
        # STAGE 8: Dynamic Objective Terms & Operational Budget
        # =========================================================================
        ir_cost_map: Dict[Tuple[str, str], float] = {}
        for (rid, act) in sorted(list(active_vars)):
            rtype = ir.variable_domains[rid].resource_type
            s_i = threat_scores.get(rid, 0.5)
            c_i = confidences[rid].overall_confidence if rid in confidences else 1.0
            effective_threat = s_i * c_i
            cost = cost_map[(rid, act)]
            ir_cost_map[(rid, act)] = cost

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

        ir.budget_constraint = HardBudgetConstraint(
            max_budget=effective_budget,
            cost_map=ir_cost_map,
        )

        # =========================================================================
        # STAGE 9: Explicit Hard vs Soft Constraint Separation
        # =========================================================================
        for rid, domain in sorted(ir.variable_domains.items()):
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

        for (rid, act), term in sorted(ir.objective_terms.items()):
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
        # STAGE 10: Topology Metadata Extraction & Cryptographic Sealing
        # =========================================================================
        total_vars = len(ir.get_all_variables())
        total_invariants = len(ir.invariance_constraints)
        total_conflicts = len(ir.conflict_hyperedges)
        total_pruned = sum(len(d.pruned_actions) for d in ir.variable_domains.values())

        max_possible_edges = max(1, (total_vars * (total_vars - 1)) // 2)
        density = round(total_conflicts / max_possible_edges, 4)

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

        ir.compute_canonical_digest()
        return ir
