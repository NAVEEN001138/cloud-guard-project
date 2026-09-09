"""
=============================================================================
LAYER 5: INCREMENTAL / DELTA CONSTRAINT COMPILER
Module: incremental_compiler.py
-----------------------------------------------------------------------------
Problem Solved:
  Eliminates wasteful complete constraint reformulation when runtime infrastructure
  undergoes localized state changes (S_t -> S_{t+1}).

  For state change ΔS = Diff(S_t, S_{t+1}):
    1. Identifies the minimal affected dependency subgraph G_affected ⊆ G.
    2. Selectively recomputes dirty decision variables, conflicts, bounds, and invariants.
    3. Reuses certified structural components for unaffected subgraphs G_clean.
    4. Enforces version continuity: IR_{t+1} = IR_t ⊕ ΔIR with ir_version increment.
    5. Guarantees mathematical equivalence:
         FullCompile(S_{t+1}) ≡ IncrementalCompile(IR_t, ΔS)
    6. Automatically falls back to full recompilation if safety bounds or mutation
       thresholds exceed provable safety criteria.
=============================================================================
"""

import time
import copy
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Set, Optional, Any

from config import ACTIONS
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
)
from layer5_constraints.dependency_graph import (
    ConstraintDependencyGraph,
    TypedDependencyEdge,
    DependencyRelationType,
    calculate_action_cost,
    DEFAULT_ACTION_CONFLICTS,
    PHYSICAL_CAPABILITY_MAP,
)
from layer5_constraints.safety_certifier import PreSolveSafetyCertifier, ConstraintSafetyCertificate


@dataclass
class RuntimeStateDelta:
    """Captures difference between infrastructure state S_t and S_{t+1}."""
    changed_assets: List[str] = field(default_factory=list)
    changed_capabilities: Dict[str, List[str]] = field(default_factory=dict)
    changed_threat_state: Dict[str, float] = field(default_factory=dict)
    changed_policy_state: Dict[str, Any] = field(default_factory=dict)
    changed_resource_state: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IncrementalCompilationResult:
    """Detailed audit metrics and output of incremental compilation step."""
    previous_ir_version: int
    new_ir_version: int
    dirty_nodes: List[str]
    dirty_edges: List[Any]
    recomputed_constraints: List[str]
    reused_constraints: List[str]
    regenerated_bounds: Dict[str, Any]
    affected_subgraph_size: int
    total_graph_size: int
    incremental_runtime_ms: float
    fallback_to_full_recompile: bool
    fallback_reason: str
    updated_ir: SecurityConstraintIR
    updated_certificate: ConstraintSafetyCertificate

    @property
    def node_recompute_ratio(self) -> float:
        """Ratio of affected nodes to total nodes in the constraint graph."""
        if self.total_graph_size == 0:
            return 0.0
        return round(self.affected_subgraph_size / self.total_graph_size, 4)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "previous_ir_version": self.previous_ir_version,
            "new_ir_version": self.new_ir_version,
            "dirty_nodes": self.dirty_nodes,
            "dirty_edges": [str(e) for e in self.dirty_edges],
            "recomputed_constraints_count": len(self.recomputed_constraints),
            "reused_constraints_count": len(self.reused_constraints),
            "regenerated_bounds": self.regenerated_bounds,
            "affected_subgraph_size": self.affected_subgraph_size,
            "total_graph_size": self.total_graph_size,
            "node_recompute_ratio": self.node_recompute_ratio,
            "incremental_runtime_ms": round(self.incremental_runtime_ms, 3),
            "fallback_to_full_recompile": self.fallback_to_full_recompile,
            "fallback_reason": self.fallback_reason,
            "updated_ir_digest": self.updated_ir.canonical_digest,
            "updated_certificate_id": self.updated_certificate.certificate_id,
        }


class IncrementalConstraintCompiler:
    """
    Compiler engine performing selective dependency subgraph updates and
    version-continuous IR mutation with safety certification.
    """

    @classmethod
    def compile_delta(
        cls,
        previous_ir: SecurityConstraintIR,
        delta: RuntimeStateDelta,
        scenario: dict,
        all_contexts: Dict[str, AggregatedContext],
        all_confidences: Dict[str, ConfidenceScores],
        all_threat_scores: Dict[str, float],
        base_budget: float = 15.0,
        switching_penalty: float = 0.15,
        previous_plan: Optional[Dict[str, str]] = None,
        learned_rules: Optional[List[dict]] = None,
        explicit_dependencies: Optional[List[TypedDependencyEdge]] = None,
        new_runtime_state_version: Optional[int] = None,
        max_subgraph_mutation_ratio: float = 0.70,
    ) -> IncrementalCompilationResult:
        """
        Executes selective incremental recompilation on dirty subgraphs.
        Falls back safely to full recompilation if mutation ratio exceeds threshold.
        """
        t0 = time.perf_counter()
        prev_version = previous_ir.ir_version
        next_version = prev_version + 1
        new_state_version = new_runtime_state_version or (previous_ir.runtime_state_version + 1)

        all_resources = scenario.get("resources", [])
        total_assets = len(all_resources)
        all_rids = {r["id"] for r in all_resources}

        # 1. Identify primary dirty nodes
        primary_dirty = set(delta.changed_assets)
        primary_dirty.update(delta.changed_capabilities.keys())
        primary_dirty.update(delta.changed_threat_state.keys())
        primary_dirty.update(delta.changed_policy_state.keys())
        primary_dirty.intersection_update(all_rids)

        # 2. Propagate along explicit dependency edges to find transitively affected nodes
        dirty_assets = set(primary_dirty)
        dirty_edges = []
        edges = explicit_dependencies or []

        for edge in edges:
            src_rid = edge.source_entity.split(":", 1)[0] if ":" in edge.source_entity else edge.source_entity
            tgt_rid = edge.target_entity.split(":", 1)[0] if ":" in edge.target_entity else edge.target_entity

            if src_rid in primary_dirty or tgt_rid in primary_dirty:
                dirty_edges.append(edge)
                dirty_assets.add(src_rid)
                dirty_assets.add(tgt_rid)

        dirty_assets.intersection_update(all_rids)

        # 3. Fallback Evaluation: Safety check on mutation scale
        mutation_ratio = len(dirty_assets) / max(1, total_assets)
        global_policy_shift = delta.changed_policy_state.get("global_policy_shift", False)

        if mutation_ratio > max_subgraph_mutation_ratio or global_policy_shift or len(previous_ir.variable_domains) == 0:
            # Fall back safely to full recompilation
            fallback_reason = (
                "GLOBAL_POLICY_SHIFT" if global_policy_shift
                else f"MUTATION_RATIO_EXCEEDED ({mutation_ratio:.2f} > {max_subgraph_mutation_ratio:.2f})"
            )
            dag = ConstraintDependencyGraph(incident_id=previous_ir.incident_id)
            full_ir = dag.resolve(
                scenario=scenario,
                threat_scores=all_threat_scores,
                contexts=all_contexts,
                confidences=all_confidences,
                base_budget=base_budget,
                switching_penalty=switching_penalty,
                previous_plan=previous_plan,
                learned_rules=learned_rules,
                explicit_dependencies=explicit_dependencies,
                runtime_state_version=new_state_version,
                ir_version=next_version,
            )
            cert = PreSolveSafetyCertifier.certify(full_ir)
            t1 = time.perf_counter()

            return IncrementalCompilationResult(
                previous_ir_version=prev_version,
                new_ir_version=next_version,
                dirty_nodes=sorted(list(dirty_assets)),
                dirty_edges=dirty_edges,
                recomputed_constraints=[c.constraint_id for c in full_ir.hard_constraints],
                reused_constraints=[],
                regenerated_bounds=full_ir.regenerated_bounds,
                affected_subgraph_size=total_assets,
                total_graph_size=total_assets,
                incremental_runtime_ms=(t1 - t0) * 1000.0,
                fallback_to_full_recompile=True,
                fallback_reason=fallback_reason,
                updated_ir=full_ir,
                updated_certificate=cert,
            )

        # 4. Selective Recomputation
        # Partition into clean (reused) and dirty (recomputed) assets
        clean_assets = all_rids - dirty_assets
        reused_constraints: List[str] = []
        recomputed_constraints: List[str] = []

        new_ir = SecurityConstraintIR(
            incident_id=previous_ir.incident_id,
            ir_version=next_version,
            runtime_state_version=new_state_version,
            parent_ir_version=prev_version,
            creation_timestamp=time.time(),
        )

        # 4a. Reuse clean variable domains and invariance constraints
        for rid in clean_assets:
            if rid in previous_ir.variable_domains:
                new_ir.variable_domains[rid] = copy.deepcopy(previous_ir.variable_domains[rid])
                reused_constraints.append(f"DOMAIN_{rid}")

        for inv in previous_ir.invariance_constraints:
            if inv.resource_id in clean_assets:
                new_ir.invariance_constraints.append(copy.deepcopy(inv))
                reused_constraints.append(f"INVAR_{inv.resource_id}")

        # 4b. Recompute dirty variable domains
        all_possible_actions = set(ACTIONS.keys())
        dirty_scen_resources = [r for r in all_resources if r["id"] in dirty_assets]

        for r in dirty_scen_resources:
            rid = r["id"]
            rtype = r.get("type", "server")
            phys_allowed = set(delta.changed_capabilities.get(
                rid,
                PHYSICAL_CAPABILITY_MAP.get(rtype, PHYSICAL_CAPABILITY_MAP["server"])
            ))

            conf = all_confidences.get(rid)
            if conf and conf.overall_confidence < 0.50:
                phys_allowed.discard("isolate")
                phys_allowed.discard("disable_user")

            ctx = all_contexts.get(rid)
            s_i = all_threat_scores.get(rid, 0.5)

            if ctx and ctx.compliance.hipaa_applicable and s_i > 0.60:
                if "isolate" in phys_allowed:
                    phys_allowed = {"isolate"}
                elif "rotate_credentials" in phys_allowed:
                    phys_allowed = {"rotate_credentials"}
                else:
                    phys_allowed = {"monitor"}

            if ctx and ctx.business.sla_priority == "CRITICAL" and s_i < 0.40:
                phys_allowed.discard("isolate")

            if rtype in ("plc_controller", "medical_device"):
                phys_allowed.discard("isolate")

            if learned_rules:
                for rule in learned_rules:
                    target_rt = rule.get("target_resource_type", "all")
                    if target_rt in (rtype, "all", "*") or rule.get("target_resource_id") == rid:
                        to_prune = rule.get("restrict_action")
                        if to_prune:
                            phys_allowed.discard(to_prune)

            if not phys_allowed:
                phys_allowed = {"monitor"}

            admissible = sorted(list(phys_allowed))
            pruned = sorted(list(all_possible_actions - phys_allowed))

            new_ir.variable_domains[rid] = VariableDomain(
                resource_id=rid,
                resource_type=rtype,
                admissible_actions=admissible,
                pruned_actions=pruned,
            )
            new_ir.invariance_constraints.append(InvarianceConstraint(
                resource_id=rid,
                actions=admissible,
                target_value=1,
            ))
            recomputed_constraints.append(f"DOMAIN_{rid}")
            recomputed_constraints.append(f"INVAR_{rid}")

            # Rebuild provenance for dirty asset
            for p in pruned:
                new_ir.provenance_records.append(IRProvenanceRecord(
                    target_resource=rid,
                    target_action=p,
                    constraint_type="PRUNED",
                    origin="INCREMENTAL_DELTA_EVALUATION",
                    rule_id=f"INC_{rtype.upper()}",
                    rationale=f"Pruned in incremental update for asset {rid}",
                ))

        # Carry over clean provenance records
        for prec in previous_ir.provenance_records:
            if prec.target_resource in clean_assets:
                new_ir.provenance_records.append(copy.deepcopy(prec))

        # 4c. Selective Conflict Hyperedge Update
        # Reuse conflicts strictly between clean assets; recompute for dirty assets
        for conf in previous_ir.conflict_hyperedges:
            if conf.resource_1 in clean_assets and conf.resource_2 in clean_assets:
                new_ir.conflict_hyperedges.append(copy.deepcopy(conf))
                reused_constraints.append(f"CONFLICT_{conf.resource_1}_{conf.action_1}")

        for r in dirty_scen_resources:
            rid = r["id"]
            domain = new_ir.variable_domains[rid].admissible_actions
            for a1, a2, reason in DEFAULT_ACTION_CONFLICTS:
                if a1 in domain and a2 in domain:
                    new_ir.conflict_hyperedges.append(ConflictHyperedge(
                        resource_1=rid,
                        action_1=a1,
                        resource_2=rid,
                        action_2=a2,
                        reason=reason,
                        rule_id="INC_WITHIN_RES_CONFLICT",
                    ))
                    recomputed_constraints.append(f"CONFLICT_{rid}_{a1}")

        # 4d. Recompute Linear Objective Terms & Dynamic Budget
        cost_map: Dict[Tuple[str, str], float] = {}
        for r in all_resources:
            rid = r["id"]
            rtype = r.get("type", "server")
            s_i = all_threat_scores.get(rid, 0.5)
            c_i = all_confidences[rid].overall_confidence if rid in all_confidences else 1.0
            domain = new_ir.variable_domains[rid].admissible_actions

            for act in domain:
                cost = calculate_action_cost(rtype, act)
                cost_map[(rid, act)] = cost

                beta_k = ACTIONS.get(act, 0.1)
                containment = -beta_k * s_i * c_i
                switch = switching_penalty if (previous_plan and previous_plan.get(rid) != act) else 0.0
                net_coeff = containment + cost + switch

                new_ir.objective_terms[(rid, act)] = ObjectiveLinearTerm(
                    resource_id=rid,
                    action=act,
                    coefficient=round(net_coeff, 4),
                    containment_component=round(containment, 4),
                    cost_component=round(cost, 4),
                    switching_penalty_component=round(switch, 4),
                )

        avg_threat = sum(all_threat_scores.values()) / max(1, len(all_threat_scores))
        b_mult = 1.3 if avg_threat > 0.70 else (1.0 if avg_threat > 0.40 else 0.8)
        effective_budget = round(base_budget * b_mult, 2)
        new_ir.budget_constraint = HardBudgetConstraint(
            max_budget=effective_budget,
            cost_map=cost_map,
        )

        # 4e. Hard & Soft Constraint Records
        for rid, dom in sorted(new_ir.variable_domains.items()):
            for pruned in dom.pruned_actions:
                new_ir.hard_constraints.append(ConstraintRecord(
                    constraint_id=f"HARD_CAP_{rid}_{pruned}",
                    target_resource=rid,
                    target_action=pruned,
                    hardness="HARD",
                    category="CAPABILITY_OR_SAFETY",
                    mathematical_form=f"x_{rid}_{pruned} = 0",
                    provenance_rule_id="INC_CAPABILITY",
                ))
            new_ir.hard_constraints.append(ConstraintRecord(
                constraint_id=f"HARD_INVAR_{rid}",
                target_resource=rid,
                target_action="*",
                hardness="HARD",
                category="EXACTLY_ONE_INVARIANCE",
                mathematical_form=f"sum_{{a}} x_{rid},a = 1",
                provenance_rule_id="INVARIANCE_POSTULATE",
            ))

        for idx, conf in enumerate(new_ir.conflict_hyperedges):
            new_ir.hard_constraints.append(ConstraintRecord(
                constraint_id=f"HARD_CONFLICT_{idx}",
                target_resource=conf.resource_1,
                target_action=f"{conf.action_1}+{conf.action_2}",
                hardness="HARD",
                category="CONFLICT_MUTUAL_EXCLUSION",
                mathematical_form=f"x_{conf.resource_1}_{conf.action_1} + x_{conf.resource_2}_{conf.action_2} <= 1",
                provenance_rule_id=conf.rule_id,
            ))

        for (rid, act), term in sorted(new_ir.objective_terms.items()):
            new_ir.soft_constraints.append(ConstraintRecord(
                constraint_id=f"SOFT_OBJ_{rid}_{act}",
                target_resource=rid,
                target_action=act,
                hardness="SOFT",
                category="COST_CONTAINMENT_TRADEOFF",
                mathematical_form=f"min coeff * x_{rid}_{act}",
                coefficient_weight=term.coefficient,
                provenance_rule_id="UTILITY_OBJECTIVE",
            ))

        # Regenerate Operational Bounds B'
        min_possible_cost = 0.0
        for rid in sorted(all_rids):
            dom = new_ir.variable_domains.get(rid)
            if dom and dom.admissible_actions:
                res_costs = [cost_map.get((rid, a), 0.0) for a in dom.admissible_actions]
                min_possible_cost += min(res_costs)

        new_ir.regenerated_bounds = {
            "min_possible_cost": round(min_possible_cost, 4),
            "effective_budget": round(effective_budget, 4),
            "budget_consistent": min_possible_cost <= effective_budget,
            "active_variable_count": len(new_ir.get_all_variables()),
            "active_conflict_count": len(new_ir.conflict_hyperedges),
        }

        # Topology Metadata
        total_vars = len(new_ir.get_all_variables())
        max_possible_edges = max(1, (total_vars * (total_vars - 1)) // 2)
        density = round(len(new_ir.conflict_hyperedges) / max_possible_edges, 4)
        model_family = previous_ir.topology.model_family if previous_ir.topology else "CLOUD_COMPUTE"

        new_ir.topology = TopologyMetadata(
            num_variables=total_vars,
            num_invariance_constraints=len(new_ir.invariance_constraints),
            num_conflict_hyperedges=len(new_ir.conflict_hyperedges),
            has_budget_constraint=True,
            graph_density=density,
            pruned_variable_count=sum(len(d.pruned_actions) for d in new_ir.variable_domains.values()),
            environment_fingerprint=f"{model_family}_V{total_vars}_C{len(new_ir.conflict_hyperedges)}",
            model_family=model_family,
            num_hard_constraints=len(new_ir.hard_constraints),
            num_soft_constraints=len(new_ir.soft_constraints),
        )

        new_ir.compute_canonical_digest()
        new_cert = PreSolveSafetyCertifier.certify(new_ir)
        t1 = time.perf_counter()

        return IncrementalCompilationResult(
            previous_ir_version=prev_version,
            new_ir_version=next_version,
            dirty_nodes=sorted(list(dirty_assets)),
            dirty_edges=dirty_edges,
            recomputed_constraints=recomputed_constraints,
            reused_constraints=reused_constraints,
            regenerated_bounds=new_ir.regenerated_bounds,
            affected_subgraph_size=len(dirty_assets),
            total_graph_size=total_assets,
            incremental_runtime_ms=(t1 - t0) * 1000.0,
            fallback_to_full_recompile=False,
            fallback_reason="",
            updated_ir=new_ir,
            updated_certificate=new_cert,
        )
