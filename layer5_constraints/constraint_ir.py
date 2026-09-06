"""
=============================================================================
LAYER 5: SECURITY CONSTRAINT INTERMEDIATE REPRESENTATION (SC-IR)
Module: constraint_ir.py
-----------------------------------------------------------------------------
Problem Solved:
  Transforms heterogeneous security runtime state (threat probabilities,
  C-I-A profiles, physical capabilities, statutory policies, confidence scores)
  into a solver-independent, canonical intermediate representation (IR).

  This IR serves as the formal boundary between security semantics and
  computational optimization solvers (QUBO, ILP, CP-SAT). It enables:
    1. Structural model-topology adaptation (variable spaces and constraint
       graphs change per incident environment).
    2. Solver-independent compilation (compile_to_qubo, compile_to_ilp).
    3. Pre-solve formal safety verification before solver invocation.
    4. Cryptographically verifiable audit trails with SHA-256 state hashing.
=============================================================================
"""

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Tuple, Set, Optional, Any


@dataclass
class VariableDomain:
    """Represents the admissible binary decision variables for an asset."""
    resource_id: str
    resource_type: str
    admissible_actions: List[str]
    pruned_actions: List[str] = field(default_factory=list)


@dataclass
class InvarianceConstraint:
    """Enforces that exactly one action must be selected for a resource: sum(x_{i,a}) = 1."""
    resource_id: str
    actions: List[str]
    target_value: int = 1


@dataclass
class ConflictHyperedge:
    """
    Enforces mutually exclusive actions within or across resources:
    x_{r1, a1} + x_{r2, a2} <= 1
    """
    resource_1: str
    action_1: str
    resource_2: str
    action_2: str
    reason: str
    rule_id: str


@dataclass
class HardBudgetConstraint:
    """Enforces that total execution cost cannot exceed the synthesized budget ceiling."""
    max_budget: float
    cost_map: Dict[Tuple[str, str], float]  # (resource_id, action) -> cost


@dataclass
class ObjectiveLinearTerm:
    """Pre-computed linear coefficient for a decision variable in the objective function."""
    resource_id: str
    action: str
    coefficient: float
    containment_component: float
    cost_component: float
    switching_penalty_component: float


@dataclass
class IRProvenanceRecord:
    """Audit provenance linking an IR element to legal statutes or physical limits."""
    target_resource: str
    target_action: str
    constraint_type: str  # "PRUNED", "MANDATED", "CONFLICT", "BUDGET", "EXPERIENCE"
    origin: str           # "PHYSICAL_CAPABILITY", "HIPAA_45_CFR_164", "SLA_TIER", "EXPERIENCE_MEMORY"
    rule_id: str
    rationale: str


class ConstraintHardness:
    HARD = "HARD"  # Mathematical Invariant: Cannot be relaxed or traded off
    SOFT = "SOFT"  # Objective Term: Evaluated in trade-off / penalty space


@dataclass
class ConstraintRecord:
    """Explicit declaration of individual constraints with hard/soft classification."""
    constraint_id: str
    target_resource: str
    target_action: str
    hardness: str  # "HARD" or "SOFT"
    category: str  # "CAPABILITY", "STATUTORY_POLICY", "SAFETY_INVARIANT", "CONFLICT", "COST_PREFERENCE", "DECISION_STABILITY"
    mathematical_form: str
    provenance_rule_id: str = ""
    coefficient_weight: float = 0.0


@dataclass
class TopologyMetadata:
    """Metrics capturing the structural shape of the optimization problem."""
    num_variables: int
    num_invariance_constraints: int
    num_conflict_hyperedges: int
    has_budget_constraint: bool
    graph_density: float
    pruned_variable_count: int
    environment_fingerprint: str
    model_family: str  # e.g. "SCADA_HARD_RT", "HEALTHCARE_HIPAA", "ENTERPRISE_API", "IDENTITY_IAM"
    num_hard_constraints: int = 0
    num_soft_constraints: int = 0


@dataclass
class SecurityConstraintIR:
    """
    Solver-independent canonical Intermediate Representation of executable
    security decision constraints with explicit Hard vs Soft constraint partitioning.
    """
    incident_id: str
    variable_domains: Dict[str, VariableDomain] = field(default_factory=dict)
    invariance_constraints: List[InvarianceConstraint] = field(default_factory=list)
    conflict_hyperedges: List[ConflictHyperedge] = field(default_factory=list)
    budget_constraint: Optional[HardBudgetConstraint] = None
    objective_terms: Dict[Tuple[str, str], ObjectiveLinearTerm] = field(default_factory=dict)
    provenance_records: List[IRProvenanceRecord] = field(default_factory=list)
    hard_constraints: List[ConstraintRecord] = field(default_factory=list)
    soft_constraints: List[ConstraintRecord] = field(default_factory=list)
    topology: Optional[TopologyMetadata] = None
    sha256_hash: str = ""

    def compute_sha256(self) -> str:
        """Computes a deterministic SHA-256 fingerprint of the constraint specification."""
        summary = {
            "incident_id": self.incident_id,
            "domains": {k: v.admissible_actions for k, v in sorted(self.variable_domains.items())},
            "conflicts": [
                (c.resource_1, c.action_1, c.resource_2, c.action_2, c.rule_id)
                for c in sorted(self.conflict_hyperedges, key=lambda x: (x.resource_1, x.action_1, x.resource_2, x.action_2))
            ],
            "max_budget": self.budget_constraint.max_budget if self.budget_constraint else None,
            "objective_keys": sorted([f"{r}:{a}:{round(term.coefficient, 4)}" for (r, a), term in self.objective_terms.items()]),
        }
        serialized = json.dumps(summary, sort_keys=True)
        self.sha256_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return self.sha256_hash

    def get_all_variables(self) -> List[Tuple[str, str]]:
        """Returns list of all active (resource_id, action) tuples."""
        vars_list = []
        for rid, domain in sorted(self.variable_domains.items()):
            for act in domain.admissible_actions:
                vars_list.append((rid, act))
        return vars_list

    def filter_to_resources(self, resource_ids: Set[str]) -> "SecurityConstraintIR":
        """Creates a slice of the IR containing only the specified resources."""
        sub_ir = SecurityConstraintIR(incident_id=f"{self.incident_id}_sub")
        sub_ir.variable_domains = {rid: dom for rid, dom in self.variable_domains.items() if rid in resource_ids}
        sub_ir.invariance_constraints = [inv for inv in self.invariance_constraints if inv.resource_id in resource_ids]
        sub_ir.conflict_hyperedges = [
            conf for conf in self.conflict_hyperedges
            if conf.resource_1 in resource_ids and conf.resource_2 in resource_ids
        ]
        sub_ir.objective_terms = {
            (rid, act): term for (rid, act), term in self.objective_terms.items() if rid in resource_ids
        }
        if self.budget_constraint:
            sub_cost_map = {(rid, act): c for (rid, act), c in self.budget_constraint.cost_map.items() if rid in resource_ids}
            sub_ir.budget_constraint = HardBudgetConstraint(max_budget=self.budget_constraint.max_budget, cost_map=sub_cost_map)
        sub_ir.provenance_records = [rec for rec in self.provenance_records if rec.target_resource in resource_ids]
        sub_ir.hard_constraints = [c for c in self.hard_constraints if c.target_resource in resource_ids]
        sub_ir.soft_constraints = [c for c in self.soft_constraints if c.target_resource in resource_ids]
        sub_ir.compute_sha256()
        return sub_ir

    def to_dict(self) -> Dict[str, Any]:
        """Converts IR to dictionary representation."""
        return {
            "incident_id": self.incident_id,
            "sha256_hash": self.sha256_hash or self.compute_sha256(),
            "variable_count": len(self.get_all_variables()),
            "conflict_count": len(self.conflict_hyperedges),
            "topology": asdict(self.topology) if self.topology else None,
            "provenance_count": len(self.provenance_records),
        }

