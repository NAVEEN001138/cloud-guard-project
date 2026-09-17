"""
=============================================================================
LAYER 5: PROOF-CARRYING SECURITY COMPILATION & FIDELITY PROOF
Module: fidelity_proof.py
-----------------------------------------------------------------------------
Proof Obligation:
    x in F(IR) <==> exists z : (x, z) in F(M_b)
where x ranges over the certified response variables and z over auxiliary
variables (e.g., integer-scaled binary slack bits in QUBO).

For QUBO:
    F(M_QUBO) is the set of assignments with zero penalty energy.
    (i)  Each hard IR constraint maps to a penalty term that is zero iff
         the constraint holds (exact integer slack encoding for the budget).
    (ii) The penalty coefficient P strictly exceeds the maximum objective
         range over all assignments (P > Delta_obj), ensuring no zero-penalty-
         violating assignment can be a global minimiser.
=============================================================================
"""

import json
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any


@dataclass
class ConstraintTranslation:
    """
    Mapping from a single IR constraint c_i to backend constraints/terms.
    """
    ir_constraint_type: str  # INVARIANCE | CONFLICT | BUDGET | MANDATE
    ir_constraint_id: str
    backend_elements: List[str]  # Constraint names (ILP) or variable pairs/terms (QUBO)
    parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ir_constraint_type": self.ir_constraint_type,
            "ir_constraint_id": self.ir_constraint_id,
            "backend_elements": sorted(self.backend_elements),
            "parameters": self.parameters,
        }


@dataclass
class FidelityProof:
    """
    Carries the constructive mapping and algebraic proof obligations
    attesting that backend model M_b faithfully preserves F(IR).
    """
    backend_id: str  # "ILP_PULP" | "QUBO_QISKIT"
    certificate_id: str
    variable_map: Dict[Tuple[str, str], str]  # (resource_id, action) -> backend_var_name
    auxiliary_variables: List[str] = field(default_factory=list)  # e.g., ["slack_0", "slack_1"]
    constraint_translations: List[Dict[str, Any]] = field(default_factory=list)
    penalty_coefficient: Optional[float] = None  # Dominating penalty P for QUBO
    objective_range_bound: Optional[float] = None  # Delta_obj bound for QUBO
    pruned_actions: List[Tuple[str, str]] = field(default_factory=list)
    proof_digest: str = ""

    def __post_init__(self):
        if not self.proof_digest:
            self.proof_digest = self.compute_digest()

    def compute_digest(self) -> str:
        """Computes canonical cryptographic digest over proof contents."""
        # Convert tuple keys in variable_map to sorted string representation
        sorted_vmap = [
            f"{r}:{a}->{self.variable_map[(r, a)]}"
            for (r, a) in sorted(self.variable_map.keys())
        ]
        sorted_pruned = [f"{r}:{a}" for (r, a) in sorted(self.pruned_actions)]
        payload = {
            "backend_id": self.backend_id,
            "certificate_id": self.certificate_id,
            "variable_map": sorted_vmap,
            "auxiliary_variables": sorted(self.auxiliary_variables),
            "constraint_translations": self.constraint_translations,
            "penalty_coefficient": self.penalty_coefficient,
            "objective_range_bound": self.objective_range_bound,
            "pruned_actions": sorted_pruned,
        }
        canon = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(canon.encode("utf-8")).hexdigest()

    def verify_digest(self) -> bool:
        return self.compute_digest() == self.proof_digest
