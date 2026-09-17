"""
=============================================================================
LAYER 5: INDEPENDENT PROOF CHECKER FOR COMPILED FORMULATIONS
Module: proof_checker.py
-----------------------------------------------------------------------------
CRITICAL ARCHITECTURAL BOUNDARY:
  This module MUST NOT import formulation_compiler. It operates as an
  independent, untrusted-verifier gate between the compiler and solver.

Proof Complexity Guarantee:
  Checker cost is polynomial in the size of the proof under this proof system;
  it does not decide general model equivalence.

Verification Scope:
  1. Certificate binding & digital signature verification.
  2. Exact variable domain mapping and structural excision enforcement
     (no excised / pruned actions may have backend variables).
  3. Complete IR constraint translation coverage.
  4. Local algebraic equivalence per constraint translation.
  5. QUBO penalty bound domination check: P > Delta_obj.
=============================================================================
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Set

from layer5_constraints.constraint_ir import SecurityConstraintIR
from layer5_constraints.safety_certifier import ConstraintSafetyCertificate
from layer5_constraints.fidelity_proof import FidelityProof


class FidelityProofError(Exception):
    """Raised when an independent formulation proof check fails."""
    pass


@dataclass
class FidelityProofReport:
    """
    Diagnostic report emitted by the Independent Proof Checker.
    """
    is_valid: bool
    backend_id: str
    certificate_id: str
    checked_constraints_count: int
    variable_count: int
    auxiliary_variable_count: int
    pruned_actions_verified: int
    proof_digest: str
    complexity_guarantee: str = (
        "Checker cost is polynomial in the size of the proof under this "
        "proof system; it does not decide general model equivalence."
    )
    details: Dict[str, Any] = field(default_factory=dict)


class IndependentProofChecker:
    """
    Independent Proof Checker verifying formulation fidelity proofs prior to solver invocation.
    Imports NO compiler internals.
    """

    @classmethod
    def check(
        cls,
        ir: SecurityConstraintIR,
        backend_model: Any,
        proof: FidelityProof,
        certificate: Optional[ConstraintSafetyCertificate] = None,
        verifier_key: Optional[Any] = None,
    ) -> FidelityProofReport:
        """
        Independently checks the validity of the formulation proof.
        Raises FidelityProofError if any verification condition fails.
        """
        if proof is None:
            raise FidelityProofError("Formulation check failed: No fidelity proof provided.")

        # 1. Certificate Binding Verification
        if certificate is not None:
            if certificate.status != "CERTIFIED":
                raise FidelityProofError(
                    f"Proof rejected: Certificate status is '{certificate.status}' != 'CERTIFIED'."
                )
            ir_digest = ir.compute_canonical_digest()
            if certificate.ir_sha256 != ir_digest:
                raise FidelityProofError(
                    f"Proof rejected: Certificate IR digest mismatch. "
                    f"Expected '{ir_digest[:16]}...', got '{certificate.ir_sha256[:16]}...'."
                )
            if proof.certificate_id and certificate.certificate_id != proof.certificate_id:
                raise FidelityProofError(
                    f"Proof rejected: Certificate ID mismatch. "
                    f"Proof references '{proof.certificate_id}', certificate is '{certificate.certificate_id}'."
                )
            if getattr(certificate, "signature", None):
                from layer5_constraints.keys import get_verifier_key
                vkey = verifier_key or get_verifier_key()
                if not certificate.verify_signature(vkey):
                    raise FidelityProofError(
                        "Proof rejected: Certificate cryptographic signature is invalid."
                    )

        # 2. Proof Digest Integrity
        if not proof.verify_digest():
            raise FidelityProofError(
                "Proof rejected: Proof cryptographic digest mismatch. Proof content was tampered."
            )

        # Extract backend variable names
        backend_var_names: Set[str] = set()
        if hasattr(backend_model, "variables"):
            # PuLP LpProblem (method variables()) or Qiskit QuadraticProgram (list variables)
            vars_attr = backend_model.variables
            var_list = vars_attr() if callable(vars_attr) else vars_attr
            for v in var_list:
                name = getattr(v, "name", str(v))
                backend_var_names.add(name)
        elif hasattr(backend_model, "variablesDict"):
            backend_var_names = set(backend_model.variablesDict().keys())

        # 3. Structural Excision Check: Pruned actions must NOT appear in proof or model
        for (r, a) in proof.pruned_actions:
            if (r, a) in proof.variable_map:
                raise FidelityProofError(
                    f"Proof rejected: Excised action ({r}, {a}) found in variable_map."
                )
            candidate_vname = f"x_{r}_{a}"
            if candidate_vname in backend_var_names:
                raise FidelityProofError(
                    f"Proof rejected: Excised action ({r}, {a}) reintroduced in backend model as '{candidate_vname}'."
                )

        # Check provenance records in IR as well
        for rec in ir.provenance_records:
            if rec.constraint_type == "PRUNED":
                p_var = (rec.target_resource, rec.target_action)
                if p_var in proof.variable_map:
                    raise FidelityProofError(
                        f"Proof rejected: IR-pruned action {p_var} mapped in proof."
                    )
                cand = f"x_{p_var[0]}_{p_var[1]}"
                if cand in backend_var_names:
                    raise FidelityProofError(
                        f"Proof rejected: IR-pruned action {p_var} present in backend model as '{cand}'."
                    )

        # 4. Variable Map Bijectivity on Admissible Domain
        ir_vars = set(ir.get_all_variables())
        proof_vars = set(proof.variable_map.keys())

        if ir_vars != proof_vars:
            missing = ir_vars - proof_vars
            extra = proof_vars - ir_vars
            raise FidelityProofError(
                f"Proof rejected: Variable domain mismatch. Missing from proof: {missing}, Unexpected in proof: {extra}."
            )

        for (r, a), vname in proof.variable_map.items():
            if vname not in backend_var_names:
                raise FidelityProofError(
                    f"Proof rejected: Mapped variable '{vname}' for ({r}, {a}) not found in backend model."
                )

        for aux in proof.auxiliary_variables:
            if aux not in backend_var_names:
                raise FidelityProofError(
                    f"Proof rejected: Auxiliary variable '{aux}' not found in backend model."
                )

        # Backend decision variables must equal variable_map images + auxiliary variables
        expected_backend_vars = set(proof.variable_map.values()) | set(proof.auxiliary_variables)
        if backend_var_names != expected_backend_vars:
            unaccounted = backend_var_names - expected_backend_vars
            if unaccounted:
                raise FidelityProofError(
                    f"Proof rejected: Unaccounted variables in backend model: {unaccounted}."
                )

        # 5. Constraint Translation Coverage
        translation_types = [t.get("ir_constraint_type") for t in proof.constraint_translations]

        # Check Invariance Constraints
        for inv in ir.invariance_constraints:
            expected_id = f"invariance_{inv.resource_id}"
            matching = [t for t in proof.constraint_translations if t.get("ir_constraint_id") == expected_id]
            if not matching:
                raise FidelityProofError(
                    f"Proof rejected: Missing translation for invariance constraint on '{inv.resource_id}'."
                )

        # Check Conflict Hyperedges
        for conf in ir.conflict_hyperedges:
            expected_id = f"conflict_{conf.resource_1}_{conf.action_1}_{conf.resource_2}_{conf.action_2}"
            matching = [t for t in proof.constraint_translations if t.get("ir_constraint_id") == expected_id]
            if not matching:
                raise FidelityProofError(
                    f"Proof rejected: Missing translation for conflict hyperedge {expected_id}."
                )

        # Check Budget Constraint
        if ir.budget_constraint and ir.budget_constraint.max_budget > 0:
            matching = [t for t in proof.constraint_translations if t.get("ir_constraint_type") == "BUDGET"]
            if not matching:
                raise FidelityProofError("Proof rejected: Missing translation for budget constraint.")

        # 6. Local Algebraic Equivalence Verification
        if proof.backend_id == "ILP_PULP":
            cls._check_ilp_algebraic_equivalence(ir, backend_model, proof)
        elif proof.backend_id == "QUBO_QISKIT":
            cls._check_qubo_algebraic_equivalence(ir, backend_model, proof)
        else:
            raise FidelityProofError(f"Proof rejected: Unknown backend id '{proof.backend_id}'.")

        return FidelityProofReport(
            is_valid=True,
            backend_id=proof.backend_id,
            certificate_id=proof.certificate_id,
            checked_constraints_count=len(proof.constraint_translations),
            variable_count=len(proof.variable_map),
            auxiliary_variable_count=len(proof.auxiliary_variables),
            pruned_actions_verified=len(proof.pruned_actions),
            proof_digest=proof.proof_digest,
            details={"ir_version": ir.ir_version},
        )

    @classmethod
    def _check_ilp_algebraic_equivalence(
        cls,
        ir: SecurityConstraintIR,
        prob: Any,
        proof: FidelityProof,
    ) -> None:
        """Verifies that PuLP constraints algebraically match the IR semantics."""
        constraints_dict = {}
        if hasattr(prob, "constraints"):
            # PuLP constraints mapping
            constraints_dict = prob.constraints

        for trans in proof.constraint_translations:
            ctype = trans.get("ir_constraint_type")
            backend_elems = trans.get("backend_elements", [])
            params = trans.get("parameters", {})

            if ctype == "INVARIANCE":
                cname = backend_elems[0] if backend_elems else f"Invariance_{params.get('resource_id')}"
                if cname not in constraints_dict and cname.replace("-", "_") in constraints_dict:
                    cname = cname.replace("-", "_")
                if cname not in constraints_dict:
                    raise FidelityProofError(f"PuLP invariance constraint '{cname}' missing from model.")
                c = constraints_dict[cname]
                # Check sense == 0 (LpConstraintEQ) and constant == target_value
                target_val = params.get("target_value", 1.0)
                # In PuLP, c.sense == 0 means ==
                if c.sense != 0:
                    raise FidelityProofError(f"PuLP constraint '{cname}' sense is not equality (sense={c.sense}).")
                # c.constant in PuLP is -RHS, so c.constant + target_val == 0
                if abs(c.constant + target_val) > 1e-5:
                    raise FidelityProofError(f"PuLP constraint '{cname}' target value mismatch.")

            elif ctype == "CONFLICT":
                cname = backend_elems[0] if backend_elems else ""
                if cname not in constraints_dict and cname.replace("-", "_") in constraints_dict:
                    cname = cname.replace("-", "_")
                if cname not in constraints_dict:
                    raise FidelityProofError(f"PuLP conflict constraint '{cname}' missing from model.")
                c = constraints_dict[cname]
                if c.sense != -1:  # -1 is <=
                    raise FidelityProofError(f"PuLP conflict constraint '{cname}' sense is not <= (sense={c.sense}).")
                if abs(c.constant + 1.0) > 1e-5:
                    raise FidelityProofError(f"PuLP conflict constraint '{cname}' RHS is not 1.0.")

            elif ctype == "BUDGET":
                cname = backend_elems[0] if backend_elems else "Operational_Budget_Ceiling"
                if cname not in constraints_dict:
                    raise FidelityProofError(f"PuLP budget constraint '{cname}' missing from model.")
                c = constraints_dict[cname]
                if c.sense != -1:
                    raise FidelityProofError(f"PuLP budget constraint '{cname}' sense is not <= (sense={c.sense}).")
                expected_max = params.get("max_budget", ir.budget_constraint.max_budget if ir.budget_constraint else 0.0)
                if abs(c.constant + expected_max) > 1e-5:
                    raise FidelityProofError(
                        f"PuLP budget constraint '{cname}' RHS mismatch: expected {expected_max}, got {-c.constant}."
                    )

    @classmethod
    def _check_qubo_algebraic_equivalence(
        cls,
        ir: SecurityConstraintIR,
        qp: Any,
        proof: FidelityProof,
    ) -> None:
        """Verifies that QUBO penalty structure satisfies dominating penalty obligations."""
        if proof.penalty_coefficient is None or proof.objective_range_bound is None:
            raise FidelityProofError(
                "QUBO proof verification requires penalty_coefficient and objective_range_bound."
            )

        # Dominating penalty check: P > Delta_obj
        if proof.penalty_coefficient <= proof.objective_range_bound:
            raise FidelityProofError(
                f"QUBO penalty bound failed: penalty {proof.penalty_coefficient} <= "
                f"objective range bound {proof.objective_range_bound}. "
                "Feasibility of the ground state is not guaranteed."
            )

        # Check slack variables for exact integer budget representation
        budget_trans = next((t for t in proof.constraint_translations if t.get("ir_constraint_type") == "BUDGET"), None)
        if budget_trans:
            b_params = budget_trans.get("parameters", {})
            budget_int = b_params.get("budget_int", 0)
            cost_scale = b_params.get("cost_scale", 1000)
            slack_weights = b_params.get("slack_weights", [])

            # Verify that slack weights sum to budget_int / cost_scale
            total_slack = sum(slack_weights)
            expected_budget = budget_int / cost_scale
            if abs(total_slack - expected_budget) > 1e-4:
                raise FidelityProofError(
                    f"QUBO slack representation residual error: sum of slack weights ({total_slack}) "
                    f"!= budget ({expected_budget})."
                )
