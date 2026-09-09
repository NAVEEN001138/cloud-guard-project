"""
=============================================================================
LAYER 5: FORMULATION COMPILER & CERTIFICATE-BOUND INTEGRITY GATE
Module: formulation_compiler.py
-----------------------------------------------------------------------------
Problem Solved:
  Translates the solver-independent SecurityConstraintIR into target
  mathematical formulations under a strict cryptographic certificate gate:
    1. compile_to_qubo: Builds QuadraticProgram Hamiltonian H(x) with exact
       algebraic penalty expansion (Qiskit QAOA / Eigensolvers).
    2. compile_to_ilp: Builds PuLP LpProblem with linear equality, conflict,
       and inequality constraints (Classical ILP / CBC).

  CERTIFICATE-BOUND COMPILATION (Patent Core):
    Compile(IR, Certificate) =
        Model, if VerifyBinding(IR, Certificate) == true
        REJECT, otherwise

    Rejects uncertified IR, failed certificates, stale versions, mutated IR,
    or swapped certificates via domain exceptions:
      - UncertifiedIRCompilationError
      - StaleCertificateError
      - IntegrityBindingError
=============================================================================
"""

import json
import hashlib
from typing import Dict, List, Tuple, Optional, Any, Union

try:
    from qiskit_optimization import QuadraticProgram
    HAS_QISKIT = True
except ImportError:
    HAS_QISKIT = False

try:
    import pulp
    HAS_PULP = True
except ImportError:
    HAS_PULP = False

from config import LAMBDA_PENALTY
from layer5_constraints.constraint_ir import (
    SecurityConstraintIR,
    SemanticManifest,
)
from layer5_constraints.safety_certifier import ConstraintSafetyCertificate


class UncertifiedIRCompilationError(Exception):
    """Raised when compilation is attempted on uncertified or invalidly certified IR."""
    pass


class StaleCertificateError(Exception):
    """Raised when certificate version does not match current IR or runtime state version."""
    pass


class IntegrityBindingError(Exception):
    """Raised when cryptographic binding between certificate and IR is broken."""
    pass


class CompilationResult(tuple):
    """
    Two-element tuple subclass preserving backward compatibility for (model, var_lookup)
    while exposing the emitted SemanticManifest via the .manifest attribute.
    """
    def __new__(cls, model: Any, var_lookup: Any, manifest: Optional[SemanticManifest] = None):
        return super().__new__(cls, (model, var_lookup))

    def __init__(self, model: Any, var_lookup: Any, manifest: Optional[SemanticManifest] = None):
        self.model = model
        self.var_lookup = var_lookup
        self.manifest = manifest


class FormulationCompiler:
    """
    Certificate-Gated Compiler translating verified SecurityConstraintIR into
    target executable solver models (PuLP ILP, Qiskit QUBO).
    """

    @staticmethod
    def verify_binding(
        ir: SecurityConstraintIR,
        certificate: Optional[ConstraintSafetyCertificate],
    ) -> None:
        """
        Enforces cryptographic and semantic binding between SC-IR and Safety Certificate.
        Throws specific domain exceptions upon any verification failure.
        """
        if certificate is None:
            raise UncertifiedIRCompilationError(
                "Compilation rejected: SC-IR has no safety certificate. "
                "Pre-solve safety certification is strictly required prior to solver compilation."
            )

        if certificate.status != "CERTIFIED":
            violations_str = "; ".join(certificate.forbidden_action_violations) or "Unspecified invariant violation"
            raise UncertifiedIRCompilationError(
                f"Compilation rejected: Certificate status is '{certificate.status}'. Violations: {violations_str}"
            )

        if certificate.ir_version != ir.ir_version:
            raise StaleCertificateError(
                f"Compilation rejected: Certificate IR version mismatch. "
                f"Certificate IR v{certificate.ir_version} != IR v{ir.ir_version}."
            )

        if certificate.runtime_state_version != ir.runtime_state_version:
            raise StaleCertificateError(
                f"Compilation rejected: Certificate runtime state version mismatch. "
                f"Certificate state v{certificate.runtime_state_version} != IR state v{ir.runtime_state_version}."
            )

        # Cryptographic canonical digest binding verification
        current_ir_digest = ir.compute_canonical_digest()
        if certificate.ir_sha256 != current_ir_digest:
            raise IntegrityBindingError(
                f"Compilation rejected: Cryptographic digest mismatch. "
                f"Certified digest '{certificate.ir_sha256}' does not match current canonical digest '{current_ir_digest}'. "
                "The SC-IR was modified after safety certification."
            )

        # Recompute and verify certificate's own integrity digest
        if certificate.integrity_digest:
            expected_cert_payload = (
                f"{certificate.certificate_id}:{certificate.ir_sha256}:{certificate.ir_version}:{certificate.runtime_state_version}:"
                f"{certificate.status}:{json.dumps(certificate.verification_checks, sort_keys=True)}:{certificate.closure_digest}"
            )
            expected_cert_hash = hashlib.sha256(expected_cert_payload.encode("utf-8")).hexdigest()
            if certificate.integrity_digest != expected_cert_hash:
                raise IntegrityBindingError(
                    f"Compilation rejected: Certificate integrity digest mismatch. "
                    f"Expected {expected_cert_hash[:16]}..., got {certificate.integrity_digest[:16]}... "
                    "The safety certificate payload was altered after issuance."
                )

        # Recompute and verify closure metadata digest if present
        if ir.dependency_closure_metadata:
            c_dict = ir.dependency_closure_metadata.to_dict() if hasattr(ir.dependency_closure_metadata, "to_dict") else str(ir.dependency_closure_metadata)
            expected_closure_hash = hashlib.sha256(json.dumps(c_dict, sort_keys=True).encode("utf-8")).hexdigest()
            if certificate.closure_digest and certificate.closure_digest != expected_closure_hash:
                raise IntegrityBindingError(
                    f"Compilation rejected: Closure metadata digest mismatch. "
                    f"Expected {expected_closure_hash[:16]}..., got {certificate.closure_digest[:16]}... "
                    "The dependency closure state was altered after certification."
                )

        # Invariant checks verification
        if not all(certificate.verification_checks.values()):
            failed_checks = [k for k, v in certificate.verification_checks.items() if not v]
            raise IntegrityBindingError(
                f"Compilation rejected: Safety certificate contains failed invariant checks: {failed_checks}"
            )

    @classmethod
    def compile_to_qubo(
        cls,
        ir: SecurityConstraintIR,
        certificate: Optional[ConstraintSafetyCertificate] = None,
        lambda_invariance: float = LAMBDA_PENALTY,
        lambda_conflict: float = 8.0,
        return_manifest: bool = False,
    ) -> Union[CompilationResult, Tuple[Any, Dict[Tuple[str, str], str], SemanticManifest]]:
        """
        Compiles certified SecurityConstraintIR into a Qiskit QuadraticProgram.
        Requires a valid, un-tampered PreSolve Safety Certificate.
        Uses binary slack variable expansion for the budget inequality (sum c_i x_i <= B):
            sum c_i x_i + sum 2^k z_k == B
        ensuring that under-budget valid responses are not incorrectly penalized.
        """
        # 1. Gate: Verify certificate binding
        cls.verify_binding(ir, certificate)

        if not HAS_QISKIT:
            raise RuntimeError("qiskit-optimization is required for compile_to_qubo")

        clean_id = str(ir.incident_id).replace(" ", "_").replace("-", "_")
        qp = QuadraticProgram(f"QUBO_{clean_id}")
        var_lookup: Dict[Tuple[str, str], str] = {}

        # 2. Allocate binary variables strictly for admissible actions in variable domains
        for rid, domain in sorted(ir.variable_domains.items()):
            for act in sorted(domain.admissible_actions):
                var_name = f"x_{rid}_{act}"
                qp.binary_var(var_name)
                var_lookup[(rid, act)] = var_name

        linear_terms: Dict[str, float] = {}
        quadratic_terms: Dict[Tuple[str, str], float] = {}

        # 3. Base Objective Linear Terms from IR
        for (rid, act), term in sorted(ir.objective_terms.items()):
            if (rid, act) in var_lookup:
                vname = var_lookup[(rid, act)]
                linear_terms[vname] = term.coefficient

        # 4. Invariance Constraint Penalty: lambda_I * (sum_a x_{i,a} - 1)^2
        # Expansion: -lambda_I * sum_a x_{i,a} + 2 * lambda_I * sum_{a < b} x_{i,a} * x_{i,b}
        for inv in ir.invariance_constraints:
            active_vars = [
                var_lookup[(inv.resource_id, a)]
                for a in sorted(inv.actions)
                if (inv.resource_id, a) in var_lookup
            ]
            for v in active_vars:
                linear_terms[v] = linear_terms.get(v, 0.0) - lambda_invariance

            for i in range(len(active_vars)):
                for j in range(i + 1, len(active_vars)):
                    v1, v2 = active_vars[i], active_vars[j]
                    pair = (v1, v2) if v1 < v2 else (v2, v1)
                    quadratic_terms[pair] = quadratic_terms.get(pair, 0.0) + 2.0 * lambda_invariance

        # 5. Conflict Hyperedge Constraint Penalty: lambda_C * x1 * x2
        for conf in ir.conflict_hyperedges:
            pair1 = (conf.resource_1, conf.action_1)
            pair2 = (conf.resource_2, conf.action_2)
            if pair1 in var_lookup and pair2 in var_lookup:
                v1 = var_lookup[pair1]
                v2 = var_lookup[pair2]
                pair = (v1, v2) if v1 < v2 else (v2, v1)
                quadratic_terms[pair] = quadratic_terms.get(pair, 0.0) + lambda_conflict

        # 6. Budget Inequality Constraint Penalty with Binary Slack Variables:
        # P_B = lambda_B * (sum c_i x_i + sum w_k z_k - B)^2
        slack_weights = []
        if ir.budget_constraint and ir.budget_constraint.max_budget > 0:
            B = float(ir.budget_constraint.max_budget)
            # Scaling factor for budget penalty to ensure dominating invariant enforcement
            lambda_B = lambda_invariance / (B ** 2) if B > 0 else lambda_invariance

            # Generate binary power slack weights to span [0, B] with 0.5 resolution
            delta = 0.5
            total = 0.0
            curr = delta
            while total + curr < B:
                slack_weights.append(curr)
                total += curr
                curr *= 2.0
            if B - total > 1e-5:
                slack_weights.append(round(B - total, 4))

            # Allocate binary slack variables
            slack_names = []
            for k, w in enumerate(slack_weights):
                s_name = f"slack_{k}"
                qp.binary_var(s_name)
                slack_names.append((s_name, w))

            # Combined list of all terms in budget sum: (variable_name, coefficient)
            budget_terms = [
                (var_lookup[(rid, act)], float(ir.budget_constraint.cost_map.get((rid, act), 0.0)))
                for (rid, act) in ir.get_all_variables()
                if (rid, act) in var_lookup
            ] + slack_names

            # Linear terms expansion: lambda_B * (c_i^2 - 2 * B * c_i) * y_i
            for vname, coeff in budget_terms:
                lin_delta = lambda_B * (coeff ** 2 - 2.0 * B * coeff)
                linear_terms[vname] = linear_terms.get(vname, 0.0) + lin_delta

            # Quadratic cross terms expansion: 2 * lambda_B * c_i * c_j * y_i * y_j
            for i in range(len(budget_terms)):
                v1, c1 = budget_terms[i]
                for j in range(i + 1, len(budget_terms)):
                    v2, c2 = budget_terms[j]
                    pair = (v1, v2) if v1 < v2 else (v2, v1)
                    quadratic_terms[pair] = quadratic_terms.get(pair, 0.0) + 2.0 * lambda_B * c1 * c2

        qp.minimize(linear=linear_terms, quadratic=quadratic_terms)
        qp.slack_weights = slack_weights

        # Build Semantic Manifest
        manifest = SemanticManifest(
            source_ir_version=ir.ir_version,
            source_certificate_id=certificate.certificate_id if certificate else "",
            active_variables=ir.get_all_variables(),
            mandatory_variables=[
                (r.target_resource, r.target_action)
                for r in ir.provenance_records if r.constraint_type == "MANDATED"
            ],
            forbidden_variables=[
                (r.target_resource, r.target_action)
                for r in ir.provenance_records if r.constraint_type == "PRUNED"
            ],
            hard_constraint_ids=[c.constraint_id for c in ir.hard_constraints],
            conflict_relations=[
                (c.resource_1, c.action_1, c.resource_2, c.action_2)
                for c in ir.conflict_hyperedges
            ],
            operational_bounds=ir.regenerated_bounds.copy(),
            backend_type="QUBO_QISKIT",
        )

        if return_manifest:
            return qp, var_lookup, manifest
        return CompilationResult(qp, var_lookup, manifest)

    @classmethod
    def compile_to_ilp(
        cls,
        ir: SecurityConstraintIR,
        certificate: Optional[ConstraintSafetyCertificate] = None,
        return_manifest: bool = False,
    ) -> Union[CompilationResult, Tuple[Any, Dict[Tuple[str, str], Any], SemanticManifest]]:
        """
        Compiles certified SecurityConstraintIR into a PuLP LpProblem model.
        Requires a valid, un-tampered PreSolve Safety Certificate.
        """
        # 1. Gate: Verify certificate binding
        cls.verify_binding(ir, certificate)

        if not HAS_PULP:
            raise RuntimeError("PuLP is required for compile_to_ilp")

        clean_id = str(ir.incident_id).replace(" ", "_").replace("-", "_")
        prob = pulp.LpProblem(f"ILP_{clean_id}", pulp.LpMinimize)
        x_vars: Dict[Tuple[str, str], pulp.LpVariable] = {}

        # 2. Allocate binary variables strictly for admissible actions in variable domains
        for rid, domain in sorted(ir.variable_domains.items()):
            for act in sorted(domain.admissible_actions):
                var_name = f"x_{rid}_{act}"
                x_vars[(rid, act)] = pulp.LpVariable(var_name, cat="Binary")

        # 3. Objective Function: Linear terms from IR
        obj_expr = []
        for (rid, act), term in sorted(ir.objective_terms.items()):
            if (rid, act) in x_vars:
                obj_expr.append(term.coefficient * x_vars[(rid, act)])
        prob += pulp.lpSum(obj_expr), "Total_Response_Cost_Objective"

        # 4. Invariance Constraints: Exactly 1 action chosen per resource
        for inv in ir.invariance_constraints:
            res_vars = [x_vars[(inv.resource_id, a)] for a in sorted(inv.actions) if (inv.resource_id, a) in x_vars]
            if res_vars:
                prob += pulp.lpSum(res_vars) == inv.target_value, f"Invariance_{inv.resource_id}"

        # 5. Conflict Hyperedges: x1 + x2 <= 1
        for idx, conf in enumerate(ir.conflict_hyperedges):
            pair1 = (conf.resource_1, conf.action_1)
            pair2 = (conf.resource_2, conf.action_2)
            if pair1 in x_vars and pair2 in x_vars:
                prob += x_vars[pair1] + x_vars[pair2] <= 1, f"Conflict_{idx}_{conf.resource_1}_{conf.action_1}"

        # 6. Hard Budget Constraint: sum(cost * x) <= max_budget
        if ir.budget_constraint:
            cost_expr = [
                ir.budget_constraint.cost_map.get((rid, act), 0.0) * x_vars[(rid, act)]
                for (rid, act) in sorted(x_vars.keys())
            ]
            prob += pulp.lpSum(cost_expr) <= ir.budget_constraint.max_budget, "Operational_Budget_Ceiling"

        # Build Semantic Manifest
        manifest = SemanticManifest(
            source_ir_version=ir.ir_version,
            source_certificate_id=certificate.certificate_id if certificate else "",
            active_variables=ir.get_all_variables(),
            mandatory_variables=[
                (r.target_resource, r.target_action)
                for r in ir.provenance_records if r.constraint_type == "MANDATED"
            ],
            forbidden_variables=[
                (r.target_resource, r.target_action)
                for r in ir.provenance_records if r.constraint_type == "PRUNED"
            ],
            hard_constraint_ids=[c.constraint_id for c in ir.hard_constraints],
            conflict_relations=[
                (c.resource_1, c.action_1, c.resource_2, c.action_2)
                for c in ir.conflict_hyperedges
            ],
            operational_bounds=ir.regenerated_bounds.copy(),
            backend_type="ILP_PULP",
        )

        if return_manifest:
            return prob, x_vars, manifest
        return CompilationResult(prob, x_vars, manifest)

    @staticmethod
    def extract_solution_from_ilp(
        prob: Any,
        ir: SecurityConstraintIR,
        x_vars: Optional[Dict[Tuple[str, str], Any]] = None,
    ) -> Dict[str, str]:
        """
        Extracts selected binary response plan from solved PuLP model.
        """
        plan = {}
        for rid, domain in sorted(ir.variable_domains.items()):
            best_k = domain.admissible_actions[0]
            for act in sorted(domain.admissible_actions):
                val = None
                if x_vars and (rid, act) in x_vars:
                    val = pulp.value(x_vars[(rid, act)])
                else:
                    var_name = f"x_{rid}_{act}"
                    for v in prob.variables():
                        if v.name == var_name:
                            val = pulp.value(v)
                            break
                if val is not None and val > 0.5:
                    best_k = act
                    break
            plan[rid] = best_k
        return plan
