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
import time
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
from layer5_constraints.fidelity_proof import FidelityProof


class UncertifiedIRCompilationError(Exception):
    """Raised when compilation is attempted on uncertified or invalidly certified IR."""
    pass


class StaleCertificateError(Exception):
    """Raised when certificate version does not match current IR or runtime state version."""
    pass


class IntegrityBindingError(Exception):
    """Raised when cryptographic binding between certificate and IR is broken."""
    pass


from layer5_constraints.validity_envelope import StateEnvelopeViolationError


class CompilationResult(tuple):
    """
    Two-element tuple subclass preserving backward compatibility for (model, var_lookup)
    while exposing the emitted SemanticManifest and FidelityProof via attributes.
    """
    def __new__(
        cls,
        model: Any,
        var_lookup: Any,
        manifest: Optional[SemanticManifest] = None,
        fidelity_proof: Optional[FidelityProof] = None,
    ):
        return super().__new__(cls, (model, var_lookup))

    def __init__(
        self,
        model: Any,
        var_lookup: Any,
        manifest: Optional[SemanticManifest] = None,
        fidelity_proof: Optional[FidelityProof] = None,
    ):
        self.model = model
        self.var_lookup = var_lookup
        self.manifest = manifest
        self.fidelity_proof = fidelity_proof
        self.proof = fidelity_proof


class FormulationCompiler:
    """
    Certificate-Gated Compiler translating verified SecurityConstraintIR into
    target executable solver models (PuLP ILP, Qiskit QUBO).
    """

    @staticmethod
    def verify_binding(
        ir: SecurityConstraintIR,
        certificate: Optional[ConstraintSafetyCertificate],
        current_snapshot: Optional[Any] = None,
        verifier_key: Optional[Any] = None,
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

        # Recompute and verify witness_digest if present
        expected_witness_digest = ""
        if certificate.feasibility_witness is not None:
            expected_witness_digest = hashlib.sha256(
                json.dumps(certificate.feasibility_witness, sort_keys=True).encode("utf-8")
            ).hexdigest()
        if certificate.witness_digest and certificate.witness_digest != expected_witness_digest:
            raise IntegrityBindingError(
                f"Compilation rejected: Witness digest mismatch. "
                f"Certificate witness digest '{certificate.witness_digest[:16]}...' does not match recomputed '{expected_witness_digest[:16]}...'. "
                "The feasibility witness was altered after certification."
            )

        # Recompute and verify envelope_digest if present
        if getattr(certificate, "envelope_digest", ""):
            expected_envelope_digest = ""
            envelope = getattr(certificate, "validity_envelope", None) or getattr(ir, "validity_envelope", None)
            if envelope is not None:
                expected_envelope_digest = getattr(envelope, "envelope_digest", "")
            if certificate.envelope_digest != expected_envelope_digest:
                raise IntegrityBindingError(
                    f"Compilation rejected: Envelope digest mismatch. "
                    f"Certificate envelope digest '{certificate.envelope_digest[:16]}...' does not match recomputed '{expected_envelope_digest[:16]}...'. "
                    "The validity envelope was altered after certification."
                )

        # Check current_snapshot against validity envelope if provided
        if current_snapshot is not None:
            envelope = getattr(certificate, "validity_envelope", None) or getattr(ir, "validity_envelope", None)
            if envelope is not None:
                ok, violations = envelope.contains(current_snapshot)
                if not ok:
                    raise StateEnvelopeViolationError(
                        f"Compilation rejected: Current state snapshot violates certified validity envelope: {violations}"
                    )

        # Recompute and verify certificate's own integrity digest and digital signature
        if hasattr(certificate, "compute_canonical_payload") and getattr(certificate, "canonical_payload_bytes", b""):
            expected_payload_bytes = certificate.compute_canonical_payload()
            expected_cert_hash = hashlib.sha256(expected_payload_bytes).hexdigest()
            if certificate.integrity_digest and certificate.integrity_digest != expected_cert_hash:
                raise IntegrityBindingError(
                    f"Compilation rejected: Certificate integrity digest mismatch. "
                    f"Expected {expected_cert_hash[:16]}..., got {certificate.integrity_digest[:16]}... "
                    "The safety certificate payload was altered after issuance."
                )

            # Digital signature verification using VerifierKey (public key only)
            if certificate.signature and hasattr(certificate, "auth_mechanism"):
                from layer5_constraints.keys import get_verifier_key
                vk = verifier_key or get_verifier_key()
                if not vk.verify(expected_payload_bytes, certificate.signature, certificate.auth_mechanism):
                    raise IntegrityBindingError(
                        "Compilation rejected: Digital signature verification failed. "
                        "Certificate signature is invalid, was signed by an unauthorized key, or payload was tampered."
                    )
        elif certificate.integrity_digest:
            witness_part = f":{certificate.witness_digest}" if certificate.witness_digest else ""
            envelope_part = f":{certificate.envelope_digest}" if getattr(certificate, "envelope_digest", "") else ""
            expected_cert_payload = (
                f"{certificate.certificate_id}:{certificate.ir_sha256}:{certificate.ir_version}:{certificate.runtime_state_version}:"
                f"{certificate.status}:{json.dumps(certificate.verification_checks, sort_keys=True)}:{certificate.closure_digest}"
                f"{witness_part}{envelope_part}"
            )
            expected_cert_hash = hashlib.sha256(expected_cert_payload.encode("utf-8")).hexdigest()
            if certificate.integrity_digest != expected_cert_hash:
                raise IntegrityBindingError(
                    f"Compilation rejected: Certificate integrity digest mismatch. "
                    f"Expected {expected_cert_hash[:16]}..., got {certificate.integrity_digest[:16]}... "
                    "The safety certificate payload was altered after issuance."
                )

        # Asset Scope verification: certificate must match active managed assets
        if getattr(certificate, "asset_scope", None):
            current_scope = sorted(list(ir.variable_domains.keys()))
            if certificate.asset_scope != current_scope:
                raise IntegrityBindingError(
                    f"Compilation rejected: Asset scope mismatch. "
                    f"Certificate asset scope {certificate.asset_scope} does not match current IR asset scope {current_scope}. "
                    "Replay attack across different infrastructure scope detected."
                )

        # State Epoch verification
        if getattr(certificate, "state_epoch", None) is not None and getattr(ir, "state_epoch", None) is not None:
            if certificate.state_epoch != ir.state_epoch:
                raise StaleCertificateError(
                    f"Compilation rejected: State epoch mismatch. "
                    f"Certificate epoch {certificate.state_epoch} != IR epoch {ir.state_epoch}."
                )

        # Lease Policy verification (max age seconds)
        if getattr(certificate, "lease_policy", None) and getattr(certificate, "timestamp", None):
            if (time.time() - certificate.timestamp) > certificate.lease_policy:
                raise StaleCertificateError(
                    f"Compilation rejected: Certificate lease expired "
                    f"({time.time() - certificate.timestamp:.1f}s elapsed > {certificate.lease_policy}s allowed)."
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
        current_snapshot: Optional[Any] = None,
    ) -> Union[CompilationResult, Tuple[Any, Dict[Tuple[str, str], str], SemanticManifest]]:
        """
        Compiles certified SecurityConstraintIR into a Qiskit QuadraticProgram.
        Requires a valid, un-tampered PreSolve Safety Certificate.
        Uses binary slack variable expansion for the budget inequality (sum c_i x_i <= B):
            sum c_i x_i + sum 2^k z_k == B
        ensuring that under-budget valid responses are not incorrectly penalized.
        """
        # 1. Gate: Verify certificate binding and state envelope
        cls.verify_binding(ir, certificate, current_snapshot=current_snapshot)

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
        constant: float = 0.0

        # Dominating penalty requirements: compute delta_obj first
        delta_obj = sum(abs(t.coefficient) for t in ir.objective_terms.values())
        min_dominating_req = delta_obj + 10.0
        if lambda_invariance <= delta_obj:
            lambda_invariance = max(lambda_invariance, min_dominating_req)
        if lambda_conflict <= delta_obj:
            lambda_conflict = max(lambda_conflict, min_dominating_req)

        # 3. Base Objective Linear Terms from IR
        for (rid, act), term in sorted(ir.objective_terms.items()):
            if (rid, act) in var_lookup:
                vname = var_lookup[(rid, act)]
                linear_terms[vname] = term.coefficient

        # 4. Invariance Constraint Penalty: lambda_I * (sum_a x_{i,a} - 1)^2
        # Expansion: -lambda_I * sum_a x_{i,a} + 2 * lambda_I * sum_{a < b} x_{i,a} * x_{i,b} + lambda_I
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
            constant += lambda_invariance

        # 5. Conflict Hyperedge Constraint Penalty: lambda_C * x1 * x2
        for conf in ir.conflict_hyperedges:
            pair1 = (conf.resource_1, conf.action_1)
            pair2 = (conf.resource_2, conf.action_2)
            if pair1 in var_lookup and pair2 in var_lookup:
                v1 = var_lookup[pair1]
                v2 = var_lookup[pair2]
                pair = (v1, v2) if v1 < v2 else (v2, v1)
                quadratic_terms[pair] = quadratic_terms.get(pair, 0.0) + lambda_conflict

        # 6. Budget Inequality Constraint Penalty with Exact Integer-Scaled Binary Slack Variables:
        # P_B = lambda_B * (sum c_i x_i + sum s_k z_k - B)^2
        # where scale = 1000, integer budget B_hat = round(B * scale),
        # integer powers w_k in {1, 2, 4, ..., B_hat - sum}, and s_k = w_k / scale.
        # Dominating penalty multiplier: lambda_B = max(2.0, M_obj) * scale^2.
        # This guarantees:
        #   - Every admissible fractional cost (e.g. 0.005, 0.025, 0.605) has EXACT binary representation (residual = 0).
        #   - For any feasible state x with optimal slack z*, P_B = 0.0 (penalty-free Hamiltonian energy).
        #   - For any over-budget state (cost > B), P_B >= M_obj, strictly dominating any objective gain.
        slack_weights = []
        slack_info = []  # List of (var_name, float_weight, int_weight)
        cost_scale = 1000
        B_float = 0.0
        B_int = 0
        lambda_B = 0.0

        if ir.budget_constraint and ir.budget_constraint.max_budget > 0:
            B_float = float(ir.budget_constraint.max_budget)
            B_int = int(round(B_float * cost_scale))

            # Dominating penalty multiplier derivation
            max_obj_gain = sum(abs(t.coefficient) for t in ir.objective_terms.values()) + 10.0
            lambda_effective = max(2.0, max_obj_gain, min_dominating_req)
            lambda_B = lambda_effective * (cost_scale ** 2)

            # Generate binary powers to span [0, B_int] with zero residual error
            weights = []
            total = 0
            curr = 1
            while total + curr < B_int:
                weights.append(curr)
                total += curr
                curr *= 2
            if B_int - total > 0:
                weights.append(B_int - total)

            # Allocate binary slack variables
            for k, iw in enumerate(weights):
                s_name = f"slack_{k}"
                fw = iw / cost_scale
                qp.binary_var(s_name)
                slack_weights.append(fw)
                slack_info.append((s_name, fw, iw))

            # Combined list of all terms in budget sum: (variable_name, float_coefficient)
            budget_terms = [
                (var_lookup[(rid, act)], float(ir.budget_constraint.cost_map.get((rid, act), 0.0)))
                for (rid, act) in ir.get_all_variables()
                if (rid, act) in var_lookup
            ] + [(sname, fw) for sname, fw, _ in slack_info]

            # Linear terms expansion: lambda_B * (c_i^2 - 2 * B * c_i) * y_i
            for vname, coeff in budget_terms:
                lin_delta = lambda_B * (coeff ** 2 - 2.0 * B_float * coeff)
                linear_terms[vname] = linear_terms.get(vname, 0.0) + lin_delta

            # Quadratic cross terms expansion: 2 * lambda_B * c_i * c_j * y_i * y_j
            for i in range(len(budget_terms)):
                v1, c1 = budget_terms[i]
                for j in range(i + 1, len(budget_terms)):
                    v2, c2 = budget_terms[j]
                    pair = (v1, v2) if v1 < v2 else (v2, v1)
                    quadratic_terms[pair] = quadratic_terms.get(pair, 0.0) + 2.0 * lambda_B * c1 * c2

            constant += lambda_B * (B_float ** 2)

        qp.minimize(constant=constant, linear=linear_terms, quadratic=quadratic_terms)
        qp.slack_weights = slack_weights
        qp.slack_info = slack_info
        qp.cost_scale = cost_scale
        qp.budget_int = B_int
        qp.budget_max = B_float
        qp.lambda_B = lambda_B
        qp.lambda_invariance = lambda_invariance
        qp.lambda_conflict = lambda_conflict
        qp.lambda_effective = lambda_effective if (ir.budget_constraint and ir.budget_constraint.max_budget > 0) else None
        qp.var_lookup = var_lookup
        qp.cost_map = ir.budget_constraint.cost_map.copy() if ir.budget_constraint else {}

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

        # Build constraint translations for FidelityProof
        qubo_translations = []
        for inv in ir.invariance_constraints:
            active_vars = [
                var_lookup[(inv.resource_id, a)]
                for a in sorted(inv.actions)
                if (inv.resource_id, a) in var_lookup
            ]
            qubo_translations.append({
                "ir_constraint_type": "INVARIANCE",
                "ir_constraint_id": f"invariance_{inv.resource_id}",
                "backend_elements": active_vars,
                "parameters": {
                    "resource_id": inv.resource_id,
                    "actions": sorted(inv.actions),
                    "penalty": lambda_invariance,
                },
            })

        for conf in ir.conflict_hyperedges:
            pair1 = (conf.resource_1, conf.action_1)
            pair2 = (conf.resource_2, conf.action_2)
            c_vars = []
            if pair1 in var_lookup and pair2 in var_lookup:
                c_vars = [var_lookup[pair1], var_lookup[pair2]]
            qubo_translations.append({
                "ir_constraint_type": "CONFLICT",
                "ir_constraint_id": f"conflict_{conf.resource_1}_{conf.action_1}_{conf.resource_2}_{conf.action_2}",
                "backend_elements": c_vars,
                "parameters": {
                    "resource_1": conf.resource_1,
                    "action_1": conf.action_1,
                    "resource_2": conf.resource_2,
                    "action_2": conf.action_2,
                    "penalty": lambda_conflict,
                },
            })

        if ir.budget_constraint and ir.budget_constraint.max_budget > 0:
            qubo_translations.append({
                "ir_constraint_type": "BUDGET",
                "ir_constraint_id": "operational_budget_ceiling",
                "backend_elements": [sname for sname, _, _ in slack_info],
                "parameters": {
                    "max_budget": B_float,
                    "budget_int": B_int,
                    "cost_scale": cost_scale,
                    "slack_weights": slack_weights,
                    "penalty": lambda_B,
                },
            })

        for mandated in ir.provenance_records:
            if mandated.constraint_type == "MANDATED":
                vname = var_lookup.get((mandated.target_resource, mandated.target_action))
                qubo_translations.append({
                    "ir_constraint_type": "MANDATE",
                    "ir_constraint_id": f"mandate_{mandated.target_resource}_{mandated.target_action}",
                    "backend_elements": [vname] if vname else [],
                    "parameters": {
                        "resource_id": mandated.target_resource,
                        "action": mandated.target_action,
                    },
                })

        delta_obj = sum(abs(t.coefficient) for t in ir.objective_terms.values())
        applied_penalties = [lambda_invariance, lambda_conflict]
        if ir.budget_constraint and ir.budget_constraint.max_budget > 0:
            applied_penalties.append(lambda_B / (cost_scale ** 2))
        actual_min_penalty = min(applied_penalties)
        penalty_coeff = actual_min_penalty

        pruned_actions = [
            (r.target_resource, r.target_action)
            for r in ir.provenance_records if r.constraint_type == "PRUNED"
        ]

        fidelity_proof = FidelityProof(
            backend_id="QUBO_QISKIT",
            certificate_id=certificate.certificate_id if certificate else "",
            variable_map=var_lookup.copy(),
            auxiliary_variables=[sname for sname, _, _ in slack_info],
            constraint_translations=qubo_translations,
            penalty_coefficient=float(penalty_coeff),
            objective_range_bound=float(delta_obj),
            pruned_actions=pruned_actions,
        )

        qp.fidelity_proof = fidelity_proof
        qp.proof = fidelity_proof

        if return_manifest:
            return qp, var_lookup, manifest
        return CompilationResult(qp, var_lookup, manifest, fidelity_proof)

    @classmethod
    def compile_to_ilp(
        cls,
        ir: SecurityConstraintIR,
        certificate: Optional[ConstraintSafetyCertificate] = None,
        return_manifest: bool = False,
        current_snapshot: Optional[Any] = None,
    ) -> Union[CompilationResult, Tuple[Any, Dict[Tuple[str, str], Any], SemanticManifest]]:
        """
        Compiles certified SecurityConstraintIR into a PuLP LpProblem model.
        Requires a valid, un-tampered PreSolve Safety Certificate.
        """
        # 1. Gate: Verify certificate binding and state envelope
        cls.verify_binding(ir, certificate, current_snapshot=current_snapshot)

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

        # Build constraint translations for FidelityProof
        ilp_translations = []
        for inv in ir.invariance_constraints:
            c_name = f"Invariance_{inv.resource_id}".replace("-", "_")
            ilp_translations.append({
                "ir_constraint_type": "INVARIANCE",
                "ir_constraint_id": f"invariance_{inv.resource_id}",
                "backend_elements": [c_name],
                "parameters": {
                    "resource_id": inv.resource_id,
                    "actions": sorted(inv.actions),
                    "target_value": inv.target_value,
                },
            })

        for idx, conf in enumerate(ir.conflict_hyperedges):
            cname = f"Conflict_{idx}_{conf.resource_1}_{conf.action_1}".replace("-", "_")
            ilp_translations.append({
                "ir_constraint_type": "CONFLICT",
                "ir_constraint_id": f"conflict_{conf.resource_1}_{conf.action_1}_{conf.resource_2}_{conf.action_2}",
                "backend_elements": [cname],
                "parameters": {
                    "resource_1": conf.resource_1,
                    "action_1": conf.action_1,
                    "resource_2": conf.resource_2,
                    "action_2": conf.action_2,
                },
            })

        if ir.budget_constraint and ir.budget_constraint.max_budget > 0:
            ilp_translations.append({
                "ir_constraint_type": "BUDGET",
                "ir_constraint_id": "operational_budget_ceiling",
                "backend_elements": ["Operational_Budget_Ceiling"],
                "parameters": {
                    "max_budget": float(ir.budget_constraint.max_budget),
                    "cost_map": {f"{r}:{a}": float(c) for (r, a), c in ir.budget_constraint.cost_map.items()},
                },
            })

        for mandated in ir.provenance_records:
            if mandated.constraint_type == "MANDATED":
                m_name = f"Invariance_{mandated.target_resource}".replace("-", "_")
                ilp_translations.append({
                    "ir_constraint_type": "MANDATE",
                    "ir_constraint_id": f"mandate_{mandated.target_resource}_{mandated.target_action}",
                    "backend_elements": [m_name],
                    "parameters": {
                        "resource_id": mandated.target_resource,
                        "action": mandated.target_action,
                    },
                })

        pruned_actions = [
            (r.target_resource, r.target_action)
            for r in ir.provenance_records if r.constraint_type == "PRUNED"
        ]

        var_map = {k: v.name for k, v in x_vars.items()}

        fidelity_proof = FidelityProof(
            backend_id="ILP_PULP",
            certificate_id=certificate.certificate_id if certificate else "",
            variable_map=var_map,
            auxiliary_variables=[],
            constraint_translations=ilp_translations,
            pruned_actions=pruned_actions,
        )

        prob.fidelity_proof = fidelity_proof
        prob.proof = fidelity_proof

        if return_manifest:
            return prob, x_vars, manifest
        return CompilationResult(prob, x_vars, manifest, fidelity_proof)

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
