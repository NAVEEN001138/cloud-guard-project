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

Feasibility Semantics:
  ILP:  x in F(IR) <=> exists z: (x, z) satisfies all backend hard constraints.
  QUBO: x in F(IR) <=> exists z: P_hard(x, z) == 0, where P_hard is the reconstructed penalty polynomial.
  Never write "feasible set of the QUBO" unqualified.

Verification Scope:
  1. Certificate binding & digital signature verification.
  2. Exact variable domain mapping and structural excision enforcement
     (no excised / pruned actions may have backend variables; bijection on admissible).
  3. Complete IR-derived constraint translation coverage and participant/endpoint bijection.
  4. Local algebraic equivalence per constraint translation and backend model LHS verification.
  5. QUBO penalty bound domination check: P > Delta_obj and exact binary-slack budget expansion.
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
        The proof is a TRANSLATION WITNESS (weights + variable naming), never a statement
        of semantics. For every hard constraint the checker derives the expected translation
        from the certified IR ITSELF and requires both the proof and the model to match it.
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

        # 3. Structural Excision & Pruned Actions Check
        all_pruned_actions: Set[Tuple[str, str]] = set(proof.pruned_actions)
        for r, dom in ir.variable_domains.items():
            for a in dom.pruned_actions:
                all_pruned_actions.add((r, a))
        for rec in ir.provenance_records:
            if rec.constraint_type == "PRUNED":
                all_pruned_actions.add((rec.target_resource, rec.target_action))

        for (r, a) in all_pruned_actions:
            if (r, a) in proof.variable_map:
                raise FidelityProofError(
                    f"Proof rejected: Excised action ({r}, {a}) found in variable_map."
                )
            candidate_vname = f"x_{r}_{a}"
            if candidate_vname in backend_var_names:
                raise FidelityProofError(
                    f"Proof rejected: Excised action ({r}, {a}) present in backend model as '{candidate_vname}'."
                )

        # 4. Variable Map Bijectivity on Admissible Domain
        # Verify a bijection between {(r,a) : a in ir.variable_domains[r].admissible_actions}
        # and the backend's non-auxiliary variables.
        ir_vars = set(ir.get_all_variables())
        proof_vars = set(proof.variable_map.keys())

        if ir_vars != proof_vars:
            missing = ir_vars - proof_vars
            extra = proof_vars - ir_vars
            raise FidelityProofError(
                f"Proof rejected: Variable domain mismatch. Missing from proof: {missing}, Unexpected in proof: {extra}."
            )

        # Injective check: no aliasing onto the same backend variable
        mapped_backend_vars = list(proof.variable_map.values())
        if len(mapped_backend_vars) != len(set(mapped_backend_vars)):
            raise FidelityProofError(
                "Proof rejected: Aliasing detected in variable_map; multiple IR variables map to the same backend variable."
            )

        budget_translations = [t for t in proof.constraint_translations if t.get("ir_constraint_type") == "BUDGET"]

        # Auxiliaries: every auxiliary must be declared as a slack of exactly one BUDGET translation
        if proof.backend_id == "QUBO_QISKIT":
            budget_slacks: List[str] = []
            for bt in budget_translations:
                elems = bt.get("backend_elements", [])
                budget_slacks.extend(elems)

            if len(budget_slacks) != len(set(budget_slacks)):
                raise FidelityProofError(
                    "Proof rejected: Duplicate slack variable declared across budget translations."
                )

            if set(proof.auxiliary_variables) != set(budget_slacks):
                missing_aux = set(proof.auxiliary_variables) - set(budget_slacks)
                extra_aux = set(budget_slacks) - set(proof.auxiliary_variables)
                raise FidelityProofError(
                    f"Proof rejected: Every auxiliary must be declared as a slack of exactly one BUDGET translation. "
                    f"Unmatched auxiliaries: {missing_aux}, undeclared slacks: {extra_aux}."
                )

            # Non-budget translations must not contain auxiliary variables
            for t in proof.constraint_translations:
                if t.get("ir_constraint_type") != "BUDGET":
                    for elem in t.get("backend_elements", []):
                        if elem in proof.auxiliary_variables:
                            raise FidelityProofError(
                                f"Proof rejected: Auxiliary variable '{elem}' appears in non-budget translation '{t.get('ir_constraint_id')}'."
                            )
        else:
            # For ILP, no auxiliary variables are expected
            if proof.auxiliary_variables:
                raise FidelityProofError(
                    f"Proof rejected: Backend '{proof.backend_id}' must not declare auxiliary variables, got {proof.auxiliary_variables}."
                )

        # Backend decision variables bijection
        backend_non_aux = backend_var_names - set(proof.auxiliary_variables)
        if set(proof.variable_map.values()) != backend_non_aux:
            unaccounted = backend_non_aux - set(proof.variable_map.values())
            missing = set(proof.variable_map.values()) - backend_non_aux
            raise FidelityProofError(
                f"Proof rejected: Variable map is not a bijection with backend non-auxiliary variables. "
                f"Unaccounted backend variables: {unaccounted}, Missing from backend: {missing}."
            )

        for aux in proof.auxiliary_variables:
            if aux not in backend_var_names:
                raise FidelityProofError(
                    f"Proof rejected: Auxiliary variable '{aux}' not found in backend model."
                )

        # Pre-image check: verify no backend variable maps back to a pruned action
        inverse_var_map = {vname: (r, a) for (r, a), vname in proof.variable_map.items()}
        for vname in backend_non_aux:
            if vname in inverse_var_map:
                pre_image = inverse_var_map[vname]
                if pre_image in all_pruned_actions:
                    raise FidelityProofError(
                        f"Proof rejected: Backend variable '{vname}' has pruned action pre-image {pre_image}."
                    )

        # 5. IR-Derived Constraint Translation Coverage & Verification
        # 5a. Exactly-one (Invariance)
        invariance_trans = [t for t in proof.constraint_translations if t.get("ir_constraint_type") == "INVARIANCE"]
        if len(invariance_trans) != len(ir.variable_domains):
            raise FidelityProofError(
                f"Proof rejected: Invariance translation count ({len(invariance_trans)}) != "
                f"resource count in IR ({len(ir.variable_domains)})."
            )

        for r, dom in ir.variable_domains.items():
            expected_admissible = set(dom.admissible_actions)
            expected_vnames = {proof.variable_map[(r, a)] for a in expected_admissible}
            expected_id = f"invariance_{r}"
            matching = [
                t for t in invariance_trans
                if t.get("ir_constraint_id") == expected_id or t.get("parameters", {}).get("resource_id") == r
            ]
            if len(matching) != 1:
                raise FidelityProofError(
                    f"Proof rejected: Expected exactly one invariance translation for resource '{r}', found {len(matching)}."
                )
            t = matching[0]
            params = t.get("parameters", {})
            if "actions" in params and set(params["actions"]) != expected_admissible:
                raise FidelityProofError(
                    f"Proof rejected: Invariance translation for '{r}' actions parameter mismatch."
                )
            if proof.backend_id == "QUBO_QISKIT":
                if set(t.get("backend_elements", [])) != expected_vnames:
                    raise FidelityProofError(
                        f"Proof rejected: Invariance translation for '{r}' participants mismatch. "
                        f"Expected {expected_vnames}, got {set(t.get('backend_elements', []))}."
                    )

        # 5b. Conflicts
        conflict_trans = [t for t in proof.constraint_translations if t.get("ir_constraint_type") == "CONFLICT"]
        if len(conflict_trans) != len(ir.conflict_hyperedges):
            raise FidelityProofError(
                f"Proof rejected: Conflict translation count ({len(conflict_trans)}) != "
                f"IR conflict hyperedge count ({len(ir.conflict_hyperedges)})."
            )

        for conf in ir.conflict_hyperedges:
            p1 = (conf.resource_1, conf.action_1)
            p2 = (conf.resource_2, conf.action_2)
            if p1 not in proof.variable_map or p2 not in proof.variable_map:
                raise FidelityProofError(f"Proof rejected: Conflict hyperedge ({p1}, {p2}) has non-admissible endpoint.")
            v1 = proof.variable_map[p1]
            v2 = proof.variable_map[p2]
            expected_endpoints = {v1, v2}
            expected_id = f"conflict_{conf.resource_1}_{conf.action_1}_{conf.resource_2}_{conf.action_2}"
            matching = [
                t for t in conflict_trans
                if t.get("ir_constraint_id") == expected_id or
                (t.get("parameters", {}).get("resource_1") == conf.resource_1 and
                 t.get("parameters", {}).get("action_1") == conf.action_1 and
                 t.get("parameters", {}).get("resource_2") == conf.resource_2 and
                 t.get("parameters", {}).get("action_2") == conf.action_2)
            ]
            if len(matching) != 1:
                raise FidelityProofError(
                    f"Proof rejected: Expected exactly one translation for conflict '{expected_id}', found {len(matching)}."
                )
            t = matching[0]
            params = t.get("parameters", {})
            if (params.get("resource_1") != conf.resource_1 or params.get("action_1") != conf.action_1 or
                params.get("resource_2") != conf.resource_2 or params.get("action_2") != conf.action_2):
                raise FidelityProofError(
                    f"Proof rejected: Conflict translation parameters mismatch for '{expected_id}'."
                )
            if proof.backend_id == "QUBO_QISKIT":
                if set(t.get("backend_elements", [])) != expected_endpoints:
                    raise FidelityProofError(
                        f"Proof rejected: Conflict translation '{expected_id}' endpoints mismatch. "
                        f"Expected {expected_endpoints}, got {set(t.get('backend_elements', []))}."
                    )

        # 5c. Mandates
        mandated_records = [r for r in ir.provenance_records if r.constraint_type == "MANDATED"]
        mandate_trans = [t for t in proof.constraint_translations if t.get("ir_constraint_type") == "MANDATE"]
        if len(mandate_trans) != len(mandated_records):
            raise FidelityProofError(
                f"Proof rejected: Mandate translation count ({len(mandate_trans)}) != "
                f"IR provenance mandated count ({len(mandated_records)})."
            )

        for rec in mandated_records:
            expected_id = f"mandate_{rec.target_resource}_{rec.target_action}"
            matching = [
                t for t in mandate_trans
                if t.get("ir_constraint_id") == expected_id or
                (t.get("parameters", {}).get("resource_id") == rec.target_resource and
                 t.get("parameters", {}).get("action") == rec.target_action)
            ]
            if len(matching) != 1:
                raise FidelityProofError(
                    f"Proof rejected: Expected exactly one translation for mandate '{expected_id}', found {len(matching)}."
                )
            t = matching[0]
            params = t.get("parameters", {})
            if params.get("resource_id") != rec.target_resource or params.get("action") != rec.target_action:
                raise FidelityProofError(
                    f"Proof rejected: Mandate translation parameters mismatch for '{expected_id}'."
                )

        # 5d. Budget
        has_budget = ir.budget_constraint and ir.budget_constraint.max_budget > 0
        if has_budget:
            if len(budget_translations) != 1:
                raise FidelityProofError(
                    f"Proof rejected: Expected exactly one budget translation, found {len(budget_translations)}."
                )
            bt = budget_translations[0]
            b_params = bt.get("parameters", {})
            if "variable_costs" in b_params:
                raise FidelityProofError(
                    "Proof rejected: Budget translation must not supply variable_costs; costs must be derived from IR."
                )
            cost_scale = int(b_params.get("cost_scale", 1000))
            expected_max = float(ir.budget_constraint.max_budget)
            if "max_budget" in b_params and abs(float(b_params["max_budget"]) - expected_max) > 1e-6:
                raise FidelityProofError(
                    f"Proof rejected: Budget translation max_budget {b_params['max_budget']} != IR max_budget {expected_max}."
                )
            expected_b_int = int(round(expected_max * cost_scale))
            if "budget_int" in b_params and int(b_params["budget_int"]) != expected_b_int:
                raise FidelityProofError(
                    f"Proof rejected: Budget translation budget_int {b_params['budget_int']} != expected {expected_b_int}."
                )

            if proof.backend_id == "QUBO_QISKIT":
                # Slack powers must be exactly the binary expansion of B_int
                expected_weights = []
                total = 0
                curr = 1
                while total + curr < expected_b_int:
                    expected_weights.append(curr)
                    total += curr
                    curr *= 2
                if expected_b_int - total > 0:
                    expected_weights.append(expected_b_int - total)

                slack_powers = b_params.get("slack_powers")
                if slack_powers != expected_weights:
                    raise FidelityProofError(
                        f"Proof rejected: QUBO slack powers {slack_powers} != binary expansion {expected_weights}."
                    )
        else:
            if budget_translations:
                raise FidelityProofError(
                    "Proof rejected: Unexpected budget translation present when IR has no budget constraint."
                )

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
        """
        Verifies that PuLP constraints algebraically match the IR semantics.
        Feasibility semantics: x in F(IR) <=> exists z: (x, z) satisfies all backend hard constraints.
        Compares every LHS coefficient of every PuLP constraint to the IR-derived expectation,
        and rejects any variable present in a constraint that the IR does not place there.
        """
        if callable(getattr(prob, "constraints", None)):
            raw_constraints = prob.constraints()
            constraints_dict = {c.name: c for c in raw_constraints}
        elif hasattr(prob, "constraints"):
            constraints_dict = dict(prob.constraints)
        else:
            constraints_dict = {}

        visited_constraints: Set[str] = set()

        # 1. Verify Invariance Constraints from IR
        for r, dom in ir.variable_domains.items():
            cname = f"Invariance_{r}"
            if cname not in constraints_dict and cname.replace("-", "_") in constraints_dict:
                cname = cname.replace("-", "_")
            if cname not in constraints_dict:
                raise FidelityProofError(f"PuLP invariance constraint '{cname}' missing from model.")
            visited_constraints.add(cname)
            c = constraints_dict[cname]

            # Sense == 0 (LpConstraintEQ) and constant == -1.0
            if c.sense != 0:
                raise FidelityProofError(f"PuLP invariance constraint '{cname}' sense is not == (sense={c.sense}).")
            if abs(c.constant + 1.0) > 1e-5:
                raise FidelityProofError(f"PuLP invariance constraint '{cname}' target value mismatch: constant={c.constant}.")

            expected_lhs = {proof.variable_map[(r, a)]: 1.0 for a in dom.admissible_actions}
            actual_lhs = {var.name: float(coeff) for var, coeff in c.items()}

            if set(actual_lhs.keys()) != set(expected_lhs.keys()):
                unexpected = set(actual_lhs.keys()) - set(expected_lhs.keys())
                missing = set(expected_lhs.keys()) - set(actual_lhs.keys())
                raise FidelityProofError(
                    f"PuLP invariance constraint '{cname}' variable mismatch: "
                    f"unexpected={unexpected}, missing={missing}."
                )

            for var, coeff in actual_lhs.items():
                if abs(coeff - 1.0) > 1e-5:
                    raise FidelityProofError(
                        f"PuLP invariance constraint '{cname}' coefficient for {var} is {coeff} != 1.0."
                    )

        # 2. Verify Conflict Hyperedges from IR
        for idx, conf in enumerate(ir.conflict_hyperedges):
            cname = f"Conflict_{idx}_{conf.resource_1}_{conf.action_1}".replace("-", "_")
            if cname not in constraints_dict:
                # Fallback match by endpoints if naming differs
                v1 = proof.variable_map[(conf.resource_1, conf.action_1)]
                v2 = proof.variable_map[(conf.resource_2, conf.action_2)]
                found_cname = None
                for cn, c_obj in constraints_dict.items():
                    if cn.startswith("Conflict") and {v.name for v, _ in c_obj.items()} == {v1, v2}:
                        found_cname = cn
                        break
                if not found_cname:
                    raise FidelityProofError(f"PuLP conflict constraint '{cname}' missing from model.")
                cname = found_cname

            visited_constraints.add(cname)
            c = constraints_dict[cname]

            if c.sense != -1:  # -1 is <=
                raise FidelityProofError(f"PuLP conflict constraint '{cname}' sense is not <= (sense={c.sense}).")
            if abs(c.constant + 1.0) > 1e-5:
                raise FidelityProofError(f"PuLP conflict constraint '{cname}' RHS is not 1.0 (constant={c.constant}).")

            v1 = proof.variable_map[(conf.resource_1, conf.action_1)]
            v2 = proof.variable_map[(conf.resource_2, conf.action_2)]
            expected_lhs = {v1: 1.0, v2: 1.0}
            actual_lhs = {var.name: float(coeff) for var, coeff in c.items()}

            if set(actual_lhs.keys()) != {v1, v2}:
                unexpected = set(actual_lhs.keys()) - {v1, v2}
                missing = {v1, v2} - set(actual_lhs.keys())
                raise FidelityProofError(
                    f"PuLP conflict constraint '{cname}' endpoint mismatch: "
                    f"unexpected={unexpected}, missing={missing}."
                )

            for var, coeff in actual_lhs.items():
                if abs(coeff - 1.0) > 1e-5:
                    raise FidelityProofError(
                        f"PuLP conflict constraint '{cname}' coefficient for {var} is {coeff} != 1.0."
                    )

        # 3. Verify Budget Constraint from IR
        if ir.budget_constraint and ir.budget_constraint.max_budget > 0:
            cname = "Operational_Budget_Ceiling"
            if cname not in constraints_dict:
                raise FidelityProofError(f"PuLP budget constraint '{cname}' missing from model.")
            visited_constraints.add(cname)
            c = constraints_dict[cname]

            if c.sense != -1:
                raise FidelityProofError(f"PuLP budget constraint '{cname}' sense is not <= (sense={c.sense}).")
            expected_max = float(ir.budget_constraint.max_budget)
            if abs(c.constant + expected_max) > 1e-5:
                raise FidelityProofError(
                    f"PuLP budget constraint '{cname}' RHS mismatch: expected {expected_max}, got {-c.constant}."
                )

            expected_budget_vars = {
                proof.variable_map[(r, a)]: float(ir.budget_constraint.cost_map[(r, a)])
                for (r, a) in ir.get_all_variables()
                if float(ir.budget_constraint.cost_map.get((r, a), 0.0)) > 0
            }
            actual_lhs = {var.name: float(coeff) for var, coeff in c.items()}

            if set(actual_lhs.keys()) != set(expected_budget_vars.keys()):
                unexpected = set(actual_lhs.keys()) - set(expected_budget_vars.keys())
                missing = set(expected_budget_vars.keys()) - set(actual_lhs.keys())
                raise FidelityProofError(
                    f"PuLP budget constraint variable mismatch: "
                    f"unexpected={unexpected}, missing={missing}."
                )

            for var, coeff in actual_lhs.items():
                exp_c = expected_budget_vars[var]
                if abs(coeff - exp_c) > 1e-5:
                    raise FidelityProofError(
                        f"PuLP budget constraint coefficient for {var} is {coeff} != expected {exp_c}."
                    )

        # 4. Reject any uncertified constraint in PuLP model not derived from IR
        unaccounted_constraints = set(constraints_dict.keys()) - visited_constraints
        if unaccounted_constraints:
            raise FidelityProofError(
                f"PuLP model contains uncertified constraints not placed by the IR: {unaccounted_constraints}."
            )

    @classmethod
    def _check_qubo_algebraic_equivalence(
        cls,
        ir: SecurityConstraintIR,
        qp: Any,
        proof: FidelityProof,
    ) -> None:
        """
        Verifies that the compiled QUBO model algebraically matches the expected objective
        reconstructed directly from the proof translations and recomputed IR objective terms.
        Verifies dominating penalty bounds from verified translation parameters.
        """
        if not (
            hasattr(qp, "objective")
            and hasattr(qp.objective, "quadratic")
            and hasattr(qp.objective, "linear")
            and hasattr(qp.objective, "constant")
        ):
            raise FidelityProofError("QuadraticProgram model is missing objective or objective components.")

        # 1. Read the model directly via the official model APIs
        raw_model_quad = qp.objective.quadratic.to_dict(use_name=True)
        raw_model_lin = qp.objective.linear.to_dict(use_name=True)
        model_const = float(qp.objective.constant)

        # Canonicalize model quadratic dictionary symmetrically (u <= v)
        model_quad: Dict[Tuple[str, str], float] = {}
        for (u, v), val in raw_model_quad.items():
            pair = (u, v) if u <= v else (v, u)
            model_quad[pair] = model_quad.get(pair, 0.0) + float(val)

        model_lin: Dict[str, float] = {k: float(v) for k, v in raw_model_lin.items()}

        # 2. Reconstruct expected objective from the PROOF alone
        recon_lin: Dict[str, float] = {}
        recon_quad: Dict[Tuple[str, str], float] = {}
        recon_const: float = 0.0

        def add_quad(u: str, v: str, val: float) -> None:
            pair = (u, v) if u <= v else (v, u)
            recon_quad[pair] = recon_quad.get(pair, 0.0) + float(val)

        def add_lin(v: str, val: float) -> None:
            recon_lin[v] = recon_lin.get(v, 0.0) + float(val)

        # 2a. Recompute base IR objective linear terms from ir.objective_terms
        for (rid, act), term in ir.objective_terms.items():
            vname = proof.variable_map.get((rid, act))
            if vname:
                add_lin(vname, float(term.coefficient))

        # 2b. Add penalty term expansions for each constraint translation from proof
        for trans in proof.constraint_translations:
            ctype = trans.get("ir_constraint_type")
            params = trans.get("parameters", {})
            elems = trans.get("backend_elements", [])

            if ctype == "INVARIANCE":
                if "penalty" not in params:
                    raise FidelityProofError(
                        f"Invariance translation '{trans.get('ir_constraint_id')}' missing explicit 'penalty' parameter."
                    )
                w = float(params["penalty"])
                # Expansion: w * (sum x - 1)^2 = w * (sum x_i - 2 * sum x_i + 2 * sum_{i<j} x_i x_j + 1)
                #            = -w * sum x_i + 2*w * sum_{i<j} x_i x_j + w
                recon_const += w
                for v in elems:
                    add_lin(v, -w)
                for i in range(len(elems)):
                    for j in range(i + 1, len(elems)):
                        add_quad(elems[i], elems[j], 2.0 * w)

            elif ctype == "CONFLICT":
                if "penalty" not in params:
                    raise FidelityProofError(
                        f"Conflict translation '{trans.get('ir_constraint_id')}' missing explicit 'penalty' parameter."
                    )
                w = float(params["penalty"])
                if len(elems) >= 2:
                    add_quad(elems[0], elems[1], w)

            elif ctype == "BUDGET":
                if "penalty" not in params:
                    raise FidelityProofError(
                        f"Budget translation '{trans.get('ir_constraint_id')}' missing explicit 'penalty' parameter."
                    )
                w = float(params["penalty"])
                cost_scale = int(params.get("cost_scale", 1000))
                b_int = int(params["budget_int"]) if "budget_int" in params else int(round(float(params["max_budget"]) * cost_scale))

                # Slack powers
                slack_powers = params.get("slack_powers")
                if slack_powers is None:
                    slack_weights = params.get("slack_weights", [])
                    slack_powers = [int(round(float(sw) * cost_scale)) for sw in slack_weights]

                # Variable costs - derived exclusively from IR; proof must NOT supply variable_costs
                if "variable_costs" in params:
                    raise FidelityProofError("Proof rejected: Budget translation must not supply variable_costs; costs must be derived from IR.")
                if ir.budget_constraint:
                    var_costs = {
                        proof.variable_map[(r, a)]: int(round(float(c) * cost_scale))
                        for (r, a), c in ir.budget_constraint.cost_map.items()
                        if (r, a) in proof.variable_map
                    }
                else:
                    var_costs = {}

                # Combined integer terms: (var_name, int_coefficient)
                int_terms: List[Tuple[str, int]] = []
                for vname, c_int in var_costs.items():
                    int_terms.append((vname, c_int))
                for sname, sp in zip(elems, slack_powers):
                    int_terms.append((sname, sp))

                # Expansion: w * (sum c_i x_i + sum slack_k * 2^k - B_int)^2 in the scaled integer space
                recon_const += float(w * (b_int ** 2))
                for v, a in int_terms:
                    add_lin(v, float(w * (a ** 2 - 2 * b_int * a)))
                for i in range(len(int_terms)):
                    v1, a1 = int_terms[i]
                    for j in range(i + 1, len(int_terms)):
                        v2, a2 = int_terms[j]
                        add_quad(v1, v2, float(2.0 * w * a1 * a2))

        # 3. Assert coefficient-by-coefficient equality (tolerance 1e-6)
        # Check constant
        if abs(model_const - recon_const) > 1e-6:
            raise FidelityProofError(
                f"QUBO objective constant mismatch: model={model_const:.6f}, reconstructed={recon_const:.6f} "
                f"(diff={abs(model_const - recon_const):.6e})."
            )

        # Check linear coefficients
        all_lin_keys = sorted(set(model_lin) | set(recon_lin))
        for key in all_lin_keys:
            m_val = float(model_lin.get(key, 0.0))
            r_val = float(recon_lin.get(key, 0.0))
            if abs(m_val - r_val) > 1e-6:
                raise FidelityProofError(
                    f"QUBO linear coefficient mismatch for key '{key}': model={m_val:.6f}, "
                    f"reconstructed={r_val:.6f} (diff={abs(m_val - r_val):.6e})."
                )

        # Check quadratic coefficients
        all_quad_keys = sorted(set(model_quad) | set(recon_quad))
        for key in all_quad_keys:
            m_val = float(model_quad.get(key, 0.0))
            r_val = float(recon_quad.get(key, 0.0))
            if abs(m_val - r_val) > 1e-6:
                raise FidelityProofError(
                    f"QUBO quadratic coefficient mismatch for key '{key}': model={m_val:.6f}, "
                    f"reconstructed={r_val:.6f} (diff={abs(m_val - r_val):.6e})."
                )

        # 4. Dominance: minimum penalty weight across translations (from the now-verified parameters)
        # must exceed the range bound recomputed from ir.objective_terms.
        translation_penalties = [
            float(t["parameters"]["penalty"])
            for t in proof.constraint_translations
            if "penalty" in t.get("parameters", {})
        ]
        if not translation_penalties:
            raise FidelityProofError("QUBO proof verification failed: No penalty parameters found in constraint translations.")

        min_penalty = min(translation_penalties)
        recomputed_range_bound = sum(abs(t.coefficient) for t in ir.objective_terms.values())

        if min_penalty <= recomputed_range_bound:
            raise FidelityProofError(
                f"QUBO dominating penalty check failed: verified minimum translation penalty {min_penalty:.4f} <= "
                f"recomputed objective range bound {recomputed_range_bound:.4f}. "
                "Feasibility of the ground state is not guaranteed."
            )

        # Assert proof.penalty_coefficient equals that minimum
        if proof.penalty_coefficient is None or abs(proof.penalty_coefficient - min_penalty) > 1e-6:
            raise FidelityProofError(
                f"QUBO proof penalty mismatch: proof reports {proof.penalty_coefficient}, "
                f"but verified minimum translation penalty is {min_penalty:.4f}."
            )

        # 5. Check slack variables for exact integer budget representation
        budget_trans = next((t for t in proof.constraint_translations if t.get("ir_constraint_type") == "BUDGET"), None)
        if budget_trans:
            b_params = budget_trans.get("parameters", {})
            budget_int = b_params.get("budget_int", 0)
            cost_scale = b_params.get("cost_scale", 1000)
            slack_weights = b_params.get("slack_weights", [])

            total_slack = sum(slack_weights)
            expected_budget = budget_int / cost_scale
            if abs(total_slack - expected_budget) > 1e-4:
                raise FidelityProofError(
                    f"QUBO slack representation residual error: sum of slack weights ({total_slack}) "
                    f"!= budget ({expected_budget})."
                )
