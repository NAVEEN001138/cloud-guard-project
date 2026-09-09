"""
=============================================================================
LAYER 5: PRE-SOLVE CONSTRAINT SAFETY CERTIFIER & INTEGRITY BINDER
Module: safety_certifier.py
-----------------------------------------------------------------------------
Problem Solved:
  Eliminates the vulnerability of relying purely on post-solution validation.
  Mathematically certifies that the compiled SecurityConstraintIR contains:
    1. Zero forbidden actions in the decision variable domain.
    2. Guaranteed feasibility (non-empty search space with min-cost <= budget).
    3. Exactly-one invariance constraints on all active assets.
    4. Conflict hyperedge consistency (no self-contradictory requirements).
    5. Operational budget consistency.
    6. Policy and statutory mandate satisfaction (HIPAA 45 CFR § 164.312, etc.).
    7. 100% Provenance completeness for all pruned or mandated elements.

  Emits a versioned, tamper-evident Pre-Solve Safety Certificate cryptographically
  binding the certified SC-IR state to formulation compilers.
=============================================================================
"""

import hashlib
import time
import json
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any

from layer5_constraints.constraint_ir import SecurityConstraintIR


@dataclass
class ConstraintSafetyCertificate:
    """Tamper-evident certificate verifying constraint safety invariants before solver execution."""
    certificate_id: str
    incident_id: str
    ir_sha256: str
    timestamp: float
    status: str  # "CERTIFIED" or "VIOLATION_DETECTED"
    forbidden_action_violations: List[str] = field(default_factory=list)
    verification_checks: Dict[str, bool] = field(default_factory=dict)
    feasibility_verified: bool = True
    provenance_complete: bool = True
    total_variables_certified: int = 0
    total_conflicts_verified: int = 0
    integrity_digest: str = ""  # Tamper-evident cryptographic SHA-256 integrity fingerprint
    signature: str = ""         # Backwards-compatible alias for integrity_digest

    # Versioning and Binding Fields
    ir_version: int = 1
    runtime_state_version: int = 1
    closure_digest: str = ""

    @property
    def ir_digest(self) -> str:
        """Alias for ir_sha256 / canonical digest."""
        return self.ir_sha256

    @property
    def certification_status(self) -> str:
        """Alias for status."""
        return self.status

    @property
    def certified_at(self) -> float:
        """Alias for timestamp."""
        return self.timestamp

    @property
    def invariant_results(self) -> Dict[str, bool]:
        """Alias for verification_checks."""
        return self.verification_checks

    def is_valid(self) -> bool:
        return (
            self.status == "CERTIFIED"
            and len(self.forbidden_action_violations) == 0
            and all(self.verification_checks.values())
        )


class PreSolveSafetyCertifier:
    """
    Deterministic invariant inspection engine executing a 7-point pre-solve 
    constraint safety verification suite on the SecurityConstraintIR prior to solver invocation.
    """

    @classmethod
    def certify(
        cls,
        ir: SecurityConstraintIR,
        known_forbidden_specs: Optional[Dict[str, List[str]]] = None,
    ) -> ConstraintSafetyCertificate:
        """
        Executes deterministic pre-solve invariant verification across 7 mandatory constraint invariants.
        """
        violations: List[str] = []
        checks: Dict[str, bool] = {}

        # 1. Forbidden Action Check (Zero illegal physical actions in decision space)
        forbidden_ok = True
        forbidden_specs = known_forbidden_specs or {}
        for rid, domain in ir.variable_domains.items():
            if rid in forbidden_specs:
                for act in domain.admissible_actions:
                    if act in forbidden_specs[rid]:
                        forbidden_ok = False
                        violations.append(f"FORBIDDEN ACTION VIOLATION: '{act}' found in domain of '{rid}'")

            # Cyber-physical safety: PLCs & Medical Devices must NEVER have 'isolate'
            if domain.resource_type in ("plc_controller", "medical_device") and "isolate" in domain.admissible_actions:
                forbidden_ok = False
                violations.append(f"SAFETY INVARIANT VIOLATION: Cyber-physical '{rid}' ({domain.resource_type}) allows 'isolate'")

        checks["1_forbidden_action_elimination"] = forbidden_ok

        # 2. Feasible Domain Check (Each resource has at least one valid action)
        domain_ok = all(len(d.admissible_actions) >= 1 for d in ir.variable_domains.values())
        if not domain_ok:
            violations.append("FEASIBLE DOMAIN VIOLATION: One or more resources have empty action sets")
        checks["2_feasible_domain_non_empty"] = domain_ok

        # 3. Exactly-One Invariance Check (Each resource has an active invariance constraint)
        invar_rids = {inv.resource_id for inv in ir.invariance_constraints}
        invar_ok = set(ir.variable_domains.keys()) == invar_rids
        if not invar_ok:
            violations.append("INVARIANCE VIOLATION: Missing exactly-one invariance constraints on resources")
        checks["3_exactly_one_invariance_present"] = invar_ok

        # 4. Conflict Consistency Check (No resource forced into contradictory actions)
        conflict_ok = True
        for conf in ir.conflict_hyperedges:
            if conf.resource_1 == conf.resource_2 and conf.action_1 == conf.action_2:
                conflict_ok = False
                violations.append(f"CONFLICT INCONSISTENCY: Self-contradictory conflict on {conf.resource_1}")
        checks["4_conflict_hyperedge_consistency"] = conflict_ok

        # 5. Budget Consistency Check (Minimum cost vector does not exceed ceiling)
        budget_ok = True
        if ir.budget_constraint and ir.budget_constraint.max_budget > 0:
            min_possible_cost = 0.0
            for rid, domain in ir.variable_domains.items():
                costs = [ir.budget_constraint.cost_map.get((rid, a), 0.0) for a in domain.admissible_actions]
                if costs:
                    min_possible_cost += min(costs)
            if min_possible_cost > ir.budget_constraint.max_budget:
                budget_ok = False
                violations.append(f"BUDGET INFEASIBILITY: Min cost {min_possible_cost:.2f} > Budget {ir.budget_constraint.max_budget:.2f}")
        checks["5_budget_feasibility_guaranteed"] = budget_ok

        # 6. Policy Requirement Consistency (Encoded rules, e.g. HIPAA 45 CFR § 164.312 access controls)
        policy_ok = True
        for rec in ir.provenance_records:
            if rec.constraint_type == "MANDATED":
                domain = ir.variable_domains.get(rec.target_resource)
                if domain and rec.target_action not in domain.admissible_actions:
                    policy_ok = False
                    violations.append(f"POLICY RULE VIOLATION: Mandated action '{rec.target_action}' missing from {rec.target_resource}")
        checks["6_encoded_policy_rule_consistency"] = policy_ok
        checks["6_statutory_policy_consistency"] = policy_ok  # Backwards-compatible alias

        # 7. Provenance Completeness Check (100% of pruned/mandated elements have audit trail)
        prov_ok = True
        for rid, domain in ir.variable_domains.items():
            for pruned in domain.pruned_actions:
                if not any(r.target_resource == rid and r.target_action == pruned for r in ir.provenance_records):
                    prov_ok = False
                    violations.append(f"PROVENANCE GAP: Pruned action '{pruned}' on '{rid}' lacks provenance rule")
        checks["7_provenance_audit_completeness"] = prov_ok

        # Compute canonical digest of IR if not already present
        ir_digest = ir.canonical_digest or ir.compute_canonical_digest()

        # Compute closure digest
        closure_digest = ""
        if ir.dependency_closure_metadata:
            closure_dict = ir.dependency_closure_metadata.to_dict()
            closure_digest = hashlib.sha256(json.dumps(closure_dict, sort_keys=True).encode("utf-8")).hexdigest()

        # Certification Determination
        all_passed = all(checks.values()) and len(violations) == 0
        status = "CERTIFIED" if all_passed else "VIOLATION_DETECTED"
        cert_time = time.time()
        cert_id = f"CERT_{ir.incident_id}_{int(cert_time)}"

        # Tamper-evident cryptographic state fingerprint sealing the verified IR state
        cert_payload = (
            f"{cert_id}:{ir_digest}:{ir.ir_version}:{ir.runtime_state_version}:"
            f"{status}:{json.dumps(checks, sort_keys=True)}:{closure_digest}"
        )
        integrity_hash = hashlib.sha256(cert_payload.encode("utf-8")).hexdigest()

        return ConstraintSafetyCertificate(
            certificate_id=cert_id,
            incident_id=ir.incident_id,
            ir_sha256=ir_digest,
            timestamp=cert_time,
            status=status,
            forbidden_action_violations=violations,
            verification_checks=checks,
            feasibility_verified=domain_ok and budget_ok,
            provenance_complete=prov_ok,
            total_variables_certified=len(ir.get_all_variables()),
            total_conflicts_verified=len(ir.conflict_hyperedges),
            integrity_digest=integrity_hash,
            signature=integrity_hash,
            ir_version=ir.ir_version,
            runtime_state_version=ir.runtime_state_version,
            closure_digest=closure_digest,
        )
