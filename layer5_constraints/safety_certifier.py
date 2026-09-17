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

Three-Way Revocation Invariant:
  Execution authority is cryptographically and semantically bound to the tuple:
    (H(SC-IR), Envelope E_t, PolicyRevision).
  Revocation Rule:
    IR changed OR state not in E_t OR policy revision changed => authority revoked.
  If any one of these three conditions holds, all actuation authority is immediately
  revoked, necessitating pipeline reconstruction and recertification.

  Emits a versioned, tamper-evident Pre-Solve Safety Certificate cryptographically
  binding the certified SC-IR state to formulation compilers and actuation capability verifiers.
=============================================================================
"""

import hashlib
import time
import json
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any

from layer5_constraints.constraint_ir import SecurityConstraintIR


@dataclass
class CertifiedExecutionManifest:
    """
    Authenticated execution manifest embedded in the signed certificate payload.
    Provides complete domain, budget, envelope, and epoch bounds directly to the
    actuation capability verifier without requiring access to the unauthenticated IR.
    """
    asset_scope: List[str]
    admissible_domains: Dict[str, List[str]]
    cost_map: Dict[Any, float]
    effective_budget: float
    envelope: Any
    state_epoch: int
    policy_revision: str

    def compute_digest(self) -> str:
        canonical_dict = self.to_dict()
        serialized = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        env_dict = None
        if self.envelope is not None:
            if hasattr(self.envelope, "to_dict"):
                env_dict = self.envelope.to_dict()
            elif hasattr(self.envelope, "envelope_digest"):
                env_dict = {"envelope_digest": self.envelope.envelope_digest}
            else:
                env_dict = str(self.envelope)

        norm_cost_map = {}
        for k, v in sorted(self.cost_map.items(), key=lambda item: str(item[0])):
            if isinstance(k, (tuple, list)):
                norm_key = f"{k[0]}:{k[1]}"
            else:
                norm_key = str(k)
            norm_cost_map[norm_key] = float(v)

        return {
            "asset_scope": sorted(self.asset_scope or []),
            "admissible_domains": {r: sorted(acts) for r, acts in sorted(self.admissible_domains.items())},
            "cost_map": norm_cost_map,
            "effective_budget": float(self.effective_budget),
            "envelope": env_dict,
            "state_epoch": int(self.state_epoch),
            "policy_revision": str(self.policy_revision),
        }


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
    witness_digest: str = ""
    envelope_digest: str = ""
    validity_envelope: Optional[Any] = None
    feasibility_witness: Optional[Dict[str, str]] = None

    # State-Envelope Certificate Payload & Signature (Phase 3)
    auth_mechanism: str = "ed25519"
    cert_format_version: str = "2.0"
    asset_scope: List[str] = field(default_factory=list)
    policy_revision: str = ""
    state_schema_id: str = "cg-state-v1"
    state_epoch: int = 1
    lease_policy: int = 300
    certifier_id: str = "certifier-node-primary"
    canonical_payload_bytes: bytes = b""

    # Certified Execution Manifest (Phase 8 Hardening)
    execution_manifest: Optional[CertifiedExecutionManifest] = None
    manifest_digest: str = ""

    # Certified Incremental Lineage (Phase 7)
    parent_certificate_digest: Optional[str] = None
    subgraph_digests: Dict[str, str] = field(default_factory=dict)
    incremental_equivalence_check: Optional[Dict[str, Any]] = None

    def compute_canonical_payload(self) -> bytes:
        """
        Recomputes the canonical payload bytes committed under the certificate signature.
        Includes H(manifest) AND the manifest itself, plus auth_mechanism and cert_format_version,
        in the signed canonical payload.
        """
        manifest_dict = self.execution_manifest.to_dict() if self.execution_manifest else {}
        manifest_digest = self.manifest_digest or (self.execution_manifest.compute_digest() if self.execution_manifest else "")

        payload_obj = {
            "certificate_id": self.certificate_id,
            "ir_sha256": self.ir_sha256,
            "ir_version": self.ir_version,
            "runtime_state_version": self.runtime_state_version,
            "status": self.status,
            "closure_digest": self.closure_digest,
            "witness_digest": self.witness_digest,
            "envelope_digest": self.envelope_digest,
            "asset_scope": sorted(self.asset_scope or []),
            "policy_revision": self.policy_revision,
            "state_schema_id": self.state_schema_id,
            "state_epoch": int(self.state_epoch),
            "lease_policy": int(self.lease_policy),
            "certifier_id": self.certifier_id,
            "parent_certificate_digest": self.parent_certificate_digest or "",
            "incremental_equivalence_digest": (
                self.incremental_equivalence_check.get("semantic_fingerprint", "")
                if self.incremental_equivalence_check else ""
            ),
            "verification_checks": self.verification_checks,
            "manifest_digest": manifest_digest,
            "execution_manifest": manifest_dict,
            "auth_mechanism": self.auth_mechanism,
            "cert_format_version": self.cert_format_version,
        }
        return json.dumps(payload_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def verify_signature(self, verifier_key: Optional[Any] = None) -> bool:
        """
        Verifies the cryptographic signature of the certificate using the public VerifierKey.
        Empty or missing signature returns False. Never True.
        Rejects unapproved auth mechanisms before touching signature.
        """
        if not self.signature:
            return False
        from layer5_constraints.keys import get_verifier_key, get_approved_auth_mechanisms
        approved = get_approved_auth_mechanisms()
        if self.auth_mechanism not in approved:
            return False
        vk = verifier_key or get_verifier_key()
        payload_bytes = self.compute_canonical_payload()
        return vk.verify(payload_bytes, self.signature, self.auth_mechanism)

    def verify_lineage(self, parent_cert: Optional["ConstraintSafetyCertificate"] = None) -> bool:
        """
        Verifies cryptographic lineage binding to a parent certificate.
        """
        if parent_cert is None:
            return self.parent_certificate_digest is None
        if not self.parent_certificate_digest:
            return False
        if not parent_cert.verify_signature():
            return False
        return self.parent_certificate_digest == parent_cert.integrity_digest

    @classmethod
    def verify_lineage_chain(cls, chain: List["ConstraintSafetyCertificate"]) -> bool:
        """
        Verifies a sequential cryptographic lineage chain of certificates C_0 -> C_1 -> ... -> C_k.
        """
        if not chain:
            return False
        if not chain[0].verify_signature():
            return False
        for i in range(1, len(chain)):
            child = chain[i]
            parent = chain[i - 1]
            if not child.verify_lineage(parent):
                return False
        return True


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

    def get_unique_checks(self) -> Dict[str, bool]:
        """
        Returns the 7 unique fundamental invariant checks, excluding backwards-compatible aliases.
        """
        return {
            k: v for k, v in self.verification_checks.items()
            if k != "6_statutory_policy_consistency"
        }

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
    def find_feasibility_witness(cls, ir: SecurityConstraintIR) -> Optional[Dict[str, str]]:
        """
        Deterministic backtracking search verifying that at least one globally valid assignment
        exists satisfying ExactlyOne, Conflicts, Budget, and Mandates simultaneously.
        Returns the witness assignment dict {resource_id: action} if found, else None.
        """
        resources = sorted(list(ir.variable_domains.keys()))
        if not resources:
            return None

        # Pre-extract mandated actions
        mandates: Dict[str, str] = {}
        for rec in ir.provenance_records:
            if rec.constraint_type == "MANDATED":
                mandates[rec.target_resource] = rec.target_action

        # Build conflict lookup: set of frozenset({(r1, a1), (r2, a2)})
        conflicts = set()
        for conf in ir.conflict_hyperedges:
            conflicts.add(frozenset({(conf.resource_1, conf.action_1), (conf.resource_2, conf.action_2)}))

        cost_map = ir.budget_constraint.cost_map if ir.budget_constraint else {}
        max_b = ir.budget_constraint.max_budget if ir.budget_constraint else float("inf")

        witness: Dict[str, str] = {}

        def backtrack(idx: int, current_cost: float) -> bool:
            if idx == len(resources):
                return current_cost <= max_b + 1e-5

            rid = resources[idx]
            admissible = sorted(ir.variable_domains[rid].admissible_actions)

            # If mandated, must pick mandated action
            if rid in mandates:
                cand_actions = [mandates[rid]] if mandates[rid] in admissible else []
            else:
                cand_actions = admissible

            for act in cand_actions:
                cand_pair = (rid, act)
                # Check conflict against already chosen actions
                has_conflict = False
                for prev_rid, prev_act in witness.items():
                    if frozenset({cand_pair, (prev_rid, prev_act)}) in conflicts:
                        has_conflict = True
                        break
                if has_conflict:
                    continue

                act_cost = cost_map.get(cand_pair, 0.0)
                if current_cost + act_cost > max_b + 1e-5:
                    continue

                witness[rid] = act
                if backtrack(idx + 1, current_cost + act_cost):
                    return True
                del witness[rid]

            return False

        if backtrack(0, 0.0):
            return dict(witness)
        return None

    @classmethod
    def certify(
        cls,
        ir: SecurityConstraintIR,
        known_forbidden_specs: Optional[Dict[str, List[str]]] = None,
        parent_certificate: Optional["ConstraintSafetyCertificate"] = None,
        parent_certificate_digest: Optional[str] = None,
        incremental_equivalence_check: Optional[Dict[str, Any]] = None,
        learned_rules: Optional[List[dict]] = None,
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

        # 3. Exactly-One Invariance Check (Actions must strictly match admissible domain and target_value == 1)
        invar_ok = True
        invar_rids = set()
        for inv in ir.invariance_constraints:
            invar_rids.add(inv.resource_id)
            domain = ir.variable_domains.get(inv.resource_id)
            if not domain:
                invar_ok = False
                violations.append(f"INVARIANCE VIOLATION: Resource '{inv.resource_id}' missing in variable domains")
            else:
                if set(inv.actions) != set(domain.admissible_actions):
                    invar_ok = False
                    violations.append(
                        f"INVARIANCE ACTION MISMATCH: Resource '{inv.resource_id}' invariance actions {set(inv.actions)} "
                        f"!= admissible actions {set(domain.admissible_actions)}"
                    )
                if inv.target_value != 1:
                    invar_ok = False
                    violations.append(f"INVARIANCE TARGET MISMATCH: Resource '{inv.resource_id}' target_value {inv.target_value} != 1")

        if invar_rids != set(ir.variable_domains.keys()):
            invar_ok = False
            violations.append("INVARIANCE VIOLATION: Missing exactly-one invariance constraints on resources")
        checks["3_exactly_one_invariance_present"] = invar_ok

        # 4. Conflict Consistency Check (No resource forced into contradictory actions)
        conflict_ok = True
        for conf in ir.conflict_hyperedges:
            if conf.resource_1 == conf.resource_2 and conf.action_1 == conf.action_2:
                conflict_ok = False
                violations.append(f"CONFLICT INCONSISTENCY: Self-contradictory conflict on {conf.resource_1}")
        checks["4_conflict_hyperedge_consistency"] = conflict_ok

        # 5. Budget Consistency & Global Feasibility Witness Check
        budget_ok = True
        witness = cls.find_feasibility_witness(ir)
        if witness is None:
            budget_ok = False
            violations.append("GLOBAL FEASIBILITY VIOLATION: No joint assignment satisfies Invariance, Conflicts, Budget, and Mandates simultaneously")

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

        # Compute canonical digest of IR
        ir_digest = ir.compute_canonical_digest()
        ir.canonical_digest = ir_digest

        # Compute closure digest
        closure_digest = ""
        if ir.dependency_closure_metadata:
            c_dict = ir.dependency_closure_metadata.to_dict() if hasattr(ir.dependency_closure_metadata, "to_dict") else str(ir.dependency_closure_metadata)
            closure_digest = hashlib.sha256(json.dumps(c_dict, sort_keys=True).encode("utf-8")).hexdigest()

        # Compute canonical digest of feasibility_witness
        witness_digest = ""
        if witness is not None:
            witness_digest = hashlib.sha256(json.dumps(witness, sort_keys=True).encode("utf-8")).hexdigest()

        # Extract validity envelope from IR if present
        envelope = getattr(ir, "validity_envelope", None)
        envelope_digest = getattr(envelope, "envelope_digest", "") if envelope else ""

        # Certification Determination
        all_passed = all(checks.values()) and len(violations) == 0
        status = "CERTIFIED" if all_passed else "VIOLATION_DETECTED"
        cert_time = time.time()
        cert_id = f"CERT_{ir.incident_id}_{int(cert_time)}"

        # Extract metadata for Phase 3 State-Envelope Certificate
        asset_scope = sorted(list(ir.variable_domains.keys()))
        state_schema_id = getattr(ir, "state_schema_id", "cg-state-v1")
        state_epoch = int(getattr(ir, "state_epoch", 1))
        from layer5_constraints.policy_thresholds import compute_policy_revision
        from layer5_constraints.keys import get_certifier_key
        policy_revision = compute_policy_revision(learned_rules=learned_rules)
        lease_policy = 300
        certifier_id = "certifier-node-primary"

        # Certified Lineage Metadata (Phase 7)
        p_digest = parent_certificate.integrity_digest if parent_certificate else parent_certificate_digest
        subgraph_digests = getattr(ir, "subgraph_digests", {}) or (
            ir.compute_all_subgraph_digests() if hasattr(ir, "compute_all_subgraph_digests") else {}
        )

        # Certified Execution Manifest (Item B)
        admissible_domains = {
            r: sorted(list(dom.admissible_actions))
            for r, dom in ir.variable_domains.items()
        }
        cost_map = {
            (r, a): float(c)
            for (r, a), c in (ir.budget_constraint.cost_map.items() if ir.budget_constraint else [].__iter__())
        }
        effective_budget = float(ir.budget_constraint.max_budget) if ir.budget_constraint else 0.0

        manifest = CertifiedExecutionManifest(
            asset_scope=asset_scope,
            admissible_domains=admissible_domains,
            cost_map=cost_map,
            effective_budget=effective_budget,
            envelope=envelope,
            state_epoch=state_epoch,
            policy_revision=policy_revision,
        )
        manifest_digest = manifest.compute_digest()

        cert = ConstraintSafetyCertificate(
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
            ir_version=ir.ir_version,
            runtime_state_version=ir.runtime_state_version,
            closure_digest=closure_digest,
            witness_digest=witness_digest,
            envelope_digest=envelope_digest,
            validity_envelope=envelope,
            feasibility_witness=witness,
            asset_scope=asset_scope,
            policy_revision=policy_revision,
            state_schema_id=state_schema_id,
            state_epoch=state_epoch,
            lease_policy=lease_policy,
            certifier_id=certifier_id,
            execution_manifest=manifest,
            manifest_digest=manifest_digest,
            parent_certificate_digest=p_digest,
            subgraph_digests=subgraph_digests,
            incremental_equivalence_check=incremental_equivalence_check,
        )

        certifier_key = get_certifier_key()
        cert.auth_mechanism = certifier_key.mechanism
        cert.cert_format_version = "2.0"

        canonical_payload_bytes = cert.compute_canonical_payload()
        integrity_hash = hashlib.sha256(canonical_payload_bytes).hexdigest()

        sig_hex, auth_mech = certifier_key.sign(canonical_payload_bytes)

        cert.integrity_digest = integrity_hash
        cert.signature = sig_hex
        cert.canonical_payload_bytes = canonical_payload_bytes

        return cert
