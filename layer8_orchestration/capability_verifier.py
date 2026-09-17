"""
=============================================================================
LAYER 8: ACTUATION CAPABILITY VERIFIER
Module: capability_verifier.py
-----------------------------------------------------------------------------
Architectural Role:
  Acts as the final, independent pre-actuation verifier at the Layer 8 boundary.
  Imports NOTHING from layer5 compiler or solver modules (only the certificate,
  envelope, state snapshot data classes and public-key verifier).

Verification Pipeline:
  1. Cryptographic digital signature check (Ed25519 / HMAC-SHA256).
  2. Certificate lease validity check (max age seconds).
  3. Validity envelope containment check (snapshot in envelope).
  4. State epoch monotonicity check (snapshot.epoch >= certificate.state_epoch).
  5. Admissible domain containment (plan actions in certified variable domains).
  6. Budget ceiling containment (plan cost <= certified budget).

Emits:
  ActuationAuthorization carrying expected_state_revision = snapshot.epoch.
=============================================================================
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any

from layer5_constraints.safety_certifier import ConstraintSafetyCertificate
from layer5_constraints.validity_envelope import ValidityEnvelope, StateEnvelopeViolationError
from layer5_constraints.runtime_state import StateSnapshot
from layer5_constraints.keys import VerifierKey, get_verifier_key
from layer5_constraints.constraint_ir import SecurityConstraintIR

NON_DOMAIN_ACTIONS = frozenset({"notify_soc", "human_approval"})


class ActuationVerificationError(Exception):
    """Raised when an actuation capability verification check fails."""
    pass


class ActuationEnvelopeViolationError(ActuationVerificationError, StateEnvelopeViolationError):
    """Raised when runtime state drifts outside certified validity envelope."""
    pass


class InadmissibleActionError(ActuationVerificationError):
    """Raised when a plan contains an action outside the certified admissible domain."""
    pass


class ActuationBudgetExceededError(ActuationVerificationError):
    """Raised when a plan's total cost exceeds the certified regenerated budget."""
    pass


@dataclass
class ActuationAuthorization:
    """
    Cryptographically and semantically verified authorization ticket for Layer 8 actuation.
    Invariant: is_authorized => domain_authenticated.
    """
    is_authorized: bool
    expected_state_revision: int
    certificate_id: str
    authorized_actions: Dict[str, str]
    auth_timestamp: float
    domain_authenticated: bool = True
    domain_certified: bool = True  # Backward compatibility alias
    envelope_valid: bool = True
    epoch_valid: bool = True
    details: Dict[str, Any] = field(default_factory=dict)


class ActuationCapabilityVerifier:
    """
    Independent pre-actuation verification gate.
    Certificate-only actuation: Domain, budget, envelope, and epoch decisions
    come ONLY from the authenticated manifest within the certificate.
    """

    @classmethod
    def authorize(
        cls,
        plan: Dict[str, str],
        certificate: Optional[ConstraintSafetyCertificate],
        current_snapshot: Optional[StateSnapshot] = None,
        public_key: Optional[VerifierKey] = None,
    ) -> ActuationAuthorization:
        """
        Enforces complete pre-actuation verification sequence.
        Domain and budget decisions come ONLY from the authenticated manifest.
        Raises ActuationVerificationError on any refusal.
        """
        if certificate is None:
            raise ActuationVerificationError("Actuation refused: Missing safety certificate.")

        # 0. Certificate Status and Invariant Verification
        if certificate.status != "CERTIFIED":
            raise ActuationVerificationError(
                f"Actuation refused: Certificate status is '{certificate.status}', expected 'CERTIFIED'."
            )
        checks = getattr(certificate, "verification_checks", {})
        if not checks or not all(checks.values()):
            failed_checks = [k for k, v in checks.items() if not v]
            raise ActuationVerificationError(
                f"Actuation refused: Certificate safety invariants failed or incomplete: {failed_checks}."
            )

        # 1. Manifest Presence and Integrity
        manifest = getattr(certificate, "execution_manifest", None)
        if manifest is None:
            raise ActuationVerificationError("Actuation refused: Certificate has no CertifiedExecutionManifest.")

        expected_manifest_digest = getattr(certificate, "manifest_digest", "")
        computed_manifest_digest = manifest.compute_digest()
        if expected_manifest_digest and computed_manifest_digest != expected_manifest_digest:
            raise ActuationVerificationError(
                f"Actuation refused: Execution manifest digest mismatch. "
                f"Expected '{expected_manifest_digest[:16]}...', computed '{computed_manifest_digest[:16]}...'."
            )

        # 2. Signature Verification
        vk = public_key or get_verifier_key()
        if not certificate.verify_signature(vk):
            raise ActuationVerificationError(
                "Actuation refused: Invalid certificate cryptographic signature."
            )

        # 3. Policy Revision Verification against verifier's own deployed POLICY_REVISION
        from layer5_constraints.policy_thresholds import POLICY_REVISION as DEPLOYED_POLICY_REVISION
        if manifest.policy_revision != DEPLOYED_POLICY_REVISION:
            raise ActuationVerificationError(
                f"Actuation refused: Policy revision mismatch. Manifest has '{manifest.policy_revision}', "
                f"deployed system requires '{DEPLOYED_POLICY_REVISION}'."
            )

        # 4. Lease Policy Check (Max age seconds)
        lease_policy = getattr(certificate, "lease_policy", 300)
        cert_time = getattr(certificate, "timestamp", 0.0)
        now = time.time()
        if lease_policy and (now - cert_time) > lease_policy:
            raise ActuationVerificationError(
                f"Actuation refused: Certificate lease expired ({now - cert_time:.1f}s > {lease_policy}s allowed)."
            )

        # 5. Validity Envelope Check (Fail closed on state)
        envelope = manifest.envelope or getattr(certificate, "validity_envelope", None)
        envelope_valid = True
        has_envelope = (envelope is not None) or bool(getattr(certificate, "envelope_digest", ""))
        if has_envelope:
            if current_snapshot is None:
                raise ActuationVerificationError("current runtime state unavailable")
            if envelope is not None:
                is_inside, violations = envelope.contains(current_snapshot)
                if not is_inside:
                    envelope_valid = False
                    raise ActuationEnvelopeViolationError(
                        f"Actuation refused: Runtime state drifted outside certified validity envelope. "
                        f"Violations: {'; '.join(violations)}"
                    )

        # 6. State Epoch Monotonicity Check
        epoch_valid = True
        manifest_epoch = int(getattr(manifest, "state_epoch", getattr(certificate, "state_epoch", 1)))
        expected_revision = manifest_epoch
        if current_snapshot is not None:
            snap_epoch = int(getattr(current_snapshot, "epoch", 1))
            if snap_epoch < manifest_epoch:
                epoch_valid = False
                raise ActuationVerificationError(
                    f"Actuation refused: State epoch regression. Snapshot epoch {snap_epoch} < Manifest epoch {manifest_epoch}."
                )
            expected_revision = snap_epoch

        # 7. Plan Admissible Domain Containment (from authenticated manifest ONLY)
        for rid, action in plan.items():
            if action in NON_DOMAIN_ACTIONS:
                continue
            if rid not in manifest.admissible_domains:
                raise InadmissibleActionError(
                    f"Actuation refused: Resource '{rid}' has no certified domain in manifest."
                )
            admissible = manifest.admissible_domains[rid]
            if action not in admissible:
                raise InadmissibleActionError(
                    f"Actuation refused: Action '{action}' on '{rid}' is inadmissible (excised). "
                    f"Admissible actions: {sorted(admissible)}."
                )

        # 8. Budget Ceiling and Cost Completeness Check (from authenticated manifest ONLY)
        plan_cost = 0.0
        for rid, action in plan.items():
            if action in NON_DOMAIN_ACTIONS:
                continue
            cost = manifest.cost_map.get((rid, action))
            if cost is None:
                cost = manifest.cost_map.get(f"{rid}:{action}")
            if cost is None:
                raise ActuationVerificationError(
                    f"Actuation refused: Missing cost for action ('{rid}', '{action}') in certified manifest."
                )
            plan_cost += float(cost)

        if manifest.effective_budget and manifest.effective_budget > 0:
            if plan_cost > manifest.effective_budget + 1e-5:
                raise ActuationBudgetExceededError(
                    f"Actuation refused: Plan cost {plan_cost:.3f} exceeds certified budget {manifest.effective_budget:.3f}."
                )

        # 9. Scope check against authenticated manifest asset scope
        if manifest.asset_scope:
            for rid, action in plan.items():
                if action not in NON_DOMAIN_ACTIONS and rid not in manifest.asset_scope:
                    raise InadmissibleActionError(
                        f"Actuation refused: Resource '{rid}' outside certified asset scope."
                    )

        return ActuationAuthorization(
            is_authorized=True,
            expected_state_revision=expected_revision,
            certificate_id=certificate.certificate_id,
            authorized_actions=dict(plan),
            auth_timestamp=now,
            domain_authenticated=True,
            domain_certified=True,
            envelope_valid=envelope_valid,
            epoch_valid=epoch_valid,
            details={
                "state_epoch": expected_revision,
                "asset_scope": manifest.asset_scope,
                "manifest_digest": computed_manifest_digest,
                "auth_mechanism": getattr(certificate, "auth_mechanism", "unknown"),
            },
        )
