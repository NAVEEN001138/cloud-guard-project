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
    """
    is_authorized: bool
    expected_state_revision: int
    certificate_id: str
    authorized_actions: Dict[str, str]
    auth_timestamp: float
    domain_certified: bool = True
    envelope_valid: bool = True
    epoch_valid: bool = True
    details: Dict[str, Any] = field(default_factory=dict)


class ActuationCapabilityVerifier:
    """
    Independent pre-actuation verification gate.
    """

    @classmethod
    def authorize(
        cls,
        plan: Dict[str, str],
        certificate: Optional[ConstraintSafetyCertificate],
        current_snapshot: Optional[StateSnapshot] = None,
        public_key: Optional[VerifierKey] = None,
        sc_ir: Optional[SecurityConstraintIR] = None,
    ) -> ActuationAuthorization:
        """
        Enforces complete pre-actuation verification sequence.
        Raises ActuationVerificationError on any refusal.
        """
        if certificate is None:
            raise ActuationVerificationError("Actuation refused: Missing safety certificate.")

        # 1. Signature Verification
        vk = public_key or get_verifier_key()
        if not certificate.verify_signature(vk):
            raise ActuationVerificationError(
                "Actuation refused: Invalid certificate cryptographic signature."
            )

        # 2. Lease Policy Check (Max age seconds)
        lease_policy = getattr(certificate, "lease_policy", 300)
        cert_time = getattr(certificate, "timestamp", 0.0)
        now = time.time()
        if lease_policy and (now - cert_time) > lease_policy:
            raise ActuationVerificationError(
                f"Actuation refused: Certificate lease expired ({now - cert_time:.1f}s > {lease_policy}s allowed)."
            )

        # 3. Validity Envelope Check
        envelope = getattr(certificate, "validity_envelope", None)
        envelope_valid = True
        if current_snapshot is not None and envelope is not None:
            is_inside, violations = envelope.contains(current_snapshot)
            if not is_inside:
                envelope_valid = False
                raise ActuationEnvelopeViolationError(
                    f"Actuation refused: Runtime state drifted outside certified validity envelope. "
                    f"Violations: {'; '.join(violations)}"
                )

        # 4. State Epoch Monotonicity Check
        epoch_valid = True
        cert_epoch = int(getattr(certificate, "state_epoch", 1))
        expected_revision = cert_epoch
        if current_snapshot is not None:
            snap_epoch = int(getattr(current_snapshot, "epoch", 1))
            if snap_epoch < cert_epoch:
                epoch_valid = False
                raise ActuationVerificationError(
                    f"Actuation refused: State epoch regression. Snapshot epoch {snap_epoch} < Certificate epoch {cert_epoch}."
                )
            expected_revision = snap_epoch

        # 5. Plan Admissible Domain Containment
        domain_certified = False
        if sc_ir is not None:
            domain_certified = True
            for rid, action in plan.items():
                if action in NON_DOMAIN_ACTIONS:
                    continue
                domain = sc_ir.variable_domains.get(rid)
                if domain is None:
                    raise InadmissibleActionError(
                        f"Actuation refused: Resource '{rid}' has no certified domain in SC-IR."
                    )
                if action not in domain.admissible_actions:
                    raise InadmissibleActionError(
                        f"Actuation refused: Action '{action}' on '{rid}' is inadmissible (excised). "
                        f"Admissible actions: {sorted(domain.admissible_actions)}."
                    )

            # 6. Budget Ceiling Check
            if sc_ir.budget_constraint and sc_ir.budget_constraint.max_budget > 0:
                cost_map = sc_ir.budget_constraint.cost_map
                plan_cost = sum(cost_map.get((r, a), 0.0) for r, a in plan.items() if a not in NON_DOMAIN_ACTIONS)
                if plan_cost > sc_ir.budget_constraint.max_budget + 1e-5:
                    raise ActuationBudgetExceededError(
                        f"Actuation refused: Plan cost {plan_cost:.3f} exceeds certified budget {sc_ir.budget_constraint.max_budget:.3f}."
                    )

        # Scope check against certificate asset scope
        if getattr(certificate, "asset_scope", None):
            for rid, action in plan.items():
                if action not in NON_DOMAIN_ACTIONS and rid not in certificate.asset_scope:
                    raise InadmissibleActionError(
                        f"Actuation refused: Resource '{rid}' outside certified asset scope."
                    )

        return ActuationAuthorization(
            is_authorized=True,
            expected_state_revision=expected_revision,
            certificate_id=certificate.certificate_id,
            authorized_actions=dict(plan),
            auth_timestamp=now,
            domain_certified=domain_certified,
            envelope_valid=envelope_valid,
            epoch_valid=epoch_valid,
            details={
                "state_epoch": expected_revision,
                "asset_scope": certificate.asset_scope,
                "auth_mechanism": getattr(certificate, "auth_mechanism", "unknown"),
            },
        )
