"""
=============================================================================
LAYER 5: VALIDITY-RELEVANT RUNTIME STATE MODEL, FINGERPRINT & EPOCH
Module: runtime_state.py
-----------------------------------------------------------------------------
Problem Solved:
  Formalizes the runtime-state representation into a strictly bounded,
  validity-relevant state vector. A state attribute is included if and only if
  it feeds an admissibility, closure, or feasibility bound rule in Layer 5.
  Non-validity-relevant telemetry churn (e.g. resource labels, transient
  unmonitored metrics) is excluded from the cryptographic state fingerprint,
  preventing spurious invalidation while ensuring any change to decision-governing
  state is captured deterministically.

Rule Mapping for Validity-Relevant Fields:
  1. resource_type:
     Feeds PHYSICAL_CAPABILITY_MAP and FEASIBLE_ACTION_MATRIX (adaptive_constraints.py).
     Defines baseline hardware/firmware admissible actions.
  2. threat_score:
     Feeds:
       - Budget scaling multiplier in dependency_graph.py (thresholds 0.40 and 0.70).
       - HIPAA mandatory isolation policy rule in adaptive_constraints.py (threshold 0.60).
       - SLA CRITICAL availability protection rule (forbids 'isolate' below 0.40).
  3. overall_confidence:
     Feeds safety interlock in adaptive_constraints.py (confidence < 0.50 forbids
     disruptive actions 'isolate' and 'disable_user').
  4. sla_priority:
     Feeds SLA CRITICAL policy rule in adaptive_constraints.py (preserves availability
     when threat_score < 0.40).
  5. hipaa_applicable:
     Feeds statutory healthcare mandate rule in adaptive_constraints.py (mandates
     'isolate' for ePHI assets under active attack).
  6. gdpr_applicable:
     Feeds statutory privacy rule in adaptive_constraints.py (restricts data export,
     mandates credential rotation).
  7. pci_dss_applicable:
     Feeds cardholder data environment compliance rule in adaptive_constraints.py.
  8. business_criticality:
     Feeds asset context aggregation and dynamic SLA weighting.
  9. data_sensitivity:
     Feeds confidential asset isolation and audit logging rules.
  10. requires_isolation_with:
     Feeds fixed-point dependency closure in dependency_graph.py (transitive trust-zone
     containment coupling).
  11. credential_provider:
     Feeds dependency closure in dependency_graph.py (key vault and authentication
     propagation coupling).
  12. physical_state:
     Feeds cyber-physical interlock verification (e.g. PLC operational mode, safety
     relay status).
=============================================================================
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


STATE_SCHEMA_ID = "cg-state-v1"


@dataclass
class ValidityRelevantState:
    """
    State vector for a single managed asset containing exclusively
    decision-governing attributes.
    """
    resource_id: str
    resource_type: str
    threat_score: float
    overall_confidence: float
    sla_priority: str
    hipaa_applicable: bool = False
    gdpr_applicable: bool = False
    pci_dss_applicable: bool = False
    business_criticality: str = "MEDIUM"
    data_sensitivity: str = "MEDIUM"
    requires_isolation_with: List[str] = field(default_factory=list)
    credential_provider: List[str] = field(default_factory=list)
    physical_state: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StateSnapshot:
    """
    Immutable snapshot of the validity-relevant state across all managed assets
    at a specific state epoch.
    """
    resources: Dict[str, ValidityRelevantState]
    epoch: int = 1
    sampled_at: float = field(default_factory=time.time)
    schema_id: str = STATE_SCHEMA_ID

    def canonicalise(self) -> bytes:
        return canonicalise(self)

    def fingerprint(self) -> str:
        return fingerprint(self)


def canonicalise(snapshot: StateSnapshot) -> bytes:
    """
    Generates deterministic canonical bytes for a StateSnapshot.
    Invariant to dictionary ordering and non-validity-relevant fields.
    """
    canon_resources = {}
    for rid, r in sorted(snapshot.resources.items()):
        canon_resources[rid] = {
            "resource_id": r.resource_id,
            "resource_type": r.resource_type,
            "threat_score": f"{float(r.threat_score):.6f}",
            "overall_confidence": f"{float(r.overall_confidence):.6f}",
            "sla_priority": str(r.sla_priority),
            "hipaa_applicable": bool(r.hipaa_applicable),
            "gdpr_applicable": bool(r.gdpr_applicable),
            "pci_dss_applicable": bool(r.pci_dss_applicable),
            "business_criticality": str(r.business_criticality),
            "data_sensitivity": str(r.data_sensitivity),
            "requires_isolation_with": sorted(r.requires_isolation_with or []),
            "credential_provider": sorted(r.credential_provider or []),
            "physical_state": {k: str(v) for k, v in sorted((r.physical_state or {}).items())},
        }

    canonical_obj = {
        "schema_id": snapshot.schema_id,
        "epoch": int(snapshot.epoch),
        "resources": canon_resources,
    }
    return json.dumps(canonical_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def fingerprint(snapshot: StateSnapshot) -> str:
    """
    Computes a cryptographic SHA-256 digest over the canonical validity-relevant state.
    """
    return hashlib.sha256(canonicalise(snapshot)).hexdigest()


def snapshot_from_contexts(
    contexts: Dict[str, Any],
    confidences: Dict[str, Any],
    scenario: Dict[str, Any],
    epoch: int = 1,
    sampled_at: Optional[float] = None,
    threat_scores: Optional[Dict[str, float]] = None,
) -> StateSnapshot:
    """
    Constructs a StateSnapshot from Layer 3 AggregatedContext and Layer 4 ConfidenceScores objects.
    """
    scores_map = threat_scores or {}
    resources_data = scenario.get("resources", []) if scenario else []
    res_states: Dict[str, ValidityRelevantState] = {}

    for r in resources_data:
        rid = r.get("id")
        if not rid:
            continue
        rtype = r.get("type", "server")
        ctx = contexts.get(rid) if contexts else None
        conf = confidences.get(rid) if confidences else None

        # Threat score extraction
        threat = 0.0
        if rid in scores_map:
            threat = float(scores_map[rid])
        elif ctx is not None:
            if hasattr(ctx, "threat") and hasattr(ctx.threat, "threat_score"):
                threat = float(ctx.threat.threat_score)
            elif isinstance(ctx, dict) and "threat_score" in ctx:
                threat = float(ctx["threat_score"])

        # Overall confidence extraction
        overall_conf = 1.0
        if conf is not None:
            if hasattr(conf, "overall_confidence"):
                overall_conf = float(conf.overall_confidence)
            elif isinstance(conf, (int, float)):
                overall_conf = float(conf)
            elif isinstance(conf, dict) and "overall_confidence" in conf:
                overall_conf = float(conf["overall_confidence"])

        # SLA priority
        sla = "MEDIUM"
        if ctx is not None:
            if hasattr(ctx, "business") and hasattr(ctx.business, "sla_priority"):
                sla = str(ctx.business.sla_priority)
            elif isinstance(ctx, dict) and "sla_priority" in ctx:
                sla = str(ctx["sla_priority"])
        elif r.get("sla_priority"):
            sla = str(r["sla_priority"])

        # Compliance flags
        hipaa = False
        gdpr = False
        pci = False
        if ctx is not None:
            if hasattr(ctx, "compliance"):
                hipaa = bool(getattr(ctx.compliance, "hipaa_applicable", False))
                gdpr = bool(getattr(ctx.compliance, "gdpr_applicable", False))
                pci = bool(getattr(ctx.compliance, "pci_dss_applicable", False))
            elif isinstance(ctx, dict):
                hipaa = bool(ctx.get("hipaa_applicable", False))
                gdpr = bool(ctx.get("gdpr_applicable", False))
                pci = bool(ctx.get("pci_dss_applicable", False))
        else:
            hipaa = bool(r.get("hipaa_applicable", False))
            gdpr = bool(r.get("gdpr_applicable", False))
            pci = bool(r.get("pci_dss_applicable", False))

        # Criticality and sensitivity
        crit = "MEDIUM"
        sens = "MEDIUM"
        if ctx is not None and hasattr(ctx, "asset"):
            crit = str(getattr(ctx.asset, "business_criticality", "MEDIUM"))
            sens = str(getattr(ctx.asset, "data_sensitivity", "MEDIUM"))

        # Declared topological relations
        def _as_list(val) -> List[str]:
            if not val:
                return []
            return [val] if isinstance(val, str) else list(val)

        req_iso = _as_list(r.get("requires_isolation_with", []))
        cred_prov = _as_list(r.get("credential_provider", []))
        phys_state = dict(r.get("physical_state", {})) if isinstance(r.get("physical_state"), dict) else {}
        if rtype == "plc_controller" and "mode" not in phys_state:
            from layer5_constraints.policy_thresholds import get_effective_plc_mode
            phys_state["mode"] = get_effective_plc_mode(r)

        res_states[rid] = ValidityRelevantState(
            resource_id=rid,
            resource_type=rtype,
            threat_score=threat,
            overall_confidence=overall_conf,
            sla_priority=sla,
            hipaa_applicable=hipaa,
            gdpr_applicable=gdpr,
            pci_dss_applicable=pci,
            business_criticality=crit,
            data_sensitivity=sens,
            requires_isolation_with=req_iso,
            credential_provider=cred_prov,
            physical_state=phys_state,
        )

    return StateSnapshot(
        resources=res_states,
        epoch=epoch,
        sampled_at=sampled_at or time.time(),
        schema_id=STATE_SCHEMA_ID,
    )
