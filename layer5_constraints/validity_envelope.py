"""
=============================================================================
LAYER 5: VALIDITY ENVELOPE (SECURITY-DECISION INVARIANCE ENVELOPE)
Module: validity_envelope.py
-----------------------------------------------------------------------------
Problem Solved:
  Constructively synthesizes a multi-dimensional security-decision invariance
  envelope E_t around a measured runtime state S_t.
  
  Theorem (Envelope Soundness):
    For every state S with validity-relevant state vector V(S) in E_t:
      1. Admissible variable domain is invariant: A'(S) == A'(S_t)
      2. Fixed-point dependency closure is invariant: R*(S) == R*(S_t)
      3. Hard mathematical constraints and conflict topology are invariant
      4. Effective response budget lies within the certified regenerated bound set.
  
  Derivation is constructive: each admissibility and bound rule contributes the
  widest interval or value set on which its logical outcome is unchanged.
=============================================================================
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Tuple


# Single canonical sources of truth for Layer 5 decision thresholds
THRESHOLD_BUDGET_HIGH = 0.70
THRESHOLD_HIPAA_MANDATE = 0.60
THRESHOLD_LOW_CONFIDENCE = 0.50
THRESHOLD_SLA_CRITICAL = 0.40
ALL_THREAT_THRESHOLDS = sorted([THRESHOLD_SLA_CRITICAL, THRESHOLD_HIPAA_MANDATE, THRESHOLD_BUDGET_HIGH])


class StateEnvelopeViolationError(Exception):
    """Raised when a runtime state vector violates the certified validity envelope."""
    pass


@dataclass
class FieldPredicate:
    """
    Predicate on a single validity-relevant field defining the invariant region.
    """
    field_path: str
    kind: str  # "interval" or "value_set"
    lower_bound: Optional[float] = None
    upper_bound: Optional[float] = None
    lower_inclusive: bool = True
    upper_inclusive: bool = True
    allowed_values: Optional[Set[Any]] = None
    rule_ids: List[str] = field(default_factory=list)

    def contains(self, value: Any) -> bool:
        if self.kind == "interval":
            if value is None:
                return False
            try:
                v = float(value)
            except (ValueError, TypeError):
                return False
            if self.lower_bound is not None:
                if self.lower_inclusive and v < self.lower_bound:
                    return False
                if not self.lower_inclusive and v <= self.lower_bound:
                    return False
            if self.upper_bound is not None:
                if self.upper_inclusive and v > self.upper_bound:
                    return False
                if not self.upper_inclusive and v >= self.upper_bound:
                    return False
            return True
        elif self.kind == "value_set":
            if self.allowed_values is None:
                return True
            if isinstance(value, list):
                value = tuple(sorted(value))
            elif isinstance(value, dict):
                value = tuple(sorted((k, str(v)) for k, v in value.items()))
            return value in self.allowed_values
        return False

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "field_path": self.field_path,
            "kind": self.kind,
            "rule_ids": sorted(self.rule_ids),
        }
        if self.kind == "interval":
            d["lower_bound"] = self.lower_bound
            d["upper_bound"] = self.upper_bound
            d["lower_inclusive"] = self.lower_inclusive
            d["upper_inclusive"] = self.upper_inclusive
        else:
            d["allowed_values"] = sorted([str(x) for x in (self.allowed_values or [])])
        return d


@dataclass
class ValidityEnvelope:
    """
    Security-decision invariance envelope E_t.
    Conjunction of per-resource field predicates.
    """
    predicates: Dict[str, List[FieldPredicate]] = field(default_factory=dict)
    envelope_digest: str = ""

    def __post_init__(self):
        if not self.envelope_digest:
            self.envelope_digest = self.compute_digest()

    def compute_digest(self) -> str:
        canon = {}
        for rid, preds in sorted(self.predicates.items()):
            canon[rid] = sorted([p.to_dict() for p in preds], key=lambda x: x["field_path"])
        payload = json.dumps(canon, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def contains(self, snapshot: Any) -> Tuple[bool, List[str]]:
        """
        Validates whether snapshot V lies strictly within E_t.
        Returns (True, []) or (False, [reasons]).
        """
        violations: List[str] = []
        if snapshot is None:
            return False, ["StateSnapshot is None"]

        resources = getattr(snapshot, "resources", {})
        for rid, preds in self.predicates.items():
            if rid not in resources:
                violations.append(f"Missing resource '{rid}' in snapshot")
                continue
            rstate = resources[rid]
            for pred in preds:
                val = getattr(rstate, pred.field_path, None)
                if val is None and hasattr(rstate, "physical_state") and isinstance(rstate.physical_state, dict):
                    val = rstate.physical_state.get(pred.field_path)
                if not pred.contains(val):
                    violations.append(
                        f"Resource '{rid}' field '{pred.field_path}' value '{val}' violates predicate "
                        f"(rule={pred.rule_ids}, bounds=[{pred.lower_bound}, {pred.upper_bound}])"
                    )

        return (len(violations) == 0), violations


def derive_validity_envelope(
    scenario: dict,
    threat_scores: Dict[str, float],
    contexts: Dict[str, Any],
    confidences: Dict[str, Any],
) -> ValidityEnvelope:
    """
    Constructively derives the widest sound validity envelope for the given scenario state.
    """
    resources = scenario.get("resources", []) if scenario else []
    predicates: Dict[str, List[FieldPredicate]] = {}

    for r in resources:
        rid = r.get("id")
        if not rid:
            continue
        rtype = r.get("type", "server")
        preds: List[FieldPredicate] = []

        # 1. Threat Score Invariance Interval
        s_i = float(threat_scores.get(rid, 0.5))
        if s_i > THRESHOLD_BUDGET_HIGH:
            preds.append(FieldPredicate(
                field_path="threat_score",
                kind="interval",
                lower_bound=THRESHOLD_BUDGET_HIGH,
                upper_bound=1.0,
                lower_inclusive=False,
                upper_inclusive=True,
                rule_ids=["BUDGET_HIGH_1.30", "HIPAA_GT_060", "SLA_GE_040"],
            ))
        elif s_i > THRESHOLD_HIPAA_MANDATE:
            preds.append(FieldPredicate(
                field_path="threat_score",
                kind="interval",
                lower_bound=THRESHOLD_HIPAA_MANDATE,
                upper_bound=THRESHOLD_BUDGET_HIGH,
                lower_inclusive=False,
                upper_inclusive=True,
                rule_ids=["BUDGET_MED_1.00", "HIPAA_GT_060", "SLA_GE_040"],
            ))
        elif s_i >= THRESHOLD_SLA_CRITICAL:
            preds.append(FieldPredicate(
                field_path="threat_score",
                kind="interval",
                lower_bound=THRESHOLD_SLA_CRITICAL,
                upper_bound=THRESHOLD_HIPAA_MANDATE,
                lower_inclusive=True,
                upper_inclusive=True,
                rule_ids=["BUDGET_MED_1.00", "HIPAA_LE_060", "SLA_GE_040"],
            ))
        else:
            preds.append(FieldPredicate(
                field_path="threat_score",
                kind="interval",
                lower_bound=0.0,
                upper_bound=THRESHOLD_SLA_CRITICAL,
                lower_inclusive=True,
                upper_inclusive=False,
                rule_ids=["BUDGET_LOW_0.80", "HIPAA_LE_060", "SLA_LT_040_FORBID_ISOLATE"],
            ))

        # 2. Overall Confidence Invariance Interval
        conf_obj = confidences.get(rid)
        c_i = 1.0
        if conf_obj is not None:
            if hasattr(conf_obj, "overall_confidence"):
                c_i = float(conf_obj.overall_confidence)
            elif isinstance(conf_obj, (int, float)):
                c_i = float(conf_obj)
            elif isinstance(conf_obj, dict) and "overall_confidence" in conf_obj:
                c_i = float(conf_obj["overall_confidence"])

        if c_i < THRESHOLD_LOW_CONFIDENCE:
            preds.append(FieldPredicate(
                field_path="overall_confidence",
                kind="interval",
                lower_bound=0.0,
                upper_bound=THRESHOLD_LOW_CONFIDENCE,
                lower_inclusive=True,
                upper_inclusive=False,
                rule_ids=["LOW_CONF_FORBID_ISOLATE_DISABLE_USER"],
            ))
        else:
            preds.append(FieldPredicate(
                field_path="overall_confidence",
                kind="interval",
                lower_bound=THRESHOLD_LOW_CONFIDENCE,
                upper_bound=1.0,
                lower_inclusive=True,
                upper_inclusive=True,
                rule_ids=["CONF_SUFFICIENT_UNRESTRICTED"],
            ))

        # 3. Categorical Resource Type
        preds.append(FieldPredicate(
            field_path="resource_type",
            kind="value_set",
            allowed_values={rtype},
            rule_ids=["PHYSICAL_CAPABILITY_MAP"],
        ))

        # 4. SLA Priority
        ctx = contexts.get(rid)
        sla = "MEDIUM"
        if ctx is not None and hasattr(ctx, "business") and hasattr(ctx.business, "sla_priority"):
            sla = str(ctx.business.sla_priority)
        elif isinstance(ctx, dict) and "sla_priority" in ctx:
            sla = str(ctx["sla_priority"])
        elif r.get("sla_priority"):
            sla = str(r["sla_priority"])

        preds.append(FieldPredicate(
            field_path="sla_priority",
            kind="value_set",
            allowed_values={sla},
            rule_ids=["SLA_AVAILABILITY_POLICY"],
        ))

        # 5. HIPAA Compliance Flag
        hipaa = False
        if ctx is not None and hasattr(ctx, "compliance"):
            hipaa = bool(getattr(ctx.compliance, "hipaa_applicable", False))
        elif isinstance(ctx, dict):
            hipaa = bool(ctx.get("hipaa_applicable", False))
        elif r.get("hipaa_applicable"):
            hipaa = bool(r["hipaa_applicable"])

        preds.append(FieldPredicate(
            field_path="hipaa_applicable",
            kind="value_set",
            allowed_values={hipaa},
            rule_ids=["HIPAA_SAFEGUARD_MANDATE"],
        ))

        # 6. Declared Coupling Relations
        def _as_tuple(val) -> Tuple[str, ...]:
            if not val:
                return ()
            return tuple(sorted([val] if isinstance(val, str) else list(val)))

        preds.append(FieldPredicate(
            field_path="requires_isolation_with",
            kind="value_set",
            allowed_values={_as_tuple(r.get("requires_isolation_with", []))},
            rule_ids=["TRUST_ZONE_CONTAINMENT_COUPLING"],
        ))
        preds.append(FieldPredicate(
            field_path="credential_provider",
            kind="value_set",
            allowed_values={_as_tuple(r.get("credential_provider", []))},
            rule_ids=["CREDENTIAL_PROVIDER_COUPLING"],
        ))

        # 7. Physical State Attributes
        phys = r.get("physical_state", {})
        for pk, pv in phys.items():
            preds.append(FieldPredicate(
                field_path=f"physical_state.{pk}",
                kind="value_set",
                allowed_values={str(pv)},
                rule_ids=[f"PHYSICAL_STATE_{pk.upper()}"],
            ))

        predicates[rid] = preds

    return ValidityEnvelope(predicates=predicates)
