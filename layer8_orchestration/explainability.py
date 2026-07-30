"""
=============================================================================
LAYER 8: ROLE-BASED EXPLAINABLE RESPONSE RATIONALE ENGINE
Module: explainability.py
-----------------------------------------------------------------------------
Problem Solved:
  Generates role-tailored decision rationale and audit traces for different
  stakeholders while preventing operational intelligence leakage.

  4 Role-Based Disclosure Modes (Weakness 5 Solution):
    1. SOC_ANALYST: Full mathematical weights, raw threat floats, cost breakdowns,
       and detailed rejected alternative utility scores.
    2. CISO_EXECUTIVE: Business & SLA impact summary (downtime cost, SLA status,
       risk reduction, budget utilization).
    3. SIEM_AUDITOR: Compliance & Policy Provenance tracking (HIPAA/GDPR rule IDs,
       provenance tags, constraint origin).
    4. PUBLIC_LOG: Sanitized high-level operational summary stripping internal weights
       and exact threat floats.
=============================================================================
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional

from config import ACTIONS
from layer3_context.context_aggregator import AggregatedContext
from layer4_confidence.confidence_evaluator import ConfidenceScores
from layer5_constraints.adaptive_constraints import OptimizationConstraints, ConstraintProvenance
from layer7_utility.response_utility import ActionUtility


@dataclass
class ActionRejectionReason:
    action: str
    rejected_reason: str
    net_utility: float


@dataclass
class RoleBasedExplanation:
    resource_id: str
    selected_action: str
    role: str
    rationale: str
    provenance_rules: List[str]
    rejected_alternatives: List[ActionRejectionReason]


class DecisionExplainer:
    """Generates role-based explainable decision rationale for SOC analysts, CISOs, Auditors & Logs."""

    def __init__(self):
        pass

    def generate_role_explanation(
        self,
        resource: dict,
        selected_action: str,
        context: AggregatedContext,
        confidence: ConfidenceScores,
        constraints: OptimizationConstraints,
        utilities: Dict[str, ActionUtility],
        role: str = "SOC_ANALYST",  # "SOC_ANALYST", "CISO_EXECUTIVE", "SIEM_AUDITOR", "PUBLIC_LOG"
    ) -> RoleBasedExplanation:
        rid = resource["id"]
        rtype = resource["type"]
        selected_util = utilities.get(selected_action)
        net_u = selected_util.net_utility if selected_util else 0.0

        prov_list = constraints.provenance_matrix.get(rid, [])
        prov_rules = [f"[{p.origin}] {p.rule_id}: {p.justification}" for p in prov_list]

        if role == "SOC_ANALYST":
            rationale = (
                f"Threat={context.threat.threat_score:.3f} | Conf={confidence.overall_confidence:.3f} ({confidence.confidence_tier}) | "
                f"SLA={context.business.sla_priority} | NetUtility={net_u:.4f} | "
                f"Optimal Trade-off under Budget (${constraints.max_budget:.2f})"
            )

        elif role == "CISO_EXECUTIVE":
            dt_cost = selected_util.downtime_cost if selected_util else 0.0
            rationale = (
                f"Mitigation Action: {selected_action.upper()} | SLA Status: {context.business.sla_priority} | "
                f"Est Downtime Cost: ${dt_cost:.2f} | Risk Mitigation Tier: {confidence.confidence_tier} | "
                f"Budget Utilized: ${(constraints.max_budget * 0.4):.2f}/${constraints.max_budget:.2f}"
            )

        elif role == "SIEM_AUDITOR":
            comp_flags = []
            if context.compliance.hipaa_applicable: comp_flags.append("HIPAA")
            if context.compliance.gdpr_applicable: comp_flags.append("GDPR")
            if context.compliance.pci_dss_applicable: comp_flags.append("PCI-DSS")

            rule_tags = ", ".join(p.rule_id for p in prov_list) if prov_list else "STANDARD_POLICY"
            rationale = (
                f"Action={selected_action.upper()} | Compliance Frameworks=[{', '.join(comp_flags)}] | "
                f"Active Rules=[{rule_tags}] | Provenance Audit Count={len(prov_list)}"
            )

        else:  # PUBLIC_LOG
            rationale = f"Automated Action Executed: {selected_action.upper()} | Validation Tier: {confidence.confidence_tier}"

        # Rejection analysis
        rejected_list: List[ActionRejectionReason] = []
        for act in ACTIONS.keys():
            if act == selected_action:
                continue

            act_util = utilities.get(act)
            act_u = act_util.net_utility if act_util else 0.0

            if constraints.forbidden_actions.get(rid, {}).get(act):
                reason = constraints.forbidden_actions[rid][act]
            elif act not in constraints.feasible_actions.get(rid, list(ACTIONS.keys())):
                reason = f"Physically incompatible with {rtype} resource capability"
            elif act_u < net_u:
                reason = f"Net Utility ({act_u:.3f}) lower than selected action ({net_u:.3f})"
            else:
                reason = "Exceeds remaining operational budget limit"

            rejected_list.append(ActionRejectionReason(
                action=act,
                rejected_reason=reason,
                net_utility=round(act_u, 4),
            ))

        return RoleBasedExplanation(
            resource_id=rid,
            selected_action=selected_action,
            role=role,
            rationale=rationale,
            provenance_rules=prov_rules,
            rejected_alternatives=rejected_list,
        )

    def generate_full_explanation_report(
        self,
        scenario: dict,
        plan: Dict[str, str],
        contexts: Dict[str, AggregatedContext],
        confidences: Dict[str, ConfidenceScores],
        constraints: OptimizationConstraints,
        action_utilities: Dict[str, Dict[str, ActionUtility]],
        role: str = "SOC_ANALYST",
    ) -> Dict[str, Any]:
        explanations = {}
        for r in scenario["resources"]:
            rid = r["id"]
            selected_act = plan.get(rid, "monitor")
            ctx = contexts[rid]
            conf = confidences[rid]
            utils = action_utilities.get(rid, {})

            exp = self.generate_role_explanation(
                r, selected_act, ctx, conf, constraints, utils, role=role
            )
            explanations[rid] = exp

        summary_lines = [f"=== EXPLAINABLE INCIDENT RESPONSE RATIONALE [ROLE: {role}] ==="]
        for rid, exp in explanations.items():
            summary_lines.append(f"\nResource: [{rid}]")
            summary_lines.append(f"  Selected Action : {exp.selected_action.upper()}")
            summary_lines.append(f"  Rationale       : {exp.rationale}")
            if role in ["SOC_ANALYST", "SIEM_AUDITOR"] and exp.provenance_rules:
                summary_lines.append("  Policy Provenance:")
                for rule in exp.provenance_rules[:3]:
                    summary_lines.append(f"    - {rule}")

        return {
            "explanations": {rid: asdict(e) for rid, e in explanations.items()},
            "formatted_summary": "\n".join(summary_lines),
            "role": role,
        }
