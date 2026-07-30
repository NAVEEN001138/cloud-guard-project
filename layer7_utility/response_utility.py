"""
=============================================================================
LAYER 7: RESPONSE UTILITY MODEL
Module: response_utility.py
-----------------------------------------------------------------------------
Problem Solved:
  Calculates multi-attribute utility scores for each potential mitigation action.
  Solves action ranking by weighing containment gain against business downtime,
  recovery costs, analyst effort, and compliance risk.

Inputs:  Scenario, AggregatedContext, ConfidenceScores, and action utility weights.
Outputs: ActionUtility dataclass containing net utility score per resource action.
=============================================================================
"""

from dataclasses import dataclass
from typing import Dict, List, Optional

from config import ACTIONS, UTILITY_WEIGHTS
from layer3_context.context_aggregator import AggregatedContext
from layer4_confidence.confidence_evaluator import ConfidenceScores


@dataclass
class ActionUtility:
    resource_id: str
    action: str
    net_utility: float
    containment_gain: float
    business_impact_cost: float
    downtime_cost: float
    compliance_cost: float


def calculate_action_utility(
    resource: dict,
    action: str,
    context: AggregatedContext,
    confidence: ConfidenceScores,
    weights: Optional[Dict[str, float]] = None,
) -> ActionUtility:
    w = weights or UTILITY_WEIGHTS
    rid = resource["id"]
    rtype = resource["type"]

    base_eff = ACTIONS.get(action, 0.1)
    containment_gain = base_eff * context.threat.threat_score * confidence.overall_confidence

    if action == "isolate":
        b_cost = 0.9 if rtype == "rds_database" else 0.5
        d_cost = 0.8
        c_cost = 0.1
    elif action == "rotate_credentials":
        b_cost = 0.2
        d_cost = 0.1
        c_cost = 0.1
    elif action == "block_ip":
        b_cost = 0.3
        d_cost = 0.05
        c_cost = 0.2
    elif action == "disable_user":
        b_cost = 0.4
        d_cost = 0.2
        c_cost = 0.3
    elif action == "snapshot_backup":
        b_cost = 0.1
        d_cost = 0.1
        c_cost = 0.05
    elif action == "monitor":
        b_cost = 0.01
        d_cost = 0.0
        c_cost = 0.0
    elif action == "increase_logging":
        b_cost = 0.05
        d_cost = 0.0
        c_cost = 0.0
    else:
        b_cost = 0.2
        d_cost = 0.1
        c_cost = 0.1

    # Scale costs by asset criticality
    b_cost *= context.asset.business_criticality
    d_cost *= context.asset.business_criticality

    net_utility = (
        w.get("containment_effectiveness", 0.3) * containment_gain
        + w.get("business_impact", -0.25) * b_cost
        + w.get("downtime", -0.20) * d_cost
        + w.get("compliance_risk", -0.10) * c_cost
    )

    return ActionUtility(
        resource_id=rid,
        action=action,
        net_utility=net_utility,
        containment_gain=containment_gain,
        business_impact_cost=b_cost,
        downtime_cost=d_cost,
        compliance_cost=c_cost,
    )


def calculate_all_action_utilities(
    scenario: dict,
    contexts: Dict[str, AggregatedContext],
    confidences: Dict[str, ConfidenceScores],
    weights: Optional[Dict[str, float]] = None,
) -> Dict[str, Dict[str, ActionUtility]]:
    result = {}
    for r in scenario.get("resources", []):
        rid = r["id"]
        ctx = contexts[rid]
        conf = confidences[rid]
        r_utils = {}
        for action in ACTIONS.keys():
            r_utils[action] = calculate_action_utility(r, action, ctx, conf, weights)
        result[rid] = r_utils
    return result
