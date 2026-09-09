"""
=============================================================================
LAYER 6: DECISION OPTIMIZATION ENGINE
Module: baseline_greedy.py
-----------------------------------------------------------------------------
Problem Solved:
  Provides classical baseline solvers (Greedy heuristic, Budgeted Greedy, and
  Integer Linear Programming via PuLP/SciPy ILP). Solves the incident response
  action selection problem classically for performance comparison vs QAOA.

  Updated to respect Layer 4 Confidence, Layer 5 Constraints, and Feasible Action Sets.

Inputs:  Scenario dictionary, threat scores (s_i), max budget, constraints, confidences.
Outputs: Action plan dictionary & objective value.
=============================================================================
"""

import time
from typing import Dict, Tuple, Optional, List
import numpy as np

from config import ACTIONS, MAX_BUDGET
from layer6_optimization.decision_engine import action_cost, calculate_objective
from layer5_constraints.adaptive_constraints import OptimizationConstraints
from layer4_confidence.confidence_evaluator import ConfidenceScores

try:
    import pulp
    HAS_PULP = True
except ImportError:
    HAS_PULP = False


def _get_allowed_actions(rid: str, constraints: Optional[OptimizationConstraints]) -> List[str]:
    if constraints and constraints.feasible_actions and rid in constraints.feasible_actions:
        return constraints.feasible_actions[rid]
    return list(ACTIONS.keys())


def solve_with_greedy(
    scenario: dict,
    threat_scores: dict,
    constraints: Optional[OptimizationConstraints] = None,
    confidences: Optional[Dict[str, ConfidenceScores]] = None,
) -> Tuple[Dict[str, str], float]:
    plan = {}
    prev_plan = constraints.previous_plan if constraints else {}
    switching_pen = constraints.switching_penalty if constraints else 0.0

    for r in scenario["resources"]:
        rid = r["id"]
        s_i = threat_scores.get(rid, 0.5)
        c_i = confidences[rid].overall_confidence if confidences and rid in confidences else 1.0
        effective_threat = s_i * c_i

        allowed = _get_allowed_actions(rid, constraints)
        best_action = None
        best_obj = float("inf")

        for k in allowed:
            # Skip forbidden actions
            if constraints and constraints.forbidden_actions.get(rid, {}).get(k):
                continue

            beta_k = ACTIONS[k]
            c_ik = action_cost(r["type"], k)
            obj = -beta_k * effective_threat + c_ik

            if prev_plan and rid in prev_plan and prev_plan[rid] != k:
                obj += switching_pen

            if constraints and constraints.required_actions.get(rid) == k:
                obj -= 500.0

            if obj < best_obj:
                best_obj = obj
                best_action = k

        plan[rid] = best_action or (allowed[0] if allowed else "monitor")

    return plan, calculate_objective(plan, scenario, threat_scores)


def solve_with_greedy_budget(
    scenario: dict,
    threat_scores: dict,
    max_budget: float = MAX_BUDGET,
    constraints: Optional[OptimizationConstraints] = None,
    confidences: Optional[Dict[str, ConfidenceScores]] = None,
) -> Tuple[Dict[str, str], float]:
    plan = {}
    remaining_budget = max_budget
    prev_plan = constraints.previous_plan if constraints else {}
    switching_pen = constraints.switching_penalty if constraints else 0.0

    # Sort resources by threat score descending
    sorted_resources = sorted(
        scenario["resources"],
        key=lambda r: threat_scores.get(r["id"], 0.0),
        reverse=True
    )

    for r in sorted_resources:
        rid = r["id"]
        s_i = threat_scores.get(rid, 0.5)
        c_i = confidences[rid].overall_confidence if confidences and rid in confidences else 1.0
        effective_threat = s_i * c_i

        allowed = _get_allowed_actions(rid, constraints)
        best_action = "monitor" if "monitor" in allowed else allowed[0]
        best_obj = float("inf")

        for k in allowed:
            if constraints and constraints.forbidden_actions.get(rid, {}).get(k):
                continue

            c_ik = action_cost(r["type"], k)
            if c_ik <= remaining_budget:
                beta_k = ACTIONS[k]
                obj = -beta_k * effective_threat + c_ik

                if prev_plan and rid in prev_plan and prev_plan[rid] != k:
                    obj += switching_pen

                if constraints and constraints.required_actions.get(rid) == k:
                    obj -= 500.0

                if obj < best_obj:
                    best_obj = obj
                    best_action = k

        plan[rid] = best_action
        remaining_budget -= action_cost(r["type"], best_action)
        remaining_budget = max(0.0, remaining_budget)

    return plan, calculate_objective(plan, scenario, threat_scores)


def solve_with_ilp(
    scenario: dict,
    threat_scores: dict,
    max_budget: float = MAX_BUDGET,
    constraints: Optional[OptimizationConstraints] = None,
    confidences: Optional[Dict[str, ConfidenceScores]] = None,
) -> Tuple[Dict[str, str], float]:
    resources = scenario["resources"]
    prev_plan = constraints.previous_plan if constraints else {}
    switching_pen = constraints.switching_penalty if constraints else 0.0

    if HAS_PULP:
        # Check if compiled SecurityConstraintIR is available
        if constraints and getattr(constraints, "constraint_ir", None):
            from layer5_constraints.formulation_compiler import FormulationCompiler
            from layer5_constraints.safety_certifier import PreSolveSafetyCertifier
            ir = constraints.constraint_ir
            scenario_rids = {r["id"] for r in resources}
            if scenario_rids != set(ir.variable_domains.keys()):
                ir = ir.filter_to_resources(scenario_rids)
                cert = PreSolveSafetyCertifier.certify(ir)
            else:
                cert = constraints.safety_certificate or PreSolveSafetyCertifier.certify(ir)

            prob, x_vars = FormulationCompiler.compile_to_ilp(ir, certificate=cert)
            prob.solve(pulp.PULP_CBC_CMD(msg=False))

            plan = {}
            for r in resources:
                rid = r["id"]
                domain = ir.variable_domains.get(rid)
                allowed = domain.admissible_actions if domain else _get_allowed_actions(rid, constraints)
                best_k = allowed[0]
                for k in allowed:
                    if (rid, k) in x_vars and pulp.value(x_vars[(rid, k)]) is not None and pulp.value(x_vars[(rid, k)]) > 0.5:
                        best_k = k
                        break
                plan[rid] = best_k

            return plan, calculate_objective(plan, scenario, threat_scores)

        prob = pulp.LpProblem("ILP_Incident_Response", pulp.LpMinimize)
        x_vars = {}
        all_pairs = []

        for i, r in enumerate(resources):
            rid = r["id"]
            allowed = _get_allowed_actions(rid, constraints)
            for k in allowed:
                var_name = f"x_{rid}_{k}"
                x_vars[(rid, k)] = pulp.LpVariable(var_name, cat="Binary")
                all_pairs.append((rid, k, r["type"]))

        # Objective function
        obj_expr = []
        for rid, k, r_type in all_pairs:
            s_i = threat_scores.get(rid, 0.5)
            c_i = confidences[rid].overall_confidence if confidences and rid in confidences else 1.0
            effective_threat = s_i * c_i

            c_ik = action_cost(r_type, k)
            beta_k = ACTIONS[k]
            coeff = -beta_k * effective_threat + c_ik

            if prev_plan and rid in prev_plan and prev_plan[rid] != k:
                coeff += switching_pen

            if constraints and constraints.required_actions.get(rid) == k:
                coeff -= 500.0

            if constraints and constraints.forbidden_actions.get(rid, {}).get(k):
                coeff += 1000.0

            obj_expr.append(coeff * x_vars[(rid, k)])
        prob += pulp.lpSum(obj_expr)

        # Constraint 1: Exactly 1 action per resource
        for r in resources:
            rid = r["id"]
            allowed = _get_allowed_actions(rid, constraints)
            res_vars = [x_vars[(rid, k)] for k in allowed if (rid, k) in x_vars]
            if res_vars:
                prob += pulp.lpSum(res_vars) == 1

        # Constraint 2: Budget
        cost_expr = [action_cost(r_type, k) * x_vars[(rid, k)] for rid, k, r_type in all_pairs]
        prob += pulp.lpSum(cost_expr) <= max_budget

        prob.solve(pulp.PULP_CBC_CMD(msg=False))

        plan = {}
        for r in resources:
            rid = r["id"]
            allowed = _get_allowed_actions(rid, constraints)
            best_k = allowed[0]
            for k in allowed:
                if (rid, k) in x_vars and pulp.value(x_vars[(rid, k)]) and pulp.value(x_vars[(rid, k)]) > 0.5:
                    best_k = k
                    break
            plan[rid] = best_k

        return plan, calculate_objective(plan, scenario, threat_scores)

    # Fallback to budgeted greedy if PuLP missing
    return solve_with_greedy_budget(scenario, threat_scores, max_budget, constraints, confidences)
