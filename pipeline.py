"""
=============================================================================
UNIFIED 9-LAYER PIPELINE COORDINATOR
Module: pipeline.py
-----------------------------------------------------------------------------
Problem Solved:
  Orchestrates all 9 layers of the Cloud Guardian Quantum-Federated Security
  System end-to-end, integrating:
    - Layer 1: Data Ingestion & Layer 0 Preprocessing
    - Layer 2: Federated Threat Detection (FedAvg, FedProx, FedNova, etc.)
    - Layer 3: Context Aggregation & SLA/Compliance Checks
    - Layer 4: Confidence Evaluation & Action Eligibility Filtering
    - Layer 5: Adaptive Constraint Synthesis & Privacy-Preserving Decision Formulation
    - Layer 6: Quantum QUBO/QAOA & ILP Decision Optimization
    - Layer 7: Response Utility Modeling
    - Layer 8: Response Orchestration & Dual-Mode Rationale (Internal / External)
    - Layer 9: Rich EMA Feedback Learning System

Inputs:  Incident scenario dictionary, solver configuration flags, previous plan, privacy mode.
Outputs: PipelineResult containing threat scores, solver plans, explanations, and execution logs.
=============================================================================
"""

import time
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from config import MAX_BUDGET, MAX_QUANTUM_RESOURCES, QUANTUM_METHOD

# Layer 2
from layer2_detection.detector import ThreatDetector

# Layer 3
from layer3_context.context_aggregator import aggregate_context, AggregatedContext

# Layer 4
from layer4_confidence.confidence_evaluator import evaluate_confidence, ConfidenceScores

# Layer 5
from layer5_constraints.adaptive_constraints import generate_adaptive_constraints, OptimizationConstraints
from layer5_constraints.constraint_ir import SecurityConstraintIR
from layer5_constraints.safety_certifier import ConstraintSafetyCertificate
from layer5_constraints.privacy_formulator import (
    transform_to_privacy_preserving_payload,
    calculate_information_leakage_reduction,
    DiscretizedContextPayload,
)

# Layer 6
from layer6_optimization.decision_engine import (
    build_qubo,
    solve_quantum,
    decode_action_plan,
    calculate_objective,
    calculate_total_cost,
    is_budget_feasible,
)
from layer6_optimization.baseline_greedy import solve_with_greedy, solve_with_greedy_budget, solve_with_ilp

# Layer 7
from layer7_utility.response_utility import calculate_all_action_utilities, ActionUtility

# Layer 8
from layer8_orchestration.executor import execute_plan, execute_strategy
from layer8_orchestration.explainability import DecisionExplainer

# Layer 9
from layer9_feedback.feedback_learner import FeedbackLearner


@dataclass
class SolverResult:
    name: str
    plan: Dict[str, str]
    objective: float
    cost: float
    runtime_sec: float
    budget_ok: bool


@dataclass
class PipelineResult:
    scenario: dict
    threat_scores: Dict[str, float]
    contexts: Dict[str, AggregatedContext] = field(default_factory=dict)
    confidences: Dict[str, ConfidenceScores] = field(default_factory=dict)
    constraints: Optional[OptimizationConstraints] = None
    action_utilities: Dict[str, Dict[str, ActionUtility]] = field(default_factory=dict)
    solver_results: List[SolverResult] = field(default_factory=list)
    explanation_report: Dict[str, Any] = field(default_factory=dict)
    privacy_payload: Dict[str, DiscretizedContextPayload] = field(default_factory=dict)
    leakage_reduction_pct: float = 0.0
    constraint_ir: Optional[SecurityConstraintIR] = None
    safety_certificate: Optional[ConstraintSafetyCertificate] = None

    def result_by_name(self, name: str) -> Optional[SolverResult]:
        for result in self.solver_results:
            if result.name == name:
                return result
        return None


def subset_scenario(scenario: dict, num_resources: int) -> dict:
    return {
        "scenario": scenario["scenario"],
        "resources": scenario["resources"][:num_resources],
    }


def run_pipeline(
    scenario: dict,
    max_budget: float = MAX_BUDGET,
    run_quantum: bool = False,
    quantum_resources: int = 2,
    quantum_method: Optional[str] = None,
    detector: Optional[ThreatDetector] = None,
    feedback_learner: Optional[FeedbackLearner] = None,
    previous_plan: Optional[Dict[str, str]] = None,
    time_of_day: str = "business_hours",
    privacy_preserving_mode: bool = True,
    role: str = "SOC_ANALYST",
    seed: int = 42,
) -> PipelineResult:
    """
    Runs the full 9-layer Cloud Guardian pipeline with context synthesis,
    privacy-preserving decision formulation, role-based explainability, and EMA feedback.
    """
    det = detector or ThreatDetector(verbose=False)
    learner = feedback_learner or FeedbackLearner()
    explainer = DecisionExplainer()

    # Layer 2: Threat detection
    scores = det.score_scenario(scenario)

    # Layer 3: Context aggregation
    contexts = aggregate_context(scenario, scores, seed=seed)

    # Layer 4: Confidence evaluation
    confidences = evaluate_confidence(scenario, scores, seed=seed)

    # Layer 5: Privacy-Preserving Decision Formulation & Discretization
    privacy_payload = {}
    leakage_reduction = 0.0
    if privacy_preserving_mode:
        privacy_payload = transform_to_privacy_preserving_payload(
            scenario, scores, contexts, confidences
        )
        raw_size = len(json.dumps(scenario)) + len(json.dumps({k: round(v, 4) for k, v in scores.items()}))
        priv_size = len(json.dumps({k: v.token_id for k, v in privacy_payload.items()}))
        leakage_reduction = calculate_information_leakage_reduction(raw_size, priv_size)

    # Layer 5: Adaptive constraint generator & context synthesizer with Policy Provenance Matrix & Constraint IR
    constraints = generate_adaptive_constraints(
        contexts,
        confidences,
        base_max_budget=max_budget,
        base_weights=learner.get_current_weights(),
        previous_plan=previous_plan,
        time_of_day=time_of_day,
        scenario=scenario,
        threat_scores=scores,
        learned_rules=learner.get_learned_rules(),
    )

    # Layer 7: Response utility
    action_utilities = calculate_all_action_utilities(
        scenario, contexts, confidences, weights=constraints.utility_weights
    )

    results: List[SolverResult] = []
    effective_budget = constraints.max_budget

    # Layer 6 — Classical solvers (Greedy, Budgeted Greedy, ILP)
    t0 = time.time()
    plan, objective = solve_with_greedy(scenario, scores, constraints=constraints, confidences=confidences)
    results.append(SolverResult(
        name="greedy",
        plan=plan,
        objective=objective,
        cost=calculate_total_cost(plan, scenario),
        runtime_sec=time.time() - t0,
        budget_ok=is_budget_feasible(plan, scenario, effective_budget),
    ))

    t0 = time.time()
    plan, objective = solve_with_greedy_budget(scenario, scores, effective_budget, constraints=constraints, confidences=confidences)
    results.append(SolverResult(
        name="greedy_budget",
        plan=plan,
        objective=objective,
        cost=calculate_total_cost(plan, scenario),
        runtime_sec=time.time() - t0,
        budget_ok=is_budget_feasible(plan, scenario, effective_budget),
    ))

    t0 = time.time()
    plan, objective = solve_with_ilp(scenario, scores, effective_budget, constraints=constraints, confidences=confidences)
    results.append(SolverResult(
        name="ilp",
        plan=plan,
        objective=objective,
        cost=calculate_total_cost(plan, scenario),
        runtime_sec=time.time() - t0,
        budget_ok=is_budget_feasible(plan, scenario, effective_budget),
    ))

    # Layer 6 — Quantum solver (optional)
    if run_quantum:
        n = min(quantum_resources, len(scenario["resources"]), MAX_QUANTUM_RESOURCES)
        q_scenario = subset_scenario(scenario, n)
        q_scores = {r["id"]: scores[r["id"]] for r in q_scenario["resources"]}
        method = quantum_method or QUANTUM_METHOD

        t0 = time.time()
        qp, var_lookup = build_qubo(
            q_scenario,
            q_scores,
            effective_budget,
            hard_budget=False,
            constraints=constraints,
            confidences=confidences,
        )
        q_result = solve_quantum(qp, method=method, seed=seed)
        q_plan = decode_action_plan(qp, var_lookup, q_result)
        q_objective = calculate_objective(q_plan, q_scenario, q_scores)
        results.append(SolverResult(
            name="qaoa" if method == "qaoa" else "quantum_qubo",
            plan=q_plan,
            objective=q_objective,
            cost=calculate_total_cost(q_plan, q_scenario),
            runtime_sec=time.time() - t0,
            budget_ok=is_budget_feasible(q_plan, q_scenario, effective_budget),
        ))

    # Layer 8: Role-Based Explainable Decision Output
    ilp_res = next((r for r in results if r.name == "ilp"), results[0])
    exp_report = explainer.generate_full_explanation_report(
        scenario, ilp_res.plan, contexts, confidences, constraints, action_utilities, role=role
    )

    return PipelineResult(
        scenario=scenario,
        threat_scores=scores,
        contexts=contexts,
        confidences=confidences,
        constraints=constraints,
        action_utilities=action_utilities,
        solver_results=results,
        explanation_report=exp_report,
        privacy_payload=privacy_payload,
        leakage_reduction_pct=leakage_reduction,
        constraint_ir=getattr(constraints, "constraint_ir", None),
        safety_certificate=getattr(constraints, "safety_certificate", None),
    )


def comparison_table(result: PipelineResult, ilp_baseline: str = "ilp") -> List[dict]:
    """Build rows for dashboard/benchmark with gap vs ILP."""
    ilp = result.result_by_name(ilp_baseline)
    ilp_obj = ilp.objective if ilp else None

    rows = []
    for solver in result.solver_results:
        gap = None
        if ilp_obj is not None and ilp_obj != 0:
            gap = ((solver.objective - ilp_obj) / abs(ilp_obj) * 100)
        rows.append({
            "solver": solver.name,
            "objective": round(solver.objective, 3),
            "cost": round(solver.cost, 3),
            "runtime_sec": round(solver.runtime_sec, 4),
            "budget_ok": solver.budget_ok,
            "gap_vs_ilp_pct": round(gap, 2) if gap is not None else None,
        })
    return rows


if __name__ == "__main__":
    from layer1_telemetry.fake_incident import SCENARIOS
    from layer8_orchestration.executor import execute_plan

    result = run_pipeline(SCENARIOS["port_scan_recon"], run_quantum=True, quantum_resources=2)
    print("Threat scores:", {k: round(v, 3) for k, v in result.threat_scores.items()})
    print(f"Privacy Leakage Reduction: {result.leakage_reduction_pct}%")
    print("\nSolver comparison:")
    for row in comparison_table(result):
        print(row)

    print("\n" + result.explanation_report.get("formatted_summary", ""))

    best = result.result_by_name("ilp")
    if best:
        logs = execute_plan(best.plan)
        print(f"\nExecuted ILP plan ({len(logs)} actions)")
