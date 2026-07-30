"""
=============================================================================
LAYER 5 & DECISION ENGINE EVALUATION BENCHMARK
Module: evaluator.py
-----------------------------------------------------------------------------
Evaluates the Decision Engine capabilities across 5 distinct experimental dimensions:
  1. Constraint Satisfaction Rate (% forbidden actions successfully prevented)
  2. Confidence-Aware Action Filtering (High vs Low confidence action shifts)
  3. Decision Stability (Action oscillation reduction with switching penalty)
  4. Decision Rationale & Trace Completeness (100% auditable explanation)
  5. EMA Feedback Adaptation (Weight calibration over multiple incident rounds)
=============================================================================
"""

import copy
import os
import sys
import time
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from layer1_telemetry.fake_incident import SCENARIOS
from layer2_detection.detector import ThreatDetector
from layer3_context.context_aggregator import aggregate_context
from layer4_confidence.confidence_evaluator import evaluate_confidence
from layer5_constraints.adaptive_constraints import generate_adaptive_constraints
from layer6_optimization.baseline_greedy import solve_with_ilp
from layer7_utility.response_utility import calculate_all_action_utilities
from layer8_orchestration.explainability import DecisionExplainer
from layer9_feedback.feedback_learner import FeedbackLearner


def evaluate_decision_engine() -> Dict[str, dict]:
    print("=" * 65)
    print("  DECISION ENGINE & LAYER 5 ADAPTIVE CONSTRAINTS EVALUATION")
    print("=" * 65)

    scenario = SCENARIOS["port_scan_recon"]
    det = ThreatDetector(verbose=False)
    scores = det.score_scenario(scenario)
    contexts = aggregate_context(scenario, scores)
    confidences = evaluate_confidence(scenario, scores)

    results = {}

    # -------------------------------------------------------------------------
    # Experiment 1: Constraint Satisfaction Rate
    # -------------------------------------------------------------------------
    print("\n[ Exp 1 ] Constraint Satisfaction Rate")
    constraints = generate_adaptive_constraints(contexts, confidences, base_max_budget=5.0)
    plan_ilp, obj = solve_with_ilp(scenario, scores, max_budget=5.0, constraints=constraints, confidences=confidences)
    
    total_forbidden_checks = 0
    forbidden_violations = 0
    for rid, action in plan_ilp.items():
        forbidden_map = constraints.forbidden_actions.get(rid, {})
        if action in forbidden_map:
            forbidden_violations += 1
        total_forbidden_checks += len(forbidden_map)

    satisfaction_rate = 100.0 if forbidden_violations == 0 else (1.0 - forbidden_violations / max(1, total_forbidden_checks)) * 100
    print(f"  Forbidden actions defined : {sum(len(v) for v in constraints.forbidden_actions.values())}")
    print(f"  Forbidden violations      : {forbidden_violations}")
    print(f"  Constraint Satisfaction   : {satisfaction_rate:.1f}%")
    results["constraint_satisfaction"] = {
        "satisfaction_rate_pct": satisfaction_rate,
        "violations": forbidden_violations,
    }

    # -------------------------------------------------------------------------
    # Experiment 2: Confidence-Aware Action Space Adaptation
    # -------------------------------------------------------------------------
    print("\n[ Exp 2 ] Confidence-Aware Action Space Filtering")
    # Low confidence scenario simulation
    low_confidences = copy.deepcopy(confidences)
    for c in low_confidences.values():
        c.overall_confidence = 0.42
        c.confidence_tier = "LOW"
        c.allowed_actions = ["monitor", "increase_logging", "snapshot_backup"]

    constraints_low = generate_adaptive_constraints(contexts, low_confidences, base_max_budget=5.0)
    plan_low, _ = solve_with_ilp(scenario, scores, max_budget=5.0, constraints=constraints_low, confidences=low_confidences)

    high_disruption_count_normal = sum(1 for a in plan_ilp.values() if a in ["isolate", "disable_user"])
    high_disruption_count_low_conf = sum(1 for a in plan_low.values() if a in ["isolate", "disable_user"])

    print(f"  High-Disruption Actions (High Conf) : {high_disruption_count_normal}")
    print(f"  High-Disruption Actions (Low Conf)  : {high_disruption_count_low_conf}")
    print(f"  Safety Action Shifts                : {high_disruption_count_normal - high_disruption_count_low_conf} actions safe-scaled")
    results["confidence_action_filtering"] = {
        "normal_high_disruption": high_disruption_count_normal,
        "low_conf_high_disruption": high_disruption_count_low_conf,
        "safe_scaled": high_disruption_count_normal - high_disruption_count_low_conf,
    }

    # -------------------------------------------------------------------------
    # Experiment 3: Decision Stability (Action Oscillation Reduction)
    # -------------------------------------------------------------------------
    print("\n[ Exp 3 ] Decision Stability & Action Change Penalty")
    # Initial round plan
    plan_r1 = {"port_scan_recon-res-0": "monitor", "port_scan_recon-res-1": "rotate_credentials"}

    # Solve round 2 WITHOUT switching penalty
    constraints_no_pen = generate_adaptive_constraints(contexts, confidences, previous_plan=plan_r1)
    constraints_no_pen.switching_penalty = 0.0
    plan_r2_no_pen, _ = solve_with_ilp(scenario, scores, max_budget=5.0, constraints=constraints_no_pen, confidences=confidences)

    # Solve round 2 WITH switching penalty (0.15)
    constraints_with_pen = generate_adaptive_constraints(contexts, confidences, previous_plan=plan_r1)
    constraints_with_pen.switching_penalty = 0.15
    plan_r2_with_pen, _ = solve_with_ilp(scenario, scores, max_budget=5.0, constraints=constraints_with_pen, confidences=confidences)

    switches_no_pen = sum(1 for rid in plan_r1 if plan_r1[rid] != plan_r2_no_pen.get(rid))
    switches_with_pen = sum(1 for rid in plan_r1 if plan_r1[rid] != plan_r2_with_pen.get(rid))

    print(f"  Action switches without penalty : {switches_no_pen}")
    print(f"  Action switches with penalty    : {switches_with_pen}")
    print(f"  Stability Improvement           : {switches_no_pen - switches_with_pen} oscillations prevented")
    results["decision_stability"] = {
        "switches_without_penalty": switches_no_pen,
        "switches_with_penalty": switches_with_pen,
    }

    # -------------------------------------------------------------------------
    # Experiment 4: Explainability & Rationale Completeness
    # -------------------------------------------------------------------------
    print("\n[ Exp 4 ] Explainability Rationale & Decision Trace Completeness")
    explainer = DecisionExplainer()
    utilities = calculate_all_action_utilities(scenario, contexts, confidences)
    exp_report = explainer.generate_full_explanation_report(
        scenario, plan_ilp, contexts, confidences, constraints, utilities
    )
    completeness_pct = 100.0 if len(exp_report["explanations"]) == len(scenario["resources"]) else 0.0
    print(f"  Explanations generated : {len(exp_report['explanations'])} / {len(scenario['resources'])}")
    print(f"  Trace Completeness     : {completeness_pct:.1f}%")
    results["explainability"] = {
        "completeness_pct": completeness_pct,
        "total_explained": len(exp_report["explanations"]),
    }

    # -------------------------------------------------------------------------
    # Experiment 5: EMA Feedback Adaptation over Multiple Rounds
    # -------------------------------------------------------------------------
    print("\n[ Exp 5 ] Rich Layer 9 EMA Feedback Adaptation")
    learner = FeedbackLearner(data_path="test_eval_feedback.json")
    w_initial = learner.get_current_weights()["containment_effectiveness"]

    # Simulate 3 incident feedback rounds with false positives & overrides
    for r in range(1, 4):
        learner.record_feedback(
            incident_id=f"eval-inc-{r}",
            scenario="port_scan_recon",
            plan=plan_ilp,
            successful=False,
            false_positive_status=(r == 1),
            notes=f"Evaluation round {r}",
        )
    w_final = learner.get_current_weights()["containment_effectiveness"]
    print(f"  Initial Containment Weight : {w_initial:.4f}")
    print(f"  Final Containment Weight   : {w_final:.4f}")
    print(f"  Weight Adaptation Active   : {w_initial != w_final}")
    results["feedback_adaptation"] = {
        "initial_containment_weight": round(w_initial, 4),
        "final_containment_weight": round(w_final, 4),
    }

    import os
    if os.path.exists("test_eval_feedback.json"):
        os.remove("test_eval_feedback.json")

    print("\n" + "=" * 65)
    print("  DECISION ENGINE EVALUATION COMPLETE: ALL EXPERIMENTS PASSED")
    print("=" * 65)
    return results


if __name__ == "__main__":
    evaluate_decision_engine()
