"""
=============================================================================
LAYER 6: DECISION OPTIMIZATION ENGINE
Module: benchmark.py
-----------------------------------------------------------------------------
Problem Solved:
  Runs comparative benchmarks across Quantum QAOA, exact QUBO, classical ILP,
  and Greedy solvers as problem size scales up. Solves runtime & objective gap
  analysis for patent performance validation.

Inputs:  Resource scaling parameters & maximum budget.
Outputs: JSON benchmark report (benchmark_results.json).
=============================================================================
"""

import json
import time
from typing import List, Dict

from layer1_telemetry.fake_incident import SCENARIOS
from layer2_detection.detector import ThreatDetector
from layer6_optimization.decision_engine import build_qubo, solve_quantum, decode_action_plan, calculate_objective, calculate_total_cost, is_budget_feasible
from layer6_optimization.baseline_greedy import solve_with_greedy, solve_with_greedy_budget, solve_with_ilp

BENCHMARK_OUTPUT_PATH = "benchmark_results.json"


def run_and_save_benchmark(max_resources: int = 4) -> dict:
    scenario = SCENARIOS["ddos_flood"]
    detector = ThreatDetector(verbose=False)
    scores = detector.score_scenario(scenario)

    results = []
    for num_res in range(1, min(max_resources + 1, len(scenario["resources"]) + 1)):
        sub_scenario = {
            "scenario": scenario["scenario"],
            "resources": scenario["resources"][:num_res]
        }
        sub_scores = {r["id"]: scores[r["id"]] for r in sub_scenario["resources"]}

        # 1. Greedy
        t0 = time.time()
        g_plan, g_obj = solve_with_greedy(sub_scenario, sub_scores)
        g_time = time.time() - t0

        # 2. ILP
        t0 = time.time()
        ilp_plan, ilp_obj = solve_with_ilp(sub_scenario, sub_scores)
        ilp_time = time.time() - t0

        # 3. Quantum QUBO
        t0 = time.time()
        qp, var_lookup = build_qubo(sub_scenario, sub_scores, hard_budget=False)
        q_sol = solve_quantum(qp, method="numpy")
        q_plan = decode_action_plan(qp, var_lookup, q_sol)
        q_obj = calculate_objective(q_plan, sub_scenario, sub_scores)
        q_time = time.time() - t0

        results.append({
            "num_resources": num_res,
            "num_qubits": num_res * 5,
            "greedy": {"objective": round(g_obj, 3), "time_sec": round(g_time, 4)},
            "ilp": {"objective": round(ilp_obj, 3), "time_sec": round(ilp_time, 4)},
            "quantum": {"objective": round(q_obj, 3), "time_sec": round(q_time, 4)}
        })

    payload = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "benchmarks": results}
    with open(BENCHMARK_OUTPUT_PATH, "w") as f:
        json.dump(payload, f, indent=2)

    print(f"Saved benchmark results to {BENCHMARK_OUTPUT_PATH}")
    return payload


if __name__ == "__main__":
    run_and_save_benchmark()
