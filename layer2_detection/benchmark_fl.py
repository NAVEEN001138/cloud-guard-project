"""
=============================================================================
LAYER 2: THREAT DETECTION & FEDERATED EDGE AI
Module: benchmark_fl.py
-----------------------------------------------------------------------------
Problem Solved:
  Executes comprehensive benchmark comparison between Federated Learning (FedAvg)
  and alternative neural network models (Centralized DNN, Local NN, 1D-CNN, ML).
  Saves results to JSON for SOC Dashboard visualizer.

Inputs:  Sample size, number of IoT Edge clients, and FL communication rounds.
Outputs: JSON benchmark report (benchmark_fl_results.json).
=============================================================================
"""

import json
import os
import time
from layer2_detection.federated_detector import FederatedEdgeManager

BENCHMARK_OUTPUT_PATH = "benchmark_fl_results.json"

def run_and_save_fl_benchmark(sample_size: int = 15_000, num_clients: int = 5, fl_rounds: int = 8) -> dict:
    print(f"Initializing Edge-IIoTset Federated Learning Manager ({sample_size} samples, {num_clients} clients)...")
    manager = FederatedEdgeManager(sample_size=sample_size, num_clients=num_clients, non_iid=True, seed=42)
    
    print("\nRunning Benchmark Across All Neural Network Algorithms...")
    t0 = time.time()
    results = manager.run_full_benchmark(fl_rounds=fl_rounds)
    total_duration = time.time() - t0

    dataset_summary = {
        "source": manager.meta.get("source", "Edge-IIoTset"),
        "total_samples": manager.meta.get("rows", len(manager.y)),
        "num_features": manager.meta.get("features_count", manager.X_train.shape[1]),
        "attack_rate": manager.meta.get("positive_rate", float(manager.y.mean())),
        "attack_classes": manager.meta.get("attack_types", {})
    }

    payload = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset_summary": dataset_summary,
        "config": {
            "sample_size": sample_size,
            "num_clients": num_clients,
            "non_iid": True,
            "fl_rounds": fl_rounds
        },
        "total_benchmark_time_sec": round(total_duration, 2),
        "results": results
    }

    with open(BENCHMARK_OUTPUT_PATH, "w") as f:
        json.dump(payload, f, indent=2)

    print(f"\nSaved FL Benchmark results to {BENCHMARK_OUTPUT_PATH}")
    return payload


if __name__ == "__main__":
    run_and_save_fl_benchmark(sample_size=12_000, num_clients=5, fl_rounds=6)
