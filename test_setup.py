"""Test script to verify the project setup."""

import os
import sys

print("Testing project setup...")
print("=" * 60)

OK = "[OK]"
FAIL = "[FAIL]"

required_files = [
    "config.py",
    "pipeline.py",
    "fake_incident.py",
    "detector.py",
    "decision_engine.py",
    "baseline_greedy.py",
    "executor.py",
    "streamlit_app.py",
    "data_loader.py",
    "benchmark.py",
    "requirements.txt",
]

print("\n1. Checking required files:")
for filename in required_files:
    exists = os.path.exists(filename)
    print(f"   {OK if exists else FAIL} {filename}")

print("\n2. Checking datasets:")
cloudtrail_files = ["nineteenFeaturesDf.csv", "dec12_18features.csv"]
iscx_files = [
    f for f in os.listdir("datasets")
    if f.endswith(".csv") and "ISCX" in f
] if os.path.isdir("datasets") else []

for filename in cloudtrail_files:
    in_root = os.path.exists(filename)
    in_datasets = os.path.exists(os.path.join("datasets", filename))
    exists = in_root or in_datasets
    location = "root" if in_root else ("datasets/" if in_datasets else "missing")
    print(f"   {OK if exists else FAIL} {filename} ({location})")

print(f"   {OK if iscx_files else FAIL} ISCX/CIC-IDS2017 files: {len(iscx_files)} found")
for filename in iscx_files[:4]:
    print(f"      - {filename}")
if len(iscx_files) > 4:
    print(f"      ... and {len(iscx_files) - 4} more")

print("\n3. Testing imports:")
modules = [
    "config",
    "data_loader",
    "fake_incident",
    "detector",
    "decision_engine",
    "baseline_greedy",
    "pipeline",
]
for mod in modules:
    try:
        __import__(mod)
        print(f"   {OK} {mod}")
    except Exception as exc:
        print(f"   {FAIL} {mod}: {exc}")

print("\n4. Testing data loading:")
try:
    from data_loader import build_training_dataset

    X, y, meta = build_training_dataset()
    if len(y):
        source = meta.get("source", "unknown")
        print(f"   {OK} Loaded {len(y)} rows from {source} (attack rate {y.mean():.2%})")
    else:
        print(f"   {OK} data_loader works (no CSV data found)")
except Exception as exc:
    print(f"   {FAIL} Data loading failed: {exc}")

print("\n5. Testing pipeline (classical only):")
try:
    from fake_incident import SCENARIOS
    from pipeline import run_pipeline

    result = run_pipeline(SCENARIOS["port_scan_recon"], run_quantum=False)
    print(f"   {OK} Pipeline ran {len(result.solver_results)} solvers")
except Exception as exc:
    print(f"   {FAIL} Pipeline failed: {exc}")

print("\n" + "=" * 60)
print("Setup test complete!")
