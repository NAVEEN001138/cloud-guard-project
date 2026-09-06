"""
=============================================================================
DIAGRAM GENERATOR: ARCHITECTURE & PROCESS FLOW IMAGES (300 DPI)
Module: generate_diagram_images.py
-----------------------------------------------------------------------------
Generates publication-quality high-resolution PNG image files (300 DPI):
  1. architecture_diagram.png - 9-Layer Security Constraint Compiler Architecture
  2. process_flow_diagram.png - Runtime Security Constraint Compilation & Decision Flow

Outputs are saved in the current directory and can be directly inserted into
the patent application, IEEE research paper, or presentation slides.
=============================================================================
"""

import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches

# Set crisp rendering styles
plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.size"] = 9


def create_architecture_diagram():
    fig, ax = plt.subplots(figsize=(16, 26), dpi=300)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    fig.patch.set_facecolor("#0b0f19")

    # Header Card
    header_box = patches.FancyBboxPatch(
        (0.05, 0.942), 0.90, 0.040,
        boxstyle="round,pad=0.004,rounding_size=0.010",
        facecolor="#0f172a", edgecolor="#00d4ff", linewidth=2.0
    )
    ax.add_patch(header_box)

    ax.text(
        0.5, 0.968,
        "CLOUD GUARDIAN: 9-LAYER SECURITY CONSTRAINT COMPILER ARCHITECTURE",
        fontsize=14.0, fontweight="bold", color="#00d4ff", ha="center", va="center"
    )
    ax.text(
        0.5, 0.952,
        "Adaptive Runtime Security Constraint Compilation and Multi-Solver Decision Framework",
        fontsize=9.5, color="#94a3b8", ha="center", va="center"
    )

    # Clean, perfectly budgeted layer definitions (3 concise bullets for standard, 5 for Layer 5)
    layer_data = [
        ("Layer 0: Preprocessing & Scaler Cache Manager (Feature Engineering Engine)", [
            "Raw Edge-IIoTset Telemetry: 36 protocol features across Modbus TCP, MQTT, TCP/UDP, ARP, ICMP",
            "Median Imputation -> 1.5x IQR Outlier Clipping -> log1p Variance Stabilization -> StandardScaler",
            "Output: Module-level fitted Scaler Cache (preprocessor_cache.pkl) for uniform FedAvg weight scaling"
        ], "#1e293b", "#38bdf8", False),

        ("Layer 1: Telemetry Ingestion & Incident Scenario Sharding", [
            "Multi-Protocol Telemetry Ingestion (157,800 network traffic flows across 15 attack classes)",
            "5 Heterogeneous Asset Incident Scenarios: Industrial SCADA PLC, Healthcare ePHI, API GW, IAM, Camera IoT",
            "Non-IID Edge Data Partitioning: Distributed client shards (PLC, Smart Gateway, IoT Sensor Node)"
        ], "#1e293b", "#818cf8", False),

        ("Layer 2: Federated Edge AI Threat Detection Hub", [
            "Local Edge Node Training: Local PyTorch MLP / 1D-CNN (Private telemetry remains strictly on-device)",
            "Global Server Aggregation: Multi-algorithm support (FedAvg, FedProx, FedNova, FedAdam, FedMedian)",
            "Youden's J ROC Threshold Calibration: 94.05% Calibrated Mean Validation Accuracy (0.9577 ROC-AUC, 98.82% Precision)"
        ], "#1e293b", "#34d399", False),

        ("Layer 3: Asset Context & Regulatory Safeguards Aggregator", [
            "Threat Ingestion: Dynamic threat score (s_i), attack velocity, and lateral movement probability",
            "Asset & Operational Context: C-I-A Priority Profiles, SLA Downtime Recovery Cost ($/min), Business Impact",
            "Regulatory Technical Safeguards: Encoded policy rules (HIPAA 45 CFR § 164.312, GDPR Art. 32, NERC CIP-007)"
        ], "#1e293b", "#fbbf24", False),

        ("Layer 4: Signal Fusion & Decision Confidence Evaluator", [
            "Multi-Factor Confidence Fusion: Model uncertainty + sensor reliability + telemetry freshness = Confidence (c_i)",
            "Calibrated Confidence Tiers: HIGH (c >= 0.85), MODERATE (0.60 <= c < 0.85), LOW (c < 0.60)",
            "Confidence-Gated Action Domain: Restricts high-disruption interventions when confidence < 0.70"
        ], "#1e293b", "#f87171", False),

        ("Layer 5: Security Constraint Compiler Architecture ★ (Patent Core)", [
            "Causal Dependency Graph (DAG): Capability Node -> Variable Domain Pruning (x_forbidden ∉ A')",
            "Topology Restructuring: Pruning downstream conflict hyperedges E(A') & synthesizing incident budget bound B",
            "Security Constraint IR (SC-IR): Solver-independent canonical JSON with explicit Hard vs. Soft Partitioning",
            "Pre-Solve Invariant Validator: 7 deterministic safety invariant checks + Cryptographic SHA-256 State Integrity Digest",
            "Incident-Specific Formulation Compiler: Compiles verified IR into target QUBO Hamiltonians & classical ILP models"
        ], "#1e1b4b", "#c084fc", True),

        ("Layer 6: Interchangeable Multi-Solver Decision Engine", [
            "Problem Formulation: Strictly constructed over pre-solve certified feasible decision variables A'",
            "Interchangeable Solvers: IBM Qiskit QAOA variational circuits & PuLP Integer Linear Programming (CBC)",
            "100.0% Decision Fidelity (DF%): Identical optimal mitigation vector x* across classical & quantum solvers"
        ], "#1e293b", "#38bdf8", False),

        ("Layer 7 & 8: Response Utility, Orchestration & Explainability", [
            "Multi-Attribute Utility: Balances containment efficacy vs downtime vs cost (P_switch suppresses churn 40% -> 0%)",
            "Automated Playbook Execution: Network isolation, credential rotation, IP rate-limiting, least-privilege tokens",
            "RBAC Role-Tailored Audit Rationale: Deterministic explainability for SOC Analysts, CISOs, Auditors & Public Logs"
        ], "#1e293b", "#4ade80", False),

        ("Layer 9: System B Experience Memory with Strict Validation Gate", [
            "Post-Incident Empirical Learning: Ingests containment latency, service interruption, and SLA outcome telemetry",
            "Strict Validation Gate: Verifies candidate constraint rules NEVER restrict failsafes (monitor) or mutate hard safety invariants",
            "Closed-Loop Structural Adaptation: Injects verified structural rules into future incident DAGs to refine variable domains"
        ], "#1e293b", "#f472b6", False),
    ]

    # Dynamically compute box heights and top-to-bottom layout
    curr_top = 0.924
    box_gap = 0.016
    rendered_boxes = []

    for idx, (title, details, bg_color, border_color, is_core) in enumerate(layer_data):
        box_height = 0.106 if is_core else 0.068
        y_pos = curr_top - box_height

        # Drawing Box with crisp rounded padding
        rect = patches.FancyBboxPatch(
            (0.05, y_pos), 0.90, box_height,
            boxstyle="round,pad=0.004,rounding_size=0.010",
            facecolor=bg_color, edgecolor=border_color,
            linewidth=2.4 if is_core else 1.8
        )
        ax.add_patch(rect)

        # Title Text
        title_size = 10.5 if is_core else 9.5
        ax.text(
            0.07, y_pos + box_height - 0.014,
            title, fontsize=title_size, fontweight="bold",
            color=border_color, va="top"
        )

        # Detail Lines
        line_spacing = 0.0142 if is_core else 0.0140
        for line_idx, line in enumerate(details):
            ax.text(
                0.08, y_pos + box_height - 0.029 - line_idx * line_spacing,
                f"• {line}", fontsize=8.2, color="#f1f5f9", va="top"
            )

        rendered_boxes.append((y_pos, box_height, border_color))
        curr_top = y_pos - box_gap

    # Clean downward arrows between consecutive boxes
    for idx in range(len(rendered_boxes) - 1):
        curr_y, _, border_color = rendered_boxes[idx]
        next_y, next_h, _ = rendered_boxes[idx + 1]
        arrow_start_y = curr_y - 0.003
        arrow_end_y = (next_y + next_h) + 0.003
        arrow = patches.FancyArrowPatch(
            (0.5, arrow_start_y), (0.5, arrow_end_y),
            arrowstyle="-|>", mutation_scale=13, color=border_color, linewidth=1.8
        )
        ax.add_patch(arrow)

    # Footer Card - Mathematical Claim & Evidence Summary
    footer_top = rendered_boxes[-1][0] - 0.018
    footer_height = 0.046
    footer_box = patches.FancyBboxPatch(
        (0.05, footer_top - footer_height), 0.90, footer_height,
        boxstyle="round,pad=0.004,rounding_size=0.010",
        facecolor="#0f172a", edgecolor="#64748b", linewidth=1.2
    )
    ax.add_patch(footer_box)

    ax.text(
        0.5, footer_top - 0.016,
        "INVENTIVE STEP: Runtime Transformation S -> A' -> (E(A'), B, P) -> SC-IR -> Verified Invariants -> {QUBO, ILP}",
        fontsize=9.5, fontweight="bold", color="#38bdf8", ha="center", va="center"
    )
    ax.text(
        0.5, footer_top - 0.033,
        "Rigorous Boundary: Problem formulation occurs STRICTLY over pre-solve certified feasible action domain A'. 100.0% Decision Fidelity (DF%).",
        fontsize=8.5, color="#94a3b8", ha="center", va="center"
    )

    out_path = "architecture_diagram.png"
    plt.savefig(out_path, dpi=300, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"[OK] Generated: {os.path.abspath(out_path)}")


def create_process_flow_diagram():
    fig, ax = plt.subplots(figsize=(18, 12.5), dpi=300)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    fig.patch.set_facecolor("#0b0f19")

    # Header Banner
    header_box = patches.FancyBboxPatch(
        (0.04, 0.935), 0.92, 0.048,
        boxstyle="round,pad=0.004,rounding_size=0.010",
        facecolor="#0f172a", edgecolor="#00d4ff", linewidth=2.0
    )
    ax.add_patch(header_box)

    ax.text(
        0.50, 0.965,
        "RUNTIME SECURITY CONSTRAINT COMPILATION & DECISION PIPELINE",
        fontsize=14.5, fontweight="bold", color="#00d4ff", ha="center", va="center"
    )
    ax.text(
        0.50, 0.947,
        "End-to-End Incident Pipeline: Telemetry -> Detection -> Causal Pruning -> SC-IR -> Invariant Validation -> Multi-Solver -> Response",
        fontsize=9.2, color="#94a3b8", ha="center", va="center"
    )

    # Box dimensions
    box_w = 0.18
    box_h = 0.19
    r1_y = 0.68
    r2_y = 0.38
    r3_y = 0.08

    # Row 1 (Left to Right): Steps 1 to 4
    top_row = [
        ("Step 1: Telemetry Ingest", [
            "Raw Edge-IIoTset Traffic",
            "Layer 0 Scaler Cache",
            "Outlier Clipping & log1p"
        ], "#1e293b", "#38bdf8", 0.04),

        ("Step 2: Federated AI", [
            "Private Local PyTorch Edge",
            "FedAvg Model Aggregation",
            "Youden's J ROC Threshold"
        ], "#1e293b", "#34d399", 0.25),

        ("Step 3: Context & Trust", [
            "C-I-A Priority Impact",
            "SLA Downtime Recovery",
            "Confidence Gating (c_i)"
        ], "#1e293b", "#fbbf24", 0.46),

        ("Step 4: Causal Pruning", [
            "Constraint DAG (L5 ★)",
            "Physical Safety Limits",
            "Domain: x_forbidden ∉ A'"
        ], "#1e1b4b", "#c084fc", 0.67),
    ]

    for title, lines, bg, border, x_pos in top_row:
        box = patches.FancyBboxPatch(
            (x_pos, r1_y), box_w, box_h,
            boxstyle="round,pad=0.004,rounding_size=0.012",
            facecolor=bg, edgecolor=border, linewidth=2.0
        )
        ax.add_patch(box)
        ax.text(x_pos + box_w/2, r1_y + box_h - 0.024, title, fontsize=9.2, fontweight="bold", color=border, ha="center", va="top")
        for l_idx, line in enumerate(lines):
            ax.text(x_pos + box_w/2, r1_y + box_h - 0.070 - l_idx * 0.034, line, fontsize=8.2, color="#ffffff", ha="center", va="top")

        # Horizontal arrow right
        if x_pos < 0.65:
            arr = patches.FancyArrowPatch(
                (x_pos + box_w + 0.004, r1_y + box_h/2), (x_pos + box_w + 0.026, r1_y + box_h/2),
                arrowstyle="-|>", mutation_scale=14, color="#38bdf8", linewidth=1.8
            )
            ax.add_patch(arr)

    # Arrow from Row 1 Step 4 DOWN to Row 2 Step 5
    arr_r1_to_r2 = patches.FancyArrowPatch(
        (0.67 + box_w/2, r1_y - 0.004), (0.67 + box_w/2, r2_y + box_h + 0.004),
        arrowstyle="-|>", mutation_scale=14, color="#c084fc", linewidth=2.0
    )
    ax.add_patch(arr_r1_to_r2)

    # Row 2 (Right to Left): Steps 5 to 8
    mid_row = [
        ("Step 5: Topology Shift", [
            "Prune Conflicts E(A')",
            "Regenerate Budget B",
            "Eliminate Dead Edges"
        ], "#1e1b4b", "#c084fc", 0.67),

        ("Step 6: SC-IR Synthesis", [
            "Canonical JSON IR",
            "Hard Invariants vs",
            "Soft Preferences"
        ], "#1e1b4b", "#c084fc", 0.46),

        ("Step 7: Invariant Cert.", [
            "7 Deterministic Checks",
            "Pre-Solve Certified",
            "SHA-256 State Digest"
        ], "#1e1b4b", "#c084fc", 0.25),

        ("Step 8: Math Compilation", [
            "Formulation Compiler",
            "Target QUBO (Qiskit)",
            "Target ILP (PuLP)"
        ], "#1e1b4b", "#38bdf8", 0.04),
    ]

    for title, lines, bg, border, x_pos in mid_row:
        box = patches.FancyBboxPatch(
            (x_pos, r2_y), box_w, box_h,
            boxstyle="round,pad=0.004,rounding_size=0.012",
            facecolor=bg, edgecolor=border, linewidth=2.0
        )
        ax.add_patch(box)
        ax.text(x_pos + box_w/2, r2_y + box_h - 0.024, title, fontsize=9.2, fontweight="bold", color=border, ha="center", va="top")
        for l_idx, line in enumerate(lines):
            ax.text(x_pos + box_w/2, r2_y + box_h - 0.070 - l_idx * 0.034, line, fontsize=8.2, color="#ffffff", ha="center", va="top")

        # Horizontal arrow left
        if x_pos > 0.10:
            arr = patches.FancyArrowPatch(
                (x_pos - 0.004, r2_y + box_h/2), (x_pos - 0.026, r2_y + box_h/2),
                arrowstyle="-|>", mutation_scale=14, color="#c084fc", linewidth=1.8
            )
            ax.add_patch(arr)

    # Arrow from Row 2 Step 8 DOWN to Row 3 Step 9
    arr_r2_to_r3 = patches.FancyArrowPatch(
        (0.04 + box_w/2, r2_y - 0.004), (0.04 + box_w/2, r3_y + box_h + 0.004),
        arrowstyle="-|>", mutation_scale=14, color="#38bdf8", linewidth=2.0
    )
    ax.add_patch(arr_r2_to_r3)

    # Row 3 (Left to Right): Steps 9 to 11
    bot_w = 0.245
    bot_row = [
        ("Step 9: Multi-Solver Execution", [
            "Interchangeable QAOA / ILP Solvers",
            "Optimizes Active Mitigations x*",
            "100.0% Decision Fidelity (DF%)"
        ], "#1e293b", "#38bdf8", 0.04),

        ("Step 10: Orchestration & Stability", [
            "Enforce Switching Penalty P_switch",
            "Automated Playbook Execution",
            "Role-Tailored Audit Explanations"
        ], "#1e293b", "#4ade80", 0.33),

        ("Step 11: Experience Memory (L9)", [
            "Post-Incident Efficacy Feedback",
            "Strict Validation Gate on Rules",
            "Admits Rules to Future DAG"
        ], "#1e293b", "#f472b6", 0.62),
    ]

    for title, lines, bg, border, x_pos in bot_row:
        box = patches.FancyBboxPatch(
            (x_pos, r3_y), bot_w, box_h,
            boxstyle="round,pad=0.004,rounding_size=0.012",
            facecolor=bg, edgecolor=border, linewidth=2.0
        )
        ax.add_patch(box)
        ax.text(x_pos + bot_w/2, r3_y + box_h - 0.024, title, fontsize=9.2, fontweight="bold", color=border, ha="center", va="top")
        for l_idx, line in enumerate(lines):
            ax.text(x_pos + bot_w/2, r3_y + box_h - 0.070 - l_idx * 0.034, line, fontsize=8.2, color="#ffffff", ha="center", va="top")

    # Connect step 9 to step 10
    arr_bot1 = patches.FancyArrowPatch(
        (0.04 + bot_w + 0.004, r3_y + box_h/2), (0.33 - 0.004, r3_y + box_h/2),
        arrowstyle="-|>", mutation_scale=14, color="#4ade80", linewidth=1.8
    )
    ax.add_patch(arr_bot1)

    # Connect step 10 to step 11
    arr_bot2 = patches.FancyArrowPatch(
        (0.33 + bot_w + 0.004, r3_y + box_h/2), (0.62 - 0.004, r3_y + box_h/2),
        arrowstyle="-|>", mutation_scale=14, color="#f472b6", linewidth=1.8
    )
    ax.add_patch(arr_bot2)

    # Clean, dedicated outer feedback loop channel:
    # From Step 11 right edge -> dedicated channel (x=0.905) -> up to Row 1 Step 4 right edge
    step11_right = 0.62 + bot_w
    step4_right = 0.67 + box_w
    channel_x = 0.905

    # Segment 1: Step 11 to channel
    arr_fb_seg1 = patches.FancyArrowPatch(
        (step11_right + 0.004, r3_y + box_h/2), (channel_x, r3_y + box_h/2),
        arrowstyle="-", color="#f472b6", linewidth=2.0, linestyle="--"
    )
    ax.add_patch(arr_fb_seg1)

    # Segment 2: Vertical run through dedicated right channel
    arr_fb_seg2 = patches.FancyArrowPatch(
        (channel_x, r3_y + box_h/2), (channel_x, r1_y + box_h/2),
        arrowstyle="-", color="#f472b6", linewidth=2.0, linestyle="--"
    )
    ax.add_patch(arr_fb_seg2)

    # Segment 3: Channel to Step 4 with arrow
    arr_fb_seg3 = patches.FancyArrowPatch(
        (channel_x, r1_y + box_h/2), (step4_right + 0.004, r1_y + box_h/2),
        arrowstyle="-|>", mutation_scale=15, color="#f472b6", linewidth=2.0, linestyle="--"
    )
    ax.add_patch(arr_fb_seg3)

    # Feedback Gate Badge Card in the right channel
    fb_card = patches.FancyBboxPatch(
        (0.880, 0.44), 0.090, 0.12,
        boxstyle="round,pad=0.004,rounding_size=0.008",
        facecolor="#1e1b4b", edgecolor="#f472b6", linewidth=1.5
    )
    ax.add_patch(fb_card)

    ax.text(
        0.925, 0.540,
        "CLOSED-LOOP\nFEEDBACK GATE",
        fontsize=8.0, fontweight="bold", color="#f472b6", ha="center", va="top"
    )
    ax.text(
        0.925, 0.495,
        "• Experience Memory\n• Strict Validation\n• Invariant Protection\n• Future DAG Update",
        fontsize=6.8, color="#cbd5e1", ha="center", va="top"
    )

    out_path = "process_flow_diagram.png"
    plt.savefig(out_path, dpi=300, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"[OK] Generated: {os.path.abspath(out_path)}")


if __name__ == "__main__":
    create_architecture_diagram()
    create_process_flow_diagram()
