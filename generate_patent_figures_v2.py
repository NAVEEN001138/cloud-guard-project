"""
CLOUD GUARDIAN — PATENT FIGURE GENERATOR V2

Generates patent/faculty-friendly figures from the corrected V2 specification.
The figures intentionally avoid volatile benchmark percentages and unsupported
production-deployment wording.

Outputs:
  patent_v2_fig1_overall_architecture.png
  patent_v2_fig2_core_compilation_flow.png
  patent_v2_fig3_incremental_recompilation.png
  patent_v2_fig4_certificate_binding.png
  patent_v2_fig5_structural_excision_vs_penalty.png

All drawings use black/white/grayscale styling and stable reference numerals.
"""

from __future__ import annotations

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch


# -----------------------------------------------------------------------------
# Common helpers
# -----------------------------------------------------------------------------

FIG_DPI = 300
FONT = "DejaVu Sans"

plt.rcParams["font.family"] = FONT


def _setup(width: float, height: float, title: str, subtitle: str = ""):
    fig, ax = plt.subplots(figsize=(width, height), dpi=FIG_DPI)
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(
        0.5,
        0.975,
        title,
        ha="center",
        va="top",
        fontsize=14,
        fontweight="bold",
        color="black",
    )
    if subtitle:
        ax.text(
            0.5,
            0.947,
            subtitle,
            ha="center",
            va="top",
            fontsize=8.5,
            color="0.25",
        )
    return fig, ax


def _box(
    ax,
    x: float,
    y: float,
    w: float,
    h: float,
    title: str,
    lines=None,
    linewidth: float = 1.4,
    face: str = "white",
    title_size: float = 9.0,
    body_size: float = 7.4,
    center: bool = True,
):
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0.004,rounding_size=0.008",
        linewidth=linewidth,
        edgecolor="black",
        facecolor=face,
    )
    ax.add_patch(patch)

    tx = x + w / 2 if center else x + 0.014
    ha = "center" if center else "left"
    ax.text(
        tx,
        y + h - 0.020,
        title,
        ha=ha,
        va="top",
        fontsize=title_size,
        fontweight="bold",
        color="black",
    )

    if lines:
        start = y + h - 0.058
        step = min(0.031, (h - 0.075) / max(1, len(lines)))
        for i, line in enumerate(lines):
            ax.text(
                tx,
                start - i * step,
                line if center else f"• {line}",
                ha=ha,
                va="top",
                fontsize=body_size,
                color="0.15",
            )
    return patch


def _arrow(ax, x1, y1, x2, y2, dashed=False, label=None, label_dx=0, label_dy=0):
    arr = FancyArrowPatch(
        (x1, y1),
        (x2, y2),
        arrowstyle="-|>",
        mutation_scale=13,
        linewidth=1.3,
        linestyle="--" if dashed else "-",
        color="black",
    )
    ax.add_patch(arr)
    if label:
        ax.text(
            (x1 + x2) / 2 + label_dx,
            (y1 + y2) / 2 + label_dy,
            label,
            ha="center",
            va="center",
            fontsize=7.2,
            color="0.2",
            bbox=dict(facecolor="white", edgecolor="none", pad=0.5),
        )
    return arr


def _save(fig, filename: str):
    plt.savefig(filename, dpi=FIG_DPI, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"[OK] Generated {filename}")


# -----------------------------------------------------------------------------
# FIGURE 1 — Overall System Architecture
# -----------------------------------------------------------------------------


def create_figure_1():
    fig, ax = _setup(
        12,
        16,
        "FIG. 1 — OVERALL SYSTEM ARCHITECTURE",
        "Runtime Security Constraint Compilation and Pre-Solve Certification for Automated Infrastructure Response",
    )

    x = 0.19
    w = 0.62
    h = 0.065
    ys = [0.855, 0.765, 0.675, 0.585, 0.495]

    stages = [
        ("10 Telemetry / Incident-State Source", ["telemetry, incident scenario, asset state"]),
        ("20 Preprocessing Subsystem", ["normalization and feature preparation"]),
        ("30 Threat-State Derivation Subsystem", ["threat score / detector output"]),
        ("40 Context Aggregation Subsystem", ["asset, business, SLA, encoded policy context"]),
        ("50 Confidence / Action-Eligibility Subsystem", ["confidence and high-disruption eligibility state"]),
    ]

    for (title, lines), y in zip(stages, ys):
        _box(ax, x, y, w, h, title, lines, face="0.97")

    for a, b in zip(ys[:-1], ys[1:]):
        _arrow(ax, 0.5, a - 0.004, 0.5, b + h + 0.004)

    core_y = 0.250
    core_h = 0.205
    _box(
        ax,
        0.11,
        core_y,
        0.78,
        core_h,
        "60 RUNTIME SECURITY CONSTRAINT COMPILER — PATENT CORE",
        [
            "Runtime Feasibility Evaluation",
            "Structural Decision-Domain Transformation",
            "Fixed-Point Dependency Closure",
            "Constraint Topology / Operational-Bound Regeneration",
            "Versioned SC-IR Generation",
            "Pre-Solve Safety Certification",
            "Certificate-Bound Formulation Gate",
        ],
        linewidth=2.2,
        face="0.93",
        title_size=10.5,
        body_size=8.0,
        center=False,
    )
    _arrow(ax, 0.5, ys[-1] - 0.004, 0.5, core_y + core_h + 0.004)

    _box(
        ax,
        0.08,
        0.115,
        0.28,
        0.085,
        "70 Solver Backend Subsystem",
        ["ILP / QUBO / other backend"],
        face="0.98",
    )
    _box(
        ax,
        0.39,
        0.115,
        0.24,
        0.085,
        "80 Utility / Explanation",
        ["ranking and explanation"],
        face="0.98",
    )
    _box(
        ax,
        0.66,
        0.115,
        0.27,
        0.085,
        "90 Response-Plan Interface",
        ["simulation or deployment adapter"],
        face="0.98",
    )
    _box(
        ax,
        0.66,
        0.015,
        0.27,
        0.070,
        "95 Experience Memory",
        ["certified learned rules only"],
        face="0.98",
    )

    _arrow(ax, 0.34, core_y, 0.22, 0.200)
    _arrow(ax, 0.36, 0.157, 0.39, 0.157)
    _arrow(ax, 0.63, 0.157, 0.66, 0.157)
    _arrow(ax, 0.795, 0.115, 0.795, 0.085)
    _arrow(ax, 0.66, 0.050, 0.09, core_y + 0.055, dashed=True, label="safe learned rule", label_dy=0.012)

    ax.text(
        0.5,
        0.005,
        "Supporting detector and solver technologies remain replaceable; the runtime constraint compiler is upstream of solver selection.",
        ha="center",
        va="bottom",
        fontsize=7.5,
        color="0.25",
    )

    _save(fig, "patent_v2_fig1_overall_architecture.png")


# -----------------------------------------------------------------------------
# FIGURE 2 — Patent-Core Runtime Compilation Flow
# -----------------------------------------------------------------------------


def create_figure_2():
    fig, ax = _setup(
        16,
        20,
        "FIG. 2 — RUNTIME SECURITY CONSTRAINT COMPILATION AND CERTIFICATION",
        "Runtime transformation of infrastructure security state into a certified solver-specific response formulation",
    )

    x = 0.25
    w = 0.50
    h = 0.072
    ys = [0.855, 0.755, 0.655, 0.555, 0.455]

    stage_data = [
        ("100 Runtime State Input S_t", ["resource/capability", "threat + confidence", "SLA / encoded policy", "prior plan / learned rule"]),
        ("110 Feasibility Evaluator F(S_t, A)", ["identify inadmissible candidate actions"]),
        ("120 Structural Decision-Domain Transformer", ["A → A'_t", "remove inadmissible decision variables"]),
        ("130 Fixed-Point Dependency Closure Engine", ["R_(k+1) = R_k ∪ Conseq(R_k)", "until R_(k+1) = R_k"]),
        ("140 Constraint Topology / Operational-Bound Regenerator", ["regenerate active conflicts, cost map, feasibility-bound metadata"]),
    ]

    for (title, lines), y in zip(stage_data, ys):
        _box(ax, x, y, w, h, title, lines, face="0.97")
    for a, b in zip(ys[:-1], ys[1:]):
        _arrow(ax, 0.5, a - 0.004, 0.5, b + h + 0.004)

    ir_y = 0.330
    ir_h = 0.092
    _box(
        ax,
        0.18,
        ir_y,
        0.64,
        ir_h,
        "150 Versioned Security Constraint Intermediate Representation (SC-IR)",
        [
            "active/pruned domains • invariance • conflicts • hard/soft constraints",
            "provenance • topology/bounds • dependency-closure metadata • IR/state versions",
        ],
        linewidth=2.0,
        face="0.94",
        title_size=9.8,
        body_size=7.7,
    )
    _arrow(ax, 0.5, ys[-1] - 0.004, 0.5, ir_y + ir_h + 0.004)

    cert_y = 0.205
    _box(
        ax,
        0.15,
        cert_y,
        0.40,
        0.090,
        "160 Pre-Solve Safety Certifier",
        ["unique invariant checks", "certificate status + integrity binding"],
        face="0.97",
    )
    _box(
        ax,
        0.62,
        cert_y,
        0.25,
        0.090,
        "165 Global Feasibility Witness",
        ["ExactlyOne + Conflicts", "Budget + Mandates"],
        face="0.97",
        title_size=8.5,
    )
    _arrow(ax, 0.5, ir_y - 0.004, 0.35, cert_y + 0.094)
    _arrow(ax, 0.55, cert_y + 0.045, 0.62, cert_y + 0.045, label="search", label_dy=0.012)
    _arrow(ax, 0.62, cert_y + 0.025, 0.55, cert_y + 0.025, label="witness", label_dy=-0.012)

    gate_y = 0.085
    _box(
        ax,
        0.24,
        gate_y,
        0.52,
        0.080,
        "170 Certificate-Bound Formulation Compiler Gate",
        ["reject absent / failed / stale / modified binding"],
        linewidth=2.0,
        face="0.94",
    )
    _arrow(ax, 0.35, cert_y - 0.004, 0.5, gate_y + 0.084, label="certified only", label_dx=0.04)

    _box(ax, 0.08, 0.005, 0.20, 0.055, "180A ILP Backend", ["solver formulation"], face="0.98", title_size=8.3, body_size=7)
    _box(ax, 0.32, 0.005, 0.20, 0.055, "180B QUBO Backend", ["solver formulation"], face="0.98", title_size=8.3, body_size=7)
    _box(ax, 0.56, 0.005, 0.17, 0.055, "185 Solver Result", ["response vector"], face="0.98", title_size=8.3, body_size=7)
    _box(ax, 0.77, 0.005, 0.20, 0.055, "190 Response Plan", ["simulation / adapter"], face="0.98", title_size=8.3, body_size=7)

    _arrow(ax, 0.42, gate_y, 0.18, 0.062)
    _arrow(ax, 0.58, gate_y, 0.42, 0.062)
    _arrow(ax, 0.28, 0.032, 0.56, 0.032)
    _arrow(ax, 0.52, 0.032, 0.56, 0.032)
    _arrow(ax, 0.73, 0.032, 0.77, 0.032)

    # Side feedback path
    ax.text(0.925, 0.37, "195\nSandboxed\nExperience-Rule\nAdmission", ha="center", va="center", fontsize=7.8,
            bbox=dict(boxstyle="round,pad=0.35", facecolor="white", edgecolor="black", linewidth=1.2))
    _arrow(ax, 0.87, 0.037, 0.925, 0.31, dashed=True, label="outcome")
    _arrow(ax, 0.925, 0.43, 0.76, 0.82, dashed=True, label="future safe rule", label_dx=0.02)

    _save(fig, "patent_v2_fig2_core_compilation_flow.png")


# -----------------------------------------------------------------------------
# FIGURE 3 — Incremental Recompilation
# -----------------------------------------------------------------------------


def create_figure_3():
    fig, ax = _setup(
        15,
        12,
        "FIG. 3 — SELECTIVE AFFECTED-SUBGRAPH RECOMPILATION",
        "Runtime delta processing with clean-structure reuse, dirty-structure recomputation, recertification, and safe full-recompile fallback",
    )

    _box(ax, 0.05, 0.73, 0.22, 0.13, "300 Previous Certified State", ["IR_t", "Certificate C_t"], face="0.97")
    _box(ax, 0.05, 0.48, 0.22, 0.13, "310 Runtime State Delta ΔS", ["asset / capability", "threat / policy / resource"], face="0.97")
    _box(ax, 0.33, 0.61, 0.23, 0.13, "320 Primary Dirty-Resource Identifier", ["changed-resource set"], face="0.97")
    _box(ax, 0.33, 0.38, 0.23, 0.13, "330 BFS Dependency Propagation", ["expand affected subgraph"], face="0.97")

    _arrow(ax, 0.16, 0.73, 0.16, 0.61)
    _arrow(ax, 0.27, 0.545, 0.33, 0.675)
    _arrow(ax, 0.445, 0.61, 0.445, 0.51)

    _box(ax, 0.64, 0.62, 0.27, 0.12, "340A Clean Subgraph Reuse", ["reuse unaffected domains", "reuse unaffected constraints/provenance"], face="0.98")
    _box(ax, 0.64, 0.38, 0.27, 0.14, "340B Dirty Subgraph Recompute", ["domains", "conflicts", "objective/cost map", "operational-bound metadata"], face="0.98")
    _box(ax, 0.64, 0.13, 0.27, 0.12, "380 Full-Recompile Fallback", ["configured mutation threshold", "global policy shift", "empty previous domain state"], face="0.98")

    _arrow(ax, 0.56, 0.445, 0.64, 0.45, label="selective")
    _arrow(ax, 0.56, 0.445, 0.64, 0.19, label="fallback condition", label_dy=-0.02)
    _arrow(ax, 0.56, 0.445, 0.64, 0.68, label="unaffected", label_dy=0.02)

    _box(ax, 0.33, 0.13, 0.23, 0.12, "350 Updated Versioned SC-IR", ["IR_(t+1)", "parent IR version"], face="0.94", linewidth=2.0)
    _box(ax, 0.33, 0.015, 0.23, 0.08, "360 Fresh Certification", ["C_(t+1)"], face="0.97")
    _box(ax, 0.64, 0.015, 0.27, 0.08, "370 Verification Path", ["semantic fingerprint comparison", "equivalence evidence"], face="0.97")

    _arrow(ax, 0.64, 0.68, 0.56, 0.19)
    _arrow(ax, 0.64, 0.45, 0.56, 0.19)
    _arrow(ax, 0.64, 0.19, 0.56, 0.19)
    _arrow(ax, 0.445, 0.13, 0.445, 0.095)
    _arrow(ax, 0.56, 0.055, 0.64, 0.055)

    ax.text(
        0.5,
        0.94,
        "The configured 0.70 mutation threshold is an implementation parameter and is intentionally not printed as a permanent patent limitation.",
        ha="center",
        va="center",
        fontsize=7.3,
        color="0.3",
    )

    _save(fig, "patent_v2_fig3_incremental_recompilation.png")


# -----------------------------------------------------------------------------
# FIGURE 4 — SC-IR / Certificate Binding / Gate
# -----------------------------------------------------------------------------


def create_figure_4():
    fig, ax = _setup(
        13,
        9,
        "FIG. 4 — SC-IR, SAFETY CERTIFICATE, AND COMPILER GATE",
        "Relationship between solver-independent state, pre-solve certification, and backend formulation permission",
    )

    _box(
        ax,
        0.05,
        0.30,
        0.26,
        0.48,
        "400 Versioned SC-IR",
        [
            "active/pruned domains",
            "invariance",
            "conflicts",
            "hard / soft constraints",
            "cost / budget",
            "provenance",
            "closure metadata",
            "IR version",
            "runtime-state version",
        ],
        face="0.97",
        center=False,
    )
    _box(
        ax,
        0.37,
        0.30,
        0.26,
        0.48,
        "410 Pre-Solve Safety Certificate",
        [
            "certification status",
            "invariant results",
            "feasibility witness",
            "IR digest",
            "closure digest",
            "IR/state versions",
            "integrity identifier",
        ],
        face="0.97",
        center=False,
    )
    _box(
        ax,
        0.69,
        0.50,
        0.26,
        0.28,
        "420 Compiler Verification Gate",
        ["compare state", "compare versions", "recompute digests", "reject mismatch"],
        linewidth=2.0,
        face="0.94",
        center=False,
    )
    _box(ax, 0.69, 0.27, 0.12, 0.12, "430 Solver Model", ["ILP / QUBO / other"], face="0.98", title_size=8.4, body_size=7)
    _box(ax, 0.83, 0.27, 0.12, 0.12, "440 Reject Compile", ["no solver model"], face="0.98", title_size=8.4, body_size=7)

    _arrow(ax, 0.31, 0.54, 0.37, 0.54, label="canonical digest")
    _arrow(ax, 0.63, 0.54, 0.69, 0.64)
    _arrow(ax, 0.75, 0.50, 0.75, 0.39, label="pass", label_dx=-0.025)
    _arrow(ax, 0.89, 0.50, 0.89, 0.39, label="fail", label_dx=0.025)

    ax.text(
        0.5,
        0.12,
        "The certificate is not merely a report: backend formulation is permitted only after successful binding verification.",
        ha="center",
        va="center",
        fontsize=9,
        fontweight="bold",
    )
    ax.text(
        0.5,
        0.075,
        "SHA-256 is used as a standard tamper-evident integrity primitive; it is not itself asserted as the inventive concept.",
        ha="center",
        va="center",
        fontsize=7.5,
        color="0.3",
    )

    _save(fig, "patent_v2_fig4_certificate_binding.png")


# -----------------------------------------------------------------------------
# FIGURE 5 — Structural Excision vs Penalty Weighting
# -----------------------------------------------------------------------------


def create_figure_5():
    fig, ax = _setup(
        13,
        8,
        "FIG. 5 — STRUCTURAL EXCISION VERSUS PENALTY WEIGHTING",
        "Conceptual comparison for faculty/IDF explanation; no hard-coded degraded-ablation percentage is used",
    )

    ax.text(0.25, 0.86, "CONVENTIONAL PENALTY-BASED DOMAIN", ha="center", va="center", fontsize=11, fontweight="bold")
    ax.text(0.75, 0.86, "CLOUD GUARDIAN STRUCTURAL DOMAIN", ha="center", va="center", fontsize=11, fontweight="bold")

    _box(ax, 0.08, 0.62, 0.34, 0.12, "Candidate Domain", ["x_safe exists", "x_unsafe also exists"], face="0.98")
    _box(ax, 0.08, 0.40, 0.34, 0.12, "Objective / Penalty", ["large penalty discourages x_unsafe"], face="0.98")
    _box(ax, 0.08, 0.18, 0.34, 0.12, "Solver Search Space", ["x_unsafe remains mathematically selectable"], face="0.98")
    _arrow(ax, 0.25, 0.62, 0.25, 0.52)
    _arrow(ax, 0.25, 0.40, 0.25, 0.30)

    _box(ax, 0.58, 0.62, 0.34, 0.12, "Runtime State Evaluation", ["x_unsafe identified as inadmissible"], face="0.98")
    _box(ax, 0.58, 0.40, 0.34, 0.12, "Structural Domain Transformation", ["x_unsafe removed from A'"], face="0.94", linewidth=2.0)
    _box(ax, 0.58, 0.18, 0.34, 0.12, "Regenerated Certified Model", ["dependent topology rebuilt", "solver model never contains x_unsafe"], face="0.98")
    _arrow(ax, 0.75, 0.62, 0.75, 0.52)
    _arrow(ax, 0.75, 0.40, 0.75, 0.30)

    ax.text(
        0.5,
        0.06,
        "Core distinction: the invention changes decision-domain membership before backend formulation rather than relying only on coefficient balancing.",
        ha="center",
        va="center",
        fontsize=9,
        fontweight="bold",
    )

    _save(fig, "patent_v2_fig5_structural_excision_vs_penalty.png")


# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------


def main():
    create_figure_1()
    create_figure_2()
    create_figure_3()
    create_figure_4()
    create_figure_5()
    print("[DONE] Patent Figure Set V2 generated.")


if __name__ == "__main__":
    main()
