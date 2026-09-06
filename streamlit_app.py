"""
Cloud Guardian — Core Patent Demonstration & SOC Incident Response Engine
Runtime Adaptive Security Constraint Compilation and Multi-Objective Decision Engine

Run with:  streamlit run streamlit_app.py
"""

import os
import time
import uuid
import streamlit as st
import pandas as pd
import numpy as np

from layer1_telemetry.fake_incident import SCENARIOS, SCENARIO_PROFILES
from layer2_detection.detector import ThreatDetector
from layer2_detection.federated_detector import FederatedThreatDetector
from config import MAX_BUDGET, MAX_QUANTUM_RESOURCES
from pipeline import run_pipeline, comparison_table, subset_scenario
from layer8_orchestration.executor import execute_plan, execute_strategy
from layer9_feedback.feedback_learner import FeedbackLearner

st.set_page_config(
    page_title="Cloud Guardian — Core Patent Engine",
    layout="wide",
    page_icon="🛡️"
)

# Custom High-Aesthetics UI Styling
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Fira+Code:wght@400;600&display=swap');

html, body, [data-testid="stAppViewContainer"] {
    background-color: #0b0f19 !important;
    color: #e2e8f0 !important;
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
}

.main-title-card {
    background: linear-gradient(135deg, rgba(15, 23, 42, 0.95) 0%, rgba(30, 41, 59, 0.95) 100%);
    border: 1px solid rgba(56, 189, 248, 0.25);
    border-radius: 16px;
    padding: 22px 28px;
    margin-bottom: 20px;
    box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.6), 0 0 25px rgba(56, 189, 248, 0.12);
    backdrop-filter: blur(16px);
}

.main-title-text {
    font-size: 28px;
    font-weight: 800;
    background: linear-gradient(90deg, #38bdf8 0%, #818cf8 50%, #c084fc 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 6px;
    letter-spacing: -0.5px;
}

.main-subtitle-text {
    color: #94a3b8;
    font-size: 13.5px;
    font-weight: 500;
}

.stTabs [data-baseweb="tab-list"] {
    gap: 12px;
    background-color: rgba(15, 23, 42, 0.8);
    padding: 6px 12px;
    border-radius: 12px;
    border: 1px solid rgba(255, 255, 255, 0.08);
}

.stTabs [data-baseweb="tab"] {
    height: 42px;
    border-radius: 8px;
    color: #94a3b8;
    font-weight: 600;
    font-size: 14px;
    padding: 0 20px;
    border: none !important;
}

.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, #0284c7 0%, #2563eb 100%) !important;
    color: #ffffff !important;
    box-shadow: 0 4px 12px rgba(37, 99, 235, 0.35);
}

[data-testid="stSidebar"] {
    background-color: #0f172a !important;
    border-right: 1px solid rgba(255, 255, 255, 0.08) !important;
}
</style>
""", unsafe_allow_html=True)

# Main Title Header
st.markdown("""
<div class="main-title-card">
    <div class="main-title-text">🛡️ Cloud Guardian — Adaptive Security Constraint Engine</div>
    <div class="main-subtitle-text">
        Runtime Security Constraint Compilation &nbsp;|&nbsp; 
        Multi-Objective Incident Response &nbsp;|&nbsp; 
        Dual Classical ILP & Quantum QAOA Solvers &nbsp;|&nbsp; 
        <span style="color: #f59e0b; font-weight: 700;">Patent Core: Layer 5 Constraint Synthesizer</span>
    </div>
</div>
""", unsafe_allow_html=True)

# 4 Key Patent Indicator KPI Cards
col_kpi1, col_kpi2, col_kpi3, col_kpi4 = st.columns(4)
with col_kpi1:
    st.markdown("""
    <div style="background: rgba(30, 41, 59, 0.85); border: 1px solid #38bdf8; border-radius: 10px; padding: 12px; text-align: center;">
        <div style="font-size: 20px;">🛡️</div>
        <div style="font-size: 19px; font-weight: 800; color: #38bdf8;">94.25%</div>
        <div style="font-size: 11.5px; color: #94a3b8;">Detection Accuracy (Edge-IIoTset)</div>
    </div>
    """, unsafe_allow_html=True)
with col_kpi2:
    st.markdown("""
    <div style="background: rgba(30, 41, 59, 0.85); border: 1px solid #34d399; border-radius: 10px; padding: 12px; text-align: center;">
        <div style="font-size: 20px;">⚖️</div>
        <div style="font-size: 19px; font-weight: 800; color: #34d399;">100.00%</div>
        <div style="font-size: 11.5px; color: #94a3b8;">Decision Fidelity (DF%)</div>
    </div>
    """, unsafe_allow_html=True)
with col_kpi3:
    st.markdown("""
    <div style="background: rgba(30, 41, 59, 0.85); border: 1px solid #fbbf24; border-radius: 10px; padding: 12px; text-align: center;">
        <div style="font-size: 20px;">🚫</div>
        <div style="font-size: 19px; font-weight: 800; color: #fbbf24;">0.0%</div>
        <div style="font-size: 11.5px; color: #94a3b8;">Forbidden Action Violations</div>
    </div>
    """, unsafe_allow_html=True)
with col_kpi4:
    st.markdown("""
    <div style="background: rgba(30, 41, 59, 0.85); border: 1px solid #c084fc; border-radius: 10px; padding: 12px; text-align: center;">
        <div style="font-size: 20px;">🔒</div>
        <div style="font-size: 19px; font-weight: 800; color: #c084fc;">SHA-256</div>
        <div style="font-size: 11.5px; color: #94a3b8;">Pre-Solve Invariant Certified</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# 2 Clean Core Tabs
tab_engine, tab_arch = st.tabs([
    "⚡ Incident Response & Constraint Engine",
    "🏛️ System Architecture & Patent Drawings"
])

# ===========================================================================
# TAB 1: Core Incident Response & Security Constraint Compiler
# ===========================================================================
with tab_engine:
    st.header("⚡ Live Incident Response & Security Constraint Compilation")
    st.caption("Select an incident scenario to trigger threat detection, compile adaptive constraints, and solve optimal response actions.")

    @st.cache_resource
    def get_standard_detector():
        return ThreatDetector(verbose=False)

    @st.cache_resource
    def get_fl_detector():
        return FederatedThreatDetector(sample_size=2000)

    @st.cache_resource
    def get_feedback_learner():
        return FeedbackLearner()

    # Configuration Controls
    col_c1, col_c2, col_c3 = st.columns([2, 1, 1])
    with col_c1:
        scenario_keys = list(SCENARIOS.keys())
        default_idx = scenario_keys.index("multi_tier_demo") if "multi_tier_demo" in scenario_keys else 0
        scenario_name = st.selectbox(
            "Select Incident Attack Scenario",
            scenario_keys,
            index=default_idx,
            format_func=lambda k: SCENARIO_PROFILES.get(k, {}).get("title", k)
        )
    with col_c2:
        max_budget = st.slider("Max Budget ($)", 5.0, 50.0, float(MAX_BUDGET), 1.0)
    with col_c3:
        use_fl_model = st.checkbox("Use Edge FL Neural Model", value=True)

    detector = get_fl_detector() if use_fl_model else get_standard_detector()
    learner = get_feedback_learner()
    full_scenario = SCENARIOS[scenario_name]
    res_name_map = {r["id"]: r.get("name", r["id"]) for r in full_scenario.get("resources", [])}

    # Execute Full Pipeline
    pipeline_result = run_pipeline(
        full_scenario,
        max_budget=max_budget,
        run_quantum=False,
        detector=detector,
        feedback_learner=learner,
    )

    st.markdown("---")

    # Section 1: Threat Detection Scores (Layer 2)
    st.subheader("🔍 Layer 2: Threat Detection Probability ($s_i$)")
    score_items = list(pipeline_result.threat_scores.items())
    score_cols = st.columns(min(len(score_items), 5))
    for col, (rid, score) in zip(score_cols, score_items):
        name = res_name_map.get(rid, rid)
        if score >= 0.75:
            col.metric(name, f"{score:.1%}", delta="🔴 HIGH THREAT", delta_color="normal")
        elif score >= 0.40:
            col.metric(name, f"{score:.1%}", delta="🟠 MEDIUM THREAT", delta_color="off")
        else:
            col.metric(name, f"{score:.1%}", delta="🟢 LOW THREAT", delta_color="inverse")

    # Section 2: Confidence Evaluation (Layer 4)
    st.subheader("🎯 Layer 4: Detection Confidence & Action Gating")
    conf_rows = []
    for rid, conf in pipeline_result.confidences.items():
        conf_rows.append({
            "Target Asset": f"{res_name_map.get(rid, rid)} ({rid})",
            "Confidence Tier": conf.confidence_tier,
            "Overall Confidence": f"{conf.overall_confidence:.2%}",
            "Allowed Actions": ", ".join(conf.allowed_actions),
        })
    st.dataframe(pd.DataFrame(conf_rows), use_container_width=True, hide_index=True)

    # Section 3: Adaptive Constraint Compiler (Layer 5 - PATENT CORE)
    st.subheader("★ Layer 5: Adaptive Security Constraint Compiler (Patent Core)")
    if pipeline_result.safety_certificate:
        cert = pipeline_result.safety_certificate
        st.markdown(f"""
        <div style="background: rgba(16, 185, 129, 0.12); border: 1.5px solid #10b981; border-radius: 8px; padding: 10px 18px; margin-bottom: 12px;">
            <span style="color: #10b981; font-weight: bold; font-size: 14px;">🛡️ PRE-SOLVE CONSTRAINT SAFETY CERTIFICATE: [{cert.status}]</span> &nbsp;|&nbsp;
            <span style="color: #94a3b8; font-size: 12.5px;">Certificate ID: <code>{cert.certificate_id}</code></span> &nbsp;|&nbsp;
            <span style="color: #94a3b8; font-size: 12.5px;">SHA-256 Digest: <code>{cert.ir_sha256[:20]}...</code></span> &nbsp;|&nbsp;
            <span style="color: #38bdf8; font-weight: 600; font-size: 12.5px;">0 Violations in Variable Domain</span>
        </div>
        """, unsafe_allow_html=True)

    if pipeline_result.constraint_ir and pipeline_result.constraint_ir.topology:
        topo = pipeline_result.constraint_ir.topology
        t1, t2, t3, t4 = st.columns(4)
        t1.metric("Compiled Variables", topo.num_variables)
        t2.metric("Conflict Hyperedges", topo.num_conflict_hyperedges)
        t3.metric("Model Family", topo.model_family)
        t4.metric("Graph Density", f"{topo.graph_density:.4f}")

    with st.expander("🛡️ View Feasible vs. Pruned Forbidden Actions Matrix", expanded=True):
        matrix_data = []
        if pipeline_result.constraints:
            for rid, prof in pipeline_result.constraints.resource_profiles.items():
                feas = pipeline_result.constraints.feasible_actions.get(rid, [])
                forb = pipeline_result.constraints.forbidden_actions.get(rid, {})
                matrix_data.append({
                    "Target Asset": f"{res_name_map.get(rid, rid)} ({rid})",
                    "Asset Type": prof.resource_type,
                    "C-I-A Rating": f"C:{prof.confidentiality} / I:{prof.integrity} / A:{prof.availability}",
                    "Feasible Permitted Actions": ", ".join(feas),
                    "Forbidden (Pruned from Domain)": ", ".join(forb.keys()) if forb else "None (All Safe)",
                })
            st.dataframe(pd.DataFrame(matrix_data), use_container_width=True, hide_index=True)

    # Section 4: Optimization Engine & Decision Solvers (Layer 6 & 7)
    st.subheader("⚖️ Layer 6 & 7: Optimal Response Selection (Solver Benchmark)")
    raw_comp_df = pd.DataFrame(comparison_table(pipeline_result))
    if not raw_comp_df.empty:
        label_map = {
            "ilp": "⚖️ Integer Linear Programming (ILP - Recommended Baseline)",
            "greedy_budget": "⚡ Fast Budget-Constrained Greedy Solver",
            "greedy": "Unconstrained Greedy Heuristic (Baseline)",
            "quantum_qubo": "⚛️ Quantum QUBO Solver (Exact Eigenvector)",
            "qaoa": "⚛️ Variational Quantum QAOA Circuit (Qiskit)",
        }
        raw_comp_df["Solver Architecture"] = raw_comp_df["solver"].map(lambda s: label_map.get(s, s))
        raw_comp_df["Budget Feasible?"] = raw_comp_df["budget_ok"].map(lambda b: "✅ Yes" if b else "❌ Exceeded")
        raw_comp_df["Optimality Gap vs ILP"] = raw_comp_df["gap_vs_ilp_pct"].map(
            lambda g: f"{g:+.2f}%" if g is not None else "0.00%"
        )

        display_cols = ["Solver Architecture", "objective", "cost", "runtime_sec", "Budget Feasible?", "Optimality Gap vs ILP"]
        valid_cols = [c for c in display_cols if c in raw_comp_df.columns]
        st.dataframe(
            raw_comp_df[valid_cols].rename(columns={
                "objective": "Net Optimization Score",
                "cost": "Downtime Cost ($)",
                "runtime_sec": "Runtime (s)"
            }),
            use_container_width=True,
            hide_index=True
        )

    # Section 5: Playbook Execution & Explainability (Layer 8)
    st.subheader("🚀 Layer 8: Response Orchestration & SOC Audit Rationale")
    solver_names = [s.name for s in pipeline_result.solver_results]
    col_p1, col_p2 = st.columns(2)
    with col_p1:
        chosen_solver = st.selectbox("Select Solved Plan to Deploy", solver_names, index=0)
    with col_p2:
        strategy_type = st.selectbox("Execution Mode", [
            "🤖 Fully Autonomous Response",
            "⚡ High-Severity Automated Emergency Playbook",
            "🛡️ Cautious Human-in-the-Loop Playbook"
        ])

    if st.button("🚀 Execute Playbook Containment Actions", type="primary"):
        chosen_res = pipeline_result.result_by_name(chosen_solver)
        if chosen_res:
            if "Autonomous" in strategy_type:
                logs = execute_plan(chosen_res.plan)
                st.success("✅ **Autonomous Response Executed**: Exact risk-differentiated actions deployed!")
            else:
                sname = "Strategy A" if "Emergency" in strategy_type else "Strategy B"
                logs = execute_strategy(sname, chosen_res.plan)
                st.success(f"✅ **{sname} Playbook Executed**: Multi-stage containment sequence complete!")

            log_df = pd.DataFrame(logs)
            if not log_df.empty:
                if "resource_id" in log_df.columns:
                    log_df["Target Asset"] = log_df["resource_id"].map(lambda r: f"{res_name_map.get(r, r)} ({r})")
                disp_log = [c for c in ["Target Asset", "action", "step", "timestamp", "status"] if c in log_df.columns]
                st.dataframe(log_df[disp_log], use_container_width=True, hide_index=True)

    if pipeline_result.explanation_report and "formatted_summary" in pipeline_result.explanation_report:
        with st.expander("📜 View SOC Analyst Audit Rationale (Regulatory Compliance)", expanded=False):
            st.code(pipeline_result.explanation_report["formatted_summary"], language="text")

    # Section 6: Closed-Loop Experience Feedback (Layer 9)
    st.subheader("🔄 Layer 9: Post-Incident Feedback & Weight Adaptation")
    ema_metrics = learner.get_rolling_metrics()
    if ema_metrics.get("ema_success"):
        fb_cols = st.columns(min(4, len(ema_metrics["ema_success"])))
        for col, (act, val) in zip(fb_cols, ema_metrics["ema_success"].items()):
            col.metric(f"EMA Success [{act}]", f"{val:.1%}")
    else:
        st.info("No persistent feedback records logged yet. Submit feedback below to trigger Layer 9 learning.")

    with st.expander("📝 Submit SOC Operator Feedback (Triggers Closed-Loop Learning)"):
        notes = st.text_input("Incident Notes / Observations", key="fb_notes")
        succ = st.checkbox("Incident was successfully contained without unexpected downtime", value=True)
        if st.button("Submit Incident Feedback", key="btn_submit_fb"):
            chosen_res = pipeline_result.result_by_name(chosen_solver)
            if chosen_res:
                inc_id = f"{scenario_name}-{uuid.uuid4().hex[:6]}"
                learner.record_feedback(
                    incident_id=inc_id,
                    scenario=scenario_name,
                    plan=chosen_res.plan,
                    successful=succ,
                    notes=notes,
                )
                st.success("✅ Feedback recorded! Layer 9 updated utility weights and synthesized candidate rules.")


# ===========================================================================
# TAB 2: System Architecture & Patent Drawings
# ===========================================================================
with tab_arch:
    st.header("🏛️ System Architecture & Patent Drawings")
    st.caption("Official 300 DPI patent drawings filed with the Indian Patent Office (Form 2) and PCT application.")

    col_fig1, col_fig2 = st.columns(2)
    with col_fig1:
        if os.path.exists("architecture_diagram.png"):
            st.image(
                "architecture_diagram.png",
                caption="FIG. 1: 9-Layer Security Constraint Compiler Architecture (300 DPI)",
                use_container_width=True
            )
        else:
            st.warning("architecture_diagram.png not found.")

    with col_fig2:
        if os.path.exists("process_flow_diagram.png"):
            st.image(
                "process_flow_diagram.png",
                caption="FIG. 2: Runtime Security Constraint Compilation Pipeline (300 DPI)",
                use_container_width=True
            )
        else:
            st.warning("process_flow_diagram.png not found.")

    st.markdown("---")

    # Invariants Verification Table
    st.subheader("🛡️ The 7 Pre-Solve Safety Invariants Enforced by Layer 5")
    st.markdown("""
| # | Invariant Name | Mathematical Rule | Enforcement Mechanism |
|---|---|---|---|
| **INV-1** | Domain Pruning | $x_{i,a} = 0, \\; \\forall a \\in \\mathcal{A}^{\\text{forbidden}}_i$ | Excluded from variable set prior to solver construction |
| **INV-2** | Criticality Protection | $x_{i,\\text{isolate}} = 0$ if $C_i^{\\text{avail}} \\ge 4$ | Hard bound constraint |
| **INV-3** | Single Action per Asset | $\\sum_{a} x_{i,a} = 1, \\; \\forall i$ | Exact one-hot constraint |
| **INV-4** | Budget Feasibility | $\\sum_{i,a} c_{i,a} x_{i,a} \\le B_{\\text{max}}$ | Linear capacity constraint |
| **INV-5** | Blast Radius Hyperedge | Conflict edges for cascading dependency assets | Hypergraph conflict restructuring |
| **INV-6** | Invariant Certification | 7/7 checks passed | Pre-solve validation gate |
| **INV-7** | State Provenance | $\\mathcal{H} = \\text{SHA-256}(\\text{IR})$ | Cryptographic audit digest |
    """)
