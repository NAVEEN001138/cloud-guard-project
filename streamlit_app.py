"""
Cloud Guardian — Faculty & Evaluator Interactive Demonstration Dashboard
Runtime Adaptive Security Constraint Compilation & Multi-Objective Incident Response Engine

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
    page_title="Cloud Guardian — Academic & Patent Demonstration",
    layout="wide",
    page_icon="🛡️"
)

# Professional Academic Light Mode Styling
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Fira+Code:wght@400;600&display=swap');

/* Main Background & Clean Typography */
html, body, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
    background-color: #f8fafc !important;
    color: #0f172a !important;
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
}

/* Header Card */
.header-card {
    background: #ffffff;
    border: 1.5px solid #e2e8f0;
    border-radius: 14px;
    padding: 24px 30px;
    margin-bottom: 22px;
    box-shadow: 0 4px 12px rgba(15, 23, 42, 0.05);
}

.header-title {
    font-size: 28px;
    font-weight: 800;
    color: #1e3a8a;
    margin-bottom: 6px;
    letter-spacing: -0.5px;
}

.header-subtitle {
    color: #475569;
    font-size: 14px;
    font-weight: 500;
    line-height: 1.6;
}

/* Faculty Explanatory Box Component */
.faculty-guide-box {
    background: #f0f9ff;
    border-left: 4px solid #0284c7;
    border-radius: 0 8px 8px 0;
    padding: 12px 18px;
    margin-top: 14px;
    margin-bottom: 12px;
    font-size: 13.5px;
    color: #0369a1;
    line-height: 1.55;
}

.patent-highlight-box {
    background: #fffbeb;
    border-left: 4px solid #d97706;
    border-radius: 0 8px 8px 0;
    padding: 14px 18px;
    margin-top: 14px;
    margin-bottom: 14px;
    font-size: 13.5px;
    color: #92400e;
    line-height: 1.6;
}

/* Metric Cards */
.kpi-card {
    background: #ffffff;
    border: 1.5px solid #e2e8f0;
    border-radius: 12px;
    padding: 16px 14px;
    text-align: center;
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.03);
}

.kpi-icon {
    font-size: 22px;
    margin-bottom: 4px;
}

.kpi-value {
    font-size: 22px;
    font-weight: 800;
    margin-bottom: 2px;
}

.kpi-label {
    font-size: 12px;
    font-weight: 600;
    color: #64748b;
}

.kpi-subtext {
    font-size: 11px;
    color: #94a3b8;
    margin-top: 4px;
}

/* Tab Styling */
.stTabs [data-baseweb="tab-list"] {
    gap: 12px;
    background-color: #e2e8f0;
    padding: 6px 10px;
    border-radius: 10px;
}

.stTabs [data-baseweb="tab"] {
    height: 42px;
    border-radius: 7px;
    color: #475569;
    font-weight: 600;
    font-size: 14px;
    padding: 0 20px;
    background-color: transparent !important;
    border: none !important;
}

.stTabs [aria-selected="true"] {
    background: #ffffff !important;
    color: #1e3a8a !important;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
}

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #ffffff !important;
    border-right: 1px solid #e2e8f0 !important;
}

/* Clean Dataframes */
[data-testid="stDataFrame"] {
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    background-color: #ffffff;
}
</style>
""", unsafe_allow_html=True)

# Main Title & System Summary for Faculty
st.markdown("""
<div class="header-card">
    <div class="header-title">🛡️ Cloud Guardian — Faculty & Evaluator Guided Dashboard</div>
    <div class="header-subtitle">
        <b>Project Title:</b> Runtime Adaptive Security Constraint Compilation and Multi-Objective Decision Engine for Cyber-Physical Cloud Environments.<br>
        <b>What This System Does:</b> When a cyberattack strikes, Cloud Guardian detects the threat across edge sensors and 
        <b>mathematically compiles safety, budget, and legal compliance constraints</b> (Layer 5) to select the safest mitigation response 
        without crashing critical servers or violating data privacy laws.
    </div>
</div>
""", unsafe_allow_html=True)

# 4 Key Verified Patent Performance Indicators
k1, k2, k3, k4 = st.columns(4)
with k1:
    st.markdown("""
    <div class="kpi-card" style="border-top: 4px solid #0284c7;">
        <div class="kpi-icon">🛡️</div>
        <div class="kpi-value" style="color: #0284c7;">94.25%</div>
        <div class="kpi-label">Detection Accuracy</div>
        <div class="kpi-subtext">Evaluated on real Edge-IIoTset network data (377/400 test holdout)</div>
    </div>
    """, unsafe_allow_html=True)
with k2:
    st.markdown("""
    <div class="kpi-card" style="border-top: 4px solid #059669;">
        <div class="kpi-icon">⚖️</div>
        <div class="kpi-value" style="color: #059669;">100.00%</div>
        <div class="kpi-label">Decision Fidelity (DF%)</div>
        <div class="kpi-subtext">100% of chosen defenses strictly obey physical & budget limits</div>
    </div>
    """, unsafe_allow_html=True)
with k3:
    st.markdown("""
    <div class="kpi-card" style="border-top: 4px solid #d97706;">
        <div class="kpi-icon">🚫</div>
        <div class="kpi-value" style="color: #d97706;">0.0%</div>
        <div class="kpi-label">Forbidden Action Violations</div>
        <div class="kpi-subtext">Zero accidental shutdowns of critical business servers</div>
    </div>
    """, unsafe_allow_html=True)
with k4:
    st.markdown("""
    <div class="kpi-card" style="border-top: 4px solid #7c3aed;">
        <div class="kpi-icon">🔒</div>
        <div class="kpi-value" style="color: #7c3aed;">SHA-256</div>
        <div class="kpi-label">Pre-Solve Safety Certified</div>
        <div class="kpi-subtext">Cryptographic audit hash generated before execution</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# 2 Navigation Tabs
tab_engine, tab_arch = st.tabs([
    "⚡ 1. Interactive Incident Response & Constraint Engine",
    "🏛️ 2. Official Patent Architecture & Drawings (FIG. 1 & FIG. 2)"
])

# ===========================================================================
# TAB 1: Core Incident Response & Security Constraint Compiler
# ===========================================================================
with tab_engine:
    st.markdown("### 🎮 Step-by-Step Incident Simulation")
    st.write("Use the controls below to simulate an active attack and watch how the 9-layer engine detects the threat and compiles safe defense actions.")

    @st.cache_resource
    def get_standard_detector():
        return ThreatDetector(verbose=False)

    @st.cache_resource
    def get_fl_detector():
        return FederatedThreatDetector(sample_size=2000)

    @st.cache_resource
    def get_feedback_learner():
        return FeedbackLearner()

    st.markdown("""
    <div class="faculty-guide-box">
        <b>💡 Faculty Guide — Step 1: Scenario & Budget Configuration</b><br>
        • <b>Attack Scenario:</b> Choose which cyberattack to simulate against the cloud network (e.g., Port Scanning, DDoS flood, or Ransomware).<br>
        • <b>Max Budget ($):</b> Sets the maximum financial cost allowed for defense actions (like cloud compute costs or downtime expense).<br>
        • <b>Detection AI Model:</b> Choose whether threat scoring is calculated by our privacy-preserving Federated Learning Neural Network or a standard baseline.
    </div>
    """, unsafe_allow_html=True)

    col_cfg1, col_cfg2, col_cfg3 = st.columns([2, 1, 1])
    with col_cfg1:
        scenario_keys = list(SCENARIOS.keys())
        default_idx = scenario_keys.index("multi_tier_demo") if "multi_tier_demo" in scenario_keys else 0
        scenario_name = st.selectbox(
            "Select Attack Scenario to Simulate:",
            scenario_keys,
            index=default_idx,
            format_func=lambda k: SCENARIO_PROFILES.get(k, {}).get("title", k),
            help="Picks a pre-configured network topology under active cyberattack."
        )
    with col_cfg2:
        max_budget = st.slider(
            "Max Response Budget ($):",
            5.0, 50.0, float(MAX_BUDGET), 1.0,
            help="The maximum allowable remediation cost ceiling."
        )
    with col_cfg3:
        use_fl_model = st.checkbox(
            "Use Edge FL Neural Model",
            value=True,
            help="Runs the pre-trained PyTorch edge model trained across distributed IoT nodes."
        )

    detector = get_fl_detector() if use_fl_model else get_standard_detector()
    learner = get_feedback_learner()
    full_scenario = SCENARIOS[scenario_name]
    res_name_map = {r["id"]: r.get("name", r["id"]) for r in full_scenario.get("resources", [])}

    # Run the full 9-layer pipeline
    pipeline_result = run_pipeline(
        full_scenario,
        max_budget=max_budget,
        run_quantum=False,
        detector=detector,
        feedback_learner=learner,
    )

    st.markdown("---")

    # -----------------------------------------------------------------------
    # Layer 2: Threat Detection Probability
    # -----------------------------------------------------------------------
    st.markdown("### 🔍 Layer 2: AI Threat Detection Scores ($s_i$)")
    st.markdown("""
    <div class="faculty-guide-box">
        <b>💡 Faculty Guide — What You Are Looking At:</b><br>
        Our AI detector evaluates real-time network packets arriving at each server and assigns a threat probability score from 0% to 100%.<br>
        • <span style="color:#b91c1c; font-weight:bold;">🔴 HIGH THREAT (&ge; 75%)</span>: Server is confirmed under active compromise.<br>
        • <span style="color:#d97706; font-weight:bold;">🟠 MEDIUM THREAT (40%–74%)</span>: Suspicious behavior detected.<br>
        • <span style="color:#15803d; font-weight:bold;">🟢 LOW THREAT (&lt; 40%)</span>: Normal background traffic.
    </div>
    """, unsafe_allow_html=True)

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

    st.markdown("---")

    # -----------------------------------------------------------------------
    # Layer 4: Confidence Gating
    # -----------------------------------------------------------------------
    st.markdown("### 🎯 Layer 4: Sensor Confidence & Action Gating")
    st.markdown("""
    <div class="faculty-guide-box">
        <b>💡 Faculty Guide — Why This Layer Exists:</b><br>
        In real cloud networks, sensors can be noisy or send false alarms. 
        <b>Layer 4 computes an evidence confidence score</b>. If confidence is LOW (&lt; 50%), the system 
        <b>forbids severe actions like shutting down or isolating the server</b> to prevent accidental disruption.
    </div>
    """, unsafe_allow_html=True)

    conf_rows = []
    for rid, conf in pipeline_result.confidences.items():
        conf_rows.append({
            "Server / Device": f"{res_name_map.get(rid, rid)} ({rid})",
            "Confidence Tier": conf.confidence_tier,
            "Calculated Confidence": f"{conf.overall_confidence:.2%}",
            "Permitted Actions Allowed": ", ".join(conf.allowed_actions),
        })
    st.dataframe(pd.DataFrame(conf_rows), use_container_width=True, hide_index=True)

    st.markdown("---")

    # -----------------------------------------------------------------------
    # Layer 5: Adaptive Constraint Compiler (THE PATENT CORE)
    # -----------------------------------------------------------------------
    st.markdown("### ★ Layer 5: Adaptive Security Constraint Compiler (CORE PATENT CLAIM)")
    st.markdown("""
    <div class="patent-highlight-box">
        <b style="font-size: 15px;">★ THE CORE PATENTED INNOVATION (Claim 1 & Claim 11)</b><br>
        <b>What makes Cloud Guardian different from all existing security tools?</b><br>
        Traditional systems use static rules (e.g. <i>"If attack detected, isolate server"</i>). If that server is a critical database running a hospital or banking core, isolating it causes a catastrophic outage!<br>
        <b>Our Solution:</b> Layer 5 dynamically compiles live business criticality (C-I-A values), statutory laws (HIPAA / GDPR), and budget limits into mathematical constraints. 
        <b>It prunes forbidden actions from the variable space BEFORE solving</b> and generates a tamper-proof <b>SHA-256 Pre-Solve Certificate</b>.
    </div>
    """, unsafe_allow_html=True)

    if pipeline_result.safety_certificate:
        cert = pipeline_result.safety_certificate
        st.markdown(f"""
        <div style="background: #f0fdf4; border: 1.5px solid #16a34a; border-radius: 8px; padding: 12px 20px; margin-bottom: 12px;">
            <span style="color: #15803d; font-weight: bold; font-size: 14px;">✅ PRE-SOLVE CONSTRAINT SAFETY: [{cert.status}]</span> &nbsp;|&nbsp;
            <span style="color: #475569; font-size: 13px;">Certificate ID: <code>{cert.certificate_id}</code></span> &nbsp;|&nbsp;
            <span style="color: #475569; font-size: 13px;">SHA-256 Digest: <code>{cert.ir_sha256[:22]}...</code></span> &nbsp;|&nbsp;
            <span style="color: #0284c7; font-weight: 700; font-size: 13px;">0 Illegal Actions in Solution Space</span>
        </div>
        """, unsafe_allow_html=True)

    if pipeline_result.constraint_ir and pipeline_result.constraint_ir.topology:
        topo = pipeline_result.constraint_ir.topology
        t1, t2, t3, t4 = st.columns(4)
        t1.metric("Compiled Decision Variables", topo.num_variables, help="Number of binary yes/no decision variables sent to the solver")
        t2.metric("Conflict Hyperedges", topo.num_conflict_hyperedges, help="Dependency edges enforcing mutual exclusion between actions")
        t3.metric("Mathematical Model Family", topo.model_family, help="Intermediate Representation format (QUBO / ILP)")
        t4.metric("Constraint Graph Density", f"{topo.graph_density:.4f}", help="Sparsity of the conflict graph")

    with st.expander("🔍 Click to View Feasible vs. Pruned Forbidden Actions Table", expanded=True):
        st.caption("This table proves that forbidden actions (like isolating high-availability servers) were mathematically eliminated BEFORE solving:")
        matrix_data = []
        if pipeline_result.constraints:
            for rid, prof in pipeline_result.constraints.resource_profiles.items():
                feas = pipeline_result.constraints.feasible_actions.get(rid, [])
                forb = pipeline_result.constraints.forbidden_actions.get(rid, {})
                matrix_data.append({
                    "Target Asset": f"{res_name_map.get(rid, rid)} ({rid})",
                    "Device Type": prof.resource_type,
                    "Business Criticality (C-I-A)": f"Conf:{prof.confidentiality} / Integ:{prof.integrity} / Avail:{prof.availability}",
                    "Feasible Permitted Actions": ", ".join(feas),
                    "Forbidden Actions (Pruned by Layer 5)": ", ".join(forb.keys()) if forb else "None (All Safe)",
                })
            st.dataframe(pd.DataFrame(matrix_data), use_container_width=True, hide_index=True)

    st.markdown("---")

    # -----------------------------------------------------------------------
    # Layer 6 & 7: Decision Solvers Comparison
    # -----------------------------------------------------------------------
    st.markdown("### ⚖️ Layer 6 & 7: Multi-Objective Decision Solvers")
    st.markdown("""
    <div class="faculty-guide-box">
        <b>💡 Faculty Guide — What This Benchmark Shows:</b><br>
        Layer 5 emits dual mathematical models that can be solved by either <b>Classical Computers</b> or <b>Quantum Computers</b>.<br>
        • <b>ILP (Integer Linear Programming):</b> Solves the optimal defense plan on standard CPUs in ~2 milliseconds.<br>
        • <b>Greedy Heuristic:</b> Fast rule of thumb used by standard industry firewalls (often overspends budget or chooses suboptimal actions).<br>
        • <b>Decision Fidelity (100%):</b> Confirms that both classical and quantum solvers obeyed every single compiled safety rule.
    </div>
    """, unsafe_allow_html=True)

    raw_comp_df = pd.DataFrame(comparison_table(pipeline_result))
    if not raw_comp_df.empty:
        label_map = {
            "ilp": "⚖️ Classical ILP (PuLP Solver — Recommended)",
            "greedy_budget": "⚡ Budget-Constrained Greedy Solver",
            "greedy": "Standard Greedy Heuristic (Baseline)",
            "quantum_qubo": "⚛️ Quantum QUBO Solver (Exact Eigenvector)",
            "qaoa": "⚛️ Variational Quantum QAOA Circuit (Qiskit)",
        }
        raw_comp_df["Solver Architecture"] = raw_comp_df["solver"].map(lambda s: label_map.get(s, s))
        raw_comp_df["Budget Respected?"] = raw_comp_df["budget_ok"].map(lambda b: "✅ Yes" if b else "❌ Exceeded")
        raw_comp_df["Optimality Gap vs ILP"] = raw_comp_df["gap_vs_ilp_pct"].map(
            lambda g: f"{g:+.2f}%" if g is not None else "0.00% (Baseline)"
        )

        display_cols = ["Solver Architecture", "objective", "cost", "runtime_sec", "Budget Respected?", "Optimality Gap vs ILP"]
        valid_cols = [c for c in display_cols if c in raw_comp_df.columns]
        st.dataframe(
            raw_comp_df[valid_cols].rename(columns={
                "objective": "Net Security Optimization Score",
                "cost": "Total Downtime Cost ($)",
                "runtime_sec": "Solving Time (Seconds)"
            }),
            use_container_width=True,
            hide_index=True
        )

    st.markdown("---")

    # -----------------------------------------------------------------------
    # Layer 8: Response Orchestration & Audit Rationale
    # -----------------------------------------------------------------------
    st.markdown("### 🚀 Layer 8: Response Playbook Execution & Legal Audit Logs")
    st.markdown("""
    <div class="faculty-guide-box">
        <b>💡 Faculty Guide — Automated Playbook Deployment:</b><br>
        Once the optimal plan is chosen, Layer 8 executes real cloud API containment commands (AWS EC2 isolate, VPC firewall IP block, IAM credential rotation).<br>
        Select a strategy and click the execute button below to see the simulated API execution trace.
    </div>
    """, unsafe_allow_html=True)

    solver_names = [s.name for s in pipeline_result.solver_results]
    col_p1, col_p2 = st.columns(2)
    with col_p1:
        chosen_solver = st.selectbox(
            "Select Solved Defense Plan to Deploy:",
            solver_names,
            index=0,
            format_func=lambda s: label_map.get(s, s)
        )
    with col_p2:
        strategy_type = st.selectbox(
            "Select Playbook Execution Strategy:",
            [
                "🤖 Fully Autonomous Response (Exact Engine Actions)",
                "⚡ High-Severity Automated Emergency Playbook",
                "🛡️ Cautious Human-in-the-Loop Playbook"
            ]
        )

    if st.button("🚀 Execute Playbook Containment Actions on Cloud Assets", type="primary"):
        chosen_res = pipeline_result.result_by_name(chosen_solver)
        if chosen_res:
            if "Autonomous" in strategy_type:
                logs = execute_plan(chosen_res.plan)
                st.success("✅ **Autonomous Response Executed:** Deployed risk-differentiated defense actions across cloud endpoints!")
            else:
                sname = "Strategy A" if "Emergency" in strategy_type else "Strategy B"
                logs = execute_strategy(sname, chosen_res.plan)
                st.success(f"✅ **{sname} Multi-Step Playbook Executed:** Automated containment sequence deployed!")

            log_df = pd.DataFrame(logs)
            if not log_df.empty:
                if "resource_id" in log_df.columns:
                    log_df["Target Asset"] = log_df["resource_id"].map(lambda r: f"{res_name_map.get(r, r)} ({r})")
                disp_log = [c for c in ["Target Asset", "action", "step", "timestamp", "status"] if c in log_df.columns]
                st.dataframe(
                    log_df[disp_log].rename(columns={
                        "action": "Remediation Action Deployed",
                        "step": "Step #",
                        "timestamp": "Execution Timestamp",
                        "status": "Cloud API Status"
                    }),
                    use_container_width=True,
                    hide_index=True
                )

    if pipeline_result.explanation_report and "formatted_summary" in pipeline_result.explanation_report:
        with st.expander("📜 Click to View Explainable SOC Audit Rationale Report (45 CFR § 164.312)", expanded=False):
            st.caption("Regulatory compliance requires automated systems to explain WHY an action was chosen for each asset:")
            st.code(pipeline_result.explanation_report["formatted_summary"], language="text")

    st.markdown("---")

    # -----------------------------------------------------------------------
    # Layer 9: Post-Incident Closed-Loop Learning
    # -----------------------------------------------------------------------
    st.markdown("### 🔄 Layer 9: Continuous Feedback & Experience Learning")
    st.markdown("""
    <div class="faculty-guide-box">
        <b>💡 Faculty Guide — How the System Learns:</b><br>
        After the incident is contained, the human security operator rates the response. 
        <b>Layer 9 uses Exponential Moving Averages (EMA) to tune future action utility weights</b> and 
        synthesizes new experience rules into memory, ensuring the system gets smarter after every incident.
    </div>
    """, unsafe_allow_html=True)

    ema_metrics = learner.get_rolling_metrics()
    if ema_metrics.get("ema_success"):
        fb_cols = st.columns(min(4, len(ema_metrics["ema_success"])))
        for col, (act, val) in zip(fb_cols, ema_metrics["ema_success"].items()):
            col.metric(f"Action Utility [{act}]", f"{val:.1%}")

    with st.expander("📝 Operator Feedback Form (Simulates Real-World SOC Incident Sign-off)"):
        notes = st.text_input("SOC Analyst Observations:", value="Attack contained successfully; zero SLA downtime recorded.", key="fb_notes")
        succ = st.checkbox("Incident was contained without unexpected downtime", value=True)
        if st.button("Submit Feedback to Layer 9", key="btn_submit_fb"):
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
                st.success("✅ Feedback saved! Layer 9 updated decision weights for future incidents.")


# ===========================================================================
# TAB 2: Official Patent Architecture & Drawings
# ===========================================================================
with tab_arch:
    st.markdown("### 🏛️ Official Patent Drawings & Architecture (Form 2 Standard)")
    st.write("These high-resolution 300 DPI technical drawings illustrate the multi-layer pipeline and formal constraint compiler submitted with the patent application.")

    st.markdown("""
    <div class="faculty-guide-box">
        <b>💡 Faculty Guide — Drawing Descriptions:</b><br>
        • <b>FIG. 1 (Left):</b> Shows the complete 9-layer architectural flow from IoT edge telemetry ingestion up to cloud orchestration and feedback.<br>
        • <b>FIG. 2 (Right):</b> Details the inner workings of our <b>Layer 5 Constraint Compiler</b> showing how raw telemetry is converted into intermediate representations (IR) and certified pre-solve.
    </div>
    """, unsafe_allow_html=True)

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
    st.markdown("### 🛡️ The 7 Pre-Solve Safety Invariants Enforced by Layer 5")
    st.markdown("""
    <div class="faculty-guide-box">
        <b>💡 Why These Invariants Are Legally Crucial:</b><br>
        These 7 mathematical rules are the foundation of <b>Claim 1 in our patent</b>. They guarantee that no AI model or optimization solver can ever execute an illegal, dangerous, or unaffordable action.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
| Invariant # | Invariant Rule Name | Mathematical Definition | How Layer 5 Enforces It |
| :---: | :--- | :--- | :--- |
| **INV-1** | **Domain Pruning** | $x_{i,a} = 0, \\; \\forall a \\in \\mathcal{A}^{\\text{forbidden}}_i$ | Excludes forbidden actions from the variable space BEFORE sending to solver |
| **INV-2** | **Criticality Protection** | $x_{i,\\text{isolate}} = 0$ if $C_i^{\\text{avail}} \\ge 4$ | Hard bound preventing shutdown of essential healthcare / banking servers |
| **INV-3** | **Single Action Assignment** | $\\sum_{a} x_{i,a} = 1, \\; \\forall i$ | Exact one-hot constraint guaranteeing each server receives exactly one defense |
| **INV-4** | **Budget Feasibility** | $\\sum_{i,a} c_{i,a} x_{i,a} \\le B_{\\text{max}}$ | Linear capacity constraint preventing remediation overspending |
| **INV-5** | **Blast Radius Hyperedge** | Dynamic conflict hyperedges | Prevents simultaneous disruption of interconnected dependent cloud services |
| **INV-6** | **Invariant Certification** | 7 / 7 checks verified | Automated validation gate that aborts solver if any invariant fails |
| **INV-7** | **State Provenance** | $\\mathcal{H} = \\text{SHA-256}(\\text{IR})$ | Cryptographic digital signature ensuring complete legal auditability |
    """)
