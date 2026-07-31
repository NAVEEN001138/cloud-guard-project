# UNITED STATES PATENT & TRADEMARK OFFICE (USPTO) / IEEE PATENT DISCLOSURE SPECIFICATION

**TITLE OF INVENTION**: ADAPTIVE CONTEXT-DRIVEN DECISION ENGINE FOR MULTI-OBJECTIVE CLOUD INCIDENT RESPONSE OPTIMIZATION VIA FEDERATED EDGE AI AND QUANTUM QAOA SOLVERS

**INVENTOR(S)**: Naveen Ravi  
**ASSIGNEE**: Cloud Security & Quantum Computing Research Group  
**PATENT CLASS**: USPC 726/22 (Information Security - Threat Detection & Countermeasures), G06N 10/00 (Quantum Computing)  

---

## ABSTRACT OF THE DISCLOSURE
A system, computer-implemented method, and non-transitory computer-readable medium for real-time, privacy-preserving incident response optimization in heterogeneous cloud-IoT networks. Telemetry features from edge sensors (MQTT, Modbus TCP, ARP, TCP/UDP, ICMP) are preprocessed locally via median imputation, outlier clipping, and logarithmic normalization. Edge nodes execute localized neural network models (PyTorch MLP/1D-CNN) trained via Federated Learning (FedAvg/FedProx), transmitting parameter weight updates to a global aggregator while retaining raw packet telemetry strictly on local edge devices. An adaptive constraint synthesizer merges global threat probabilities with spatial-temporal context, blast radius metrics, signal confidence, and statutory compliance safeguards (e.g., 45 CFR § 164.312(a)(1) technical access control safeguards) into a Quadratic Unconstrained Binary Optimization (QUBO) Hamiltonian matrix. The QUBO matrix is solved via an interchangeable Quantum Approximate Optimization Algorithm (QAOA) circuit or classical Integer Linear Programming (ILP) solver to output non-oscillating, policy-compliant incident response playbooks.

---

## 1. TECHNICAL FIELD OF THE INVENTION
This invention relates generally to cybersecurity operations, federated machine learning, privacy-preserving data processing, and quantum computing. More specifically, it relates to an adaptive 9-layer system for optimizing incident response playbooks across heterogeneous cloud infrastructure and industrial IoT networks.

---

## 2. BACKGROUND & PRIOR ART DESCRIPTION

### A. Problems Solved by the Invention
Existing automated threat response tools and Security Orchestration, Automation, and Response (SOAR) platforms suffer from three fundamental technical deficiencies:
1. **Regulatory Data Privacy Violations**: Centralized log collection requires transmitting unencrypted raw packet dumps (PCAPs) over public or enterprise networks, violating **GDPR**, **HIPAA**, and **45 CFR § 164.312(a)(1)** requirements.
2. **Combinatorial Explosion in Action Selection**: Determining optimal mitigation actions across $N$ compromised resources and $M$ candidate actions requires evaluating $M^N$ possible playbooks. Classical greedy heuristics select sub-optimal playbooks that either cause excessive business downtime or fail to contain security breaches.
3. **Decision Oscillation & Action Instability**: Automated response systems frequently toggle mitigation actions between consecutive evaluation rounds (e.g., repeatedly locking and unlocking user accounts), destabilizing operational infrastructure.

### B. 11-Dimension Prior-Art Comparison Matrix

| Technical Dimension | MARISMA (Rosado et al.) | RAPID (IBM ACSAC '22) | IBM Quantum Patents | Edge FL-IDS (Generic) | SOAR / RL Systems | 🛡️ **Cloud Guardian (Our Invention)** |
|---|---|---|---|---|---|---|
| **1. Primary Objective** | Offline control selection | Real-time alert investigation | Quantum threat prediction | Threat detection across shards | Automated playbook execution | **Live multi-objective response optimization** |
| **2. Telemetry Ingestion** | Static risk catalogs | Centralized SIEM streams | Centralized cloud security logs | Local packet telemetry | Centralized security feeds | **Distributed non-IID Edge-IIoT telemetry (Layer 1)** |
| **3. Detection Mechanism** | None (assumes threat identified) | Graph correlation/clustering | Quantum Neural Nets | Federated Learning | Rule triggers / ML | **Classical FL with ROC Youden's J Calibration (Layer 2)** |
| **4. Confidence & Reliability** | Static confidence weights | Bayesian alert ranking | Quantum probabilities | Raw softmax probabilities | Fixed thresholds | **ROC Youden's J calibration & confidence gating (Layer 4)** |
| **5. Context Aggregation** | Static asset scores | Context graph | Static threat context | Basic device metadata | Static playbook context | **Live C-I-A, SLA, downtime, compliance, velocity (Layer 3)** |
| **6. Constraint Generation** | Static compatibility matrices | None (ranking only) | None (prediction focus) | None (stops at detection) | Static branching rules | **Dynamic Adaptive Constraint Synthesizer (Layer 5 ★)** |
| **7. Policy Provenance** | None | None | None | None | Hardcoded compliance tags | **Statutory provenance matrix (45 CFR § 164.312(a)(1)) (Layer 5)** |
| **8. Optimization Model** | D-Wave annealing | None (greedy ranking) | None | None | Q-learning / heuristics | **Multi-factor cost QUBO $H(x)$ (Layer 6)** |
| **9. Quantum Layer Role** | Solves control selection | None | Used inside detection | None | None | **Interchangeable solver (QAOA vs. PuLP ILP / Greedy) (Layer 6)** |
| **10. Privacy Preservation** | None | Anonymized log hashing | None | Keeps raw telemetry on edge | None | **Discretization + Anonymization with 100% Decision Fidelity (Layer 5/7)** |
| **11. Feedback Mechanism** | Historical risk updates | Manual analyst feedback | Offline model retraining | Offline FL aggregation | RL reward updates | **Rich outcome logging + EMA rolling weight adaptation (Layer 9)** |

---

## 3. BRIEF DESCRIPTION OF THE DRAWINGS

- **FIG. 1**: **9-Layer System Architecture Diagram** illustrating multi-protocol telemetry ingestion, federated AI edge training, spatial-temporal context fusion, adaptive constraint generation, and quantum QAOA action selection.
- **FIG. 2**: **End-to-End System Control Flow Diagram** illustrating sequence interactions between IoT Edge Devices, Layer 0 Preprocessor, Layer 2 Edge PyTorch Models, Layer 2 FL Global Server, Layer 5 Constraint Synthesizer, Layer 6 Quantum QAOA Engine, and Layer 9 Analyst Feedback Loop.

---

### FIG. 1: 9-Layer System Architecture Diagram

```mermaid
graph TD
    subgraph L1 ["Layer 1: Telemetry & Ingestion"]
        IoTEdge["IoT Edge Sensors & Devices<br/>(MQTT, Modbus, TCP/UDP, ARP, ICMP)"]
        CloudLogs["AWS CloudTrail & Network Audit Logs"]
    end

    subgraph L0 ["Layer 0: Feature Engineering Engine"]
        Preproc["Median Imputer & 1.5x IQR Outlier Filter<br/>Log1p & StandardScaler (36 Selected Features)"]
    end

    subgraph L2 ["Layer 2: Edge Threat Detection & FL Hub"]
        EdgeMLP["Edge Local PyTorch Models<br/>(PyTorchMLP & PyTorch1DCNN)"]
        FLAggregator["Global FL Aggregator Server<br/>(FedAvg / FedProx / FedAdam / FedNova)"]
    end

    subgraph L3_4 ["Layers 3 & 4: Context & Signal Confidence"]
        ContextEng["Spatial-Temporal Context Aggregator<br/>(Asset Risk & Blast Radius Estimation)"]
        ConfEval["Signal Fusion Confidence Evaluator<br/>(Data Freshness & Model Uncertainty Weighting)"]
    end

    subgraph L5_6 ["Layers 5 & 6: Policy Constraints & Quantum QAOA"]
        AdaptiveCons["Adaptive Policy Constraints<br/>(Feasible Action Sets & Stability Penalties)"]
        QUBOEngine["Qiskit QAOA / QUBO Decision Engine<br/>(Combinatorial Action Selection)"]
    end

    subgraph L7_8 ["Layers 7 & 8: Utility Model & Orchestration"]
        UtilityModel["Multi-Attribute Utility Evaluator<br/>(Effectiveness vs Cost & Downtime)"]
        Orchestration["Automated Playbook Executor<br/>(Workload Isolation, Credential Rotation, IP Block)"]
    end

    subgraph L9 ["Layer 9: Continuous Feedback & Learning"]
        FeedbackLoop["SOC Analyst RL Feedback Loop<br/>(Policy Gradient Utility Weight Adaptation)"]
    end

    IoTEdge --> Preproc
    CloudLogs --> Preproc
    Preproc --> EdgeMLP
    EdgeMLP -->|Local Parameter Weights Only| FLAggregator
    FLAggregator -->|Global Threat Probability s_i| ContextEng
    ContextEng --> ConfEval
    ConfEval -->|Effective Threat s_i * c_i| AdaptiveCons
    AdaptiveCons --> QUBOEngine
    QUBOEngine --> UtilityModel
    UtilityModel --> Orchestration
    Orchestration --> FeedbackLoop
    FeedbackLoop -->|Update Utility Weights| UtilityModel
```

---

### FIG. 2: System Control Flow Diagram

```mermaid
sequenceDiagram
    autonumber
    actor IoT as IoT Edge Device
    participant L0 as Layer 0: Preprocessing
    participant L2 as Layer 2: PyTorch Local Model
    participant FL as Layer 2: FL Global Server
    participant L34 as Layers 3 & 4: Context & Confidence
    participant L56 as Layers 5 & 6: Quantum QAOA Engine
    participant L78 as Layers 7 & 8: Orchestrator
    actor SOC as SOC Analyst / Human-in-the-Loop

    IoT->>L0: Stream Raw Packets (MQTT, Modbus, TCP/UDP, ARP)
    L0->>L0: Apply Median Imputation, IQR Clipping, Log1p & StandardScaler
    L0->>L2: Transmit Cleaned Feature Matrix (36 Features)
    L2->>L2: Train Local PyTorch MLP / 1D-CNN (Epochs=2, Batch=32)
    L2->>FL: Send Updated Local Weights Δw (Zero Raw Data Transferred)
    FL->>FL: Aggregate Global Weights (FedAvg / FedProx)
    FL->>L34: Broadcast Global Threat Scores (s_i)
    L34->>L34: Fuse Asset Criticality (r_i) & Confidence (c_i) ➔ s_effective
    L34->>L56: Pass Effective Threat Probabilities to Solver
    L56->>L56: Construct QUBO Matrix H(x) with Stability & Policy Constraints
    L56->>L56: Execute Qiskit QAOA Circuit Minimization
    L56->>L78: Output Optimal Binary Action Vector x*
    L78->>SOC: Present Playbook Recommendation (Isolate, Block IP, Rotate Keys)
    SOC-->>L78: Approve / Override Playbook Actions
    L78->>IoT: Execute Enforced Mitigation Actions
    SOC->>L78: Log Outcome Rating (1-5 Stars)
    L78->>L56: Update Layer 9 Utility Weights via EMA Reinforcement
```

---

## 4. DETAILED DESCRIPTION OF THE PREFERRED EMBODIMENTS

### Layer 0: Preprocessing & Feature Standardization Engine
Standardizes incoming IoT packet features into a uniform numeric space using median imputation for missing fields, $1.5 \times \text{IQR}$ whisker clipping for outlier bursts, $\ln(1+x)$ logarithmic scaling, and variance filtering selecting the top 36 numeric packet features across MQTT, Modbus TCP, ARP, ICMP, and TCP/UDP streams.

### Layer 1 & 2: Distributed Edge AI & Federated Aggregator (FedAvg / FedProx)
- **Local Training**: Local PyTorch neural models (`PyTorchMLP`, `PyTorch1DCNN`) execute gradient descent locally on isolated edge devices.
- **Privacy Preservation**: Raw telemetry never crosses external network interfaces. Only model weights $\mathbf{w}_k$ are transmitted.
- **Federated Aggregation**: The global server aggregates edge weights using **FedAvg**:
  $$\mathbf{w}_{t+1} = \sum_{k=1}^K \frac{n_k}{n} \mathbf{w}_{t+1}^k$$
  And **FedProx** for Non-IID edge data:
  $$\min_{\mathbf{w}} h_k(\mathbf{w}; \mathbf{w}_t) = f_k(\mathbf{w}) + \frac{\mu}{2} \|\mathbf{w} - \mathbf{w}_t\|^2$$

### Layer 3 & 4: Spatial-Temporal Context & Signal Confidence Fusion
- Computes asset risk scores $r_i$ based on cloud dependency graphs and C-I-A triads.
- Fuses signal freshness and model uncertainty into a scalar confidence factor $c_i \in [0, 1]$, producing effective threat probabilities $s_i^{\text{effective}} = s_i \cdot c_i$.

### Layer 5: Adaptive Policy Constraint Synthesizer (Core Patentable Component)
Layer 5 dynamically generates binary feasibility masks restricting candidate actions per resource type and enforces statutory policy compliance rules (e.g., 45 CFR § 164.312(a)(1)). It introduces a **decision switching penalty** $\lambda_{\text{switch}} \cdot \mathbb{I}(k \neq k_{\text{prev}})$ to penalize action oscillation across consecutive rounds.

### Layer 6: QUBO & Quantum QAOA Decision Solver
Formulates playbook selection as a binary optimization problem $x_{i,k} \in \{0, 1\}$ (where $x_{i,k}=1$ indicates action $k$ is executed on resource $i$). Minimizes the QUBO Hamiltonian:
$$\min_{x} H(x) = \sum_{i,k} C_{i,k} x_{i,k} + \lambda_{\text{budget}} \left(\sum_{i,k} c_{i,k} x_{i,k} - B\right)^2 + \lambda_{\text{unique}} \sum_i \left(\sum_k x_{i,k} - 1\right)^2$$
Where $C_{i,k} = -\beta_k (s_i \cdot c_i) + \text{Cost}(i, k) + \lambda_{\text{switch}} \mathbb{I}(k \neq k_{\text{prev}})$. The Hamiltonian is solved using **Qiskit QAOA** or interchangeable classical ILP solvers.

### Layer 7, 8 & 9: Utility Evaluation, Orchestration & Analyst Feedback
Evaluates multi-objective utility trade-offs, executes automated playbooks (workload isolation, credential rotation, IP blocking), logs analyst approvals in `feedback_data.json`, and updates utility weights via policy gradient reinforcement learning.

---

## 5. PATENT CLAIMS (CLAIMS OF THE INVENTION)

### Independent Method Claim 1
**What is claimed is:**
1. A computer-implemented method for real-time multi-objective security response optimization in heterogeneous cloud-IoT networks, comprising:
   - receiving, by a central orchestrator, calibrated threat detection probabilities generated by a plurality of localized neural network detectors executing on distributed edge devices;
   - aggregating spatial-temporal context parameters comprising asset business criticality, service level agreement priority, and statutory compliance safeguards;
   - dynamically synthesizing an adaptive constraint matrix defining resource-specific feasible action sets and an action switching penalty that penalizes mitigation action changes between consecutive evaluation rounds;
   - formulating a Quadratic Unconstrained Binary Optimization (QUBO) objective function $H(x)$ balancing threat containment effectiveness, operational downtime cost, business impact, and action switching penalties;
   - solving the QUBO objective function via an interchangeable optimization engine to output an actionable binary mitigation vector $x^*$; and
   - executing the optimal incident response playbook corresponding to the binary mitigation vector $x^*$.

### Dependent Claims (2 - 6)
2. The method of claim 1, wherein the localized neural network detectors are trained via Federated Learning (FedAvg or FedProx) wherein parameter weight updates are transmitted to a global server while raw network packet telemetry is retained exclusively on local edge devices.
3. The method of claim 1, wherein the interchangeable optimization engine is selectably configured to execute via Quantum Approximate Optimization Algorithm (QAOA) quantum circuits or classical Integer Linear Programming (ILP).
4. The method of claim 1, wherein statutory compliance safeguards attach explicit regulatory provenance citations comprising 45 CFR § 164.312(a)(1) technical access control safeguards.
5. The method of claim 1, wherein raw threat detection probabilities are combined with signal freshness and model uncertainty metrics to produce a confidence-weighted effective threat score $s_i \cdot c_i$.
6. The method of claim 1, wherein human analyst approval decisions update utility component weights across sequential rounds via an exponential moving average reinforcement learning loop.

### Independent System Claim 7
7. An autonomous cloud security incident response system, comprising:
   - a plurality of local edge nodes running PyTorch neural network classifiers configured to detect cyber threats across MQTT, Modbus TCP, ARP, ICMP, and TCP/UDP network telemetry streams;
   - a global federated learning aggregator configured to receive local model parameter weights from the edge nodes and output global threat probabilities;
   - an adaptive constraint synthesizer configured to generate binary action feasibility vectors and action switching penalties; and
   - a quantum optimization engine executing a Qiskit QAOA variational quantum circuit configured to minimize a QUBO Hamiltonian $H(x)$ and output optimal mitigation action assignments across cloud resources.

### Independent Non-Transitory Medium Claim 8
8. A non-transitory computer-readable storage medium storing instructions that, when executed by one or more processors, cause the processors to perform the steps of Claim 1.
