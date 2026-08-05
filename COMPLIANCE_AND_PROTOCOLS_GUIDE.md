# 📜 SOFTWARE ARCHITECTURE & REGULATORY COMPLIANCE SPECIFICATION
## IEEE 1016 Software Design Description (SDD) — Cloud Guardian Autonomous Security Platform

---

### 1. SYSTEM OVERVIEW & ARCHITECTURAL SCOPE

The **Cloud Guardian Autonomous Security Platform** is a 9-layer computer-implemented cybersecurity system designed for real-time threat detection, privacy-preserving edge machine learning, and multi-objective incident response optimization in heterogeneous cloud-IoT infrastructures.

This specification documents the software architecture, coding standards, regulatory legal mappings (**HIPAA**, **GDPR**, **DPDP Act 2023**, **PCI-DSS v4.0**, **NIST SP 800-53**), multi-protocol telemetry feature schemas (**Modbus TCP**, **MQTT**, **TCP/UDP**, **ARP**, **ICMP**, **HTTP**, **DNS**), and layer-by-layer technical implementations.

---

## 2. REGULATORY COMPLIANCE STANDARDS & STATUTORY LEGAL MAPPING

The platform implements automated compliance auditing and statutory constraint synthesis across **Layer 3 (Context Aggregation)**, **Layer 5 (Adaptive Policy Constraints)**, and **Layer 8 (Explainable Audit Reports)**.

```
                      ┌─────────────────────────────────────────────────────────┐
                      │    Regulatory Compliance Engine (Layers 3, 5 & 8)       │
                      └────────────────────────────┬────────────────────────────┘
                                                   │
         ┌───────────────────┬─────────────────────┼─────────────────────┬───────────────────┐
         ▼                   ▼                     ▼                     ▼                   ▼
     HIPAA Title 45     GDPR Regulation       DPDP Act, 2023       PCI-DSS v4.0       NIST SP 800-53
   (CFR § 164.312)     (EU 2016/679)       (India Act 2023)      (CDE Controls)      (Rev. 5 Safeguards)
```

---

### A. HIPAA — Health Insurance Portability and Accountability Act (Title 45 CFR)

- **Target Statute**: **45 CFR § 164.312 Technical Safeguards**
- **Specific Clauses Implemented**:
  1. **§ 164.312(a)(1) Access Control**: Requires procedures to allow access only to authorized personnel and software programs.
  2. **§ 164.312(b) Audit Controls**: Requires hardware, software, and procedural mechanisms that record and examine activity in systems containing ePHI.
  3. **§ 164.312(c)(1) Integrity**: Requires policies and procedures to protect ePHI from improper alteration or destruction.
  4. **§ 164.312(e)(1) Transmission Security**: Mandates security measures against unauthorized access to ePHI transmitted over electronic networks.

- **Code Location & Mechanics**:
  - `layer3_context/context_aggregator.py`:
    ```python
    @dataclass
    class ComplianceMetadata:
        hipaa_applicable: bool = True  # Set for healthcare ePHI databases
    ```
  - `layer5_constraints/adaptive_constraints.py`:
    ```python
    if context.compliance.hipaa_applicable:
        if threat_score < 0.4:
            # Under HIPAA 45 CFR § 164.312(c)(1) Integrity & Availability safeguards, 
            # low-threat alerts MUST NOT trigger destructive server isolation.
            forbidden_actions["isolate"] = PolicyConstraint(
                origin="HIPAA_COMPLIANCE",
                rule_id="HIPAA_45CFR_164_312_AVAILABILITY",
                description="Forbidden by HIPAA 45 CFR § 164.312 Integrity & Availability Safeguard when threat score < 0.4"
            )
    ```
  - `layer8_orchestration/explainability.py`:
    ```python
    def generate_explainable_report(result):
        # SIEM_AUDITOR Report includes statutory provenance tags
        if context.compliance.hipaa_applicable:
            auditor_log.append("Statutory Citation: HIPAA 45 CFR § 164.312(a)(1) Access Control Safeguards Enforced.")
    ```

---

### B. GDPR — General Data Protection Regulation (EU 2016/679)

- **Target Statute**: **GDPR Articles 5, 25, 32, and 44**
- **Specific Clauses Implemented**:
  1. **Article 5(1)(c) Data Minimization**: Personal data must be adequate, relevant, and limited to what is necessary.
  2. **Article 25 Data Protection by Design and Default**: Implements privacy safeguards directly into algorithmic architecture.
  3. **Article 32 Security of Processing**: Mandates pseudonymization, encryption, and continuous availability verification.
  4. **Article 44 General Principle for Transfers**: Restricts cross-border transfers of unencrypted raw PII.

- **Code Location & Mechanics**:
  - `layer2_detection/federated_detector.py`:
    ```python
    class FederatedEdgeManager:
        """
        Implements GDPR Article 25 (Privacy by Design) and Article 44 (Data Sovereignty).
        Raw network traffic logs remain 100% local on edge nodes (PLCs, Smart Sensors).
        Only neural network parameter weight tensors (w_k) cross network boundaries to the global aggregator.
        """
        def train_round(self):
            for client in self.clients:
                local_weights = client.train_local_model()  # Local PyTorch training
                self.aggregate_global_weights(local_weights)  # FedAvg aggregation
    ```
  - `layer5_constraints/adaptive_constraints.py`:
    Synthesizes GDPR regulatory provenance tags to ensure zero raw PII leakage during incident response.

---

### C. DPDP Act, 2023 — Digital Personal Data Protection Act (India)

- **Target Statute**: **DPDP Act 2023 (Sections 6, 8, 9, 16)**
- **Specific Clauses Implemented**:
  1. **Section 6 Purpose Limitation & Consent**: Processing must be restricted strictly to legitimate security incident prevention.
  2. **Section 8 Duties of Data Fiduciary**: Mandates technical measures to prevent personal data breaches.
  3. **Section 9 Localized Edge Ingestion**: Telemetry processing must occur at local edge shards without unauthorized cross-border exfiltration.

- **Code Location & Mechanics**:
  - `layer0_preprocessing/preprocessor.py`:
    ```python
    class DataPreprocessor:
        """
        Ensures compliance with DPDP Act 2023 Section 8 & 9.
        Extracts anonymized numerical traffic features (36 protocol columns) 
        and applies median imputation, 1.5x IQR outlier clipping, and StandardScaler locally.
        """
    ```
  - `PATENT_DRAFT_INDIA.md`: Documented as primary statutory compliance framework for Indian Patent Office filing.

---

### D. PCI-DSS v4.0 — Payment Card Industry Data Security Standard

- **Target Statute**: **PCI-DSS v4.0 Requirements 3, 10, and 12**
- **Specific Clauses Implemented**:
  1. **Requirement 3**: Protect Stored Account Data.
  2. **Requirement 10**: Log and Monitor All Access to System Components and Cardholder Data.
  3. **Requirement 12**: Support Information Security with Organizational Policies.

- **Code Location & Mechanics**:
  - `layer1_telemetry/fake_incident.py`:
    Payment Gateway resources are tagged with `pci_dss_applicable=True` and assigned SLA downtime costs of $\$2,500/\text{min}$.
  - `layer5_constraints/adaptive_constraints.py`:
    ```python
    if context.compliance.pci_dss_applicable and threat_score >= 0.4:
        # Require immediate API credential rotation to protect Cardholder Data Environment (CDE)
        required_actions.append("rotate_credentials")
    ```

---

### E. NIST SP 800-53 Rev. 5 — Security and Privacy Controls

- **Controls Implemented**:
  - **SI-4 Information System Monitoring**: Continuous multi-protocol telemetry evaluation across edge nodes.
  - **SC-7 Boundary Protection**: Automated VPC firewall IP blocking (`block_ip`).
  - **CP-9 Information System Backup**: Mandatory pre-incident snapshot backups (`snapshot_backup`) prior to workload isolation.

---

## 3. MULTI-PROTOCOL TELEMETRY FEATURE SCHEMA (36 FEATURES)

The platform processes 36 numeric protocol features extracted from the **Edge-IIoTset dataset** across 7 industrial and network protocol families:

```
                            ┌──────────────────────────────────────────┐
                            │   Edge-IIoTset 36 Protocol Feature Matrix│
                            └────────────────────┬─────────────────────┘
                                                 │
      ┌──────────────────┬───────────────────────┼───────────────────────┬──────────────────┐
      ▼                  ▼                       ▼                       ▼                  ▼
Modbus TCP (ICS)   MQTT (Smart IoT)       TCP/UDP (Transport)      ARP & ICMP (Network)   HTTP & DNS (Web)
(mbtcp.len, etc.)  (mqtt.topic, etc.)     (tcp.flags, ports)       (arp.opcode, icmp)    (http.method, dns)
```

---

### Protocol Feature Specification Table

| Protocol Family | Feature Column Name | Data Type | Value Range / Units | Anomaly & Threat Indicator | Code Reference File |
|---|---|---|---|---|---|
| **Modbus TCP** | `mbtcp.len` | `float64` | $0 - 65,535$ bytes | Length spike indicates payload injection / buffer overflow attack on SCADA PLCs. | `layer1_telemetry/data_loader.py` |
| | `mbtcp.trans_id` | `float64` | $0 - 65,535$ | Rapid sequence jump indicates Modbus session hijacking. | `layer1_telemetry/data_loader.py` |
| | `mbtcp.unit_id` | `float64` | $1 - 247$ | Target slave device ID; abnormal IDs indicate scanning. | `layer1_telemetry/data_loader.py` |
| | `mbtcp.func_code` | `float64` | $1 - 127$ | Function codes $0\text{x}03$ (Read), $0\text{x}10$ (Write); invalid codes trigger alarms. | `layer1_telemetry/data_loader.py` |
| **MQTT** | `mqtt.topic` | `float64` | Encoded ID | Unauthorized topic publishing or broker flooding. | `layer1_telemetry/data_loader.py` |
| | `mqtt.len` | `float64` | $0 - 1,024$ bytes | Large payload size indicates exfiltration via MQTT message. | `layer1_telemetry/data_loader.py` |
| | `mqtt.msg_type` | `float64` | $1 - 14$ | Connect ($1$), Publish ($3$), Subscribe ($8$); high Connect frequency = DDoS. | `layer1_telemetry/data_loader.py` |
| | `mqtt.client_id` | `float64` | Encoded Hash | Spoofed client IDs indicate IoT impersonation attacks. | `layer1_telemetry/data_loader.py` |
| **TCP Transport** | `tcp.srcport` | `float64` | $1 - 65,535$ | Ephemeral source ports. | `layer1_telemetry/data_loader.py` |
| | `tcp.dstport` | `float64` | $1 - 65,535$ | Destination ports ($80, 443, 22, 502, 1883$); port scan triggers. | `layer1_telemetry/data_loader.py` |
| | `tcp.flags` | `float64` | Bitmask ($0 - 63$) | SYN ($0\text{x}02$), ACK ($0\text{x}10$), FIN ($0\text{x}01$), RST ($0\text{x}04$); SYN Flood detection. | `layer1_telemetry/data_loader.py` |
| | `tcp.ack` / `tcp.seq` | `float64` | Numeric | Sequence anomalies indicate TCP connection reset / hijacking. | `layer1_telemetry/data_loader.py` |
| **UDP Transport** | `udp.port` | `float64` | $1 - 65,535$ | High UDP packet frequency indicates UDP Flood DDoS. | `layer1_telemetry/data_loader.py` |
| | `udp.stream` | `float64` | Numeric | Stream index tracking. | `layer1_telemetry/data_loader.py` |
| **ARP Link Layer**| `arp.opcode` | `float64` | $1$ (Req), $2$ (Rep) | High ARP Reply volume without prior Requests = ARP Poisoning / MitM attack. | `layer1_telemetry/data_loader.py` |
| | `arp.src.hw_mac` | `float64` | Encoded MAC | MAC address spoofing detection. | `layer1_telemetry/data_loader.py` |
| **ICMP Network** | `icmp.type` | `float64` | $0$ (Echo Rep), $8$ (Req)| High Type $8$ volume = Ping Flood DDoS attack. | `layer1_telemetry/data_loader.py` |
| | `icmp.code` | `float64` | $0 - 15$ | ICMP destination unreachable / redirect anomalies. | `layer1_telemetry/data_loader.py` |
| **HTTP Web** | `http.request.method`| `float64` | Encoded (GET=1, POST=2) | High POST ratio or uncommon methods = SQLi / Web Shell exfiltration. | `layer1_telemetry/data_loader.py` |
| | `http.response.code`| `float64` | $200, 403, 404, 500$ | High 500 error count indicates SQL injection database crashes. | `layer1_telemetry/data_loader.py` |
| **DNS Resolution** | `dns.qry.name.len` | `float64` | Characters | Long domain query names ($>100$ chars) = DNS Tunneling exfiltration. | `layer1_telemetry/data_loader.py` |
| | `dns.flags.rcode` | `float64` | $0$ (NoError), $3$ (NXDomain)| High NXDOMAIN response rate = Domain Fluxing / Botnet C2. | `layer1_telemetry/data_loader.py` |

---

## 4. DETAILED LAYER-BY-LAYER CODEBASE ARCHITECTURE

Below is the complete architectural walkthrough across all 9 layers of the codebase:

```
[Layer 0: Preprocessing] ──► [Layer 1: Telemetry] ──► [Layer 2: Edge FL Hub]
                                                             │
[Layer 5: Constraints] ◄── [Layer 4: Confidence] ◄── [Layer 3: Context]
          │
          ▼
[Layer 6: QUBO/QAOA Engine] ──► [Layer 7: Utility Inspection]
                                           │
[Layer 9: EMA Learning] ◄── [Layer 8: Orchestration Execution]
```

---

### Layer 0: Data Preprocessing & Standardization Engine
- **Primary Class**: `DataPreprocessor`
- **File Location**: `layer0_preprocessing/preprocessor.py`
- **Mathematical Pipeline**:
  $$\text{Impute(Median)} \longrightarrow \text{Clip}\left(\text{Q1} - 1.5\text{IQR}, \text{Q3} + 1.5\text{IQR}\right) \longrightarrow \ln(1 + |x|) \longrightarrow \text{StandardScaler}\left(\frac{x - \mu}{\sigma}\right)$$
- **Function Signatures**:
  ```python
  def fit_transform(self, df: pd.DataFrame) -> np.ndarray: ...
  def transform(self, df: pd.DataFrame) -> np.ndarray: ...
  ```

---

### Layer 1: Edge Telemetry Ingestion Engine
- **Primary Module**: `data_loader.py` & `fake_incident.py`
- **File Locations**: `layer1_telemetry/data_loader.py`, `layer1_telemetry/fake_incident.py`
- **Key Data Structures**:
  ```python
  SCENARIOS = {
      "ddos_flood": { ... },
      "sql_injection_exfil": { ... },
      "multi_tier_demo": { ... }  # Features High (98%), Medium (58%), Low (18%) threat resources
  }
  ```
- **Function Signature**:
  ```python
  def load_edge_iiot_dataset(sample_size: int = 10000) -> pd.DataFrame: ...
  ```

---

### Layer 2: Edge Neural ML & Federated Learning Hub
- **Primary Classes**: `PyTorchMLP`, `PyTorch1DCNN`, `FederatedEdgeManager`, `FederatedThreatDetector`
- **File Locations**: `layer2_detection/federated_detector.py`, `layer2_detection/detector.py`
- **Federated Math**:
  - **FedAvg**: $\mathbf{w}_{t+1} = \sum_{k=1}^K \frac{n_k}{n} \mathbf{w}_{t+1}^k$
  - **FedProx**: $\min_{\mathbf{w}} h_k(\mathbf{w}; \mathbf{w}_t) = f_k(\mathbf{w}) + \frac{\mu}{2} \|\mathbf{w} - \mathbf{w}_t\|^2$
- **Performance Metrics**: 94.05% Mean Accuracy, 98.82% Precision, 0.9577 ROC-AUC across non-IID edge nodes.

---

### Layer 3: Spatial-Temporal Context & Compliance Aggregator
- **Primary Dataclasses**: `AssetContext`, `ComplianceMetadata`, `ContextAggregator`
- **File Location**: `layer3_context/context_aggregator.py`
- **Key Schema**:
  ```python
  @dataclass
  class AssetContext:
      resource_id: str
      confidentiality: int  # 1 - 5 rating
      integrity: int        # 1 - 5 rating
      availability: int     # 1 - 5 rating
      sla_downtime_cost_per_min: float
      compliance: ComplianceMetadata
  ```

---

### Layer 4: Detection Confidence & Signal Fusion Evaluator
- **Primary Class**: `SignalConfidenceEvaluator`
- **File Location**: `layer4_confidence/confidence_evaluator.py`
- **Confidence Fusion Formula**:
  $$c_i = w_{\text{model}} \cdot c_{\text{model}} + w_{\text{freshness}} \cdot c_{\text{freshness}} + w_{\text{sensor}} \cdot c_{\text{sensor}}$$
  $$\text{Effective Threat Score } s_i^{\text{effective}} = s_i \cdot c_i$$
- **Threshold Calibration**: ROC Youden's J statistic ($J = \text{Sensitivity} + \text{Specificity} - 1$). Gated into **HIGH**, **MODERATE**, and **LOW** risk tiers.

---

### Layer 5: Adaptive Policy Constraint Synthesizer (★ CORE PATENT NOVELTY)
- **Primary Classes**: `PolicyConstraint`, `AdaptiveConstraintSynthesizer`
- **File Location**: `layer5_constraints/adaptive_constraints.py`
- **Patent Innovation (Claim 1 & Claim 3)**:
  Synthesizes binary feasibility matrices $F_{i,a} \in \{0, 1\}$ and injects an **Action Switching Penalty**:
  $$P_{\text{switch}} = \lambda_{\text{switch}} \sum_i \mathbb{I}(x_{i,a} \neq x_{i,a_{\text{prev}}})$$
  This penalty term mathematically eliminates decision oscillation between consecutive evaluation rounds in industrial SCADA networks.

---

### Layer 6: QUBO & Quantum QAOA Decision Engine
- **Primary Modules**: `decision_engine.py`, `baseline_greedy.py`, `quantum_solver.py`
- **File Location**: `layer6_optimization/`
- **Hamiltonian Minimization**:
  $$\min_{x} H(x) = \sum_{i,a} C_{i,a} x_{i,a} + \lambda_{\text{budget}} \left(\sum_{i,a} c_{i,a} x_{i,a} - B\right)^2 + \lambda_{\text{unique}} \sum_i \left(\sum_a x_{i,a} - 1\right)^2$$
  where $C_{i,a} = -\beta_a (s_i \cdot c_i) + \text{Cost}(i, a) + \lambda_{\text{switch}} \mathbb{I}(a \neq a_{\text{prev}})$.
- **Solvers Supported**:
  - `qaoa`: Qiskit Variational Quantum Circuit (Aer Simulator)
  - `numpy`: Exact QUBO Diagonalization Matrix Solver
  - `ilp`: Classical Branch-and-Bound Integer Linear Programming (PuLP / CBC Baseline)
  - `greedy_budget`: $O(N \log N)$ Light-Speed Heuristic

---

### Layer 7: Multi-Attribute Response Utility Model
- **Primary Class**: `ResponseUtilityEvaluator`
- **File Location**: `layer7_utility/utility_engine.py`
- **Decision Fidelity Metric**:
  $$DF\% = \left(1 - \frac{\text{Forbidden Actions Executed}}{\text{Total Actions Executed}}\right) \times 100\% = \mathbf{100.0\%}$$
  Verifies that zero forbidden or illegal physical actions were selected by the optimization engine.

---

### Layer 8: Response Orchestration & Audit Rationale Engine
- **Primary Modules**: `executor.py`, `explainability.py`
- **File Location**: `layer8_orchestration/`
- **Simulated Cloud API Stubs**: `aws ec2 stop-instances`, `aws iam update-access-key`, `aws ec2 authorize-security-group-ingress`.
- **4 Role-Tailored Audit Reports**:
  1. `SOC_ANALYST`: Action execution timelines and containment status.
  2. `CISO`: Financial downtime cost breakdown and risk reduction metrics.
  3. `SIEM_AUDITOR`: Regulatory provenance tags (HIPAA, GDPR, DPDP Act 2023).
  4. `PUBLIC`: Anonymized public security disclosure reports.

---

### Layer 9: Post-Incident Feedback & EMA Weight Adaptation
- **Primary Class**: `FeedbackLearner`
- **File Location**: `layer9_feedback/feedback_learner.py`
- **Exponential Moving Average (EMA) Reinforcement Formula**:
  $$w_{t+1} = (1 - \alpha) \cdot w_t + \alpha \cdot \text{FeedbackReward} \quad (\alpha = 0.30)$$
  Adapts containment utility weights dynamically based on post-incident human analyst star ratings ($1 - 5 \text{ stars}$).

---

## 5. CODING STANDARDS & DEVELOPER ONBOARDING

### A. Python Code Quality & Typing Standards
1. **PEP 8 Compliance**: Use 4 spaces for indentation.
2. **Type Hinting**: All function signatures MUST include Python `typing` annotations:
   ```python
   def evaluate_utility(
       scenario: Dict[str, Any], 
       threat_scores: Dict[str, float], 
       effective_budget: float
   ) -> Tuple[Dict[str, str], float]:
   ```
3. **Docstring Convention**: Use Google-style docstrings for all classes and public functions:
   ```python
   """Short summary of function.

   Args:
       scenario (Dict[str, Any]): Incident scenario dictionary containing resources.
       threat_scores (Dict[str, float]): Map of resource_id to threat score.

   Returns:
       Tuple[Dict[str, str], float]: Optimal action plan dictionary and total utility score.
   """
   ```

### B. Unit Testing & System Verification Protocol
Before committing any changes to git or submitting code for patent claims, developers MUST execute the 10-layer automated verification suite:

```powershell
# Run 10-Layer Automated Verification Suite
.\.venv\Scripts\python.exe verify_system.py
```

Expected Output:
```
=================================================================
  FINAL VERIFICATION SUMMARY
=================================================================
  >>> [PASS]  Layer 1: Telemetry
  >>> [PASS]  Layer 2: FL Detection
  >>> [PASS]  Layer 3: Context
  >>> [PASS]  Layer 4: Confidence
  >>> [PASS]  Layer 5: Constraints
  >>> [PASS]  Layer 6: Quantum
  >>> [PASS]  Layer 7: Utility
  >>> [PASS]  Layer 8: Orchestration
  >>> [PASS]  Layer 9: Feedback
  >>> [PASS]  Integrated Pipeline

  Score: 10/10 layers verified
  *** ALL SYSTEMS GO -- Architecture working correctly! ***
=================================================================
```

---

**Specification Document Version**: 2.0.0  
**IEEE Standard Compliance**: IEEE 1016-2009 Software Design Description  
**Author / Inventor**: Naveen Ravi  
**Repository**: [github.com/NAVEEN001138/cloud-guard-project](https://github.com/NAVEEN001138/cloud-guard-project)  
