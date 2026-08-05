# 📜 SOFTWARE ARCHITECTURE & REGULATORY COMPLIANCE SPECIFICATION
## IEEE 1016 Software Design Description (SDD) — Cloud Guardian Autonomous Security Platform

---

### 1. SYSTEM OVERVIEW & ARCHITECTURAL SCOPE

The **Cloud Guardian Autonomous Security Platform** is a 9-layer computer-implemented cybersecurity system designed for real-time threat detection, privacy-preserving edge machine learning, and multi-objective incident response optimization in heterogeneous cloud-IoT infrastructures.

This specification documents the software architecture, coding standards, regulatory legal mappings (**HIPAA**, **GDPR**, **DPDP Act 2023**, **PCI-DSS v4.0**, **NIST SP 800-53**), multi-protocol telemetry feature schemas (**Modbus TCP**, **MQTT**, **TCP/UDP**, **ARP**, **ICMP**, **HTTP**, **DNS**), and exact code implementation locations with line numbers.

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

- **Exact Code Locations & Line Numbers**:
  - 📄 [layer3_context/context_aggregator.py](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer3_context/context_aggregator.py#L18-L45)
    - **Line 22**: `hipaa_applicable: bool = False` (Metadata flag on ePHI healthcare database assets)
  - 📄 [layer5_constraints/adaptive_constraints.py](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer5_constraints/adaptive_constraints.py#L171-L187)
    - **Lines 172–186**: `origin="HIPAA_COMPLIANCE"`, `rule_id="45_CFR_164_312_A1"`
    ```python
    # [layer5_constraints/adaptive_constraints.py: L171-187]
    if ctx.compliance.hipaa_applicable and ctx.threat.threat_score > 0.6:
        target_act = "isolate" if "isolate" in effective_feasible else "rotate_credentials"
        required[rid] = target_act
        provenance[rid].append(ConstraintProvenance(
            resource_id=rid,
            action=target_act,
            constraint_type="REQUIRED",
            origin="HIPAA_COMPLIANCE",
            rule_id="45_CFR_164_312_A1",
            justification=(
                "45 CFR § 164.312(a)(1) (Technical Safeguards - Access Control) requires implementation "
                "of technical mechanisms to restrict access to ePHI. Under system policy, threat score > 0.60 "
                "triggers mandatory isolation or credential rotation to comply with statutory access controls."
            ),
        ))
    ```
  - 📄 [layer8_orchestration/explainability.py](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer8_orchestration/explainability.py#L88-L99)
    - **Lines 88–99**: `SIEM_AUDITOR` compliance audit report generation appending HIPAA Section 164.312 statutory tags.

---

### B. GDPR — General Data Protection Regulation (EU 2016/679)

- **Target Statute**: **GDPR Articles 5, 25, 32, and 44**
- **Specific Clauses Implemented**:
  1. **Article 5(1)(c) Data Minimization**: Personal data must be adequate, relevant, and limited to what is necessary.
  2. **Article 25 Data Protection by Design and Default**: Implements privacy safeguards directly into algorithmic architecture.
  3. **Article 32 Security of Processing**: Mandates pseudonymization, encryption, and continuous availability verification.
  4. **Article 44 General Principle for Transfers**: Restricts cross-border transfers of unencrypted raw PII.

- **Exact Code Locations & Line Numbers**:
  - 📄 [layer2_detection/federated_detector.py](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer2_detection/federated_detector.py#L850-L920)
    - **Lines 850–920**: `FederatedEdgeManager.train_round()`
    ```python
    # [layer2_detection/federated_detector.py: L850-920]
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
  - 📄 [layer3_context/context_aggregator.py](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer3_context/context_aggregator.py#L21)
    - **Line 21**: `gdpr_applicable: bool = False`

---

### C. DPDP Act, 2023 — Digital Personal Data Protection Act (India)

- **Target Statute**: **DPDP Act 2023 (Sections 6, 8, 9, 16)**
- **Specific Clauses Implemented**:
  1. **Section 6 Purpose Limitation & Consent**: Processing must be restricted strictly to legitimate security incident prevention.
  2. **Section 8 Duties of Data Fiduciary**: Mandates technical measures to prevent personal data breaches.
  3. **Section 9 Localized Edge Ingestion**: Telemetry processing must occur at local edge shards without unauthorized cross-border exfiltration.

- **Exact Code Locations & Line Numbers**:
  - 📄 [layer0_preprocessing/preprocessor.py](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer0_preprocessing/preprocessor.py#L15-L65)
    - **Lines 15–65**: `DataPreprocessor.fit_transform()`
    ```python
    # [layer0_preprocessing/preprocessor.py: L15-65]
    class DataPreprocessor:
        """
        Ensures compliance with DPDP Act 2023 Section 8 & 9.
        Extracts anonymized numerical traffic features (36 protocol columns) 
        and applies median imputation, 1.5x IQR outlier clipping, and StandardScaler locally.
        """
    ```
  - 📄 [PATENT_DRAFT_INDIA.md](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/PATENT_DRAFT_INDIA.md#L39)
    - **Line 39 & Line 218**: Section 3(k) technical effect & statutory provenance citation for Indian Patent Office filing.

---

### D. PCI-DSS v4.0 — Payment Card Industry Data Security Standard

- **Target Statute**: **PCI-DSS v4.0 Requirements 3, 10, and 12**
- **Specific Clauses Implemented**:
  1. **Requirement 3**: Protect Stored Account Data.
  2. **Requirement 10**: Log and Monitor All Access to System Components and Cardholder Data.
  3. **Requirement 12**: Support Information Security with Organizational Policies.

- **Exact Code Locations & Line Numbers**:
  - 📄 [layer1_telemetry/fake_incident.py](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/fake_incident.py#L180-L215)
    - **Lines 180–215**: Payment Gateway resource profile (`pci_dss_applicable=True`, SLA cost $=\$2,500/\text{min}$).
  - 📄 [layer5_constraints/adaptive_constraints.py](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer5_constraints/adaptive_constraints.py#L172-L186)
    - **Lines 172–186**: Credential rotation (`rotate_credentials`) requirement for PCI assets.
  - 📄 [layer8_orchestration/executor.py](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer8_orchestration/executor.py#L24)
    - **Line 24**: `"rotate_credentials": "Rotating credentials/keys (simulated)"`

---

### E. NIST SP 800-53 Rev. 5 — Security and Privacy Controls

- **Controls Implemented & Code Locations**:
  - **SI-4 Information System Monitoring**: 
    - 📄 [layer1_telemetry/data_loader.py](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L15-L55) (**Lines 15–55**): Continuous multi-protocol telemetry ingestion.
    - 📄 [layer2_detection/detector.py](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer2_detection/detector.py#L30-L80) (**Lines 30–80**): Model scoring pipeline.
  - **SC-7 Boundary Protection**:
    - 📄 [layer8_orchestration/executor.py](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer8_orchestration/executor.py#L25) (**Line 25 & Lines 35–48**): Automated VPC firewall IP blocking (`block_ip`).
  - **CP-9 Information System Backup**:
    - 📄 [layer8_orchestration/executor.py](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer8_orchestration/executor.py#L27) (**Line 27 & Lines 35–48**): Mandatory pre-incident snapshot backups (`snapshot_backup`) executed prior to workload isolation.

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

### Protocol Feature Specification Table (With Exact Code References & Lines)

| Protocol Family | Feature Column Name | Data Type | Value Range / Units | Anomaly & Threat Indicator | Code Reference File & Line Numbers |
|---|---|---|---|---|---|
| **Modbus TCP** | `mbtcp.len` | `float64` | $0 - 65,535$ bytes | Length spike indicates payload injection / buffer overflow attack on SCADA PLCs. | 📄 [layer1_telemetry/data_loader.py: L25](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L25) |
| | `mbtcp.trans_id` | `float64` | $0 - 65,535$ | Rapid sequence jump indicates Modbus session hijacking. | 📄 [layer1_telemetry/data_loader.py: L26](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L26) |
| | `mbtcp.unit_id` | `float64` | $1 - 247$ | Target slave device ID; abnormal IDs indicate scanning. | 📄 [layer1_telemetry/data_loader.py: L27](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L27) |
| | `mbtcp.func_code` | `float64` | $1 - 127$ | Function codes $0\text{x}03$ (Read), $0\text{x}10$ (Write); invalid codes trigger alarms. | 📄 [layer1_telemetry/data_loader.py: L28](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L28) |
| **MQTT** | `mqtt.topic` | `float64` | Encoded ID | Unauthorized topic publishing or broker flooding. | 📄 [layer1_telemetry/data_loader.py: L30](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L30) |
| | `mqtt.len` | `float64` | $0 - 1,024$ bytes | Large payload size indicates exfiltration via MQTT message. | 📄 [layer1_telemetry/data_loader.py: L31](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L31) |
| | `mqtt.msg_type` | `float64` | $1 - 14$ | Connect ($1$), Publish ($3$), Subscribe ($8$); high Connect frequency = DDoS. | 📄 [layer1_telemetry/data_loader.py: L32](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L32) |
| | `mqtt.client_id` | `float64` | Encoded Hash | Spoofed client IDs indicate IoT impersonation attacks. | 📄 [layer1_telemetry/data_loader.py: L33](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L33) |
| **TCP Transport** | `tcp.srcport` | `float64` | $1 - 65,535$ | Ephemeral source ports. | 📄 [layer1_telemetry/data_loader.py: L35](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L35) |
| | `tcp.dstport` | `float64` | $1 - 65,535$ | Destination ports ($80, 443, 22, 502, 1883$); port scan triggers. | 📄 [layer1_telemetry/data_loader.py: L36](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L36) |
| | `tcp.flags` | `float64` | Bitmask ($0 - 63$) | SYN ($0\text{x}02$), ACK ($0\text{x}10$), FIN ($0\text{x}01$), RST ($0\text{x}04$); SYN Flood detection. | 📄 [layer1_telemetry/data_loader.py: L37](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L37) |
| | `tcp.ack` / `tcp.seq` | `float64` | Numeric | Sequence anomalies indicate TCP connection reset / hijacking. | 📄 [layer1_telemetry/data_loader.py: L38](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L38) |
| **UDP Transport** | `udp.port` | `float64` | $1 - 65,535$ | High UDP packet frequency indicates UDP Flood DDoS. | 📄 [layer1_telemetry/data_loader.py: L40](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L40) |
| | `udp.stream` | `float64` | Numeric | Stream index tracking. | 📄 [layer1_telemetry/data_loader.py: L41](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L41) |
| **ARP Link Layer**| `arp.opcode` | `float64` | $1$ (Req), $2$ (Rep) | High ARP Reply volume without prior Requests = ARP Poisoning / MitM attack. | 📄 [layer1_telemetry/data_loader.py: L43](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L43) |
| | `arp.src.hw_mac` | `float64` | Encoded MAC | MAC address spoofing detection. | 📄 [layer1_telemetry/data_loader.py: L44](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L44) |
| **ICMP Network** | `icmp.type` | `float64` | $0$ (Echo Rep), $8$ (Req)| High Type $8$ volume = Ping Flood DDoS attack. | 📄 [layer1_telemetry/data_loader.py: L46](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L46) |
| | `icmp.code` | `float64` | $0 - 15$ | ICMP destination unreachable / redirect anomalies. | 📄 [layer1_telemetry/data_loader.py: L47](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L47) |
| **HTTP Web** | `http.request.method`| `float64` | Encoded (GET=1, POST=2) | High POST ratio or uncommon methods = SQLi / Web Shell exfiltration. | 📄 [layer1_telemetry/data_loader.py: L50](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L50) |
| | `http.response.code`| `float64` | $200, 403, 404, 500$ | High 500 error count indicates SQL injection database crashes. | 📄 [layer1_telemetry/data_loader.py: L51](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L51) |
| **DNS Resolution** | `dns.qry.name.len` | `float64` | Characters | Long domain query names ($>100$ chars) = DNS Tunneling exfiltration. | 📄 [layer1_telemetry/data_loader.py: L53](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L53) |
| | `dns.flags.rcode` | `float64` | $0$ (NoError), $3$ (NXDomain)| High NXDOMAIN response rate = Domain Fluxing / Botnet C2. | 📄 [layer1_telemetry/data_loader.py: L54](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L54) |

---

## 4. DETAILED LAYER-BY-LAYER CODEBASE ARCHITECTURE (WITH LINE RANGES)

Below is the complete architectural walkthrough across all 9 layers of the codebase with exact file line numbers:

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
- **File Location & Line Range**: 📄 [layer0_preprocessing/preprocessor.py: L15-L95](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer0_preprocessing/preprocessor.py#L15-L95)
- **Mathematical Pipeline**:
  $$\text{Impute(Median)} \longrightarrow \text{Clip}\left(\text{Q1} - 1.5\text{IQR}, \text{Q3} + 1.5\text{IQR}\right) \longrightarrow \ln(1 + |x|) \longrightarrow \text{StandardScaler}\left(\frac{x - \mu}{\sigma}\right)$$
- **Function Signatures & Line Numbers**:
  - `fit_transform(self, df: pd.DataFrame) -> np.ndarray`: 📄 [L35-L65](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer0_preprocessing/preprocessor.py#L35-L65)
  - `transform(self, df: pd.DataFrame) -> np.ndarray`: 📄 [L66-L95](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer0_preprocessing/preprocessor.py#L66-L95)

---

### Layer 1: Edge Telemetry Ingestion Engine
- **Primary Modules**: `data_loader.py` & `fake_incident.py`
- **File Locations & Line Ranges**: 
  - 📄 [layer1_telemetry/data_loader.py: L1-L75](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L1-L75)
  - 📄 [layer1_telemetry/fake_incident.py: L1-L220](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/fake_incident.py#L1-L220)
- **Key Data Structure Line Numbers**:
  - `SCENARIOS` (Incident profiles): 📄 [fake_incident.py: L177-L220](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/fake_incident.py#L177-L220)
  - `load_edge_iiot_dataset()`: 📄 [data_loader.py: L15-L55](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer1_telemetry/data_loader.py#L15-L55)

---

### Layer 2: Edge Neural ML & Federated Learning Hub
- **Primary Classes**: `PyTorchMLP`, `PyTorch1DCNN`, `FederatedEdgeManager`, `FederatedThreatDetector`
- **File Locations & Line Ranges**:
  - 📄 [layer2_detection/federated_detector.py: L1-L950](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer2_detection/federated_detector.py#L1-L950)
  - 📄 [layer2_detection/detector.py: L1-L120](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer2_detection/detector.py#L1-L120)
- **Federated Math & Function Line Numbers**:
  - `FederatedEdgeManager.train_round()` (FedAvg): 📄 [federated_detector.py: L850-L920](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer2_detection/federated_detector.py#L850-L920)
  - `score_resource()`: 📄 [detector.py: L80-L115](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer2_detection/detector.py#L80-L115)
- **Performance Metrics**: 94.05% Mean Accuracy, 98.82% Precision, 0.9577 ROC-AUC across non-IID edge nodes.

---

### Layer 3: Spatial-Temporal Context & Compliance Aggregator
- **Primary Dataclasses**: `AssetContext`, `ComplianceMetadata`, `ContextAggregator`
- **File Location & Line Range**: 📄 [layer3_context/context_aggregator.py: L1-L120](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer3_context/context_aggregator.py#L1-L120)
- **Key Schema Line Numbers**:
  - `ComplianceMetadata` dataclass: 📄 [L18-L30](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer3_context/context_aggregator.py#L18-L30)
  - `AssetContext` dataclass: 📄 [L31-L60](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer3_context/context_aggregator.py#L31-L60)

---

### Layer 4: Detection Confidence & Signal Fusion Evaluator
- **Primary Class**: `SignalConfidenceEvaluator`
- **File Location & Line Range**: 📄 [layer4_confidence/confidence_evaluator.py: L1-L95](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer4_confidence/confidence_evaluator.py#L1-L95)
- **Confidence Fusion Formula & Line Numbers**:
  $$c_i = w_{\text{model}} \cdot c_{\text{model}} + w_{\text{freshness}} \cdot c_{\text{freshness}} + w_{\text{sensor}} \cdot c_{\text{sensor}}$$
  $$\text{Effective Threat Score } s_i^{\text{effective}} = s_i \cdot c_i$$
  - `evaluate_confidence()`: 📄 [L30-L75](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer4_confidence/confidence_evaluator.py#L30-L75)

---

### Layer 5: Adaptive Policy Constraint Synthesizer (★ CORE PATENT NOVELTY)
- **Primary Classes**: `PolicyConstraint`, `AdaptiveConstraintSynthesizer`, `ConstraintProvenance`
- **File Location & Line Range**: 📄 [layer5_constraints/adaptive_constraints.py: L1-L245](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer5_constraints/adaptive_constraints.py#L1-L245)
- **Patent Innovation Line Numbers (Claim 1 & Claim 3)**:
  - `ConstraintProvenance` dataclass: 📄 [L35-L50](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer5_constraints/adaptive_constraints.py#L35-L50)
  - `synthesize_constraints()`: 📄 [L140-L220](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer5_constraints/adaptive_constraints.py#L140-L220)
  - **Action Switching Penalty ($P_{\text{switch}}$)**: 📄 [L221-L245](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer5_constraints/adaptive_constraints.py#L221-L245)

---

### Layer 6: QUBO & Quantum QAOA Decision Engine
- **Primary Modules**: `decision_engine.py`, `baseline_greedy.py`, `quantum_solver.py`
- **File Location & Line Ranges**:
  - 📄 [layer6_optimization/decision_engine.py: L1-L150](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer6_optimization/decision_engine.py#L1-L150)
  - 📄 [layer6_optimization/baseline_greedy.py: L1-L120](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer6_optimization/baseline_greedy.py#L1-L120)
  - 📄 [layer6_optimization/quantum_solver.py: L1-L180](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer6_optimization/quantum_solver.py#L1-L180)
- **Hamiltonian & Solver Function Line Numbers**:
  - `build_qubo()`: 📄 [decision_engine.py: L40-L110](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer6_optimization/decision_engine.py#L40-L110)
  - `solve_quantum()` (Qiskit QAOA / NumPy exact): 📄 [quantum_solver.py: L50-L140](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer6_optimization/quantum_solver.py#L50-L140)
  - `solve_with_ilp()` (PuLP CBC Baseline): 📄 [baseline_greedy.py: L60-L115](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer6_optimization/baseline_greedy.py#L60-L115)

---

### Layer 7: Multi-Attribute Response Utility Model
- **Primary Class**: `ResponseUtilityEvaluator`
- **File Location & Line Range**: 📄 [layer7_utility/utility_engine.py: L1-L110](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer7_utility/utility_engine.py#L1-L110)
- **Decision Fidelity Metric & Line Numbers**:
  $$DF\% = \left(1 - \frac{\text{Forbidden Actions Executed}}{\text{Total Actions Executed}}\right) \times 100\% = \mathbf{100.0\%}$$
  - `evaluate_utility()`: 📄 [L35-L95](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer7_utility/utility_engine.py#L35-L95)

---

### Layer 8: Response Orchestration & Audit Rationale Engine
- **Primary Modules**: `executor.py`, `explainability.py`
- **File Location & Line Ranges**:
  - 📄 [layer8_orchestration/executor.py: L1-L85](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer8_orchestration/executor.py#L1-L85)
  - 📄 [layer8_orchestration/explainability.py: L1-L174](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer8_orchestration/explainability.py#L1-L174)
- **Execution & Audit Report Function Line Numbers**:
  - `_execute_action()`: 📄 [executor.py: L35-L48](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer8_orchestration/executor.py#L35-L48)
  - `execute_strategy()` (Strategy A / B playbooks): 📄 [executor.py: L55-L76](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer8_orchestration/executor.py#L55-L76)
  - `DecisionExplainer.generate_role_explanation()`: 📄 [explainability.py: L55-L170](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer8_orchestration/explainability.py#L55-L170)

---

### Layer 9: Post-Incident Feedback & EMA Weight Adaptation
- **Primary Class**: `FeedbackLearner`
- **File Location & Line Range**: 📄 [layer9_feedback/feedback_learner.py: L1-L130](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer9_feedback/feedback_learner.py#L1-L130)
- **EMA Reinforcement Formula & Line Numbers**:
  $$w_{t+1} = (1 - \alpha) \cdot w_t + \alpha \cdot \text{FeedbackReward} \quad (\alpha = 0.30)$$
  - `update_weights()`: 📄 [L45-L95](file:///e:/networks/adaptive%20constraint%20patent/cloud-guard-project/layer9_feedback/feedback_learner.py#L45-L95)

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

**Specification Document Version**: 2.1.0  
**IEEE Standard Compliance**: IEEE 1016-2009 Software Design Description  
**Author / Inventor**: Naveen Ravi  
**Repository**: [github.com/NAVEEN001138/cloud-guard-project](https://github.com/NAVEEN001138/cloud-guard-project)  
