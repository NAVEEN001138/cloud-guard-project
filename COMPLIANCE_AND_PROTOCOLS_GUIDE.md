# 📜 COMPLIANCE STANDARDS & NETWORK PROTOCOLS DEVELOPER GUIDE
## Technical Reference for Future Systems Development & Audit Verification

---

### 1. Executive Summary & Purpose

This document provides a comprehensive technical breakdown of how regulatory compliance standards (**HIPAA**, **GDPR**, **DPDP Act 2023**, **PCI-DSS**) and industrial/network protocols (**Modbus TCP**, **MQTT**, **TCP/UDP**, **ARP**, **ICMP**, **HTTP**, **DNS**) are implemented, processed, and enforced across the **Cloud Guardian** 9-Layer Architecture.

It serves as a primary reference guide for future developers, security engineers, and legal auditors expanding the platform or verifying compliance provenance.

---

## 2. Regulatory Compliance Standards Implementation Matrix

The platform integrates compliance safeguards as first-class decision parameters in **Layer 3 (Context Aggregation)**, **Layer 5 (Adaptive Constraints)**, and **Layer 8 (Audit Explainability)**.

| Regulatory Standard | Primary Focus | Code Implementation Files & Functions | How It Is Enforced in Code |
|---|---|---|---|
| **HIPAA** <br>*(45 CFR § 164.312)* | Technical Access Controls, Availability Safeguards & Audit Logs | 📁 `layer3_context/context_aggregator.py`<br>📁 `layer5_constraints/adaptive_constraints.py`<br>📁 `layer8_orchestration/explainability.py` | - Flags `hipaa_applicable=True` on healthcare assets.<br>- Synthesizes policy rules forbidding destructive server isolation when threat score $< 0.4$, preserving system availability.<br>- Generates audit log citations referencing 45 CFR § 164.312(a)(1). |
| **GDPR** <br>*(Articles 25, 32 & 44)* | Data Protection by Design, Cross-Border Transfer Restrictions, Anonymization | 📁 `layer2_detection/federated_detector.py`<br>📁 `layer3_context/context_aggregator.py`<br>📁 `layer5_constraints/adaptive_constraints.py` | - Enforces **Federated Edge Learning (FedAvg)**: raw user traffic remains 100% local on edge nodes; only model weight tensors $\mathbf{w}_k$ cross network boundaries.<br>- Flags `gdpr_applicable=True` to enforce anonymized audit reports. |
| **DPDP Act, 2023** <br>*(India — Sec. 6, 8, 9)* | Data Localism, Zero Raw PII Transmission, Statutory Audit Provenance | 📁 `layer0_preprocessing/preprocessor.py`<br>📁 `layer5_constraints/adaptive_constraints.py`<br>📄 `PATENT_DRAFT_INDIA.md` | - Restricts data ingestion to numerical feature extraction.<br>- Implements localized median imputation and IQR outlier clipping without transmitting PII.<br>- Attaches DPDP Act 2023 statutory provenance tags to QUBO matrices. |
| **PCI-DSS** <br>*(Req. 10 & 12)* | Payment Card Industry Data Security Standard (Cardholder Data Environment) | 📁 `layer1_telemetry/fake_incident.py`<br>📁 `layer3_context/context_aggregator.py`<br>📁 `layer5_constraints/adaptive_constraints.py` | - Flags payment gateway assets (`pci_dss_applicable=True`).<br>- Mandates instant credential rotation (`rotate_credentials`) upon medium-threat detection to protect API tokens. |

---

### Detailed Code Implementation of Regulatory Standards

#### A. HIPAA (45 CFR § 164.312 Technical Safeguards)
- **Location**: `layer3_context/context_aggregator.py`
  ```python
  @dataclass
  class ComplianceMetadata:
      gdpr_applicable: bool = False
      hipaa_applicable: bool = False
      pci_dss_applicable: bool = False
      dpdp_2023_applicable: bool = True
  ```
- **Constraint Synthesis (`layer5_constraints/adaptive_constraints.py`)**:
  ```python
  if context.compliance.hipaa_applicable:
      if threat_score < 0.4:
          # Forbid aggressive isolation on HIPAA assets to satisfy 45 CFR § 164.312 availability access controls
          forbidden_actions["isolate"] = PolicyConstraint(
              origin="HIPAA_COMPLIANCE",
              rule_id="HIPAA_45CFR_164_312",
              description="Forbidden by HIPAA 45 CFR § 164.312 Availability Safeguard when threat score < 0.4"
          )
  ```
- **Audit Provenance Report (`layer8_orchestration/explainability.py`)**:
  Generates compliance audit logs mapping exact action rationale to HIPAA Section 164.312.

#### B. GDPR (Data Protection by Design & Federated Privacy)
- **Location**: `layer2_detection/federated_detector.py`
  ```python
  class FederatedEdgeManager:
      def train_round(self):
          # Local training happens on edge nodes. 
          # Zero raw network telemetry is transmitted over the network.
          for client in self.clients:
              local_weights = client.train_local_model()
              self.aggregate_global_weights(local_weights) # FedAvg
  ```
  This architecture satisfies **GDPR Article 25 (Privacy by Design)** and **Article 44 (International Data Transfer Restrictions)** by keeping raw data local.

---

## 3. Ingested Network & Industrial IoT Protocols Schema

The system ingests and processes telemetry extracted from the **Edge-IIoTset dataset**, covering **36 numeric protocol features** across 7 protocol families:

```
                          ┌─────────────────────────────────────────┐
                          │   Edge-IIoTset Ingested Protocol Features│
                          └────────────────────┬────────────────────┘
                                               │
       ┌──────────────────┬────────────────────┼───────────────────┬──────────────────┐
       ▼                  ▼                    ▼                   ▼                  ▼
 Industrial IoT      Core Transport         Network Layer      Application/Web       DNS Protocol
 (Modbus & MQTT)      (TCP & UDP)              (ARP)            (HTTP Protocol)       (Query & Flags)
```

### Protocol Feature Breakdown & Code Mapping

| Protocol Category | Supported Protocols | Key Extracted Feature Columns (Layer 0 & 1) | Purpose & Threat Indicator | Code Reference File |
|---|---|---|---|---|
| **Industrial IoT** | **Modbus TCP** | `mbtcp.len`, `mbtcp.trans_id`, `mbtcp.unit_id`, `mbtcp.func_code` | Detects SCADA PLC injection, unauthorized function code overrides, and Modbus length anomalies. | `layer1_telemetry/data_loader.py` |
| **Smart Sensors** | **MQTT** | `mqtt.topic`, `mqtt.len`, `mqtt.msg_type`, `mqtt.client_id` | Detects broker flooding, unauthorized topic publishing, and payload tampered messages. | `layer1_telemetry/data_loader.py` |
| **Transport Layer** | **TCP / UDP** | `tcp.srcport`, `tcp.dstport`, `tcp.flags`, `tcp.len`, `udp.port` | Detects SYN floods, port scanning reconnaissance, invalid TCP flag combinations. | `layer1_telemetry/data_loader.py` |
| **Link & Network** | **ARP & ICMP** | `arp.opcode`, `arp.src.hw_mac`, `icmp.type`, `icmp.code` | Detects ARP poisoning, Man-in-the-Middle (MitM) spoofing, and ICMP Ping Flood DDoS attacks. | `layer1_telemetry/data_loader.py` |
| **Web & Application** | **HTTP** | `http.request.method`, `http.response.code`, `http.content_length` | Detects SQL Injection attempts, directory traversal, and abnormal HTTP payload sizes. | `layer1_telemetry/data_loader.py` |
| **Name Resolution** | **DNS** | `dns.qry.name.len`, `dns.flags.rcode`, `dns.count.answers` | Detects DNS tunneling data exfiltration, NXDOMAIN flooding, and domain fluxing. | `layer1_telemetry/data_loader.py` |

---

## 4. Codebase File Index & Function Reference Map

This section lists every core file in the project, its layer responsibility, and key functions for future developers:

```
cloud-guard-project/
├── config.py                           # Central configuration (budget limits, quantum qubit bounds)
├── pipeline.py                         # 9-Layer end-to-end pipeline execution engine
├── streamlit_app.py                    # Streamlit SOC Dashboard & Glassmorphic Frontend
├── PATENT_DRAFT_INDIA.md               # Indian Patent Office Form 2 Complete Specification
├── PATENT_INNOVATION.md                # Patent Innovation Strategy & Claim Breakdown
├── COMPLIANCE_AND_PROTOCOLS_GUIDE.md   # [THIS DOCUMENT] Developer Reference for Compliance & Protocols
│
├── layer0_preprocessing/
│   └── preprocessor.py                # DataPreprocessor: Median Imputation, IQR Clipping, Log1p, StandardScaler
│
├── layer1_telemetry/
│   ├── data_loader.py                 # Edge-IIoTset CSV data loader (36 numeric protocol features)
│   └── fake_incident.py               # Incident scenario profiles (multi_tier_demo, ddos_flood, etc.)
│
├── layer2_detection/
│   ├── detector.py                    # Classical Threat Detector (Random Forest baseline)
│   ├── federated_detector.py          # PyTorch Federated Learning Hub (FedAvg / FedProx Edge Manager)
│   └── benchmark_domain_fl.py         # Multi-domain FL efficiency benchmarks
│
├── layer3_context/
│   └── context_aggregator.py          # Spatial-temporal context, C-I-A ratings & Compliance Metadata
│
├── layer4_confidence/
│   └── confidence_evaluator.py        # ROC Youden's J calibration & HIGH/MODERATE/LOW confidence gating
│
├── layer5_constraints/
│   └── adaptive_constraints.py        # ★ PATENT CORE: Dynamic Constraint Synthesizer & Action Switching Penalty
│
├── layer6_optimization/
│   ├── decision_engine.py             # QUBO Hamiltonian matrix formulation
│   ├── baseline_greedy.py             # Classical ILP (PuLP) & Greedy baseline solvers
│   └── quantum_solver.py              # Qiskit QAOA variational circuit & NumPy exact QUBO solvers
│
├── layer7_utility/
│   └── utility_engine.py              # Multi-attribute utility model & 100% Decision Fidelity inspection
│
├── layer8_orchestration/
│   ├── executor.py                    # Cloud API stubs (AWS EC2 stop, IAM update, VPC block)
│   └── explainability.py              # 4 Role-Tailored Audit Reports (SOC, CISO, Auditor, Public)
│
└── layer9_feedback/
    └── feedback_learner.py            # Post-incident EMA reinforcement learning loop (α = 0.30)
```

---

## 5. Developer Guide: How to Extend the Platform

### A. How to Add a New Regulatory Compliance Standard (e.g. NIS2 or ISO 27001)

1. **Step 1 — Update `ComplianceMetadata`** in `layer3_context/context_aggregator.py`:
   ```python
   @dataclass
   class ComplianceMetadata:
       ...
       nis2_applicable: bool = False
       iso_27001_applicable: bool = False
   ```

2. **Step 2 — Inject Policy Rules** in `layer5_constraints/adaptive_constraints.py`:
   ```python
   if context.compliance.nis2_applicable:
       # Add NIS2 mandatory incident reporting constraint
       required_actions.append("notify_soc")
   ```

3. **Step 3 — Add Audit Citations** in `layer8_orchestration/explainability.py`:
   Add NIS2 / ISO 27001 section tags to the `SIEM_AUDITOR` report generator.

---

### B. How to Add New Protocol Features (e.g. CoAP or OPC UA)

1. **Step 1 — Add Feature Names** in `config.py`:
   ```python
   FEATURE_NAMES.extend(["coap.code", "coap.msg_type", "opcua.node_id"])
   ```

2. **Step 2 — Update Data Loader** in `layer1_telemetry/data_loader.py`:
   Ensure `load_edge_iiot_dataset()` extracts and cleans the new protocol columns.

3. **Step 3 — Re-verify Architecture**:
   Run the verification suite to ensure 10/10 layers pass:
   ```bash
   python verify_system.py
   ```

---

**Document Version**: 1.0.0  
**Author**: Naveen Ravi  
**Project**: Cloud Guardian Patent Engine  
