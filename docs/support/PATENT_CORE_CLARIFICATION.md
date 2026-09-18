# Cloud Guardian — Patent Core and Novelty Clarification (Invention Candidate v2)

**For:** patent agent, technical reviewers, faculty examiners  
**Subject:** precise statement of the claimed subject matter, its mechanism, its support in code, and its position against the closest prior art  
**Reference drawings:**  
- FIG. 6, `../../images/patent_v2_fig6_layer5_patent_core.png` (reference numerals 500–595)  
- FIG. 7, `../../images/patent_v2_fig7_v2_chain_and_incremental_loop.png` (reference numerals 600–680)  
**Companion documents:** `PRIOR_ART_LAYER5_CORE.md` (prior-art search), `INDEPENDENT_CODE_AUDIT_REFERENCE.md` (code audit reference), `V2_IMPLEMENTATION_REPORT.md` (v2 implementation and empirical verification report)  
**Date:** 2026-09-17  

---

## 1. Statement of the claimed subject matter

> **The invention computes a security-decision invariance envelope around a measured runtime infrastructure state, transforms and closes an admissible decision space, certifies that space with a constructive feasibility witness, compiles the certified model into a backend formulation accompanied by a fidelity proof verified by an independent checker, and gates actuation on cryptographic certificate verification, envelope containment, and state-epoch validation.**

The claimed subject matter is embodied in the Layer 5 / Layer 8 patent core of the implementation — the *state-enveloped proof-carrying security compiler and actuation capability verifier* — specifically in the ordered combination of:

| Ref. (FIG. 6/7) | Element | Role in the claim |
|---|---|---|
| 610 / 510 | **Security-decision invariance envelope derivation ($E_t$)** and **runtime-state fingerprinting ($F_t$)** with monotonic state epoch ($n$) | Delimits the continuous state region of semantic invariance |
| 620 / 520–540 | **Structural decision-domain transformation**, **fixed-point dependency closure ($R^*_t$)**, and bound regeneration | Excises inadmissible variables; derives least fixed-point consequences |
| 630 / 550–570 | **Versioned SC-IR**, **constructive feasibility witness ($W_t$)**, and **state-envelope certificate ($C_t$)** with asymmetric digital signature | Binds IR digest, closure digest, witness digest, envelope, epoch, and policy revision under separated key roles |
| 640 / 580–590 | **Certificate-bound formulation compiler** emitting backend model ($M_b$) and **fidelity proof ($\Pi_b$)**, verified by an **independent proof checker** | Enforces the projection obligation $x \in F(\text{SC-IR}) \iff \exists z : (x, z) \in F(M_b)$ in polynomial time relative to proof size |
| 650 | **Feasibility gate** with conditional repair post-solve | Guarantees $x^* \in F(\text{SC-IR})$ prior to execution, with conditional LP relaxation loss bound |
| 660 / 595 | **Actuation capability verifier** and **device revision check** | Gated execution verifying signature, lease, $V_{\text{now}} \in E_t$, epoch $n_{\text{now}} \ge n$, domain, and budget; dispatch carrying expected revision validated by device simulator |
| 670 | **Closed-loop recertification** | Invalidates certificate on envelope violation or epoch race; triggers pipeline reconstruction and recertification |
| 680 | **Certified incremental lineage** | Chains certificates via parent digest and requires clean subgraph digest invariance |

### 1.1 What is expressly *not* claimed as inventive

| Component | Status |
|---|---|
| Machine-learning / federated threat detection, threat scoring, confidence tiers | Supporting input to Layer 5 (runtime state vector $S_t$) |
| Integer linear programming, QUBO, QAOA, any solver | Downstream backend; the compiler targets them, the invention is not them |
| Ed25519 / HMAC-SHA256 cryptographic primitives | Standard primitives; claimed only as the mechanism binding the certificate and separating certifier/compiler/actuator roles |
| Modbus, OPC-UA, OpenFlow, cloud control-plane APIs | Actuation embodiments; implemented as protocol command builders, not live device I/O |
| Fixed-point iteration, constraint propagation, variable elimination | Known techniques; claimed only as the means by which the closed IR is produced |
| Solver-independent modelling languages as such | Known (MiniZinc/FlatZinc, MathOptInterface); the IR's *existence* carries no weight |
| General model equivalence | Deciding general model equivalence is intractable; the checker verifies equivalence *under the emitted proof system in polynomial time in the size of the proof* |

---

## 2. Technical problem

Automated infrastructure response selects mitigation actions (isolate, rotate credentials, block, snapshot, monitor, increase logging) for affected resources under competing objectives — containment, business impact, downtime, budget. Optimisation-based approaches formulate this as a combinatorial problem and hand it to a solver.

Four deficiencies arise when the response domain contains cyber-physical or regulated assets:

1. **The action set is fixed at design time.** Whether isolating a programmable logic controller is admissible depends on its current operational state, but the decision variable $x[\text{PLC}, \text{isolate}]$ exists in the model regardless, and inadmissibility is expressed by a constraint or a penalty on that variable.
2. **Safety is delegated to the solver.** Whether a forbidden action is avoided depends on the solver honouring a hard constraint (exact solvers) or on a penalty out-weighing the containment reward (heuristic, approximate and quantum solvers, where hard constraints are not guaranteed in the returned assignment).
3. **No checkable proof attests that the compiled model preserves the checked semantics.** A compiler may mis-translate a constraint, drop a conflict, or calibrate a penalty insufficiently, allowing infeasible assignments to be returned as optimal.
4. **Time-of-check to time-of-use (TOCTOU) vulnerability.** Telemetry changes or device state mutations between certification and actuation cause stale decisions to be dispatched to hardware whose operational context has diverged.

The invention addresses all four by moving safety **upstream of the optimiser into an attested, state-enveloped artefact carrying a checkable fidelity proof and gated at device actuation**.

---

## 3. Mechanism (FIG. 6 and FIG. 7)

### 3.1 Security-decision invariance envelope and state fingerprint (610)

From measured infrastructure telemetry, a validity-relevant state vector $V_t$ is extracted, capturing threat scores, detection confidences, SLA priorities, statutory compliance flags (HIPAA, GDPR, PCI-DSS), business criticality, declared relations, and physical operational state (PLC operating mode, safety interlocks, network segment).

A canonical serialization produces a tamper-evident **runtime-state fingerprint** $F_t = H(\text{canon}(V_t))$ and records a monotonically increasing **state epoch** $n$.

A **validity envelope** (security-decision invariance envelope) $E_t$ is constructively derived during rule resolution as the conjunction of per-field predicates:
- For continuous fields with thresholds ($\theta \in \{0.40, 0.50, 0.60, 0.70\}$), each rule contributes the widest interval $(\theta_l, \theta_u]$ containing the observed value on which that rule's outcome is invariant.
- For discrete categorical fields (asset type, SLA priority, compliance applicability, physical state), each rule contributes a singleton value set.

**Definition:** A validity envelope $E_t$ is a security-decision invariance envelope such that for any state $S$ whose validity-relevant projection satisfies $V(S) \in E_t$:
1. Admissible decision-domain membership is invariant: $A'(S) = A'_t$;
2. Fixed-point dependency closure is invariant: $R^*(S) = R^*_t$;
3. Hard constraints and conflict hyperedges remain semantically identical;
4. Operational bounds remain within the certified bound set.

### 3.2 Structural decision-domain transformation (620 / 510–520)

For each resource $i$ with candidate action set $A_i$, the runtime state $S_t$ determines an inadmissible subset. The admissible domain is:
$$A'_i = A_i \setminus \text{Inadmissible}(i, S_t)$$
A decision variable is created **only** for $(i, a)$ with $a \in A'_i$. An inadmissible action has no decision variable; it is not constrained to zero, it is structurally absent.

### 3.3 Fixed-point dependency closure (620 / 530)

Removal has structural consequences. Declared typed relations (`REQUIRES`, `MANDATES`, `CONFLICTS_WITH`, `CONSUMES_RESOURCE`, `DERIVES_BOUND`, `PROTECTS_FAILSAFE`) are propagated:
$$R_{k+1} = R_k \cup \text{DependentConsequences}(R_k), \quad \text{iterated until } R_{k+1} = R_k =: R^*_t$$
A dependent whose prerequisite has been removed is itself removed; the iteration is deterministic and converges to a unique least fixed point regardless of evaluation order (`test_03`, `test_54`).

### 3.4 Bound regeneration and versioned SC-IR (620 / 540–550)

Operational bounds (effective budget, minimum achievable cost, active variable/conflict counts) are regenerated over the remaining admissible domain by a single owner (`test_36`). The result is serialized into a solver-independent **Security Constraint Intermediate Representation (SC-IR)** carrying $F_t$, $E_t$, state schema identifier, state epoch $n$, variable domains, exactly-one constraints, conflict hyperedges, and hard budget bounds.

### 3.5 Constructive safety certification (630 / 560–570)

Prior to backend compilation, the certifier verifies safety invariants over the SC-IR and executes a constructive backtracking search to discover a **constructive feasibility witness** $W_t = (\text{assignment}, \text{budget\_slack}, \text{active\_constraints})$ that simultaneously satisfies exactly-one, conflict, budget, and mandate constraints (`test_28`).

On success, it emits a **state-envelope certificate** $C_t$ signed under the certifier's private key (Ed25519 or HMAC-SHA256 fallback), binding:
$$C_t = \text{Sign}_K\Big(H(\text{SC-IR}_t), H(R^*_t), H(W_t), E_t, \text{AssetScope}, \text{PolicyRevision}, \text{StateSchema}, n, \text{LeasePolicy}, H(\text{Manifest}), \text{Manifest}\Big)$$

**Three-Way Revocation Rule:** Actuation authority is governed by an explicit three-way binding rule:
$$\text{IR changed} \lor \text{state} \notin E_t \lor \text{policy revision changed} \implies \text{authority revoked}$$
If the SC-IR is altered, if the runtime state drifts outside the decision invariance envelope $E_t$, or if the deployed policy revision differs from the certified revision, all execution authority is immediately and unconditionally revoked.

### 3.6 Proof-carrying formulation compiler and independent checker (640 / 580–590)

The compiler holds only the verification key. It verifies $C_t$ and asserts $V_{\text{now}} \in E_t$. If verified, it compiles the SC-IR into a backend formulation $M_b$ (ILP or QUBO) and emits an explicit **fidelity proof** $\Pi_b$.

The proof satisfies the formal projection obligation:
$$x \in F(\text{SC-IR}) \iff \exists z : (x, z) \in F(M_b)$$
where $x$ ranges over certified response variables and $z$ ranges over auxiliary variables (e.g., QUBO binary slack variables). For QUBO, the proof certifies that the penalty coefficient $P$ satisfies $P > \Delta_{\text{obj}}$, where $\Delta_{\text{obj}}$ is the independently bounded maximum objective range over all binary assignments, guaranteeing that every feasible assignment has zero penalty energy and no penalty-violating assignment can minimize the objective.

An **independent proof checker** (a standalone module importing no compiler internals) verifies $\Pi_b$ against the SC-IR and $M_b$ prior to solver invocation. The checker cost is polynomial in the size of the proof under this proof system; it does not decide general model equivalence.

### 3.7 Feasibility gate and conditional repair (650)

The solver is treated as untrusted. The formal feasibility semantics enforced by the compiler and independent checker are:
- **ILP:** $x \in F(\text{IR}) \iff \exists z: (x, z) \text{ satisfies all backend hard constraints}$.
- **QUBO:** $x \in F(\text{IR}) \iff \exists z: P_{\text{hard}}(x, z) = 0$, where $P_{\text{hard}}$ is the reconstructed penalty polynomial.

Upon receiving solver output $x^*$, a feasibility gate checks $x^* \in F(\text{SC-IR})$. If satisfied, $x^*$ passes through. If violated, a deterministic projection repair onto $F(\text{SC-IR})$ is attempted, with the certified witness $W_t$ serving as an infallible fallback. A certified loss bound $\delta$ is computed conditionally when an independently verifiable LP relaxation bound is available; otherwise, no universal bound is claimed.

### 3.8 Actuation capability verifier and device revision check (660 / 595)

At the actuation boundary, a standalone capability verifier checks:
1. Certificate signature validity under the public key;
2. Certificate lease validity (current timestamp within lease window);
3. Current state snapshot containment $V_{\text{now}} \in E_t$;
4. Current state epoch $n_{\text{now}} \ge n_{\text{cert}}$;
5. Plan action containment within certified admissible domains;
6. Plan cost within certified budget bound.

Approved dispatches carry `expected_state_revision = snapshot.epoch`. Actuator command handlers interface with device controllers (simulated in test via `SimulatedDeviceInterface`) that reject any command whose expected revision differs from the current device-side revision, preventing epoch race conditions.

### 3.9 Closed-loop recertification (670) and certified incremental lineage (680)

On any verification failure, the plan and certificate are invalidated, triggering an automated closed-loop reconstruction and recertification request. When telemetry changes affect a subgraph, incremental compilation emits a successor certificate $C_{t+1}$ carrying $H(C_t)$ as `parent_certificate_digest` and reuses subgraphs only upon verifying the invariance of their canonical digests (`test_50`).

---

## 4. Worked example

An industrial PLC (`plc-node-01`) is under attack with threat score 0.85 and detection confidence 0.93. Its safety profile forbids automated network isolation. Downstream, a gateway (`gw-01`) depends on the PLC (`requires_isolation_with: [plc-node-01]`).

1. **Validity envelope derivation:** The rule set derives $E_t$ with threat interval $(0.70, 1.0]$ for both nodes, SLA priority `CRITICAL`, and physical state `RUN`. Telemetry fluctuations between 0.71 and 0.99 remain strictly within $E_t$.
2. **Structural transformation:** $A'_{\text{PLC}} = \{\text{rotate\_credentials}, \text{monitor}, \text{increase\_logging}\}$. Variable $x[\text{PLC}, \text{isolate}]$ is structurally absent. Fixed-point closure propagates along `requires_isolation_with`, removing $x[\text{gw-01}, \text{isolate}]$.
3. **Certification:** Certifier finds feasible witness $W_t = \{(\text{PLC}, \text{monitor}), (\text{gw-01}, \text{monitor})\}$, verifies all 7 invariants, and signs certificate $C_t$ committing the witness digest, envelope digest, and epoch $n=1$.
4. **Proof-carrying compilation:** Formulation compiler emits ILP/QUBO models and fidelity proof $\Pi$. Independent checker verifies variable mapping, constraint translations, and penalty dominance ($P=100.0 > \Delta_{\text{obj}}=2.45$).
5. **Actuation gate:** At epoch $n=1$, telemetry shifts threat to 0.88. Verifier checks $0.88 \in (0.70, 1.0]$, confirms epoch $1 \ge 1$, verifies signature, and issues authorization. If threat drops to 0.20 or device epoch increments to 2, actuation is refused and recertification is triggered.

---

## 5. Why structural absence is not merely a constraint or a penalty

For exact solvers, removing a variable and fixing it to zero yield the identical feasible set. The technical distinction rests on three demonstrated grounds:

1. **Heuristic, approximate, and quantum backends:** Approximate solvers (QAOA, simulated annealing, greedy heuristics) do not guarantee that hard constraints or penalty terms hold in the returned sample. An absent variable cannot be sampled under any penalty failure.
2. **Calibration independence:** Penalized models are safe only when the penalty coefficient exceeds a threshold $\lambda^*(w)$ that scales with the objective weighting. In Experiment 6, $\lambda=0$ selects forbidden actions on 40.0% of assets. The structural approach is safe for all $\lambda$ and all $w$ without calibration.
3. **Checkable attestation and proof checking:** A penalty is an internal solver parameter. The state-envelope certificate and fidelity proof are checkable artifacts verifiable in polynomial time by independent parties prior to solving and actuation.

---

## 6. Patent claim structure

### Independent Claim 1 (Five-Element Ordered Combination)

> **1.** A computer-implemented method for generating and executing verified infrastructure security response formulations, comprising:
>
> (a) **computing a security-decision invariance envelope** from a measured runtime state vector of a plurality of infrastructure resources having an associated runtime-state fingerprint and a monotonic state epoch, wherein the security-decision invariance envelope comprises a conjunction of per-field predicates defining a region of state space within which decision-domain membership, dependency closure, hard constraints, and operational bounds are invariant;
>
> (b) **transforming an initial decision domain** for the infrastructure resources by structurally excising candidate response actions determined inadmissible under the measured runtime state, iteratively propagating the excision through declared typed dependency relations to a fixed-point dependency closure, and regenerating operational bounds over the remaining admissible domain to generate a solver-independent Security Constraint Intermediate Representation (SC-IR) carrying the runtime-state fingerprint, the security-decision invariance envelope, and the state epoch;
>
> (c) **generating a state-envelope certificate** by verifying a plurality of safety invariants over the SC-IR, executing a constructive search to generate a joint response assignment satisfying constraint requirements as a feasibility witness, and cryptographically committing into the certificate a canonical digest of the SC-IR, a closure digest, a witness digest, the security-decision invariance envelope, an asset scope, a policy revision identifier, and the state epoch;
>
> (d) **compiling the certified SC-IR into a solver-specific optimisation formulation** upon verifying the certificate and confirming that a current runtime state is contained within the security-decision invariance envelope, and emitting a fidelity proof demonstrating that an assignment of certified response variables is feasible in the SC-IR if and only if there exists an assignment of auxiliary variables feasible in the solver-specific formulation, wherein an independent proof checker verifies the fidelity proof prior to solver invocation; and
>
> (e) **authorising actuation at an actuation capability verifier** prior to emitting control commands to the infrastructure resources by verifying the cryptographic authenticity of the certificate, verifying that a current state snapshot is contained within the security-decision invariance envelope and has a state epoch greater than or equal to the state epoch in the certificate, verifying that a solved response plan contains only actions within the certified admissible domain, and dispatching control commands carrying an expected state revision validated by a device-side interface against a current device revision, wherein actuation authority is subject to a three-way revocation rule establishing that execution authority is revoked upon occurrence of any of: alteration of the SC-IR, drift of the measured runtime infrastructure state outside the security-decision invariance envelope, or modification of the policy revision identifier.

---

### Dependent Claims

> **2.** The method of claim 1, wherein the fixed-point dependency closure converges to a unique least fixed point that is invariant to the evaluation order of the declared typed dependency relations.
>
> **3.** The method of claim 1, wherein compiling the certified SC-IR comprises generating an integer linear programming formulation and a quadratic unconstrained binary optimisation (QUBO) formulation, wherein for the QUBO formulation the fidelity proof establishes that an exact binary-slack budget penalty coefficient strictly exceeds an independently bounded maximum objective range over all binary assignments.
>
> **4.** The method of claim 1, further comprising receiving a response assignment from an untrusted solver, verifying feasibility against the SC-IR at a feasibility gate, and upon detecting constraint violation, executing a deterministic projection repair onto the SC-IR with fallback to the feasibility witness, and conditionally computing a certified loss bound when an independently verifiable linear programming relaxation bound is available.
>
> **5.** The method of claim 1, wherein the state-envelope certificate is digitally signed using an asymmetric private key held by a certifier role, and wherein the formulation compiler and actuation capability verifier verify the digital signature using a corresponding public key without access to the private key.
>
> **6.** The method of claim 1, wherein the declared typed dependency relations comprise typed prerequisite relations and typed credential-provider relations derived from measured topology, and wherein an undeclared dependency relation derives no prerequisite action.
>
> **7.** The method of claim 1, wherein the security-decision invariance envelope comprises continuous interval predicates over threat scores and confidence values, and discrete value-set predicates over physical operational states and statutory compliance applicability flags.
>
> **8.** The method of claim 1, further comprising generating an incremental lineage of state-envelope certificates in response to telemetry mutations, wherein each successor certificate commits a digest of its immediate predecessor certificate, wherein unchanged subgraphs are reused only upon verifying invariance of their canonical digests against the certified predecessor, and wherein the incremental equivalence attestation records the method as digest-gated reuse together with the set of reused subgraph digests and the set of recomputed assets.
>
> **9.** The method of claim 1, wherein dispatching control commands comprises constructing protocol-specific control payloads for at least one of an industrial controller register interface, an industrial OPC-UA method interface, an OpenFlow network-switch forwarding-table interface, or a cloud control-plane interface, and wherein command execution is rejected when the expected state revision does not match the current device revision.

---

## 7. Claim-element support matrix

| Claim element | Implementation module | Verified by |
|---|---|---|
| 1(a) Validity envelope, fingerprint, epoch | `layer5_constraints/runtime_state.py`, `validity_envelope.py` | tests 40, 41, 42, 51, 52, 57, 58, 60, 61; Exp 14 ($N=1000$ churn sweep) |
| 1(b) Structural transformation, closure, bounds | `layer5_constraints/dependency_graph.py`, `constraint_ir.py` | tests 01–08, 20, 35, 36, 38, 54, 59; Exp 1, 3, 7 |
| 1(c) Witness, certificate, digital signature | `safety_certifier.py`, `keys.py` | tests 12, 13, 16, 27, 28, 29, 30, 39, 43, 44; Exp 2, 8, 16 |
| 1(d) Proof-carrying compiler, independent checker | `formulation_compiler.py`, `fidelity_proof.py`, `proof_checker.py` | tests 09–13, 17, 21–26, 47, 53; Exp 10, 12, 13 |
| 1(e) Actuation verifier, device revision check | `layer8_orchestration/capability_verifier.py`, `executor.py` | tests 37, 48, 49; Exp 15 (TOCTOU & race suite) |
| 2 Least fixed point uniqueness | `dependency_graph.py` (`compute_fixed_point_closure`) | tests 01–04, 54; Exp 7 |
| 3 ILP and QUBO backends, penalty dominance | `formulation_compiler.py`, `fidelity_proof.py` | tests 21–24, 53; Exp 13 |
| 4 Feasibility gate, conditional repair | `layer6_optimization/feasibility_gate.py` | test 48 |
| 5 Asymmetric signature & separated roles | `layer5_constraints/keys.py`, `safety_certifier.py` | tests 43, 44, 45, 46; Exp 16 (9 attack vectors) |
| 6 Topology-derived typed relations | `dependency_graph.py` | tests 02, 05, 31, 35, 38 |
| 7 Continuous intervals & discrete value sets | `validity_envelope.py` | tests 41, 42, 51, 52, 57, 58, 60, 61 |
| 8 Incremental lineage & digest invariance | `incremental_compiler.py` | tests 14, 15, 31–34, 50, 62; Exp 9 |
| 9 Protocol-specific payloads & revision check | `executor.py`, `SimulatedDeviceInterface` | test 49; `verify_system.py` Layer 8 |

*All 62 unit tests pass; 10/10 layer verification passes; Experiments 1–16 execute without error (2026-09-17).*

---

## 8. Position against the closest prior art

| Closest reference | What it teaches | Limitation in Claim 1 it lacks |
|---|---|---|
| Alshiekh et al. 2018 (safe-RL shielding); action masking in autonomous cyber defence | Removing unsafe actions from an agent's choice set before decision | Operates on RL policy distributions, not on an optimization model; lacks validity envelopes, intermediate representations, constructive feasibility witnesses, certificates, proof-carrying compilers, and actuation gates. |
| **Dutta et al. 2021** (SMT-verified autonomous cyber defence) | Optimizer selects over full action space; SMT solver vetoes selected action post-decision | **Opposite ordering (teaches away).** Leaves forbidden variables in the formulation; delegates safety to post-solve rejection; generates no certificates, proofs, or invariance envelopes. |
| MiniZinc/FlatZinc, MathOptInterface | Solver-independent modeling languages compiled to multiple backends | Static problem descriptions; no runtime-state-driven domain transformation; no validity envelopes, feasibility witnesses, cryptographic certificates, or actuation capability verification. |
| OR-Tools `ValidateCpModel`; MIP presolve | Model validation and variable elimination prior to solve | Internal solver routine; emits no checkable certificate or proof; does not gate compilation or execution; unlinked to external infrastructure telemetry. |
| VeriPB / VIPR proof logging; certified presolve reductions | Independently checkable proof certificates in combinatorial optimization | Certifies solver output or search reductions **post-solve**; the invention certifies the **decision space and formulation pre-solve**, emits a proof-carrying translation, and gates physical actuation. |
| OPA signed bundles; GCP Binary Authorization; proof-carrying code | Cryptographic attestation of static code or policy artifacts | Attests static artifact origin and integrity; the invention attests mathematical properties (invariants and constructive feasibility) bound to a continuous state-invariance envelope and dynamic state epoch. |
| Intent-based networking change validation (US11539592), Batfish | Static pre-deployment configuration verification | Verifies static configuration files against network invariants; does not perform runtime optimization, decision-domain compilation, or cryptographic actuation gating. |

---

## 9. Questions the reviewer is asked to evaluate

1. Does runtime infrastructure state define a **security-decision invariance envelope** within which mathematical decisions are guaranteed invariant? (§3.1, Exp 14)
2. Does the system **structurally transform** the optimization decision domain by excising inadmissible variables rather than penalizing them? (§3.2, Exp 1, Exp 6)
3. Does fixed-point dependency closure converge to a **unique least fixed point** order-independently? (§3.3, test 54, Exp 7)
4. Is the SC-IR certified by a **constructive feasibility witness** before any solver formulation is generated? (§3.5, test 28, test 39)
5. Does the formulation compiler emit a **fidelity proof** verifiable by an **independent proof checker in polynomial time relative to proof size**? (§3.6, tests 47, 53, Exp 12, Exp 13)
6. Does actuation require **cryptographic certificate verification, envelope containment, and state-epoch validation**? (§3.8, test 49, Exp 15)
7. Does the device interface reject commands on **state-revision mismatch**? (§3.8, test 49, Exp 15)

---

## 10. Disclosures and simulation boundaries

- **Actuation is simulated:** Actuators construct correct protocol payloads (Modbus register writes, OPC-UA method invocations, OpenFlow flow-mod structures, and AWS IAM credential-rotation / session-revocation policies) but do not open live network sockets; command handlers return `status="simulated_success"`.
- **Device-side interface is a software simulator:** The device-side revision check is demonstrated using `SimulatedDeviceInterface`, an in-process stateful simulator verifying that expected revisions match simulated device state.
- **Proof checker tractability:** The proof checker verifies equivalence *under the emitted proof system in time polynomial in the size of the proof*. It does not decide general model equivalence.
- **Cryptographic mechanism:** Digital signatures use Ed25519 asymmetric cryptography (`cryptography` library) with an automated fallback to HMAC-SHA256 authenticated digests.
- **Search limits:** `PRIOR_ART_LAYER5_CORE.md` is an engineering literature search. Formal patentability searches across patent offices (USPTO, EPO, WIPO, IPO) remain required.

---

## 11. Reference numerals (FIG. 6 and FIG. 7)

| Numeral | Element | Numeral | Element |
|---|---|---|---|
| 500 | Layer 5 claimed core (trust boundary) | 610 | State fingerprinting & validity envelope ($F_t, E_t, n$) |
| 510 | Feasibility evaluation | 620 | Structural decision-domain transformer & closure ($R^*_t$) |
| 520 | Domain transformation | 630 | Constructive certification & signed certificate ($W_t, C_t$) |
| 530 | Fixed-point closure | 640 | Proof-carrying compiler & independent checker ($\Pi_b$) |
| 540 | Regeneration (topology, bounds) | 650 | Feasibility gate & conditional repair ($x^* \in F(\text{SC-IR})$) |
| 550 | Versioned SC-IR | 660 | Actuation capability verifier & device revision check |
| 560 | Pre-solve certifier | 670 | Closed-loop recertification loop |
| 570 | Safety certificate | 680 | Certified incremental lineage ($C_{t+1} \to H(C_t)$) |
| 580 | Certificate-bound gate | — | Solver backends (ILP, QUBO) (unclaimed) |
| 585 | Multi-target compiler | — | Actuation interfaces (Modbus, OPC-UA, etc.) |
| 590 | Semantic fidelity check | — | Measured telemetry & declared rules (inputs) |
| 595 | Actuation-boundary re-check | | |

*Prepared to fix the scope of the patent assessment for Invention Candidate v2. It states what is claimed, what is not, and how each limitation is supported; it does not assert a patentability outcome.*
