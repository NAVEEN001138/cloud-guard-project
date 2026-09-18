# FORM 2 — THE PATENTS ACT, 1970 (39 OF 1970) AND THE PATENTS RULES, 2003
## COMPLETE SPECIFICATION — TECHNICAL DRAFT V2
*(See Section 10 and Rule 13)*

> **Drafting status:** Faculty/patent-development working draft prepared from the frozen repository implementation and `CLOUD_GUARDIAN_MASTER_TECHNICAL_REFERENCE_V2.md`. This document is a technical drafting aid and should be reviewed by a qualified patent professional before filing.

---

## 1. TITLE OF THE INVENTION

**SYSTEM AND METHOD FOR RUNTIME SECURITY CONSTRAINT COMPILATION AND PRE-SOLVE SAFETY CERTIFICATION OF AUTOMATED INFRASTRUCTURE RESPONSE**

---

## 2. APPLICANT(S) / INVENTOR(S)

**Inventor:** Naveen Ravi  
**Nationality:** Indian  
**Address:** India  

> Replace or expand applicant/inventor/address particulars according to the actual filing entity before submission.

---

## 3. PREAMBLE TO THE DESCRIPTION

**THE FOLLOWING SPECIFICATION PARTICULARLY DESCRIBES THE INVENTION AND THE MANNER IN WHICH IT IS TO BE PERFORMED.**

---

# 4. FIELD OF THE INVENTION

The present invention relates generally to automated cybersecurity response, protection of heterogeneous computing and cyber-physical infrastructure, computer-implemented optimization, constraint compilation, and safety-controlled machine decision systems.

More particularly, the invention relates to a computer-implemented system and method that converts a live infrastructure security state into a **runtime-specific mathematical response problem** by changing the membership of an optimization decision domain, propagating the structural consequences of such changes through dependency relations, regenerating associated constraint topology and operational feasibility information, generating a solver-independent **Security Constraint Intermediate Representation (SC-IR)**, deterministically certifying the reconstructed representation prior to solver formulation, and permitting solver-specific compilation only when a certificate remains bound to the current representation and runtime state.

The invention may be used with classical optimization backends such as Integer Linear Programming (ILP), quantum-oriented formulations such as Quadratic Unconstrained Binary Optimization (QUBO), heuristic solvers, or other solver technologies without changing the upstream runtime security compilation mechanism.

---

# 5. BACKGROUND OF THE INVENTION

## 5.1 Heterogeneous infrastructure creates response-safety problems

Modern enterprise, cloud, Internet-of-Things (IoT), industrial, healthcare, and cyber-physical environments contain heterogeneous resources having different physical capabilities, availability requirements, operational risks, policy obligations, and permissible remediation actions.

A response that is technically appropriate for one asset can be unsafe or operationally unacceptable for another. For example, automated network isolation can be permissible for a general-purpose compute instance but can be undesirable for a programmable logic controller (PLC) or medical-device class whose continuous connectivity or control availability is required for an ongoing physical or safety process.

Accordingly, an autonomous response system cannot safely assume that every nominal response action remains selectable for every resource at every instant.

## 5.2 Limitation of fixed-domain optimization

A conventional automated response optimizer can represent a fixed set of candidate actions as decision variables and adjust objective coefficients or penalty values according to threat severity, business cost, or context.

For resource \(r_i\) and action \(a\), a conventional formulation may retain a binary variable:

\[
x_{i,a}\in\{0,1\}
\]

and discourage an unsafe action by assigning a large objective penalty.

However, such a variable remains part of the search space. If objective benefits, numerical scaling, penalty interactions, or formulation errors outweigh or bypass the intended penalty, the solver can still return a response containing an action that should never have been eligible for the resource.

The present invention addresses this architectural limitation by changing **decision-domain membership itself** before a solver-specific mathematical model is created.

## 5.3 Limitation of local-only pruning

Removing a decision variable can affect other parts of the mathematical problem. A removed action can invalidate prerequisite relations, conflict relations, cost maps, invariance equations, operational bounds, or other dependent structures.

Merely deleting a variable without reconstructing dependent mathematical structures can therefore leave stale references or an inconsistent problem.

## 5.4 Limitation of solver-coupled security logic

When physical, policy, business, and safety logic is embedded directly in a specific ILP, QUBO, rule engine, or solver API, it becomes difficult to establish that multiple backend formulations represent the same runtime security semantics.

The present invention therefore introduces a solver-independent intermediate representation from which multiple solver-specific formulations can be generated after certification.

## 5.5 Limitation of post-solve validation

A system that validates safety only after a solver has produced a response can allow malformed, stale, or inconsistent mathematical problems to reach the solver. The present invention introduces **pre-solve certification** and makes the certificate an enforced prerequisite to formulation generation.

## 5.6 Runtime change and recompilation overhead

Infrastructure state can change repeatedly. Reconstructing every mathematical component from zero for every localized state change can be unnecessary when only a small dependent subgraph is affected. The present invention therefore further provides an incremental recompilation embodiment that identifies an affected dependency subgraph, reuses unaffected structure, reconstructs affected components, emits a new versioned intermediate representation, and obtains a new certificate.

---

# 6. OBJECTS OF THE INVENTION

An object of the invention is to provide a runtime security compilation system in which live infrastructure state modifies the active membership of a response-optimization decision domain before solver execution.

Another object is to remove one or more inadmissible response-action variables and, **in response to such removal**, regenerate dependent mathematical structures associated with the remaining decision domain.

Another object is to provide deterministic fixed-point propagation of structural changes across one or more dependency relations.

Another object is to generate a solver-independent, versioned intermediate representation containing active decision domains, hard constraints, soft preferences, conflict relations, budget/resource information, provenance, topology information, and runtime-version information.

Another object is to provide deterministic pre-solve safety certification of the reconstructed intermediate representation, including verification that at least one joint feasible response assignment exists.

Another object is to bind a certificate to the exact intermediate representation and runtime-state version using one or more tamper-evident integrity identifiers.

Another object is to prevent an uncertified, stale, modified, or mismatched intermediate representation from being compiled into a solver-specific formulation.

Another object is to permit the same certified intermediate representation to be compiled into different solver backends while preserving the underlying certified semantics.

Another object is to provide selective incremental recompilation for localized runtime-state changes while preserving mathematical equivalence with a corresponding full recompilation for the evaluated state.

Another object is to admit learned structural response rules only after sandbox reconstruction and safety certification.

---

# 7. SUMMARY OF THE INVENTION

The invention provides a computer-implemented runtime security constraint compilation architecture.

A runtime-state acquisition stage receives or derives security and operational state associated with one or more infrastructure resources. The state can include resource type, available capabilities, threat severity, confidence, policy state, service-level requirements, business criticality, previous response state, and approved historical rules.

For each resource, a feasibility evaluator identifies candidate actions that are inadmissible under the current state. A decision-domain transformer removes corresponding action variables from the active decision domain.

The initial structural changes are supplied to a dependency engine. The dependency engine iteratively propagates structural consequences over dependency relations until a fixed point is reached. In an embodiment, prerequisite and mandate relations participate in transitive propagation, while conflict, resource-bound, and failsafe relations participate in associated regeneration or protection operations.

After closure, one or more dependent mathematical structures are regenerated. Such structures can include conflict relations, exactly-one invariance relations, active cost mappings, operational resource-feasibility values, active-variable counts, conflict counts, minimum achievable response cost, and budget-consistency information.

A solver-independent Security Constraint Intermediate Representation (SC-IR) is then generated. The SC-IR can include active and pruned variable domains, invariance constraints, conflict hyperedges, hard budget/resource constraints, objective terms, hard constraints, soft preferences, provenance, topology metadata, regenerated-bound metadata, dependency-closure metadata, and version information.

A pre-solve safety certifier verifies a plurality of deterministic safety properties. In one implemented embodiment, seven unique invariant categories are evaluated. The certifier further constructs a global feasibility witness by searching for at least one joint response assignment satisfying exactly-one, conflict, budget, and mandate requirements.

On successful certification, a certificate is generated and bound to the exact SC-IR and runtime state using version identifiers, a canonical digest of the SC-IR, a digest of dependency-closure metadata, and a certificate integrity identifier.

A formulation compiler verifies the certificate before producing a solver-specific mathematical model. If the certificate is absent, failed, stale, mismatched, or inconsistent with the current SC-IR, solver-specific compilation is rejected.

When the certificate is valid, the SC-IR can be translated into one or more backend formulations, including ILP or QUBO. A selected backend can then determine a response plan from the already-certified decision space.

In a further embodiment, a runtime delta is used to identify a dependency-connected affected subgraph. Unaffected mathematical components are reused, affected components are reconstructed, the representation version is incremented, and a fresh certificate is issued. The system can fall back to full recompilation when a mutation threshold or global change condition is reached.

---

# 8. BRIEF DESCRIPTION OF THE DRAWINGS

**FIG. 1** illustrates an overall system architecture comprising telemetry/preprocessing, threat detection, context and confidence processing, the runtime security constraint compiler, solver backends, utility/explanation functions, orchestration, and experience memory.

**FIG. 2** illustrates the principal runtime security compilation flow using reference numerals:

- **100** — Runtime State Input;
- **110** — Feasibility Evaluator;
- **120** — Structural Decision-Domain Transformer;
- **130** — Fixed-Point Dependency Closure Engine;
- **140** — Constraint Topology and Operational-Bound Regenerator;
- **150** — Versioned SC-IR Generator;
- **160** — Pre-Solve Safety Certifier;
- **170** — Certificate-Bound Compiler Gate;
- **180A** — Classical Solver Formulation Backend;
- **180B** — QUBO / Quantum-Oriented Formulation Backend;
- **190** — Response Plan / Actuation Interface.

**FIG. 3** illustrates incremental runtime recompilation comprising detection of state delta, dirty-node identification, breadth-first dependency propagation, clean-structure reuse, affected-structure recomputation, generation of a new SC-IR version, recertification, and optional fallback to full recompilation.

> Numerical benchmark values should be presented in the experimental section and not embedded as permanent figure labels unless figures are regenerated from the current evidence files.

---

# 9. DETAILED DESCRIPTION OF THE INVENTION

## 9.1 System overview

The system operates as an upstream safety and formulation layer between live security/infrastructure state and a mathematical response solver.

A representative flow is:

\[
S_t
\rightarrow F(S_t,A)
\rightarrow A'_t
\rightarrow R^*
\rightarrow E'_t
\rightarrow B'_t
\rightarrow SC\!\text{-}IR_t
\rightarrow C_t
\rightarrow M_t
\rightarrow x^*_t
\]

where \(M_t\) is a solver-specific model and \(x^*_t\) is a selected response plan.

The solver is intentionally downstream of the structural safety transformation.

---

## 9.2 Runtime state input — block 100

The runtime state can contain one or more of:

- infrastructure resource identifiers;
- resource types or workload classes;
- physical or software capability information;
- threat scores;
- confidence values;
- operational state;
- service-level or availability state;
- encoded policy/compliance state;
- current budget/resource availability;
- previous response plan;
- approved experience-memory rules;
- dependency relations between resources or actions.

In one implementation, these inputs are distributed across scenario dictionaries, context objects, confidence objects, previous-plan mappings, and learned-rule structures.

---

## 9.3 Feasibility evaluation — block 110

For a resource \(r_i\), the system begins from a candidate action set \(A_i\) and evaluates whether an action can remain in the active domain for the present state.

\[
A'_{t,i}=\{a\in A_i \mid F(S_{t,i},a)=1\}
\]

Examples of state conditions include:

- physical capability of the resource;
- confidence level of the detection;
- service-level availability requirement;
- encoded policy mandate;
- approved historical structural rule.

An implemented embodiment prohibits automated `isolate` for PLC-controller and medical-device resource classes and removes high-disruption actions when confidence is below a predetermined threshold.

The invention is not limited to those particular rules or thresholds.

---

## 9.4 Structural decision-domain transformation — block 120

The decision-domain transformer removes an inadmissible response action from the active decision domain.

For example:

\[
x_{r_i,a_f}\notin A'_{t,i}
\]

for a forbidden action \(a_f\).

The technical distinction from a soft-penalty system is that the downstream solver-specific model is generated without allocating the removed variable.

The removal can also create an auditable provenance record identifying the target resource, target action, origin, rule identifier, constraint type, and rationale.

---

## 9.5 Fixed-point dependency closure — block 130

Let \(R_0\) denote the initially removed action variables.

The closure engine iteratively computes:

\[
R_{k+1}=R_k\cup DependentConsequences(R_k)
\]

until:

\[
R_{k+1}=R_k
\]

The resulting fixed point is denoted \(R^*\).

The implemented relationship taxonomy includes:

- `REQUIRES`;
- `CONFLICTS_WITH`;
- `CONSUMES_RESOURCE`;
- `DERIVES_BOUND`;
- `MANDATES`;
- `PROTECTS_FAILSAFE`.

In the implemented embodiment, transitive removal propagation is principally applied to prerequisite/mandate semantics. Conflict relations, resource/bound relationships, and failsafe protections are handled through regeneration or protection stages associated with the closed domain.

The closure output can include:

- initial changes;
- total removed variables;
- removed edges;
- affected constraints;
- affected resources;
- regenerated bounds;
- propagation depth;
- iterations to fixed point;
- causal trace;
- closure status.

Because removal is monotonic over a finite candidate-variable universe, the closure reaches a fixed point.

---

## 9.6 Topology and operational-bound regeneration — block 140

Following structural pruning and closure, mathematical relations referencing removed variables are regenerated so that only active endpoints remain.

A regenerated conflict set can be expressed as:

\[
E'_t=\{e\in E\mid vars(e)\subseteq A'_t\}
\]

The implementation also reconstructs active cost mappings and operational feasibility metadata such as:

- minimum achievable response cost;
- effective runtime budget;
- budget-consistency indicator;
- active-variable count;
- active-conflict count.

The effective runtime budget in the implemented resolver is selected using an average-threat tier applied to the supplied base budget. The invention is not limited to the particular tier values used in the proof-of-concept.

The term “bound regeneration” therefore includes reconstruction of resource-feasibility and operational-bound information associated with the remaining decision domain and is not limited to one particular budget formula.

---

## 9.7 Versioned Security Constraint Intermediate Representation — block 150

The reconstructed mathematical state is encoded in a solver-independent SC-IR.

An embodiment of SC-IR stores:

- variable domains including admissible and pruned actions;
- exactly-one invariance constraints;
- conflict hyperedges;
- hard budget/resource constraints;
- active action cost map;
- objective terms;
- hard constraints;
- soft preferences;
- provenance records;
- topology metadata;
- regenerated-bound metadata;
- dependency-closure metadata;
- IR version;
- runtime-state version;
- parent IR version;
- canonical digest.

### Canonical digest

A deterministic canonical representation of the runtime SC-IR is hashed to create an integrity identifier sensitive to a semantic mutation of the certified runtime state.

### Semantic fingerprint

A separate semantic fingerprint is generated from mathematical structures while excluding incident identifiers, timestamps, and version metadata. The semantic fingerprint is usable for comparing mathematical equivalence between different compilation paths, including full and incremental recompilation.

---

## 9.8 Hard constraints and soft preferences

SC-IR separates non-relaxable safety rules from optimization preferences.

Hard constraints can include:

- structurally removed action variables;
- exactly-one action requirements;
- conflict mutual exclusion;
- mandatory action requirements;
- hard operational budget constraints.

Soft preferences can include:

- threat containment benefit;
- operational cost;
- downtime/business impact;
- switching cost;
- analyst effort or other preference coefficients.

Accordingly:

\[
\text{Safety defines the feasible search space; optimization ranks candidates inside that space.}
\]

---

## 9.9 Pre-solve safety certifier — block 160

Before solver-specific model generation, the SC-IR is passed to a deterministic pre-solve safety certifier.

In the implemented proof-of-concept, seven unique invariant categories are checked:

1. forbidden-action elimination;
2. non-empty feasible domains;
3. exactly-one invariance consistency with current active domains;
4. conflict consistency;
5. budget consistency and global feasibility;
6. encoded mandate/policy consistency;
7. provenance completeness for structural changes.

Historical benchmark data can expose eight check keys because one policy check is also provided through a backwards-compatible alias; the normalized architecture contains seven unique categories.

---

## 9.10 Global feasibility witness

The certifier performs deterministic backtracking over resource domains to identify at least one joint assignment satisfying:

\[
ExactlyOne \land ConflictFree \land BudgetFeasible \land MandatesSatisfied
\]

If no such assignment exists, certification fails.

A successful witness can be stored in the certificate as a mapping from resource identifiers to selected actions.

---

## 9.11 Tamper-evident safety certificate

Following successful certification, the system generates a certificate containing one or more of:

- certificate identifier;
- incident identifier;
- canonical IR digest;
- certification status;
- invariant results;
- IR version;
- runtime-state version;
- dependency-closure digest;
- feasibility witness;
- certificate integrity digest.

In an implemented embodiment, SHA-256 is used to generate integrity identifiers. SHA-256 is used as a standard tamper-evident integrity primitive and is not itself asserted as the inventive concept.

---

## 9.12 Certificate-bound compiler gate — block 170

A formulation compiler verifies the certificate before generating a solver model.

Compilation is permitted only if certificate and current SC-IR remain mutually consistent.

The implemented verification includes:

- certificate presence;
- `CERTIFIED` status;
- IR-version equality;
- runtime-state-version equality;
- recomputed canonical-digest equality;
- recomputed certificate-integrity equality;
- dependency-closure digest equality where present;
- successful invariant results.

If verification fails, compilation terminates without generating a solver-specific formulation.

---

## 9.13 Classical formulation backend — block 180A

For ILP compilation, binary variables are allocated only for actions present in the active SC-IR domain.

The compiler constructs an objective from active objective terms and adds hard mathematical constraints corresponding to invariance, conflict, and budget semantics.

A conventional ILP solver can then select an optimal response from the already-certified search space.

---

## 9.14 QUBO formulation backend — block 180B

For QUBO compilation, binary decision variables are likewise allocated only for active SC-IR actions.

Invariance and conflict semantics are encoded as quadratic penalties.

For a budget inequality:

\[
\sum_i c_i x_i \le B
\]

an implemented embodiment uses integer scaling and binary slack variables:

\[
\sum_i \hat c_i x_i+\sum_k w_k z_k=\hat B
\]

where \(\hat c_i\) and \(\hat B\) are scaled integer representations and \(z_k\) are binary slack variables representing unused budget.

The current proof-of-concept uses a scale value of 1000. This value is an embodiment parameter and should not limit the broader invention.

A dominating penalty multiplier is selected relative to objective magnitude so that an over-budget state is penalized more strongly than any objective improvement available by violating the budget constraint.

---

## 9.15 Backend semantic validator

A semantic validator can compare the certified SC-IR with one or more compiled backend models.

For a tractable number of decision variables, the validator can enumerate discrete assignments and determine whether each assignment is feasible under:

- the SC-IR hard semantics;
- an ILP formulation;
- a QUBO formulation including optimal slack assignment.

A Semantic Fidelity metric can be expressed as:

\[
SF=\frac{\text{number of assignments receiving the same feasibility classification}}{\text{number of evaluated assignments}}\times100
\]

The semantic validator is a verification embodiment and need not execute on every production response cycle.

---

## 9.16 Response selection and actuation interface — block 190

After successful backend optimization, the selected action vector is translated into a structured response plan.

The proof-of-concept repository includes a simulation executor returning structured `simulated_success` records rather than live physical device or production cloud actuation.

In other embodiments, the response plan can be transmitted through one or more infrastructure adapters, including network-control APIs, cloud identity interfaces, firewall interfaces, orchestration systems, industrial communication interfaces, or human-approval workflows.

The present technical evidence should be understood as demonstrating the runtime compilation, certification, and response-generation architecture in an integrated simulation environment.

---

# 10. INCREMENTAL RECOMPILATION EMBODIMENT

Let a certified representation \(IR_t\) correspond to state \(S_t\). When a new state \(S_{t+1}\) differs locally, a delta is determined:

\[
\Delta S=Diff(S_t,S_{t+1})
\]

The delta can identify changes in:

- assets;
- capabilities;
- threat state;
- policy state;
- resource state.

An affected set is expanded using breadth-first traversal along dependency edges.

The compiler partitions the graph into:

\[
G_{dirty}\quad\text{and}\quad G_{clean}
\]

Clean structures are reused where appropriate while dirty structures are recomputed.

The updated representation is generated as a new version and is recertified.

In the implemented embodiment, a full recompilation fallback is used when:

- the dirty-node ratio exceeds a configured threshold, presently 0.70;
- a global-policy-shift flag is present; or
- the previous representation contains no variable domains.

The threshold is an implementation parameter and is not limiting.

---

# 11. SAFETY-GATED EXPERIENCE MEMORY EMBODIMENT

A feedback subsystem can derive a candidate structural rule from prior incident outcomes.

A candidate learned rule does not directly modify the production action domain.

Instead, the candidate is subjected to safety checks and, where a baseline IR is available, is applied in a sandbox compilation path using the same dependency resolver and pre-solve certifier.

Rules that remove failsafe actions, attempt to reintroduce prohibited cyber-physical actions, create an empty resource domain, or otherwise fail certification are rejected.

Only an admitted rule can influence a subsequent runtime compilation.

In the current proof-of-concept, sandbox reconstruction uses simplified/default runtime context rather than a complete persisted replay of the original incident state. A further embodiment can persist a complete runtime snapshot for exact incident replay.

---

# 12. OPTIONAL THREAT-DETECTION EMBODIMENT

The runtime security compiler can receive threat state from any detector or analyst source.

In one implemented proof-of-concept, the threat detector uses federated-style training over non-IID partitions of Edge-IIoTset telemetry.

The detector is a supporting upstream component and is not required to define the central runtime constraint-compilation mechanism.

The proof-of-concept simulates multiple federated clients as isolated data partitions within a single application environment. Physically distributed edge devices represent a deployment embodiment.

---

# 13. TECHNICAL EFFECTS AND ADVANTAGES

The invention provides one or more of the following technical effects:

1. **Structural exclusion of inadmissible machine responses** before solver generation.
2. **Propagation of structural consequences** so that downstream constraint topology remains consistent with the active variable domain.
3. **Solver-independent security semantics** through a versioned intermediate representation.
4. **Prevention of stale or modified certified states** from silently reaching a solver-specific formulation.
5. **Detection of globally infeasible reconstructed response states** before solving through a feasibility witness search.
6. **Multi-backend formulation from one certified semantic representation**.
7. **Selective recompilation of localized runtime changes**, reducing avoidable reconstruction work.
8. **Safety-controlled adaptation of learned structural rules**.
9. **Machine-actionable output suitable for connection to infrastructure-control interfaces**, with present experimental validation performed through an integrated simulation executor.

---

# 14. EXPERIMENTAL VALIDATION OF THE PROOF-OF-CONCEPT

The following results describe the implemented repository embodiment and are examples of technical validation. They are not intended to limit the scope of the claims.

## 14.1 Federated detector scaling

Six detector scaling trials were recorded at:

\[
N=\{2{,}000,4{,}000,10{,}000,50{,}000,100{,}000,1{,}000{,}000\}
\]

At the 1,000,000-sample scale:

- training samples: **800,000**;
- holdout samples: **200,000**;
- initialization/load time: **11.82 s**;
- federated training time: **19.66 s**;
- recorded load + training time: **31.47 s**;
- accuracy: **98.65%**;
- precision: **95.94%**;
- recall: **97.06%**;
- F1-score: **96.50%**;
- ROC-AUC: **0.9948**;
- correct holdout classifications: **197,305 / 200,000**.

The benchmark did not independently record inference/test latency; accordingly, no separate exact inference-time claim is made.

Across all six detector scaling trials, the cumulative input volume was 1,166,000 samples. At each scale, a representative Layer-5 incident evaluation was also performed and produced zero forbidden-action violations in that evaluated scenario.

## 14.2 Dependency closure experiment

A multi-hop Web → API → DB dependency test recorded:

- one initially removed variable;
- two transitively affected entities;
- three total removed variables;
- propagation depth 2;
- three closure iterations;
- dangling references reduced from 1 to 0;
- stale conflicts reduced from 1 to 0;
- closure status `CONVERGED`.

## 14.3 Certificate-binding attack suite

Six cases were evaluated, including mutation, stale-state, swapped-certificate, failed-certificate, and post-certification budget modification cases.

Observed false accepts: **0 / 6 tested cases**.

## 14.4 Incremental compilation experiment

Thirty measured trials were performed per fleet size.

| Assets | Full median | Incremental median | Median reduction | Semantic fingerprint equivalent |
|---:|---:|---:|---:|:---:|
| 10 | 1.032 ms | 0.997 ms | 3.36% | Yes |
| 50 | 6.577 ms | 5.195 ms | 21.01% | Yes |
| 100 | 17.877 ms | 11.622 ms | 34.99% | Yes |
| 250 | 199.875 ms | 80.175 ms | **59.89%** | Yes |

## 14.5 Backend semantic-fidelity experiment

For one tractable benchmark instance:

- binary assignments evaluated: **1024**;
- SC-IR feasible assignments: **21**;
- ILP feasible assignments: **21**;
- QUBO semantically valid assignments: **21**;
- SC-IR vs ILP mismatches: **0**;
- SC-IR vs QUBO mismatches: **0**;
- ILP vs QUBO mismatches: **0**;
- measured ILP Semantic Fidelity: **100.0%**;
- measured QUBO Semantic Fidelity: **100.0%**.

These percentages apply to the enumerated assignment set of the evaluated benchmark instance and are not asserted as a universal numerical guarantee for every future instance.

## 14.6 Safety-gated learning experiment

Four candidate rules were evaluated:

- one safe rule admitted;
- three unsafe rules rejected;
- unsafe rules admitted: **0**.

## 14.7 Ablation evidence boundary

The repository also contains an ablation harness. The Full Architecture branch is executed, but several degraded-control outputs in variants B–D are presently configured/hard-coded summary values rather than independently executed degraded implementations.

Accordingly, those values are not relied upon herein as primary experimental patent evidence.

---

# 15. INDUSTRIAL APPLICABILITY

The invention can be applied to automated cybersecurity response in:

- enterprise networks;
- cloud infrastructure;
- industrial control systems;
- IoT and edge environments;
- healthcare computing environments;
- security orchestration systems;
- identity and access management systems;
- network security control planes;
- autonomous infrastructure-management platforms.

The architecture is particularly useful where response actions have different admissibility conditions across heterogeneous resources and where a solver must not be permitted to optimize over actions that violate current physical, operational, or policy state.

---

# 16. INVENTIVE-STEP / TECHNICAL-CONTRIBUTION POSITIONING

This section is included as an internal drafting aid and can be adapted or removed from the filed specification based on professional advice.

The contribution is not the use of a graph, ILP, QUBO, QAOA, SHA-256, or federated learning individually.

The central technical contribution is the ordered mechanism:

\[
\boxed{S_t\rightarrow A'_t\rightarrow R^*\rightarrow E'_t/B'_t\rightarrow SC\!\text{-}IR_t\rightarrow Certify\rightarrow Certificate\text{-}Bound\ Compile}
\]

The system operates before solver-specific formulation and uses live infrastructure semantics to determine which decision variables and dependent structures are allowed to exist.

This differs from a conventional presolve operation performed on an already-created optimization matrix, because the invention synthesizes the active mathematical problem from runtime security and infrastructure semantics before backend formulation.

Detailed prior-art assertions should be inserted only after independent source verification. Internal benchmark failure rates must not be attributed to external prior-art systems.

---

# 17. SECTION 3(k) TECHNICAL-EFFECT POSITIONING

This section is technical drafting support and not a legal conclusion.

The invention is framed as a computer-implemented infrastructure-control architecture producing a technical effect through:

- structural removal of unsafe executable response options;
- regeneration of machine-executable constraint topology based on live system state;
- pre-solve prevention of globally infeasible or structurally inconsistent response problems;
- integrity-bound control over whether a solver formulation can be generated;
- generation of structured network/access/credential or other infrastructure response instructions.

The present repository demonstrates these effects in simulation. Live Modbus, OPC-UA, cloud-IAM, firewall, switch, or other adapters are contemplated deployment embodiments and should not be represented as already demonstrated unless corresponding implementation evidence exists.

---

# 18. CLAIMS

## Independent System Claim

**1. A computer-implemented system for automated infrastructure response, comprising:**

(a) a runtime-state acquisition interface configured to receive or derive a runtime state associated with a plurality of infrastructure resources;

(b) a feasibility evaluator configured to determine, from the runtime state, that one or more candidate response actions are inadmissible for at least one of the infrastructure resources;

(c) a structural decision-domain transformer configured to remove one or more decision variables corresponding to the inadmissible candidate response actions from an active optimization decision domain;

(d) a dependency-closure engine configured, **in response to removal of the one or more decision variables**, to iteratively propagate structural consequences through one or more dependency relations until a fixed point is reached;

(e) a regeneration engine configured to regenerate one or more dependent constraint relations and operational or resource-feasibility bounds associated with a remaining decision domain after the fixed point is reached;

(f) an intermediate-representation generator configured to generate a solver-independent, versioned security constraint intermediate representation comprising at least the remaining decision domain and the regenerated constraint relations;

(g) a pre-solve safety certifier configured to verify a plurality of safety invariants of the security constraint intermediate representation and to determine a joint feasible response assignment satisfying a plurality of hard constraints;

(h) a certificate generator configured, responsive to successful verification, to generate a tamper-evident safety certificate bound to the security constraint intermediate representation and a corresponding runtime-state version;

(i) a certificate-bound formulation compiler configured to refuse generation of a solver-specific optimization formulation when the safety certificate is absent, failed, stale, or inconsistent with the security constraint intermediate representation, and to generate the solver-specific optimization formulation when certificate verification succeeds; and

(j) a response interface configured to obtain a response plan from a solver operating on the solver-specific optimization formulation.

---

## Dependent System Claims

**2.** The system as claimed in claim 1, wherein the dependency-closure engine propagates at least a prerequisite dependency or a mandate dependency and regenerates at least one conflict relation referencing a removed decision variable.

**3.** The system as claimed in claim 1, wherein the regeneration engine calculates at least one of a minimum achievable response cost, an effective runtime budget, a budget-consistency indicator, an active-variable count, or an active-conflict count for the remaining decision domain.

**4.** The system as claimed in claim 1, wherein the security constraint intermediate representation further comprises one or more of: an exactly-one invariance constraint, a conflict hyperedge, a hard budget constraint, an objective term, a hard constraint record, a soft preference record, a provenance record, topology metadata, dependency-closure metadata, an intermediate-representation version, a runtime-state version, or a parent-version identifier.

**5.** The system as claimed in claim 1, wherein the pre-solve safety certifier constructs the joint feasible response assignment using a deterministic search configured to simultaneously satisfy an exactly-one requirement, a conflict requirement, a resource-budget requirement, and a mandated-action requirement.

**6.** The system as claimed in claim 1, wherein the safety certificate comprises a canonical digest of the security constraint intermediate representation, a dependency-closure digest, an intermediate-representation version, a runtime-state version, invariant results, and a certificate integrity identifier.

**7.** The system as claimed in claim 1, further comprising an incremental compiler configured to receive a runtime-state delta, identify one or more dirty resources, expand an affected set through dependency relations, reuse one or more unaffected representation components, reconstruct one or more affected representation components, generate a new version of the security constraint intermediate representation, and obtain a new safety certificate.

**8.** The system as claimed in claim 7, wherein the incremental compiler falls back to full recompilation when an affected-resource ratio exceeds a configured mutation threshold or when a global-policy-change condition is detected.

**9.** The system as claimed in claim 1, wherein the certificate-bound formulation compiler is configured to generate at least an Integer Linear Programming formulation or a Quadratic Unconstrained Binary Optimization formulation from the same certified security constraint intermediate representation.

**10.** The system as claimed in claim 9, wherein the Quadratic Unconstrained Binary Optimization formulation represents a budget inequality by integer scaling of response costs and a budget value together with binary slack variables representing unused budget.

---

## Independent Method Claim

**11. A computer-implemented method for automated infrastructure response, the method comprising:**

receiving or deriving a runtime state associated with one or more infrastructure resources;

determining, from the runtime state, that at least one response action is inadmissible for at least one infrastructure resource;

removing a decision variable corresponding to the inadmissible response action from an active optimization decision domain;

**in response to removing the decision variable**, iteratively propagating one or more structural consequences through dependency relations until a fixed point is reached;

regenerating one or more dependent constraint relations and operational or resource-feasibility bounds for a remaining decision domain;

generating a solver-independent, versioned security constraint intermediate representation of the remaining decision domain and regenerated mathematical structure;

prior to generating a solver-specific formulation, verifying a plurality of safety invariants of the security constraint intermediate representation and determining at least one joint feasible response assignment satisfying a plurality of hard constraints;

generating, responsive to successful verification, a tamper-evident safety certificate bound to the security constraint intermediate representation and a corresponding runtime-state version;

verifying the safety certificate at a formulation compiler;

responsive to successful verification of the safety certificate, compiling the security constraint intermediate representation into a solver-specific optimization formulation; and

obtaining a response plan from a solver operating on the solver-specific optimization formulation.

---

## Dependent Method Claims

**12.** The method as claimed in claim 11, wherein determining that the response action is inadmissible comprises evaluating at least one of a physical capability, a detection confidence, an availability requirement, an encoded policy condition, a resource state, or an approved historical response rule.

**13.** The method as claimed in claim 11, wherein iteratively propagating the one or more structural consequences comprises removing a dependent action whose prerequisite action has been removed and repeating propagation until no additional dependent action is removed.

**14.** The method as claimed in claim 11, further comprising preserving or restoring at least one failsafe monitoring action when structural pruning would otherwise leave a resource without an admissible response action.

**15.** The method as claimed in claim 11, wherein generating the security constraint intermediate representation comprises generating provenance information that identifies a resource, an affected response action, a rule origin, a rule identifier, and a rationale associated with a structural change.

**16.** The method as claimed in claim 11, wherein verifying the safety certificate comprises recomputing a canonical digest of the current security constraint intermediate representation and rejecting compilation when the recomputed canonical digest differs from a certified digest.

**17.** The method as claimed in claim 11, further comprising computing a semantic fingerprint of the mathematical structure of the security constraint intermediate representation while excluding runtime metadata, and comparing the semantic fingerprint with a semantic fingerprint of a corresponding independently compiled representation.

**18.** The method as claimed in claim 11, further comprising receiving a runtime-state delta, identifying an affected dependency subgraph by breadth-first traversal from one or more changed resources, reusing mathematical components associated with an unaffected subgraph, reconstructing mathematical components associated with the affected subgraph, and generating a new version of the security constraint intermediate representation.

**19.** The method as claimed in claim 11, further comprising receiving a candidate learned structural rule, applying the candidate learned structural rule in a sandbox compilation path, certifying a sandbox security constraint intermediate representation, and admitting the candidate learned structural rule for subsequent use only when the sandbox security constraint intermediate representation satisfies the safety certification.

**20.** The method as claimed in claim 11, wherein the response plan is output to at least one of a simulation executor, a network-control interface, a cloud-control interface, an identity-management interface, an industrial-control interface, or a human-approval workflow.

---

## Independent Computer-Readable-Medium Claim

**21. A non-transitory computer-readable medium storing instructions which, when executed by one or more processors, cause the one or more processors to:**

receive or derive a runtime infrastructure state;

remove, based on the runtime infrastructure state, one or more inadmissible response-action variables from an active optimization decision domain;

propagate structural consequences of the removal through dependency relations until a fixed point is reached;

regenerate one or more dependent constraint relations and operational or resource-feasibility bounds associated with a remaining decision domain;

generate a solver-independent, versioned security constraint intermediate representation;

perform pre-solve safety certification of the security constraint intermediate representation and determine a joint feasible response assignment;

generate a tamper-evident safety certificate bound to the security constraint intermediate representation and a runtime-state version;

prevent generation of a solver-specific optimization formulation unless the safety certificate is valid for the current security constraint intermediate representation; and

responsive to successful certificate verification, generate the solver-specific optimization formulation for determination of an infrastructure response plan.

---

## Dependent Computer-Readable-Medium Claims

**22.** The non-transitory computer-readable medium as claimed in claim 21, wherein the instructions further cause the one or more processors to maintain a canonical integrity digest and a mathematical semantic fingerprint having different included metadata.

**23.** The non-transitory computer-readable medium as claimed in claim 21, wherein the instructions further cause the one or more processors to generate a QUBO representation having binary slack variables for a hard resource-budget inequality.

**24.** The non-transitory computer-readable medium as claimed in claim 21, wherein the instructions further cause the one or more processors to selectively recompile an affected dependency subgraph in response to a runtime-state delta and issue a new safety certificate for an updated intermediate-representation version.

**25.** The non-transitory computer-readable medium as claimed in claim 21, wherein the instructions further cause the one or more processors to evaluate a learned structural rule in a sandbox representation and reject the learned structural rule when the sandbox representation fails a safety invariant or fails to admit a joint feasible response assignment.

---

# 19. ABSTRACT

A computer-implemented system and method are disclosed for runtime security constraint compilation and pre-solve safety certification of automated infrastructure response. Live infrastructure state is used to remove inadmissible response-action variables from an active optimization decision domain. In response to such removal, dependency consequences are iteratively propagated to a fixed point, and dependent constraint topology and operational feasibility information are regenerated. A versioned, solver-independent Security Constraint Intermediate Representation (SC-IR) is generated from the reconstructed state. Prior to solver formulation, a safety certifier verifies deterministic invariants and determines a joint feasible response assignment. A tamper-evident certificate is bound to the SC-IR and runtime-state version. A formulation compiler rejects absent, failed, stale, or mismatched certificates and otherwise generates a solver-specific formulation, including an ILP or QUBO formulation. Incremental affected-subgraph recompilation and safety-gated learned-rule admission are also disclosed.

---

# 20. INTERNAL FILING CHECKLIST — REMOVE OR ADAPT BEFORE FORMAL FILING

- Verify final applicant/inventor legal names and addresses.
- Verify all IPC/CPC classifications separately; do not copy classifications from an older draft without confirmation.
- Perform a fresh cited prior-art search and insert only source-verified distinctions.
- Ensure Figures 1–3 use the same reference numerals as the specification.
- Ensure the final drawing set contains no volatile benchmark text unless intentionally included.
- Decide with patent counsel whether the Section 3(k) positioning and experimental sections should remain in the complete specification or be shortened.
- Verify antecedent basis and dependency of every claim after legal editing.
- Confirm whether claim count/fee strategy requires reducing dependent claims.
- Do not convert measured benchmark percentages into universal guarantees.
- Preserve the current implementation boundary: orchestration is demonstrated through simulation; live infrastructure adapters are deployment embodiments.

---

**END OF TECHNICAL PATENT DRAFT V2**
