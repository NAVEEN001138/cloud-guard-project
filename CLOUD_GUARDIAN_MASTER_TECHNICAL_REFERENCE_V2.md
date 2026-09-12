# CLOUD GUARDIAN — MASTER TECHNICAL REFERENCE V2

**Document status:** Corrected source-of-truth technical dossier for faculty review, IDF preparation, patent drafting, viva preparation, figures, and experimental reporting.  
**Repository basis:** `NAVEEN001138/cloud-guard-project`, `main` branch, frozen technical architecture after the Layer-5 hardening commits.  
**Patent-positioning note:** This document is a technical and drafting reference, not a legal opinion on patentability or grant outcome.

---

## 1. Final Invention Title

**System and Method for Runtime Security Constraint Compilation and Pre-Solve Safety Certification of Automated Infrastructure Response**

This title should be used consistently across the patent draft, IDF, faculty presentation, diagrams, and supporting documentation.

---

## 2. One-Sentence Invention Statement

Cloud Guardian converts live infrastructure state into an incident-specific mathematical response problem by **removing inadmissible decision variables before optimization, propagating the consequences through dependency closure and regenerated constraints/bounds, generating a versioned solver-independent Security Constraint Intermediate Representation (SC-IR), certifying that reconstructed state, and only then allowing solver-specific compilation**.

The core sequence is:

\[
S_t \rightarrow A'_t \rightarrow R^* \rightarrow E'_t \rightarrow B'_t \rightarrow SC\!\text{-}IR_t \rightarrow C_t \rightarrow \text{Compile} \rightarrow \text{Solve}
\]

where:

- \(S_t\) = live runtime infrastructure state,
- \(A'_t\) = admissible action domain after structural pruning,
- \(R^*\) = fixed-point dependency closure,
- \(E'_t\) = regenerated active conflict/dependency topology,
- \(B'_t\) = regenerated operational/budget-consistency metadata,
- \(SC\!\text{-}IR_t\) = solver-independent security constraint intermediate representation,
- \(C_t\) = pre-solve safety certificate bound to the exact IR/state version.

---

## 3. What the Project Is — and What It Is Not

Cloud Guardian is best described as a **validated proof-of-concept runtime security constraint compiler and autonomous response decision architecture** for heterogeneous cloud, enterprise, and cyber-physical assets.

It is **not** primarily a “Federated Learning + QAOA” invention. Federated learning, ILP, QUBO, QAOA, SHA-256, graph structures, and standard optimization techniques are supporting technologies or execution backends.

The patent core is the ordered runtime transformation:

\[
\boxed{\text{Runtime State} \rightarrow \text{Structural Domain Change} \rightarrow \text{Dependency Closure} \rightarrow \text{Regenerated Mathematical State} \rightarrow \text{SC-IR} \rightarrow \text{Certification} \rightarrow \text{Certificate-Gated Compilation}}
\]

---

## 4. Faculty Feedback That Must Drive the Documentation

The faculty review should be treated as a design constraint for the patent narrative.

### 4.1 Main patentability concern

The principal concern is **inventive step / non-obviousness**, not merely whether individual elements are new.

### 4.2 Strongest technical differentiators

The strongest aspects of the implementation are:

1. runtime removal of inadmissible action variables from the active decision domain;
2. propagation of removal consequences through dependency structure;
3. regeneration of conflict topology and operational feasibility metadata after pruning;
4. generation of a solver-independent SC-IR from the reconstructed problem;
5. deterministic pre-solve safety certification with a global feasibility witness;
6. certificate-bound compilation that rejects stale, mutated, or uncertified IR states;
7. incremental affected-subgraph recompilation with semantic-fingerprint equivalence checks.

### 4.3 Technologies that must not be claimed as individually novel

Do **not** claim the following by themselves as the invention:

- Federated Learning / FedAvg,
- QAOA,
- QUBO,
- ILP,
- SHA-256,
- dependency graphs / DAGs,
- hard and soft constraints,
- objective switching penalties,
- context-aware optimization,
- generic presolve variable elimination.

The inventive-step argument must focus on the **ordered mechanism and the technical interaction between these stages**, not on ownership of standard algorithms or libraries.

---

## 5. The Core Technical Problem

In a conventional response optimizer, every candidate response can remain represented as a variable, while undesirable actions are merely discouraged with penalties or weights.

For a critical asset, that can leave a dangerous action mathematically selectable if its containment benefit outweighs its penalty.

Cloud Guardian changes the problem before optimization.

For resource \(i\), instead of using a static action set \(A_i\), the runtime compiler constructs:

\[
A'_{t,i}=\{a \in A_i \mid F(S_{t,i},a)=1\}
\]

An inadmissible action is not merely given a bad score; the corresponding decision variable is structurally absent from the active compiled domain.

### Example: PLC

If a PLC controller is not permitted to undergo automated network isolation, then:

\[
x_{\text{PLC,isolate}} \notin A'_{t,\text{PLC}}
\]

This is fundamentally different from:

\[
Penalty(x_{\text{PLC,isolate}})=1000
\]

because a solver cannot choose a variable that does not exist in the certified active model.

---

## 6. Two Different Pipelines Must Be Distinguished

The repository now contains two categories of execution paths.

### 6.1 Operational pipeline

The normal `run_pipeline()` path performs:

**Scenario → Threat Detection → Context → Confidence → Optional Privacy Payload → Adaptive Constraint Generation / SC-IR / Certification → Utility Computation → Solver Evaluation → Explanation**

Important implementation detail: subsystem numbering does not exactly equal call order. `run_pipeline()` computes Layer-7 utilities before it calls the Layer-6 solvers. The layer number is therefore a subsystem identity, not a strict chronological numbering rule.

### 6.2 Strengthening / verification / update paths

These are separate advanced mechanisms and are not automatically executed for every `run_pipeline()` call:

- incremental recompilation from \(IR_t + \Delta S\),
- exhaustive backend semantic validation on tractable instances,
- sandboxed experience-rule admission,
- patent-strengthening experiments and attack suites.

This distinction must remain explicit in all patent and faculty documentation.

---

## 7. Current Operational `run_pipeline()` Flow

Source: `pipeline.py`.

### 7.1 Input

`run_pipeline()` receives a prepared incident scenario plus runtime options such as budget, previous plan, privacy mode, solver settings, and role.

### 7.2 Operational sequence

1. **Layer 2 — Threat Detection**  
   `ThreatDetector.score_scenario()` produces threat scores per resource.

2. **Layer 3 — Context Aggregation**  
   Business criticality, SLA, resource type, and compliance metadata are aggregated.

3. **Layer 4 — Confidence Evaluation**  
   Detection/sensor/evidence confidence is converted into an overall confidence and action eligibility.

4. **Layer 5 — Optional Privacy Payload**  
   A discretized privacy-preserving payload can be generated for reporting/privacy analysis.

   **Important:** in the current PoC, `generate_adaptive_constraints()` still receives the structured contexts, confidences, and threat scores directly. Therefore the privacy payload is a parallel supporting output, not the sole input to the constraint compiler.

5. **Layer 5 — Adaptive Constraint Generation**  
   Runtime context, confidence, policy, previous plan, and approved learned rules are converted into a `SecurityConstraintIR` and safety certificate.

6. **Layer 7 — Utility Computation**  
   Multi-attribute action utilities are calculated.

7. **Layer 6 — Solvers**  
   Greedy, budgeted greedy, and ILP are evaluated; QUBO/QAOA is optional.

8. **Layer 8 — Explainability**  
   The ILP result is used as the primary explanation plan in the current operational flow.

9. **Return**  
   `PipelineResult` contains threat scores, contexts, confidences, constraints, SC-IR, certificate, solver results, privacy payload, and explanation report.

When `pipeline.py` is executed directly as a demonstration script, the selected ILP plan is passed to the Layer-8 simulated executor.

---

## 8. Layer-by-Layer Role Summary

| Layer | Current role | Patent relevance |
|---|---|---|
| Layer 0 | Preprocessing: numeric coercion, median imputation, IQR clipping, log compression, standardization, variance filtering | Supporting |
| Layer 1 | Edge-IIoTset loading, feature extraction, train/test partitioning, federated client partitions | Supporting |
| Layer 2 | Federated/local threat detection and threat scores | Supporting input |
| Layer 3 | Asset/business/compliance/SLA context | Important runtime input |
| Layer 4 | Detection confidence and high-disruption action gating | Important runtime input |
| **Layer 5** | **Runtime security constraint compilation, SC-IR, closure, certification, compiler gate, incremental compiler, semantic validator** | **Patent core** |
| Layer 6 | Greedy, ILP, QUBO/QAOA solver backends | Backend implementation |
| Layer 7 | Response utility model | Supporting objective logic |
| Layer 8 | Explanation and simulated orchestration | Technical output / PoC execution |
| Layer 9 | Experience memory and sandboxed rule admission | Secondary protected extension |

---

## 9. Runtime State Model

A useful conceptual state model is:

\[
S_t = \langle R,\; s_t,\; c_t,\; P_t,\; O_t,\; x_{t-1},\; L_t \rangle
\]

where:

- \(R\): monitored resources and resource types,
- \(s_t\): threat scores,
- \(c_t\): confidence values,
- \(P_t\): encoded policy/compliance state,
- \(O_t\): operational/business/SLA state,
- \(x_{t-1}\): previous response plan,
- \(L_t\): approved learned experience rules.

This is a conceptual documentation model; the implementation stores these elements across scenario dictionaries, context objects, confidence objects, previous-plan mappings, and learned-rule structures rather than in a single `RuntimeState` class.

---

## 10. Structural Action-Domain Transformation

Source: `layer5_constraints/dependency_graph.py` and `adaptive_constraints.py`.

The compiler begins from candidate actions and identifies actions that are not admissible for the current runtime state.

### 10.1 Physical capability

Resource type determines which actions can exist.

For PLC and medical-device profiles, automated `isolate` is removed.

### 10.2 Confidence gating

When overall confidence is below 0.50, high-disruption actions such as `isolate` and `disable_user` are removed.

### 10.3 HIPAA-encoded policy path implemented in the repository

If HIPAA context applies and threat score is greater than 0.60, the current dependency-graph implementation chooses a mandated strong-containment action:

1. `isolate`, if still available;
2. otherwise `rotate_credentials`;
3. otherwise `monitor`.

Other actions in that resource domain are removed so the mandated action remains.

This is an implementation-specific encoded policy rule. The patent should claim **runtime policy-to-constraint compilation generically** and use HIPAA only as an embodiment/example, not claim legal interpretation itself as the invention.

### 10.4 SLA critical availability rule

If SLA priority is `CRITICAL` and threat is below 0.40, `isolate` is removed.

### 10.5 Experience-memory rules

Approved learned rules can restrict actions for matching resource types or resource IDs.

### 10.6 Important correction

The current Layer-5 dependency resolver does **not** implement the PCI-DSS-specific rule that older documentation described. Any PCI-DSS-specific automatic mandate must therefore be omitted from the source-of-truth description unless corresponding code is added later.

---

## 11. Fixed-Point Dependency Closure

Source: `ConstraintDependencyGraph.compute_fixed_point_closure()`.

Initial pruning can invalidate dependent actions. Therefore the compiler computes a monotone closure over removed decision variables.

Let \(R_0\) be the initially removed action-variable set:

\[
R_0 = \{(r_i,a) \mid a \text{ is initially inadmissible}\}
\]

Then iteratively:

\[
R_{k+1}=R_k \cup DependentConsequences(R_k)
\]

until:

\[
R_{k+1}=R_k
\]

The final state is \(R^*\).

### 11.1 What propagates directly

The iterative transitive-removal semantics are strongest for prerequisite/mandate relationships, especially `REQUIRES` and `MANDATES`.

### 11.2 What is regenerated after/during closure

The architecture also carries typed relations for:

- `CONFLICTS_WITH`,
- `CONSUMES_RESOURCE`,
- `DERIVES_BOUND`,
- `PROTECTS_FAILSAFE`.

The correct faculty/patent wording is:

> **Fixed-point propagation over prerequisite/mandate dependencies followed by typed conflict, resource-bound, and failsafe regeneration/protection.**

Do not claim that all six relation types have identical transitive-removal semantics.

### 11.3 Termination

The closure is monotone over a finite action-variable universe, so repeatedly adding removed variables reaches a fixed point. The implementation also tracks closure iterations, propagation depth, affected resources, removed conflicts, regenerated bounds, and a causal trace.

---

## 12. Topology Regeneration

When a decision variable disappears, any conflict relation that references the removed endpoint must not remain in the compiled model.

Conceptually:

\[
E'_t = \{e \in E \mid vars(e) \subseteq A'_t\}
\]

The implementation removes stale conflict relationships whose variables are no longer active and records affected constraints/resources in closure metadata.

This is one of the strongest technical effects to emphasize to faculty: **the system reconstructs the optimization topology instead of merely changing coefficients**.

---

## 13. Budget and Operational-Bound Regeneration — Exact Current Behavior

This section must be documented carefully because older drafts overstated how the budget ceiling itself is derived.

### 13.1 Threat-tier budget multiplier

Inside `ConstraintDependencyGraph.resolve()`, the effective budget is derived from the supplied base budget and average threat:

\[
\bar{s}>0.70 \Rightarrow m_B=1.3
\]

\[
0.40<\bar{s}\le0.70 \Rightarrow m_B=1.0
\]

\[
\bar{s}\le0.40 \Rightarrow m_B=0.8
\]

\[
B_{effective}=B_{base}\cdot m_B
\]

`adaptive_constraints.py` also applies threat-based budget scaling before calling the dependency graph. Therefore documentation should avoid inventing a single closed-form budget formula that is not present in code.

### 13.2 What is genuinely regenerated from the active domain

After pruning/closure, the compiler computes active-domain feasibility metadata including:

- `min_possible_cost`,
- `effective_budget`,
- `budget_consistent`,
- `active_variable_count`,
- `active_conflict_count`.

For the incremental compiler, the same type of regenerated-bound metadata is explicitly rebuilt from the updated active domains.

### 13.3 Patent wording

Prefer:

> “regenerating operational resource-bound metadata and budget-feasibility bounds associated with the remaining decision domain”

rather than claiming that action pruning itself directly computes a wholly new budget ceiling.

---

## 14. Security Constraint Intermediate Representation (SC-IR)

Source: `layer5_constraints/constraint_ir.py`.

SC-IR is the solver-independent representation produced after runtime structural reconstruction.

It includes:

- incident identifier,
- variable domains (admissible and pruned actions),
- exactly-one invariance constraints,
- conflict hyperedges,
- hard budget constraint and cost map,
- objective terms,
- provenance records,
- hard constraints,
- soft constraints,
- topology metadata,
- `ir_version`,
- `runtime_state_version`,
- `parent_ir_version`,
- canonical digest,
- regenerated bounds,
- dependency-closure metadata.

The compiler analogy is:

\[
\text{Runtime Security State} \rightarrow \text{SC-IR} \rightarrow \{\text{ILP},\text{QUBO}\}
\]

SC-IR is important because solver backends no longer need to re-interpret business, physical, or policy meaning. They receive a certified mathematical state.

---

## 15. Hard Constraints vs Soft Preferences

Cloud Guardian separates **what is allowed** from **what is preferred**.

### Hard constraints

Cannot be traded away for better objective value.

Examples:

- physical action removal,
- exactly-one action selection,
- conflict mutual exclusion,
- mandatory policy action,
- hard budget constraint.

### Soft preferences

Influence ranking among safe options.

Examples:

- containment effectiveness,
- operational cost,
- switching penalty,
- business impact.

The central explanation is:

\[
\boxed{\text{Safety determines what may exist; optimization chooses the best option among the safe domain.}}
\]

---

## 16. Provenance and Causal Trace

Every structural pruning/mandate can be associated with an `IRProvenanceRecord`, including:

- target resource,
- target action,
- constraint type,
- origin,
- rule identifier,
- rationale.

The closure engine additionally records causal propagation information.

This provenance is important for:

- auditability,
- explanation,
- certificate verification,
- patent support for deterministic transformation rather than opaque model behavior.

---

## 17. Canonical Digest vs Semantic Fingerprint

These two identifiers serve different purposes.

### 17.1 Canonical digest

`compute_canonical_digest()` hashes a deterministic canonical summary containing, among other things:

- incident and version information,
- admissible/pruned domains,
- invariance definitions,
- conflicts,
- budget and cost map,
- objective coefficients,
- full hard constraints,
- soft constraints,
- provenance,
- closure digest,
- topology fingerprint,
- regenerated bounds.

Purpose: **tamper-evident integrity binding of a particular runtime IR state**.

### 17.2 Semantic fingerprint

`semantic_fingerprint()` hashes the mathematical optimization structure while intentionally excluding runtime metadata such as incident ID, versions, and timestamps.

It includes:

- variable domains,
- invariance definitions,
- conflict relations,
- budget ceiling,
- cost map,
- objective coefficients,
- hard/soft constraints,
- selected regenerated-bound values.

Purpose: **compare mathematical equivalence between independently generated formulations**, particularly full vs incremental recompilation.

This is stronger and more precise than describing the fingerprint as only a tuple of counts or density values.

---

## 18. Pre-Solve Safety Certification

Source: `PreSolveSafetyCertifier`.

The current implementation contains **7 unique invariant checks**.

1. **Forbidden-action elimination**  
   No known forbidden action remains in the active domain; PLC/medical-device domains cannot contain `isolate`.

2. **Non-empty feasible domain**  
   Every resource has at least one admissible action.

3. **Exactly-one invariance consistency**  
   Invariance actions must exactly equal the current admissible domain and target value must equal 1.

4. **Conflict consistency**  
   Rejects self-contradictory self-conflicts.

5. **Budget and global feasibility**  
   A deterministic feasibility witness must exist and minimum feasible cost must not exceed budget.

6. **Encoded policy-rule consistency**  
   Mandated actions recorded in provenance must remain present in the target domain.

7. **Provenance completeness**  
   Pruned actions must have provenance records.

### Legacy 8/8 clarification

Historical scaling JSON reports `8/8` because check #6 was exposed both as:

- `6_encoded_policy_rule_consistency`, and
- the backwards-compatible alias `6_statutory_policy_consistency`.

The current normalized architecture therefore has **7 unique invariants**, accessible through `certificate.get_unique_checks()`.

Do not edit the old JSON; explain the historical alias.

---

## 19. Global Feasibility Witness

`find_feasibility_witness()` performs deterministic backtracking to construct at least one joint assignment satisfying:

\[
ExactlyOne \land Conflicts \land Budget \land Mandates
\]

The witness is a mapping such as:

```text
resource_A -> monitor
resource_B -> rotate_credentials
resource_C -> block_ip
```

If no witness exists, certification fails.

This is stronger than checking each resource independently.

---

## 20. Tamper-Evident Certificate Binding

A certified IR is associated with:

- certificate ID,
- IR canonical digest,
- IR version,
- runtime-state version,
- certification status,
- verification checks,
- closure digest,
- certificate integrity digest,
- feasibility witness.

The implementation uses SHA-256 as an **integrity digest**, not an asymmetric digital signature.

Use the phrase:

> **tamper-evident pre-solve safety certificate with a cryptographic integrity identifier**

Do not call SHA-256 itself a digital signature, authentication mechanism, or “unbreakable” link.

---

## 21. Certificate-Gated Compilation

Source: `FormulationCompiler.verify_binding()`.

The architecture enforces:

\[
Compile(IR,C)=Model \quad \text{iff} \quad VerifyBinding(IR,C)=true
\]

The gate rejects:

- missing certificate,
- non-`CERTIFIED` status,
- IR-version mismatch,
- runtime-state-version mismatch,
- canonical-digest mismatch,
- certificate-integrity mismatch,
- closure-digest mismatch,
- failed invariant checks.

The key faculty sentence is:

> **Certification is not advisory; it is an enforced compiler gate.**

---

## 22. ILP and QUBO Backends

The same certified SC-IR can be translated into different solver-specific representations.

### ILP

The ILP compiler creates binary variables only for admissible actions, adds objective terms, exactly-one constraints, conflict constraints, and budget inequality constraints.

### QUBO

The QUBO compiler creates binary variables only for admissible actions and expands hard constraints into dominating penalty terms.

### Why QAOA is not the invention

QAOA/QUBO is one backend. The invention exists before the backend is selected.

This strengthens the patent position because the central mechanism is backend-independent.

---

## 23. QUBO Budget Inequality Encoding

The current compiler uses an integer-scaled binary slack representation.

Given:

\[
\sum_i c_i x_i \le B
\]

it uses scale:

\[
S=1000
\]

and creates integer-scaled cost/budget values together with binary slack variables so an under-budget state can satisfy an equality form without penalty.

Conceptually:

\[
\sum_i \hat{c_i}x_i + \sum_k w_k z_k = \hat{B}
\]

This avoids the earlier incorrect direct penalty:

\[
(\sum_i c_i x_i-B)^2
\]

which would penalize valid under-budget solutions.

Correct wording:

> **exact with respect to the repository's 0.001 integer scaling used for supported action costs**, rather than exact for arbitrary real-valued costs.

---

## 24. Semantic Backend Validator

Source: `SemanticValidator.validate_backend_semantics()`.

For tractable instances, the validator enumerates binary assignments and compares feasibility under:

- certified SC-IR,
- generated PuLP ILP constraints,
- actual generated QUBO polynomial with reconstructed optimal slack values.

Semantic Fidelity is:

\[
SF=\frac{\text{assignments classified identically by backend and SC-IR}}{\text{total evaluated assignments}}\times100
\]

### Experiment 10 — recorded result

- assignments evaluated: **1024**,
- SC-IR feasible states: **21**,
- ILP feasible states: **21**,
- QUBO semantically valid states: **21**,
- IR–ILP mismatches: **0**,
- IR–QUBO mismatches: **0**,
- ILP–QUBO mismatches: **0**,
- measured ILP SF: **100.0%**,
- measured QUBO SF: **100.0%**.

Correct claim:

> **100% Semantic Fidelity across the 1024 enumerated assignments in the evaluated benchmark instance.**

Do not convert this into a universal proof for every possible future problem instance.

---

## 25. Incremental / Delta Constraint Compiler

Source: `IncrementalConstraintCompiler.compile_delta()`.

For a runtime change:

\[
\Delta S = Diff(S_t,S_{t+1})
\]

primary dirty nodes are identified from:

- changed assets,
- changed capabilities,
- changed threat state,
- changed policy state,
- changed resource state.

A queue-based BFS propagates the affected set along explicit dependency edges.

The compiler then:

- reuses clean variable domains/invariance/provenance where safe,
- recomputes dirty domains,
- rebuilds dirty and cross-resource conflicts,
- recomputes objective terms and cost map,
- rebuilds budget and operational-bound metadata,
- generates updated topology metadata,
- increments IR/state versioning,
- computes a new canonical digest,
- issues a fresh safety certificate.

### Fallback conditions actually implemented

Default threshold:

\[
max\_subgraph\_mutation\_ratio=0.70
\]

Full recompilation occurs when:

- dirty-node ratio exceeds 70%, or
- `global_policy_shift` is true, or
- previous IR contains no variable domains.

Do not document unsupported fallback triggers unless code later adds them.

---

## 26. Incremental Compilation Evidence

Source: `patent_strengthening_results.json`, Experiment 9.

Each fleet size uses **30 measured trials** and reports median, standard deviation, and p95.

| Assets | Full median | Incremental median | Reduction | Semantic fingerprint equivalent |
|---:|---:|---:|---:|:---:|
| 10 | 1.032 ms | 0.997 ms | 3.36% | Yes |
| 50 | 6.577 ms | 5.195 ms | 21.01% | Yes |
| 100 | 17.877 ms | 11.622 ms | 34.99% | Yes |
| 250 | 199.875 ms | 80.175 ms | **59.89%** | Yes |

The most defensible statement is:

> **In the recorded 30-run Windows benchmark, the 250-asset case showed a 59.89% median compilation-latency reduction while preserving semantic-fingerprint equivalence with full recompilation.**

---

## 27. Certificate Attack Evidence

Source: `patent_strengthening_results.json`, Experiment 8.

Six attack/consistency cases were tested:

- unchanged IR + valid certificate → accepted,
- mutated active domain → rejected,
- stale runtime-state version → rejected,
- swapped certificate → rejected,
- failed safety certificate → rejected,
- modified budget after certification → rejected.

Recorded false accepts: **0**.

Correct wording:

> **0 false accepts were observed across the six tested certificate-binding attack cases.**

Do not generalize this into a proof against every possible attack.

---

## 28. Dependency-Closure Evidence

Source: `patent_strengthening_results.json`, Experiment 7.

Scenario: 3-tier Web → API → DB multi-hop dependency chain.

Recorded comparison:

- initially removed variables: **1**,
- fixed-point transitively affected entities: **2**,
- total removed variables: **3**,
- propagation depth: **2**,
- closure iterations: **3**,
- dangling references: **1 → 0**,
- stale conflicts: **1 → 0**,
- closure status: **CONVERGED**.

This is direct evidence for the value of dependency closure over local-only pruning in the tested chain.

---

## 29. Safety-Gated Experience Memory

Source: `FeedbackLearner.admit_candidate_rule_sandboxed()` and Experiment 11.

A candidate rule is not allowed to directly mutate future policy state.

The sandbox path performs safety checks, reconstructs a sandbox IR using the real dependency resolver, runs the pre-solve certifier, and admits the rule only when safety checks pass.

### Experiment 11

- candidate rules evaluated: **4**,
- safe rules admitted: **1**,
- unsafe rules admitted: **0**.

Unsafe cases included:

- forbidden `isolate` reintroduction on a cyber-physical controller,
- failsafe removal,
- empty-domain creation.

### Current limitation

The sandbox reconstructs context with simplified/default threat/context information rather than persisting the exact original runtime snapshot. Therefore describe it as **safety-gated sandbox recompilation**, not perfect replay of the original incident state.

---

## 30. ML / Federated Threat-Detection Subsystem

The detection subsystem is supporting input to the constraint compiler.

`FederatedEdgeManager` loads the dataset, creates an 80/20 train/test split, partitions the training set into non-IID client shards, trains local PyTorch models, and aggregates them using a FedAvg server.

### Important deployment honesty

The current PoC simulates federated clients as isolated data partitions within one application/process. It demonstrates the federated training logic, but it is not a physically distributed multi-device deployment.

Therefore use:

> **three simulated federated edge clients with non-IID partitions**

for the scaling experiment.

Do not claim that three independent physical edge machines were used unless separately demonstrated.

---

## 31. Edge MLP Architecture and Parameter Count

Source: `layer2_detection/local_clients/edge_client.py`.

The current PyTorch MLP is:

```text
Input D
  -> Linear(D,64)
  -> BatchNorm1d(64)
  -> ReLU
  -> Dropout(0.2)
  -> Linear(64,32)
  -> BatchNorm1d(32)
  -> ReLU
  -> Dropout(0.1)
  -> Linear(32,2)
```

The number of trainable parameters depends on actual post-preprocessing input dimension \(D\):

\[
P(D)=64D+2402
\]

Examples:

- if \(D=9\), \(P=2978\),
- if \(D=36\), \(P=4706\).

The scaling JSON does **not** independently record the final feature dimension used in each trial. Therefore the master documentation must not state a single parameter count for those trials unless the corresponding runtime feature dimension is separately logged or verified.

---

## 32. Preprocessing

Source: `layer0_preprocessing/preprocessor.py` and `layer1_telemetry/data_loader.py`.

Current preprocessing sequence:

1. coerce raw values to numeric,
2. median imputation,
3. 1.5× IQR outlier clipping,
4. `log1p(abs(x))` compression,
5. standardization using fitted mean/std,
6. variance filtering,
7. optional top-K cap (configured maximum `TOP_K_FEATURES = 36`).

The preprocessor is fitted once and cached/reused to maintain consistent transforms across client shards and later datasets.

---

## 33. Scaling Experiment Configuration

Source: `run_data_scaling_trials.py`.

Recorded configuration:

- sample scales: 2,000; 4,000; 10,000; 50,000; 100,000; 1,000,000,
- train/test split: 80/20,
- simulated federated clients: **3**,
- non-IID partitioning: enabled,
- random seed: **42**,
- global federated rounds: **3**,
- local epochs per round: **1**,
- learning rate: **0.01**,
- optimizer in the edge client: **Adam**,
- loss: class-weighted cross-entropy,
- batch size: **dynamic**, computed as

\[
bs=\max(32,\min(1024,\lfloor n_{local}/50\rfloor))
\]

- PyTorch compute threads: **3**,
- interop threads: **2**,
- process priority on Windows: `BELOW_NORMAL_PRIORITY_CLASS`.

Do not document a fixed batch size of 64; the implementation does not use one.

---

## 34. Faculty-Requested Training / Testing / Scaling Evidence

Source: `benchmark_scaling_trials_results.json`.

### 34.1 Recorded values

| N | Train / Test | Load time | FL training time | Recorded load+training time | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2,000 | 1,600 / 400 | 1.47 s | 1.38 s | 2.85 s | 94.25% | 99.68% | 93.31% | 96.39% | 0.9521 |
| 4,000 | 3,200 / 800 | 1.54 s | 0.40 s | 1.94 s | 91.12% | 97.52% | 91.96% | 94.66% | 0.9346 |
| 10,000 | 8,000 / 2,000 | 1.52 s | 0.68 s | 2.21 s | 89.30% | 99.86% | 87.34% | 93.18% | 0.9545 |
| 50,000 | 40,000 / 10,000 | 1.64 s | 1.34 s | 2.97 s | 88.98% | 97.93% | 88.84% | 93.16% | 0.9435 |
| 100,000 | 80,000 / 20,000 | 1.91 s | 2.21 s | 4.12 s | 96.10% | 99.87% | 95.52% | 97.65% | 0.9735 |
| 1,000,000 | 800,000 / 200,000 | **11.82 s** | **19.66 s** | **31.47 s** | **98.65%** | **95.94%** | **97.06%** | **96.50%** | **0.9948** |

At 1,000,000 samples, **197,305 of 200,000** holdout samples were classified correctly.

The six-trial suite recorded **48.97 seconds wall-clock total** across **1,166,000 cumulative input samples**.

### 34.2 Critical timing clarification

The current script computes `total_time_sec` as:

```python
load_time + train_time
```

It performs holdout inference and metric calculation afterwards, but does **not** record an independent `test_time_sec` or `inference_time_sec`.

Therefore:

- **11.82 s** may be reported as the 1M-sample load/ingestion initialization time,
- **19.66 s** may be reported as the 1M-sample federated training time,
- **31.47 s** must be labelled **recorded load + training time**, not complete end-to-end trial time,
- exact inference/testing latency is **not independently measured in the present artifact**.

### 34.3 Faculty-ready sentence

> “At the one-million-sample scale, 800,000 records were used for training and 200,000 for holdout testing. Dataset initialization took 11.82 seconds and three federated rounds across three simulated clients took 19.66 seconds under a three-thread CPU cap. Holdout evaluation achieved 98.65% accuracy, 95.94% precision, 97.06% recall, 96.50% F1, and 0.9948 ROC-AUC. Exact inference latency was not independently instrumented in this benchmark, so we do not report a separate testing-time value.”

---

## 35. What the Scaling Experiment Does and Does Not Prove

The scaling suite demonstrates that the detector can be trained/evaluated over increasing telemetry volume while the representative Layer-5 incident evaluation remains certified at each scale.

However, the Layer-5 compiler is **not run once per packet**.

At each scale, after detector evaluation, the script runs Layer 5 on a representative `port_scan_recon` incident scenario.

Therefore avoid:

> “0% forbidden actions across 1,166,000 infrastructure decisions.”

Use:

> **“Across six detector scaling trials totaling 1,166,000 cumulative telemetry samples, the representative Layer-5 incident evaluation at every scale produced zero forbidden-action violations.”**

This distinction is essential for academic and patent credibility.

---

## 36. Metric Terminology

Use the following consistently.

### Constraint Compliance Rate (CCR)

Safety/compliance outcome for the evaluated response formulation.

### Semantic Fidelity (SF)

Feasibility-preservation agreement between certified SC-IR and a compiled backend across an evaluated assignment set.

### Legacy “Decision Fidelity”

The scaling script currently sets:

```python
decision_fidelity = ccr_pct
```

Therefore the historical `decision_fidelity_pct` field is an alias for CCR in that benchmark and must **not** be presented as cross-backend optimal-decision agreement.

Do not report Cross-Backend Decision Agreement unless a dedicated experiment explicitly compares selected optimal action vectors.

---

## 37. Ablation Evidence — Correct Evidence Classification

Source: `run_constraint_compiler_benchmark.py`, Experiment 6.

This section requires strict evidence labeling.

### 37.1 Variant A — directly executed

The Full Architecture variant is actually constructed, certified, compiled, and solved across five heterogeneous assets.

### 37.2 Variants B, C, and D — configured / hard-coded degraded-control outputs

The current script does **not** execute full implementations of the three degraded variants. Instead, values such as:

- 40% forbidden-action rate,
- 60% policy consistency,
- 20% infeasibility,
- unresolved-conflict counts,

are inserted as configured values in `ablation_summary`.

Therefore these numbers must **not** be described as independently measured empirical results.

Correct wording:

> “The current ablation harness contains a directly executed Full Architecture baseline and illustrative configured outputs for degraded-control variants B–D. Those configured values are useful for design discussion but should not be used as primary patent evidence until each degraded variant is independently implemented and executed.”

### 37.3 Patent implication

For current patent evidence, prioritize Experiments 7–11 because their key outputs are generated by actual code paths and stored in `patent_strengthening_results.json`.

---

## 38. Test and Verification Evidence

The frozen implementation includes:

- `test_patent_strengthening.py` with **34 strengthening/regression tests**,
- `verify_system.py` with a **10-layer/system verification path**,
- GitHub CI configuration covering Python versions and benchmark/test execution.

When quoting pass counts in a filing or faculty document, use the most recent successful recorded CI/run evidence rather than assuming a commit message alone proves execution success.

---

## 39. Layer-8 Orchestration — Current PoC Boundary

Source: `layer8_orchestration/executor.py`.

The current executor logs actions and returns:

```text
status = "simulated_success"
```

Actions such as isolation, credential rotation, IP blocking, backup, and monitoring are therefore simulated in the repository.

Correct description:

> **The system generates structured machine-actionable response plans and evaluates orchestration through an integrated simulation executor.**

Do not claim that this repository has already actuated a physical PLC, modified a production firewall, or changed live cloud IAM state.

Potential deployment embodiments may integrate Modbus, OPC-UA, cloud IAM, firewall, switch, or SOAR connectors, but those integrations are outside the demonstrated PoC.

---

## 40. Custom Code vs Third-Party Technology

| Component | Classification |
|---|---|
| Runtime action-domain transformation | Custom / patent core |
| Fixed-point dependency closure | Custom / patent core |
| SC-IR | Custom / patent core |
| Regenerated topology/bound metadata | Custom / patent core |
| Pre-solve certifier | Custom / patent core |
| Global feasibility witness | Custom / patent core |
| Certificate binding / formulation gate | Custom / patent core |
| Incremental compiler | Custom / patent core |
| Semantic validator | Custom / patent-support mechanism |
| Safety-gated experience admission | Custom / secondary protected extension |
| Federated orchestration code | Custom supporting subsystem |
| PyTorch | Third-party ML framework |
| NumPy / Pandas | Third-party numerical/data libraries |
| scikit-learn | Third-party metrics/preprocessing utilities |
| PuLP / CBC | Third-party classical optimization backend |
| Qiskit / qiskit-optimization | Third-party quantum/optimization framework |
| SHA-256 / `hashlib` | Standard cryptographic primitive |
| QAOA | Known solver algorithm; backend only |

---

## 41. Inventive-Step Defense — Faculty-Aligned Version

Do not argue that ordinary technologies are individually novel.

The strongest non-obviousness narrative is:

> Existing categories of technology can separately provide policy rules, optimization, solver compilation, graph reasoning, or safety checks. The Cloud Guardian core is the ordered runtime transformation in which live infrastructure state first changes the membership of the optimization decision domain, that membership change is propagated to a fixed point across dependencies, dependent conflict/resource structures are regenerated, a solver-independent versioned SC-IR is synthesized from the reconstructed state, the SC-IR is deterministically certified including a joint feasibility witness, and solver-specific model generation is then cryptographically gated to that exact certified state.

The distinction is not “we use a graph” or “we use QUBO.” The distinction is **where and how structural security semantics enter the compilation pipeline**.

### Strong examiner/faculty contrast

**Conventional penalty adaptation:**

\[
\text{same variables} + \text{new weights}
\]

**Cloud Guardian:**

\[
\text{new runtime state} \Rightarrow \text{new variable membership} \Rightarrow \text{new dependent structure} \Rightarrow \text{new certified intermediate representation}
\]

---

## 42. Difference from Ordinary Presolve

Ordinary optimizer presolve typically receives an already-formulated mathematical model and simplifies algebraic rows/variables.

Cloud Guardian operates **upstream of solver formulation** using runtime semantic information such as resource type, confidence, policy, SLA, and approved learned constraints.

The key difference to explain is:

> The system is not merely simplifying an existing ILP/QUBO. It is synthesizing the active mathematical problem from live infrastructure semantics before solver-specific formulation exists.

---

## 43. Section 3(k) / Technical-Effect Positioning

This section is technical patent positioning, not a legal eligibility conclusion.

The architecture should be described in terms of concrete computing/infrastructure effects:

- preventing forbidden machine-response commands from entering the active executable decision space,
- preserving availability/safety constraints for cyber-physical resource classes,
- regenerating machine-executable constraint topology according to live system state,
- binding the exact certified runtime state to downstream solver generation,
- generating structured response instructions for network/access/credential controls.

### Current PoC limitation must remain explicit

The repository currently demonstrates these effects in an integrated software simulation. It does not presently contain live PLC/firewall/cloud actuator connectors.

For patent embodiments, real infrastructure adapters may be described as deployment embodiments, but experimental claims must remain tied to the demonstrated simulation.

---

## 44. Prior-Art Documentation Rule

The master reference must **not** attribute internal benchmark failure rates to external prior-art systems.

For example, the 40% parameter-only failure value in the current ablation harness is not a published MARISMA result and must not appear in a prior-art comparison table as though MARISMA produced it.

Prior-art tables used in the patent must contain only:

- claims/features verifiable from the cited publication/patent,
- neutral “not disclosed / not identified” entries where evidence is absent,
- Cloud Guardian evidence from its own repository clearly separated from external-source evidence.

The prior-art search and legal citations should be independently verified before filing.

---

## 45. Evidence Hierarchy for the Final Patent / IDF

Use evidence in this order:

1. **Current executable source code** — implementation truth.
2. **Generated JSON benchmark outputs** — measured numerical evidence.
3. **Automated tests / CI logs** — verification evidence.
4. **Generated Markdown reports** — explanatory summaries.
5. **README / older patent drafts** — secondary; never override current source code or JSON.

When old documentation and code disagree, the current frozen implementation wins.

---

## 46. Recommended Patent-Core Figures

### Figure 1 — Overall System Architecture

Show Layers 0–9 with Layer 5 visually dominant.

### Figure 2 — Patent Core

Use numbered patent blocks:

```text
100 Runtime State Input
  -> 110 Feasibility Evaluation
  -> 120 Structural Decision-Domain Transformation
  -> 130 Fixed-Point Dependency Closure
  -> 140 Topology / Operational-Bound Regeneration
  -> 150 Versioned SC-IR Generation
  -> 160 Pre-Solve Safety Certification
  -> 170 Certificate-Bound Compiler Gate
  -> 180A ILP Backend / 180B QUBO Backend
  -> 190 Response Plan / Actuation Interface
```

### Figure 3 — Incremental Recompilation

```text
IR_t + Delta S
  -> Primary Dirty Nodes
  -> BFS Affected Subgraph
  -> Reuse Clean Structure + Recompute Dirty Structure
  -> IR_t+1
  -> Fresh Certificate
  -> Semantic Fingerprint Check / Safe Fallback
```

Figures should avoid embedding volatile benchmark numbers unless generated automatically from current JSON evidence.

---

## 47. Patent Claim Support Concepts

Claim drafting should protect mechanisms, not benchmark percentages.

Strong claim concepts include:

- receiving live infrastructure state,
- evaluating runtime feasibility of response actions,
- removing one or more response-action variables from an active decision domain,
- in response to removal, propagating dependency consequences to a fixed point,
- regenerating dependent conflict/resource structures,
- generating a solver-independent intermediate representation,
- performing deterministic pre-solve invariant verification,
- constructing a global feasibility witness,
- generating a tamper-evident certificate bound to IR and state versions,
- refusing solver compilation unless the certificate matches the current IR,
- compiling the certified IR into one of multiple solver-specific formulations,
- incrementally recompiling an affected dependency subgraph after a runtime delta,
- admitting learned structural rules only after sandbox recompilation and certification.

Do **not** place measured claims such as “100% Semantic Fidelity” or “59.89% faster” inside an independent claim. Keep measurements in embodiments/experimental evidence.

---

## 48. Source-of-Truth Function Map

| Concept | Current implementation |
|---|---|
| Full Layer-5 resolution | `ConstraintDependencyGraph.resolve()` |
| Fixed-point closure | `ConstraintDependencyGraph.compute_fixed_point_closure()` |
| SC-IR | `SecurityConstraintIR` |
| Canonical integrity digest | `SecurityConstraintIR.compute_canonical_digest()` |
| Mathematical equivalence fingerprint | `SecurityConstraintIR.semantic_fingerprint()` |
| Safety certification | `PreSolveSafetyCertifier.certify()` |
| Global feasibility witness | `PreSolveSafetyCertifier.find_feasibility_witness()` |
| Certificate gate | `FormulationCompiler.verify_binding()` |
| ILP compiler | `FormulationCompiler.compile_to_ilp()` |
| QUBO compiler | `FormulationCompiler.compile_to_qubo()` |
| Incremental compiler | `IncrementalConstraintCompiler.compile_delta()` |
| Backend semantic validator | `SemanticValidator.validate_backend_semantics()` |
| Safety-gated experience admission | `FeedbackLearner.admit_candidate_rule_sandboxed()` |
| Main operational coordinator | `run_pipeline()` |
| Simulated response executor | `execute_plan()` / `execute_strategy()` |

---

## 49. Experimental Evidence Summary

### Detector / scaling

- six scales: 2K → 1M,
- cumulative input volume: 1,166,000,
- 1M scale: 800K train / 200K test,
- 1M load initialization: 11.82 s,
- 1M FL training: 19.66 s,
- 1M recorded load+training: 31.47 s,
- 1M holdout accuracy: 98.65%,
- 1M precision: 95.94%,
- 1M recall: 97.06%,
- 1M F1: 96.50%,
- 1M ROC-AUC: 0.9948,
- exact independent inference latency: not recorded.

### Patent-strengthening experiments

- Exp 7: multi-hop closure converged, dangling references 1 → 0,
- Exp 8: 0 false accepts in 6 certificate attack cases,
- Exp 9: 59.89% median reduction at 250 assets with semantic-fingerprint equivalence,
- Exp 10: 100% measured SF over 1024 enumerated assignments in the evaluated instance,
- Exp 11: 0 unsafe rules admitted among 4 evaluated candidates.

---

## 50. Faculty-Ready 2-Minute Explanation

> “Our project is an automated cybersecurity response architecture, but the main invention is not the detector or the quantum solver. The core is a Runtime Security Constraint Compiler. When an incident occurs, we combine threat severity, confidence, asset type, SLA and policy state and decide which response actions are actually allowed to exist in the optimization problem. For example, if automated isolation is unsafe for a PLC, the `isolate` decision variable is removed rather than merely penalized. The compiler then propagates the consequences through dependency relationships until a fixed point, removes stale conflicts, rebuilds operational feasibility metadata, and creates a versioned solver-independent SC-IR. Before ILP or QUBO is generated, a pre-solve certifier checks seven unique safety invariants and constructs a joint feasible response witness. A certificate-bound compiler gate rejects stale, tampered, or uncertified IR. Only then is the problem given to a solver. We also implemented incremental recompilation for local runtime changes and measured a 59.89% median compilation-latency reduction at 250 assets while preserving the same semantic fingerprint as full recompilation. The current actuation layer is a simulation PoC, so we present it as a validated runtime compilation and decision architecture rather than a production-deployed SOC controller.”

---

## 51. Faculty-Ready Training / Testing Answer

> “For the detector, we ran scaling trials from 2,000 to 1,000,000 Edge-IIoT samples. At one million samples, 800,000 were used for training and 200,000 for holdout testing. Initialization/loading took 11.82 seconds, and three federated rounds across three simulated non-IID clients took 19.66 seconds while PyTorch was restricted to three compute threads. The holdout test achieved 98.65% accuracy, 95.94% precision, 97.06% recall, 96.50% F1 and 0.9948 ROC-AUC. The current benchmark did not independently time inference, so I would not claim an exact testing-time value until we instrument that separately.”

---

## 52. Likely Faculty Questions and Precise Answers

### “What exactly is novel?”

The ordered runtime compilation mechanism: **state-driven variable-domain membership change → dependency closure → regenerated mathematical structure → solver-independent SC-IR → deterministic certification → certificate-bound backend compilation**.

### “Why not simply give dangerous actions a very large penalty?”

A penalty leaves the dangerous variable in the search space. Structural excision removes the variable before the solver exists, so the backend cannot choose it.

### “Is QAOA your invention?”

No. QAOA is an interchangeable backend. The patent core is upstream and also compiles to classical ILP.

### “Is this ordinary presolve?”

No. Ordinary presolve simplifies an already-formulated mathematical model. Cloud Guardian uses live security and infrastructure semantics to synthesize the active model before solver-specific formulation.

### “What happens if pruning makes the whole problem infeasible?”

The pre-solve certifier performs a global backtracking feasibility search. If no joint assignment satisfies exactly-one, conflict, budget, and mandate requirements, certification fails and compilation is rejected.

### “What if someone changes the IR after certification?”

The formulation compiler recomputes canonical and closure digests, checks version continuity and certificate integrity, and rejects mismatches.

### “Why do old files say 8/8 but you now say 7/7?”

One policy check was historically exposed under two keys for backward compatibility. There are seven unique invariant categories.

### “How long did the model take to train and test?”

At 1M samples, recorded loading was 11.82 s and federated training was 19.66 s. Exact inference/testing time was not independently logged, so it should not be invented.

### “Did you actually control a PLC?”

No. The current Layer-8 executor is simulated and returns `simulated_success`. The PoC demonstrates generation/certification of machine-actionable response plans; physical connectors are a future deployment embodiment.

### “Are the 40% ablation failures measured?”

The Full Architecture branch is executed, but the current B–D degraded-variant values are configured in the benchmark script rather than independently solved. They should be treated as illustrative controls until those degraded variants are implemented and executed.

---

## 53. Documentation Rules From This Point Forward

1. This V2 file is the preferred technical source for all new patent/IDF/faculty material.
2. Current source code and JSON evidence override older README/patent prose.
3. Do not invent inference times, deployment capabilities, or prior-art performance.
4. Use **7 unique invariants** in new prose; label 8/8 only as historical benchmark output.
5. Use **CCR** for safety compliance and **SF** for backend semantic preservation.
6. Do not use legacy “Decision Fidelity” as a new scientific metric.
7. Keep measured percentages out of independent patent claims.
8. Keep QAOA/FL as supporting technologies, not the central inventive concept.
9. State simulation boundaries explicitly.
10. Any future prior-art table must be independently sourced and verified.

---

## Appendix A — Evidence Source Map

| Evidence | Source |
|---|---|
| Scaling train/test/load/training metrics | `benchmark_scaling_trials_results.json` |
| Scaling implementation and timing semantics | `run_data_scaling_trials.py` |
| Closure/certificate/incremental/SF/learning experiments | `patent_strengthening_results.json` |
| Closure implementation | `layer5_constraints/dependency_graph.py` |
| SC-IR / digests / semantic fingerprint | `layer5_constraints/constraint_ir.py` |
| Seven unique invariant certifier | `layer5_constraints/safety_certifier.py` |
| Certificate gate / ILP / QUBO | `layer5_constraints/formulation_compiler.py` |
| Incremental compiler | `layer5_constraints/incremental_compiler.py` |
| Backend semantic fidelity | `layer5_constraints/semantic_validator.py` |
| Experience rule sandbox | `layer9_feedback/feedback_learner.py` |
| Operational pipeline | `pipeline.py` |
| Simulated executor | `layer8_orchestration/executor.py` |
| MLP architecture / optimizer / dynamic batch size | `layer2_detection/local_clients/edge_client.py` |
| FL orchestration | `layer2_detection/federated_detector.py` |
| Preprocessing | `layer0_preprocessing/preprocessor.py` |
| Dataset loader | `layer1_telemetry/data_loader.py` |
| Ablation evidence limitations | `run_constraint_compiler_benchmark.py` |

---

## Appendix B — Discrepancy Register

| Older statement | Correct V2 interpretation |
|---|---|
| 8 safety invariants | 7 unique invariants; 8 historical keys because of alias |
| Decision Fidelity = 100% | historical alias for CCR in scaling script; use SF separately |
| 31.47 s total 1M trial | actually recorded load + FL training time; inference not independently timed |
| 0% forbidden across 1.166M decisions | 1.166M detector samples; one representative Layer-5 incident evaluation per scale |
| 40% prior-art failure | not an external-system result; degraded ablation values are configured controls |
| 2,978 parameters as universal | parameter count depends on runtime input dimension D; P(D)=64D+2402 |
| fixed batch size 64 | dynamic batch size based on local shard size |
| SGD / Adam | current local MLP training uses Adam |
| fallback threshold 50% | current incremental default is 70% |
| PCI-DSS mandate in current Layer-5 resolver | not implemented in current dependency resolver |
| SHA-256 “signature” / unbreakable link | tamper-evident integrity digest; not an asymmetric digital signature |
| live PLC / firewall actuation | current executor is simulated |

---

**End of corrected Master Technical Reference V2.**