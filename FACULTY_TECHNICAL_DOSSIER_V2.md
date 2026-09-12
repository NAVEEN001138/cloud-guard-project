# CLOUD GUARDIAN — FACULTY TECHNICAL DOSSIER V2

**Purpose:** concise but technically complete faculty-facing explanation of the current frozen Cloud Guardian architecture, experimental evidence, novelty position, implementation boundaries, and likely viva questions.  
**Primary source basis:** `CLOUD_GUARDIAN_MASTER_TECHNICAL_REFERENCE_V2.md`, `PATENT_DRAFT_INDIA_V2.md`, frozen source code, and current benchmark JSON files.

---

# 1. Project Title

**System and Method for Runtime Security Constraint Compilation and Pre-Solve Safety Certification of Automated Infrastructure Response**

---

# 2. One-Line Project Explanation

Cloud Guardian detects a cyber threat, combines it with live infrastructure context, **changes which response variables are allowed to exist in the mathematical decision problem**, rebuilds all dependent constraints around that safe domain, certifies the reconstructed problem, and only then permits an ILP/QUBO solver to produce a response plan.

---

# 3. Core Problem We Solve

A conventional security optimizer can keep dangerous actions in its search space and merely assign them large penalties.

Example:

```text
PLC actions = {isolate, rotate_credentials, monitor, ...}
```

If `isolate` is unsafe for the PLC, a traditional model may still contain:

```text
x_PLC,isolate
```

with a large negative/positive penalty.

Cloud Guardian instead performs a structural transformation:

\[
A_i \rightarrow A'_i
\]

and removes:

\[
x_{PLC,isolate}
\]

from the active domain itself.

The solver therefore never receives that variable.

This is the most important conceptual difference in the project.

---

# 4. Final Core Pipeline

\[
\boxed{
S_t
\rightarrow
A'_t
\rightarrow
R^*
\rightarrow
E'_t/B'_t
\rightarrow
SC\!\text{-}IR_t
\rightarrow
C_t
\rightarrow
Compile
\rightarrow
Solve
}
\]

where:

- \(S_t\): runtime infrastructure/security state;
- \(A'_t\): admissible action domain;
- \(R^*\): fixed-point dependency closure;
- \(E'_t\): regenerated active conflict topology;
- \(B'_t\): regenerated operational/resource-feasibility metadata;
- \(SC\!\text{-}IR_t\): solver-independent Security Constraint Intermediate Representation;
- \(C_t\): pre-solve safety certificate;
- `Compile`: certificate-bound backend formulation;
- `Solve`: ILP/QUBO/other optimization backend.

---

# 5. Layer-by-Layer Explanation

## Layer 0 — Preprocessing

Raw telemetry is numerically cleaned and transformed using:

- median imputation;
- IQR clipping;
- log compression;
- standardization;
- variance filtering;
- optional feature cap.

This is supporting ML infrastructure, not the patent core.

## Layer 1 — Telemetry / Data Loader

Loads Edge-IIoT telemetry, builds train/test partitions, and creates non-IID federated client shards.

## Layer 2 — Threat Detection

The detector produces a threat score:

\[
s_i\in[0,1]
\]

for each monitored resource.

The current federated-training experiment uses simulated federated client partitions rather than separate physical devices.

## Layer 3 — Context Aggregation

Adds resource/business/policy context such as:

- resource type;
- business criticality;
- SLA priority;
- compliance flags;
- estimated operational impact.

## Layer 4 — Confidence Evaluation

Produces detection confidence and restricts high-disruption actions when confidence is low.

## Layer 5 — Patent Core

Layer 5 performs:

1. feasibility evaluation;
2. structural action-domain pruning;
3. fixed-point dependency closure;
4. conflict and operational-bound regeneration;
5. SC-IR generation;
6. pre-solve safety certification;
7. certificate-bound compilation;
8. optional incremental recompilation;
9. backend semantic validation;
10. sandboxed safety-gated experience-rule admission.

## Layer 6 — Solver Backends

Supports classical and quantum-oriented formulations.

Current important backends:

- PuLP ILP / CBC;
- Qiskit QUBO / QAOA-related path;
- greedy baselines.

The solver is not the invention. It consumes an already-certified problem.

## Layer 7 — Utility

Computes response trade-offs among safe candidate actions.

## Layer 8 — Explanation / Orchestration

Produces an explainable response plan and passes it to a simulated executor.

The repository currently returns `simulated_success`; it does not demonstrate live PLC/firewall/cloud control.

## Layer 9 — Experience Memory

Stores validated experience-derived rules. Candidate rules can only be admitted after safety checks and sandbox certification.

---

# 6. Layer 5 in Detail

## 6.1 Structural action pruning

For each resource:

\[
A'_{t,i}=\{a\in A_i\mid F(S_{t,i},a)=1\}
\]

Runtime rules include:

- physical capability restrictions;
- confidence restrictions;
- SLA rules;
- encoded policy mandates;
- approved experience rules.

### Example

A PLC controller has a physically constrained action set such as:

```text
rotate_credentials
monitor
increase_logging
```

`isolate` is not retained.

---

## 6.2 Fixed-point dependency closure

Initial removed variables form \(R_0\).

The engine repeatedly evaluates:

\[
R_{k+1}=R_k\cup DependentConsequences(R_k)
\]

until:

\[
R_{k+1}=R_k
\]

The fixed point is \(R^*\).

The strongest direct propagation behavior is on prerequisite (`REQUIRES`) semantics. Mandate consistency, conflict cleanup, failsafe preservation, and bound regeneration are handled as associated closure/regeneration operations.

---

## 6.3 Conflict regeneration

If a conflict relation contains a removed variable, the stale relation is removed from the active topology.

Conceptually:

\[
E'_t=\{e\in E\mid vars(e)\subseteq A'_t\}
\]

---

## 6.4 Operational-bound regeneration

The system rebuilds active cost and feasibility information such as:

- minimum achievable cost;
- effective budget;
- budget consistency;
- active variable count;
- active conflict count.

The exact budget ceiling is threat-tier dependent in the current PoC; the important invention is regeneration of the feasibility structure around the current active domain.

---

## 6.5 SC-IR

The Security Constraint Intermediate Representation stores the reconstructed mathematical state independently of any solver.

It contains:

- active and pruned domains;
- exactly-one constraints;
- conflict hyperedges;
- budget and cost map;
- objective terms;
- hard constraints;
- soft preferences;
- provenance;
- topology metadata;
- regenerated-bound metadata;
- closure metadata;
- IR/state versioning;
- integrity digest information.

Analogy:

```text
Programming language -> compiler IR -> machine code

Runtime security state -> SC-IR -> ILP / QUBO
```

---

# 7. Seven Unique Pre-Solve Safety Invariants

The current certifier evaluates seven unique invariant categories:

1. forbidden-action elimination;
2. non-empty domain;
3. exactly-one invariance consistency;
4. conflict consistency;
5. budget/global-feasibility consistency;
6. encoded policy-rule consistency;
7. provenance completeness.

Older benchmark output shows `8/8` because policy consistency was exposed under two keys for backward compatibility.

So the correct current explanation is:

> **7 unique invariants; historical artifact reported 8 keys because of one alias.**

---

# 8. Global Feasibility Witness

The certifier does not only inspect constraints independently.

It searches for at least one joint assignment satisfying:

\[
ExactlyOne\land Conflicts\land Budget\land Mandates
\]

If no assignment exists, certification fails.

This proves the reconstructed problem has at least one globally feasible response before the solver is allowed to run.

---

# 9. Certificate-Bound Compiler Gate

The certificate contains:

- IR digest;
- closure digest;
- IR version;
- runtime-state version;
- invariant results;
- certificate integrity digest;
- feasibility witness.

The compiler performs:

\[
Compile(IR,C)
\]

only if:

\[
VerifyBinding(IR,C)=true
\]

It rejects:

- missing certificates;
- failed certificates;
- stale versions;
- mutated IR;
- swapped certificates;
- modified budget/state after certification.

Important terminology:

> **tamper-evident integrity binding**

not “digital signature” or “unbreakable encryption.”

---

# 10. ILP and QUBO Formulations

The same SC-IR can be compiled into multiple backends.

## ILP

The ILP model creates binary variables only for actions that remain active in SC-IR.

## QUBO

The QUBO formulation also allocates variables only for active actions and encodes hard constraints using penalty terms.

### Budget inequality fix

For:

\[
\sum_i c_i x_i\le B
\]

the current implementation uses integer scaling and binary slack variables:

\[
\sum_i\hat c_i x_i+\sum_k w_kz_k=\hat B
\]

with a configured scale of 1000.

This should be described as exact at the configured cost precision used by the system, not as exact for arbitrary real numbers.

---

# 11. Incremental Recompilation

For a localized runtime change:

\[
\Delta S=Diff(S_t,S_{t+1})
\]

the compiler identifies primary dirty assets and propagates impact through explicit dependency edges using BFS.

It then:

- reuses clean domains/constraints;
- recomputes dirty domains;
- updates conflicts;
- rebuilds objective/cost information;
- regenerates feasibility metadata;
- creates \(IR_{t+1}\);
- creates a fresh certificate.

Default full-recompile triggers include:

- affected ratio > 0.70;
- global policy shift;
- empty previous IR domain state.

The threshold is an implementation parameter and should not be treated as a patent limitation.

---

# 12. Experimental Evidence — Strongest Current Results

## Experiment 7 — Fixed-Point Closure

- initial removed variable: 1;
- transitively affected entities: 2;
- total removed variables: 3;
- propagation depth: 2;
- closure iterations: 3;
- dangling references: 1 → 0;
- stale conflicts: 1 → 0;
- status: `CONVERGED`.

## Experiment 8 — Certificate Binding

Six test cases.

Recorded false accepts:

\[
0/6
\]

## Experiment 9 — Incremental Compilation

| Assets | Full median | Incremental median | Reduction |
|---:|---:|---:|---:|
| 10 | 1.032 ms | 0.997 ms | 3.36% |
| 50 | 6.577 ms | 5.195 ms | 21.01% |
| 100 | 17.877 ms | 11.622 ms | 34.99% |
| 250 | 199.875 ms | 80.175 ms | **59.89%** |

All recorded cases reported semantic-fingerprint equivalence with full recompilation.

## Experiment 10 — Semantic Fidelity

- assignments evaluated: 1024;
- SC-IR feasible states: 21;
- ILP feasible states: 21;
- QUBO semantically valid states: 21;
- all mismatch counts: 0;
- measured Semantic Fidelity: 100% for the evaluated instance.

Correct wording:

> **100% Semantic Fidelity across the 1024 enumerated assignments in the evaluated benchmark instance.**

## Experiment 11 — Safety-Gated Learning

- candidate rules: 4;
- safe admitted: 1;
- unsafe admitted: 0.

---

# 13. Faculty-Requested ML Training and Scaling Evidence

Six detector scaling runs were recorded:

\[
N=\{2K,4K,10K,50K,100K,1M\}
\]

| Samples | Train / Test | Load | FL training | Recorded load+training | Accuracy |
|---:|---:|---:|---:|---:|---:|
| 2K | 1,600 / 400 | 1.47 s | 1.38 s | 2.85 s | 94.25% |
| 4K | 3,200 / 800 | 1.54 s | 0.40 s | 1.94 s | 91.12% |
| 10K | 8,000 / 2,000 | 1.52 s | 0.68 s | 2.21 s | 89.30% |
| 50K | 40,000 / 10,000 | 1.64 s | 1.34 s | 2.97 s | 88.98% |
| 100K | 80,000 / 20,000 | 1.91 s | 2.21 s | 4.12 s | 96.10% |
| 1M | 800,000 / 200,000 | **11.82 s** | **19.66 s** | **31.47 s** | **98.65%** |

At 1M:

- precision: 95.94%;
- recall: 97.06%;
- F1: 96.50%;
- ROC-AUC: 0.9948;
- correct predictions: 197,305 / 200,000.

### Critical timing clarification

The benchmark records loading and federated training separately.

`31.47 s` is calculated as:

```text
11.82 s load + 19.66 s FL training
```

The current benchmark does **not** independently log exact test/inference latency.

Therefore do not say:

> “testing took 31.47 seconds.”

Correct faculty answer:

> “At one million samples, loading took 11.82 seconds and federated training took 19.66 seconds. Holdout evaluation was performed on 200,000 samples, but inference/testing latency was not independently instrumented in that run.”

---

# 14. ML Experimental Configuration

Current scaling setup:

- 3 simulated federated clients;
- non-IID partitions;
- 3 FL rounds;
- 1 local epoch per round;
- learning rate 0.01;
- Adam optimizer;
- class-weighted cross entropy;
- dynamic batch size;
- 3 PyTorch compute threads;
- random seed 42;
- Windows process priority set below normal in the scaling harness.

The current MLP is:

```text
Input D
 -> Linear(D, 64)
 -> BatchNorm
 -> ReLU
 -> Dropout
 -> Linear(64, 32)
 -> BatchNorm
 -> ReLU
 -> Dropout
 -> Linear(32, 2)
```

Parameter count depends on input dimension:

\[
P(D)=64D+2402
\]

Do not quote 2,978 parameters as universal unless \(D=9\) is independently verified for that run.

---

# 15. Important Evidence Boundary — Ablation Study

The repository contains an ablation benchmark.

The Full Architecture path is actually executed.

However, several degraded variants currently use configured summary values rather than fully executing separate degraded implementations.

Therefore values such as:

- 40% forbidden rate for parameter-only baseline;
- 20% infeasible rate for no-dependency variant;

should be treated as **illustrative internal controls**, not primary patent evidence.

Do not attribute the 40% number to MARISMA or another prior-art system.

The strongest current patent evidence is Experiments 7–11.

---

# 16. What Is Actually Novel?

Do not say:

> “Federated learning + quantum computing is our invention.”

Use:

> **Our invention is a runtime security constraint compiler where live infrastructure state changes the membership of the optimization decision domain itself. The structural consequences of those removals are propagated and regenerated into a solver-independent SC-IR, which is certified before the system is allowed to generate an ILP/QUBO or other solver-specific formulation.**

The strongest causal phrase is:

> **“in response to removal of an inadmissible decision variable, dependent constraint relations and resource-feasibility structures are regenerated before solver compilation.”**

---

# 17. Why This Is Not Ordinary Presolve

Ordinary presolve starts from an already-created mathematical model and simplifies it.

Cloud Guardian acts before backend formulation.

It uses:

- asset type;
- physical capability;
- confidence;
- SLA;
- policy state;
- learned structural rules;

and then synthesizes the mathematical model that is allowed to exist.

So:

```text
Ordinary presolve:
existing ILP -> simplify ILP

Cloud Guardian:
runtime security semantics -> construct certified IR -> generate ILP/QUBO
```

---

# 18. Section 3(k) Technical-Effect Position

The technical argument should focus on concrete computing/infrastructure behavior:

- unsafe response variables are structurally removed;
- the executable optimization search space changes according to live infrastructure state;
- stale/inconsistent mathematical models can be blocked before solver generation;
- cyber-physical availability restrictions can be enforced before optimization;
- output is a machine-readable response plan suitable for an infrastructure adapter.

Current PoC executes through simulation, so do not claim already-demonstrated physical PLC actuation.

---

# 19. Current Limitations

1. Layer-8 actuation is simulated.
2. Federated clients are simulated data partitions, not separate physical edge devices.
3. Exact independent inference latency is not logged in the current scaling artifact.
4. Some degraded ablation variants are illustrative/configured rather than independently executed.
5. Prior-art legal characterization must be separately source-verified before filing.
6. Incremental equivalence is strongly demonstrated for tested scenarios, not a universal theorem for every conceivable runtime mutation.

These are normal PoC limitations and should be disclosed accurately rather than hidden.

---

# 20. Two-Minute Faculty Pitch

> “Cloud Guardian is an automated cybersecurity response architecture, but our main invention is Layer 5 — the Runtime Security Constraint Compiler. Existing optimizers often keep all response actions in the search space and only change their weights. We instead use live threat, confidence, asset capability, SLA and policy state to decide which action variables are allowed to exist at all. If automated isolation is unsafe for a PLC, that variable is removed before solver formulation. The system then propagates the consequences of the removal through dependencies until a fixed point, removes stale conflicts, regenerates operational feasibility metadata, and builds a solver-independent Security Constraint IR. Before ILP or QUBO is generated, a deterministic certifier checks seven unique safety invariants and searches for a global feasible response witness. A certificate is bound to the exact IR and runtime-state version, and the formulation compiler refuses to create a solver model if the certificate is stale, failed or mismatched. For local runtime changes we also implemented incremental recompilation; at 250 assets it reduced median compilation latency from 199.875 ms to 80.175 ms, a 59.89% reduction, while preserving the same semantic fingerprint as full recompilation. The current execution layer is simulated, so we present this as a validated runtime compilation and decision architecture rather than a production-deployed control system.”

---

# 21. Faculty Training/Testing Answer

> “We scaled the detector from 2,000 to 1,000,000 Edge-IIoT samples. At one million samples, 800,000 were used for training and 200,000 for holdout testing. Dataset initialization took 11.82 seconds and three federated rounds across three simulated non-IID clients took 19.66 seconds under a three-thread PyTorch cap. The holdout set achieved 98.65% accuracy, 95.94% precision, 97.06% recall, 96.50% F1 and 0.9948 ROC-AUC. Exact inference latency was not separately instrumented, so I would not claim an exact testing-time number from that benchmark.”

---

# 22. Likely Viva Questions

## Q1. What is your main invention?

Runtime structural compilation of a safe optimization problem from live infrastructure state before solver formulation.

## Q2. Why not just use a very large penalty?

Because a penalized unsafe variable still exists and can still be mathematically selected. Structural removal guarantees the solver never receives that variable.

## Q3. What is SC-IR?

A versioned solver-independent representation containing the active decision domain, constraints, cost/budget information, provenance, topology, and runtime metadata.

## Q4. Why do you need a feasibility witness?

Because independent local checks do not prove a globally consistent assignment exists. The witness proves at least one joint response satisfies exactly-one, conflicts, budget and mandates.

## Q5. What does SHA-256 do here?

It provides tamper-evident integrity binding between the certified IR/certificate state. SHA-256 itself is not the invention.

## Q6. Is QAOA necessary?

No. ILP and QUBO are interchangeable backends. The invention is upstream of both.

## Q7. Why is incremental compilation useful?

Only a small part of the infrastructure state may change. Recompiling only the affected dependency subgraph can reduce latency while reusing unaffected structure.

## Q8. Did you control real PLC hardware?

No. The current orchestration executor is simulated. Real Modbus/OPC-UA/cloud adapters are future deployment integrations.

## Q9. Why 7 invariants if an old report says 8/8?

One policy consistency check had a backwards-compatible alias, giving eight dictionary keys but only seven unique categories.

## Q10. What evidence is strongest for the patent?

Experiments 7–11: closure, certificate attack rejection, incremental recompilation, backend semantic fidelity, and safety-gated rule admission.

---

# 23. Final Faculty Review Status

**Architecture:** frozen.  
**Patent core:** implementation-aligned.  
**Primary documentation source:** `CLOUD_GUARDIAN_MASTER_TECHNICAL_REFERENCE_V2.md`.  
**Patent technical draft:** `PATENT_DRAFT_INDIA_V2.md`.  
**Claim traceability:** `PATENT_CLAIM_SUPPORT_MATRIX_V2.md`.  
**Figure policy/specification:** `PATENT_FIGURE_SPEC_V2.md`.  
**Figure generator:** `generate_patent_figures_v2.py`.  

The remaining work is document polishing, figure generation/review, IDF formatting, source-verified prior-art research, and final filing-language review.
