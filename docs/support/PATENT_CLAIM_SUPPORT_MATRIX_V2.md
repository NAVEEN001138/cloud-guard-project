# CLOUD GUARDIAN — PATENT CLAIM SUPPORT MATRIX V2

**Purpose:** implementation-to-claim traceability for `PATENT_DRAFT_INDIA_V2.md`.  
**Use:** faculty review, IDF preparation, patent-drafting review, antecedent-basis review, and evidence checking.  
**Status:** technical support matrix; not a legal opinion on claim validity, scope, patentability, or grant outcome.

---

## 1. Evidence Classification

Each claim element is classified as one of the following:

- **DIRECT — CODE:** directly implemented in the frozen repository.
- **DIRECT — CODE + BENCHMARK:** directly implemented and supported by recorded benchmark evidence.
- **SUPPORTED EMBODIMENT:** supported by implementation/specification but not necessarily exercised in the primary operational pipeline every cycle.
- **CONTEMPLATED DEPLOYMENT:** described as a possible integration/deployment path but not demonstrated by the present PoC.
- **DRAFTING CAUTION:** wording should be narrowed or explained so it does not overstate the implementation.

The governing evidence hierarchy is:

1. current source code;
2. generated JSON benchmark evidence;
3. automated tests/CI;
4. generated reports;
5. README and older patent prose.

---

# 2. Independent Claim 1 — System

| Claim element | Implementation support | Evidence classification | Drafting note |
|---|---|---|---|
| **1(a) runtime-state acquisition interface** | `pipeline.py::run_pipeline()`, scenario dictionaries, contexts, confidences, previous plan, approved learned rules | DIRECT — CODE | Runtime state is distributed across objects rather than one monolithic state class. Current wording is appropriately functional. |
| **1(b) feasibility evaluator determines inadmissible actions** | `ConstraintDependencyGraph.resolve()` stages 1–3; `adaptive_constraints.py::generate_adaptive_constraints()` | DIRECT — CODE | Supported by physical-capability, confidence, SLA, encoded-policy, and learned-rule gates. |
| **1(c) structural decision-domain transformer removes variables** | `dependency_graph.py`: active variables are `all_variables_set - removed_vars`; downstream compilers allocate only admissible variables | DIRECT — CODE | Strong patent-core element. Keep “remove decision variables” rather than only “assign penalties.” |
| **1(d) fixed-point dependency closure in response to removal** | `ConstraintDependencyGraph.compute_fixed_point_closure()` | DIRECT — CODE + BENCHMARK | Experiment 7: depth 2, 3 iterations, 1→0 dangling references. Strong support. |
| **1(e) regenerate dependent relations and operational/resource-feasibility bounds** | conflict pruning and `regenerated_bounds` in `compute_fixed_point_closure()`; similar rebuild in `IncrementalConstraintCompiler.compile_delta()` | DIRECT — CODE | Avoid implying the entire budget ceiling is derived only from pruning. Strongest literal support is conflict topology, cost/min-cost/budget-consistency and active-count metadata. |
| **1(f) solver-independent versioned SC-IR** | `constraint_ir.py::SecurityConstraintIR` | DIRECT — CODE | Strong support. |
| **1(g) certifier verifies invariants and determines joint feasible response assignment** | `PreSolveSafetyCertifier.certify()` + `find_feasibility_witness()` | DIRECT — CODE | Strong support. Seven unique invariant categories. |
| **1(h) tamper-evident certificate bound to SC-IR and state version** | `ConstraintSafetyCertificate`; canonical digest, state/IR versions, closure digest, integrity digest | DIRECT — CODE + BENCHMARK | Use “tamper-evident integrity identifier,” not digital signature. Experiment 8 supports attack handling. |
| **1(i) compiler refuses absent/failed/stale/inconsistent certificate** | `FormulationCompiler.verify_binding()` | DIRECT — CODE + BENCHMARK | Strong. Experiment 8: 0 false accepts among 6 tested cases. |
| **1(j) response interface obtains response plan from solver** | ILP/QUBO/greedy solver paths in Layer 6; `PipelineResult.solver_results`; Layer-8 explanation/executor | DIRECT — CODE | Present executor is simulated. Claim does not require physical actuation, which is appropriate. |

### Claim 1 technical support verdict

**Strongly supported by the frozen implementation.** This is the most defensible independent claim family because each functional stage has a concrete code counterpart and the core stages are independently testable.

---

# 3. Dependent System Claims 2–10

## Claim 2 — prerequisite/mandate dependencies + regenerated conflicts

**Current support:**

- `REQUIRES` directly propagates removal when a prerequisite target is removed.
- `MANDATES` records a mandate conflict when a mandated target has been removed.
- conflict relations referencing removed variables are deactivated during topology regeneration.

**Classification:** DIRECT — CODE, with **DRAFTING CAUTION**.

**Recommended precise wording:**

> “wherein the dependency-closure engine propagates at least a prerequisite dependency, evaluates a mandate-consistency relationship, and regenerates at least one conflict relation referencing a removed decision variable.”

Reason: the implementation does not perform identical transitive-removal semantics for `MANDATES` and `REQUIRES`.

---

## Claim 3 — regenerated operational/resource-feasibility values

Supported values include:

- `min_possible_cost`,
- `effective_budget`,
- `budget_consistent`,
- `active_variable_count`,
- `active_conflict_count`.

**Implementation:** `compute_fixed_point_closure()` and `IncrementalConstraintCompiler.compile_delta()`.

**Classification:** DIRECT — CODE.

---

## Claim 4 — SC-IR content

Supported by `SecurityConstraintIR` fields:

- variable domains,
- invariance constraints,
- conflict hyperedges,
- budget constraint,
- objective terms,
- provenance,
- hard/soft constraints,
- topology,
- closure metadata,
- versioning and digests.

**Classification:** DIRECT — CODE.

---

## Claim 5 — deterministic joint feasibility search

`PreSolveSafetyCertifier.find_feasibility_witness()` performs deterministic backtracking and checks:

- one action per resource,
- conflict exclusion,
- mandates,
- cumulative budget.

**Classification:** DIRECT — CODE.

---

## Claim 6 — certificate contents

Supported certificate fields include:

- canonical IR digest,
- closure digest,
- IR version,
- runtime-state version,
- invariant results,
- integrity digest,
- feasibility witness.

**Classification:** DIRECT — CODE.

---

## Claim 7 — incremental compiler

Supported by `IncrementalConstraintCompiler.compile_delta()`:

- runtime delta,
- primary dirty nodes,
- BFS propagation over explicit dependencies,
- clean reuse,
- dirty recomputation,
- new IR version,
- fresh certificate.

**Classification:** DIRECT — CODE + BENCHMARK.

Experiment 9 records semantic-fingerprint equivalence at all four evaluated fleet sizes.

---

## Claim 8 — incremental fallback

Implemented fallback conditions include:

- dirty-resource ratio above the configured threshold (default 0.70),
- `global_policy_shift`,
- previous IR containing no variable domains.

Claim 8 currently recites the first two and is therefore supported without requiring every implementation condition to appear in the claim.

**Classification:** DIRECT — CODE.

---

## Claim 9 — same certified SC-IR to ILP or QUBO

Supported by:

- `FormulationCompiler.compile_to_ilp()`;
- `FormulationCompiler.compile_to_qubo()`;
- both call `verify_binding()` first.

**Classification:** DIRECT — CODE + BENCHMARK.

Experiment 10 supports feasibility-semantic preservation across the evaluated assignment set.

---

## Claim 10 — integer-scaled QUBO budget slack

Supported by `compile_to_qubo()`:

- `cost_scale = 1000`,
- integer-scaled budget,
- binary slack variables,
- dominating budget penalty.

**Classification:** DIRECT — CODE + BENCHMARK.

**Drafting caution:** “exact” should be stated relative to the configured/supported 0.001 cost precision, not arbitrary real-valued costs.

---

# 4. Independent Method Claim 11

Claim 11 mirrors the implementation sequence of claim 1:

\[
S_t \rightarrow A'_t \rightarrow R^* \rightarrow E'_t/B'_t \rightarrow SC\!\text{-}IR_t \rightarrow C_t \rightarrow Compile \rightarrow Solve
\]

**Classification:** DIRECT — CODE.

### Strongest clause

The phrase:

> **“in response to removing the decision variable”**

should be retained. It creates an explicit causal connection between domain excision and subsequent structural propagation/regeneration, which aligns with the faculty’s inventive-step emphasis.

---

# 5. Dependent Method Claims 12–20

| Claim | Support | Classification | Note |
|---|---|---|---|
| **12** runtime inadmissibility factors | physical capability, confidence, SLA, encoded policy, learned rules in resolver/adaptive constraints | DIRECT — CODE | “resource state” is broad but consistent with the runtime architecture. |
| **13** prerequisite removal propagation to fixed point | `REQUIRES` path in `compute_fixed_point_closure()` | DIRECT — CODE + BENCHMARK | Strong. |
| **14** preserve/restore failsafe monitor | failsafe pruning protection and explicit `FAILSAFE_RESTORED` path when a domain would become empty | DIRECT — CODE | Strong direct support. |
| **15** provenance information | `IRProvenanceRecord`, closure provenance | DIRECT — CODE | Strong. |
| **16** recompute canonical digest and reject mismatch | `verify_binding()` | DIRECT — CODE + BENCHMARK | Strong. |
| **17** semantic fingerprint and comparison | `SecurityConstraintIR.semantic_fingerprint()`; Experiment 9 full-vs-incremental comparison | DIRECT — CODE + BENCHMARK | Keep distinct from canonical integrity digest. |
| **18** runtime delta + BFS affected subgraph | `compile_delta()` | DIRECT — CODE + BENCHMARK | Strong. |
| **19** learned structural rule sandbox + certification | `FeedbackLearner.admit_candidate_rule_sandboxed()` | DIRECT — CODE + BENCHMARK | Experiment 11 directly supports tested rule admission/rejection. |
| **20** response to simulation/network/cloud/identity/industrial/human interfaces | simulation executor directly present; other interfaces are not implemented | SUPPORTED EMBODIMENT + CONTEMPLATED DEPLOYMENT | For maximum conservatism, phrase as “output in a machine-readable form suitable for delivery to…” rather than implying each live interface is already implemented. |

---

# 6. Independent Computer-Readable-Medium Claim 21

Claim 21 recites the same core computer-executable sequence as claims 1 and 11.

**Classification:** DIRECT — CODE.

It is useful because it protects the instruction-level implementation form independently of a particular physical deployment topology.

---

# 7. Dependent CRM Claims 22–25

| Claim | Support | Classification |
|---|---|---|
| **22** canonical digest + semantic fingerprint | `constraint_ir.py` | DIRECT — CODE |
| **23** QUBO binary slack | `formulation_compiler.py` | DIRECT — CODE + BENCHMARK |
| **24** selective affected-subgraph recompilation + new cert | `incremental_compiler.py` | DIRECT — CODE + BENCHMARK |
| **25** sandboxed learned rule rejection on invariant/feasibility failure | `feedback_learner.py`, certifier | DIRECT — CODE + BENCHMARK |

---

# 8. Claim-to-Source-Code Traceability Table

| Claim concept | Primary source | Key function/class | Supporting evidence |
|---|---|---|---|
| Runtime domain excision | `layer5_constraints/dependency_graph.py` | `ConstraintDependencyGraph.resolve()` | source + tests |
| Fixed-point closure | `layer5_constraints/dependency_graph.py` | `compute_fixed_point_closure()` | Experiment 7 |
| Conflict regeneration | `layer5_constraints/dependency_graph.py` | `compute_fixed_point_closure()` | Experiment 7 |
| Operational-bound metadata | `dependency_graph.py`, `incremental_compiler.py` | closure and delta rebuild | source + Experiment 9 |
| Solver-independent IR | `constraint_ir.py` | `SecurityConstraintIR` | source + tests |
| Canonical digest | `constraint_ir.py` | `compute_canonical_digest()` | tests + Experiment 8 indirectly |
| Semantic fingerprint | `constraint_ir.py` | `semantic_fingerprint()` | Experiment 9 |
| Pre-solve certifier | `safety_certifier.py` | `certify()` | tests, scaling runs |
| Feasibility witness | `safety_certifier.py` | `find_feasibility_witness()` | source + tests |
| Certificate gate | `formulation_compiler.py` | `verify_binding()` | Experiment 8 |
| ILP compiler | `formulation_compiler.py` | `compile_to_ilp()` | Experiment 10 |
| QUBO compiler | `formulation_compiler.py` | `compile_to_qubo()` | Experiment 10 |
| Incremental compiler | `incremental_compiler.py` | `compile_delta()` | Experiment 9 |
| Semantic validator | `semantic_validator.py` | `validate_backend_semantics()` | Experiment 10 |
| Safety-gated learning | `feedback_learner.py` | `admit_candidate_rule_sandboxed()` | Experiment 11 |
| Response plan/execution | Layer 6 + `layer8_orchestration/executor.py` | solver output + `execute_plan()` | simulation only |

---

# 9. Empirical Support That May Be Safely Associated With Claims

The following are useful as **description/examples**, not claim limitations:

### Fixed-point closure

Experiment 7:

- 1 initial removal;
- 2 transitively affected entities;
- 3 total removals;
- depth 2;
- 3 closure iterations;
- dangling dependencies 1→0;
- stale conflicts 1→0.

### Certificate gate

Experiment 8:

- six tested cases;
- zero false accepts.

### Incremental compilation

Experiment 9:

- 10 assets: 3.36% median reduction;
- 50 assets: 21.01%;
- 100 assets: 34.99%;
- 250 assets: 59.89%;
- semantic fingerprint equivalent at each recorded fleet size.

### Backend semantic preservation

Experiment 10:

- 1024 assignments evaluated;
- 21 feasible under SC-IR;
- 21 feasible under ILP;
- 21 semantically valid under QUBO;
- zero mismatches;
- measured SF 100% for the evaluated instance.

### Safety-gated learning

Experiment 11:

- 4 candidate rules;
- 1 safe admission;
- 0 unsafe admissions.

---

# 10. Evidence That Should NOT Become Claim Limitations

Do not narrow the claims by embedding:

- “59.89% faster”;
- “100% Semantic Fidelity”;
- “0/6 false accepts”;
- exact threshold `0.70`;
- exact QUBO scale `1000`;
- exact detector accuracy `98.65%`;
- exact number of seven invariant categories unless strategically desired after professional claim review.

These are embodiments/evidence, not the fundamental inventive mechanism.

---

# 11. Claims Requiring Particular Drafting Care

### Claim 2

Prefer separating prerequisite propagation from mandate consistency because current `MANDATES` behavior records a conflict rather than applying the same removal rule as `REQUIRES`.

### Claim 3

Use “operational or resource-feasibility bounds/metadata” instead of claiming that the entire runtime budget is mathematically regenerated solely as a consequence of pruning.

### Claim 10 / 23

Use integer-scaled slack as an embodiment. Avoid asserting arbitrary-real exactness.

### Claim 20

Current PoC directly supports a simulation executor. Live cloud/network/industrial interfaces are deployment embodiments. Consider:

> “wherein the response plan is generated in a machine-readable representation suitable for a simulation executor, network-control adapter, cloud-control adapter, identity-management adapter, industrial-control adapter, or human-approval workflow.”

This better matches current enablement while preserving broader deployment coverage.

---

# 12. Faculty Inventive-Step Mapping

The faculty’s strongest inventive-step pathway maps directly to Claim 1 as follows:

| Faculty emphasis | Claim 1 element |
|---|---|
| Live state changes decision membership | 1(b)–1(c) |
| Removal causes structural propagation | 1(d) |
| Topology/bounds regenerated | 1(e) |
| Solver-independent representation | 1(f) |
| Pre-solve certification | 1(g)–1(h) |
| Solver cannot run on stale/uncertified state | 1(i) |
| Result used for response | 1(j) |

The core narrative is therefore not scattered across dependent claims; it is already present in one coherent independent claim.

---

# 13. Final Technical Support Verdict

**Claim families 1, 11 and 21 are technically well aligned with the frozen implementation.**

The strongest directly implemented claim concepts are:

\[
\boxed{A \rightarrow A' \rightarrow R^* \rightarrow E'/B' \rightarrow SC\!\text{-}IR \rightarrow Certify \rightarrow Certificate\text{-}Bound\ Compile}
\]

The main drafting cautions are limited and manageable:

1. distinguish prerequisite propagation from mandate-consistency handling;
2. describe regenerated budget/resource information precisely;
3. keep QUBO precision claims scoped to the configured representation;
4. distinguish current simulated actuation from contemplated live adapters;
5. keep empirical percentages in examples/evidence rather than legal claim limitations.

**Technical claim-support status: READY FOR FACULTY / PROFESSIONAL PATENT DRAFTING REVIEW.**
