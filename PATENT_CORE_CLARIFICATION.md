# Cloud Guardian — Patent Core and Novelty Clarification

**For:** patent agent, technical reviewers, faculty examiners
**Subject:** precise statement of the claimed subject matter, its mechanism, its support in code, and its position against the closest prior art
**Reference drawing:** FIG. 6, `patent_v2_fig6_layer5_patent_core.png` (reference numerals 500–595)
**Companion documents:** `PRIOR_ART_LAYER5_CORE.md` (prior-art search), `INDEPENDENT_CODE_AUDIT_REFERENCE.md` (code audit), `PATENT_DRAFT_INDIA_V2.md` (current full draft)
**Date:** 2026-09-17

---

## 1. Statement of the claimed subject matter

> **The invention compiles the live security state of an infrastructure into a new admissible decision space, certifies that mathematical space, and only then permits an optimisation formulation to be generated from it.**

The claimed subject matter is confined to **Layer 5** of the implementation — the *runtime security constraint compiler* — and specifically to the ordered combination of:

| Ref. | Element | Role in the claim |
|---|---|---|
| 520–540 | Runtime-state-driven **transformation of decision-domain membership**, with fixed-point dependency closure and regeneration of dependent relations and bounds | The mechanism that *produces* the certified object |
| 550 | A **versioned, solver-independent Security Constraint Intermediate Representation (SC-IR)** of the transformed domain | The certified object |
| 560–570 | **Pre-solve certification** of the SC-IR — invariant verification and a constructive joint-feasible witness — producing a **certificate bound to the IR digest and to the runtime-state version** | The safety attestation |
| 580–590 | A **certificate-bound multi-target compiler** that refuses to emit any solver-specific formulation when the certificate is absent, failed, mismatched, or stale, and verifies the emitted formulation's **semantic fidelity** to the certified IR | The enforcement mechanism |
| 595 | Re-verification of the solved plan against the certified domain at the **actuation boundary** | Dependent claim; machine-link anchor |

### 1.1 What is expressly *not* claimed as inventive

| Component | Status |
|---|---|
| Machine-learning / federated threat detection, threat scoring, confidence tiers | Supporting input to Layer 5 (runtime state S_t) |
| Integer linear programming, QUBO, QAOA, any solver | Downstream backend; the compiler targets them, the invention is not them |
| SHA-256 | Integrity primitive; tamper-evident digest, **not** a digital signature |
| Modbus, OPC-UA, OpenFlow, cloud control-plane APIs | Actuation embodiments; implemented as protocol command builders, not live device I/O |
| Fixed-point iteration, constraint propagation, variable elimination | Known techniques; claimed only as the means by which the IR is produced |
| Solver-independent modelling languages as such | Known (MiniZinc/FlatZinc, MathOptInterface); the IR's *existence* carries no weight |

The distinction matters because the surrounding nine-layer system, evaluated as a whole, is an assembly of known components. Evaluated at the wrong scope, the invention will appear to be "ML + ILP + QUBO + security automation". Evaluated at the correct scope, the question becomes whether the *ordered combination* in §1 is disclosed or rendered obvious — a question the prior-art search in `PRIOR_ART_LAYER5_CORE.md` addresses directly.

---

## 2. Technical problem

Automated infrastructure response selects mitigation actions (isolate, rotate credentials, block, snapshot, monitor …) for affected resources under competing objectives — containment, business impact, downtime, budget. Optimisation-based approaches formulate this as a combinatorial problem and hand it to a solver.

Three deficiencies arise when the response domain contains cyber-physical or regulated assets:

1. **The action set is fixed at design time.** Whether isolating a programmable logic controller is *admissible* depends on its current operational state, but the decision variable `x[PLC, isolate]` exists in the model regardless, and inadmissibility is expressed by a constraint or a penalty on that variable.
2. **Safety is delegated to the solver.** Whether a forbidden action is avoided depends on the solver honouring a hard constraint (exact solvers) or on a penalty out-weighing the containment reward (heuristic, approximate and quantum solvers, where hard constraints are not guaranteed in the returned assignment).
3. **No artefact attests that the model handed to the solver is the model that was checked.** A model may be mutated, re-generated from stale state, or compiled by a different backend between verification and solving, with nothing downstream able to detect it.

The invention addresses all three by moving safety **upstream of the optimiser and into an attested artefact**.

---

## 3. Mechanism (FIG. 6)

### 3.1 Domain transformation (510–520)

For each resource *i* with candidate action set A_i, the runtime state S_t determines an inadmissible subset. The admissible domain is

  A'_i = A_i − Inadmissible(i, S_t)

A decision variable is created **only** for (i, a) with a ∈ A'_i. An inadmissible action has no variable; it is not constrained to zero, it is absent.

### 3.2 Fixed-point dependency closure (530)

Removal has consequences. Declared typed relations (`REQUIRES`, `MANDATES`, `CONFLICTS_WITH`, `CONSUMES_RESOURCE`, `DERIVES_BOUND`, `PROTECTS_FAILSAFE`) are propagated:

  R_{k+1} = R_k ∪ DependentConsequences(R_k),  iterated until R_{k+1} = R_k =: R*

A dependent whose prerequisite has been removed is itself removed; the iteration is deterministic and terminates (cycle guard, `test_03`; provenance of every transitive removal, `test_04`). The default pipeline exercises a two-hop cascade (PLC → gateway → HMI) with no explicit edges supplied (`test_35`).

### 3.3 Regeneration (540)

After R*, the conflict topology E' and the operational bounds B' (effective budget, minimum achievable cost, budget-consistency indicator, active variable/conflict counts) are recomputed over the *remaining* domain. Bound regeneration has a single owner in the compiler (`test_36`).

### 3.4 Versioned SC-IR (550)

The result is serialised as a canonical, solver-independent representation carrying: variable domains (admissible and pruned actions with provenance), exactly-one invariance constraints, conflict hyperedges, hard budget constraint with cost map, objective terms with component decomposition, dependency-closure metadata, `ir_version`, `runtime_state_version`, and a canonical digest invariant to serialisation order (`test_06`, `test_07`, `test_08`).

### 3.5 Pre-solve certification (560–570)

Before any solver-specific object exists, the certifier verifies seven invariants over the IR (non-empty domains, exactly-one well-formedness, conflict referential integrity, budget consistency, mandate satisfiability, provenance completeness, closure convergence) **and constructs a joint-feasible assignment** satisfying exactly-one, conflict, budget and mandate constraints simultaneously — a witness that the certified problem is solvable (`test_28`). On success it emits a certificate containing: the IR digest, the closure digest, `ir_version`, `runtime_state_version`, the invariant results, the witness, and a certificate integrity digest over those fields.

### 3.6 Certificate-bound compilation (580–585)

The compiler **refuses** to generate a formulation when the certificate is absent, when its status is not CERTIFIED, when `ir_version` or `runtime_state_version` differ from the IR's, when the IR digest, closure digest or certificate digest do not match, or when any invariant result is false (`tests 09–13, 26, 29, 30`). On success the *same* certified IR is compiled to at least two solver families (ILP and QUBO).

### 3.7 Semantic fidelity (590)

The emitted backend model is checked exhaustively against the certified IR over all binary assignments of the active variables: an assignment is feasible in the backend model if and only if it is feasible in the IR (`tests 17, 24, 25`; Experiment 10, 1024/1024). This is performed before the solver is invoked and detects a compiler defect or a mutated backend model.

### 3.8 Actuation-boundary re-verification (595, dependent)

A plan returned by the solver is verified against the certified admissible domain and budget before any control command is emitted (`test_37`).

---

## 4. Worked example

An industrial PLC (`plc-node-01`) is under attack with threat score 0.90 and detection confidence 0.93. Its safety profile forbids automated network isolation.

**Conventional formulation.** Variables x[PLC, a] for all seven actions; add constraint x[PLC, isolate] = 0, or add penalty λ to its objective coefficient.

**This invention.**
A'_PLC = {rotate_credentials, monitor, increase_logging}. No variable x[PLC, isolate] is created. Provenance records `PRUNED / PHYSICAL_SAFETY_PROFILE / SAFETY_PROFILE_PLC_CONTROLLER`. If a downstream gateway declares `requires_isolation_with: [plc-node-01]`, closure removes x[gateway, isolate] as an unsatisfiable prerequisite (`UNSATISFIED_PREREQUISITE`), and the HMI depending on the gateway loses it in the second hop. Bounds are regenerated over the remaining variables. The IR is certified; the certificate is bound to the IR digest and state version; ILP and QUBO are compiled from it; both are checked for fidelity; the returned plan is re-checked at actuation.

Measured on the implementation (`run_constraint_compiler_benchmark.py`, Experiment 1): the same threat signal (s = 0.85, c = 0.92) applied to five asset types produces five structurally different problems — 3 to 5 variables, different conflict topologies, different graph densities — not one problem with different coefficients.

---

## 5. Why structural absence is not merely a constraint or a penalty

This point must be stated carefully, because an examiner will observe — correctly — that for an **exact** solver, removing a variable and fixing it to zero yield the identical feasible set and optimum, and that MIP presolve routinely eliminates fixed variables. The distinction is therefore **not** mathematical for exact solvers. It is real in three respects, each supported by evidence in the repository:

**5.1 Heuristic, approximate and quantum backends.** QAOA, annealers and greedy heuristics do not guarantee that hard constraints hold in the returned assignment. A penalised variable can be selected by an imperfect solver; an absent variable cannot. The invention's guarantee is therefore *solver-independent*, which is precisely why the IR is solver-independent and why a QUBO target is a first-class backend rather than an afterthought.

**5.2 Calibration independence (measured).** Experiment 6 executes a parameter-only baseline in which every action remains a live variable and policy is expressed only as an additive penalty λ. With λ = 0 it selects forbidden actions on 40.0 % of assets; compliance is restored only for λ ≥ λ* = 0.25 in the benchmark configuration; and λ* scales approximately linearly with the threat-utility weighting (≈ 0.33·*w*: 0.15 at *w* = 1, 8.15 at *w* = 25, 33.3 at *w* = 100). The penalty baseline is therefore safe only within a configuration-specific region that must be re-derived whenever utilities, costs or threat scaling change, and nothing in that architecture attests that the deployed λ is inside it. The structural approach is compliant for every λ and every *w* because the variable does not exist. **Safety is obtained as a structural invariant, not as a numerical tuning outcome.**

**5.3 Attestation.** A constraint or penalty is a property of one model instance. The certificate is a *checkable artefact* stating that a specific, digest-identified, state-versioned model satisfies the invariants and is feasible — and downstream stages refuse to proceed without it. The property becomes verifiable by a party that did not construct the model.

The claim should rest on 5.2 and 5.3, with 5.1 as the motivating deployment context. It should **not** rest on "the variable does not exist" as a bare mathematical assertion.

---

## 6. Redrafted independent claim (proposed)

The current Claim 1 in `PATENT_DRAFT_INDIA_V2.md` recites elements (a)–(j). Elements (a)–(e) are individually anticipated by safe-RL shielding, action masking and constraint propagation; elements (f)–(i) are individually anticipated by FlatZinc, OR-Tools model validation, OPA signed bundles and Binary Authorization. The elements the prior-art search could **not** find — runtime-state-version binding with staleness refusal, the feasibility witness as certificate content, and IR-to-backend semantic fidelity — are not currently limitations of the independent claim. The following redraft moves them in and demotes (a)–(e) to the means by which the IR is produced.

> **1.** A computer-implemented system for generating an optimisation formulation for automated infrastructure response, comprising:
>
> (a) an intermediate-representation generator configured to generate, from a runtime state of a plurality of infrastructure resources having an associated **runtime-state version**, a solver-independent security constraint intermediate representation, wherein the intermediate representation comprises, for each infrastructure resource, an admissible decision domain from which one or more candidate response actions determined inadmissible under the runtime state have been **removed**, and further comprises constraint relations and operational bounds **regenerated over the admissible decision domains after iterative propagation of the removal through declared dependency relations to a fixed point**;
>
> (b) a pre-solve certifier configured, prior to generation of any solver-specific formulation, to verify a plurality of safety invariants of the intermediate representation **and to construct a joint response assignment that simultaneously satisfies an exactly-one requirement, a conflict requirement, a resource-budget requirement and any mandated-action requirement of the intermediate representation**;
>
> (c) a certificate generator configured, responsive to successful verification, to generate a tamper-evident certificate comprising **a canonical digest of the intermediate representation, the runtime-state version from which the intermediate representation was generated, the invariant results, and the constructed joint response assignment**;
>
> (d) a certificate-bound formulation compiler configured to **refuse** generation of a solver-specific optimisation formulation when the certificate is absent, when any invariant result is unsatisfied, when the canonical digest does not correspond to the intermediate representation, **or when the runtime-state version recorded in the certificate differs from a current runtime-state version**, and otherwise to generate, from the same certified intermediate representation, **solver-specific optimisation formulations for at least two distinct solver families**; and
>
> (e) a semantic-fidelity verifier configured, **prior to invocation of any solver**, to verify that each generated solver-specific formulation admits an assignment of the decision variables of the admissible decision domains as feasible **if and only if** the intermediate representation admits that assignment as feasible.

> **2.** The system of claim 1, wherein the declared dependency relations comprise at least a typed prerequisite relation and a typed conflict relation, and wherein the iterative propagation removes a dependent candidate response action whose prerequisite has been removed and regenerates at least one conflict relation referencing a removed decision variable.
>
> **3.** The system of claim 1, wherein the regenerated operational bounds comprise an effective response budget derived from the runtime state by a single bound-regeneration stage, and wherein the constructed joint response assignment satisfies the effective response budget.
>
> **4.** The system of claim 1, wherein the certificate further comprises a digest of dependency-closure metadata and a certificate integrity digest computed over the certificate's fields, and the formulation compiler further refuses generation when either digest does not correspond.
>
> **5.** The system of claim 1, further comprising an incremental compiler configured to receive a runtime-state delta, identify affected infrastructure resources, expand the affected set through the declared dependency relations, reuse unaffected components of the intermediate representation, regenerate affected components, increment the runtime-state version, and obtain a new certificate, whereby a certificate generated for the prior runtime-state version is refused by the formulation compiler.
>
> **6.** The system of claim 1, further comprising a response verifier configured to receive a response plan from a solver operating on a generated solver-specific formulation and to **refuse emission of any control command** to an infrastructure resource when the response plan assigns to that resource an action outside its admissible decision domain in the certified intermediate representation, or when the cost of the response plan exceeds the certified effective response budget.
>
> **7.** The system of claim 6, wherein emission of a control command comprises constructing a protocol-specific control payload for at least one of an industrial controller register interface, an industrial OPC-UA method interface, a network-switch forwarding-table interface, or a cloud control-plane interface.
>
> **8.** The system of claim 1, wherein the at least two distinct solver families comprise an integer linear programming formulation and a quadratic unconstrained binary optimisation formulation, and wherein the semantic-fidelity verifier verifies both against the same certified intermediate representation.
>
> **9.** The system of claim 1, wherein at least one solver family is a heuristic, approximate or quantum solver for which satisfaction of hard constraints in a returned assignment is not guaranteed, and wherein the removal of inadmissible candidate response actions from the admissible decision domain precludes selection of a removed action by that solver independently of any penalty weighting.

Method and computer-readable-medium claims mirror claim 1. Claims 6–7 preserve the hardware nexus for subject-matter eligibility when the independent claim is data-domain. Claim 9 captures §5.1 explicitly.

---

## 7. Claim-element support matrix

| Claim element | Module | Verified by |
|---|---|---|
| 1(a) removal, closure, regeneration, versioned IR | `layer5_constraints/dependency_graph.py` (`resolve`, `compute_fixed_point_closure`, `extract_scenario_dependencies`), `constraint_ir.py` | tests 01–08, 20, 35, 36, 38; Experiments 1, 3, 7 |
| 1(b) invariants + joint-feasible witness | `safety_certifier.py` (`certify`, witness search) | tests 13, 27, 28; Experiment 2 |
| 1(c) certificate content and binding | `safety_certifier.py` (`ConstraintSafetyCertificate`) | tests 12, 16, 29, 30; Experiment 8 |
| 1(d) refusal conditions, two solver families | `formulation_compiler.py` (`verify_binding`, `compile_to_ilp`, `compile_to_qubo`) | tests 09–13, 21–23, 26; Experiment 6 Variant D (4/4 detected) |
| 1(e) semantic fidelity before solve | `semantic_validator.py` | tests 17, 24, 25; Experiment 10 (1024/1024) |
| 2 typed relations, conflict regeneration | `dependency_graph.py` | tests 02, 05, 31, 35, 38 |
| 3 single-owner effective budget | `dependency_graph.py`, `adaptive_constraints.py` | test 36 |
| 5 incremental recompilation, version increment | `incremental_compiler.py` | tests 31–34; Experiment 9 |
| 6 actuation-boundary refusal | `layer8_orchestration/executor.py` (`validate_plan_against_certified_ir`) | test 37 |
| 7 protocol-specific payloads | `executor.py` (four actuator classes) | `verify_system.py` Layer 8; simulated I/O |
| 9 heuristic/quantum backend | `formulation_compiler.py` QUBO path, `decision_engine.py` | `verify_system.py` Layer 6 |

All 38 tests pass; 10/10 layer verification; Experiments 1–11 execute (2026-09-17).

---

## 8. Position against the closest prior art

Full analysis in `PRIOR_ART_LAYER5_CORE.md`. Summary of the distinguishing limitation for each closest reference:

| Closest reference | What it teaches | Limitation in claim 1 it lacks |
|---|---|---|
| Alshiekh et al. 2018 (safe-RL shielding); action masking in autonomous cyber defence | Removing unsafe actions from the agent's choice set before decision | No model IR, no regeneration of dependent relations, no certificate, no compiler; the shield acts on an RL policy, not on a compiled optimisation formulation |
| **Dutta et al. 2021** (SMT-verified autonomous cyber defence) | Optimiser recommends over the full action space; SMT vetoes the chosen action before execution | **Opposite ordering.** Constraints are deliberately kept out of the optimiser and verified post-decision; nothing is removed from the domain, no artefact is produced, nothing is compiled. Teaches away from pre-solve domain certification. |
| MiniZinc/FlatZinc, MathOptInterface | Solver-independent model compiled to multiple solver families | No runtime-state-driven domain transformation; no certification; no gate; no state-version binding |
| OR-Tools `ValidateCpModel`; MIP presolve | Model validated / reduced before solve | Emits no certificate; no witness; nothing downstream refuses; not bound to environment state |
| VeriPB / VIPR proof logging; certified presolve reductions | Independently checkable certificates in optimisation | Certify the solver's **answer** (or a transformation) *after* the fact; the invention certifies the **model** *before* any solver exists, and checks the compiled model against it (1(e)) |
| OPA signed bundles; GCP Binary Authorization; proof-carrying code | Digest-bound attestation; downstream refuses without it | Attest **provenance** of an artefact, bound to its digest only. The invention's certificate attests **semantic properties of a decision model** (invariants + feasibility witness) and is bound to a **version of live infrastructure state**, so that state mutation — not only artefact mutation — invalidates it |
| Intent-based networking change validation (US11539592), Batfish | Verify planned infrastructure change against invariants before pushing | Verification of a *configuration*, not of an optimisation decision domain; no certificate, no compiler, no solver |

No single reference found teaches the ordered combination of claim 1. The inventive-step position rests on (i) Dutta's teaching away, (ii) the absence in all found art of state-version-bound staleness refusal (1(d)) and pre-solve model-to-backend fidelity (1(e)), and (iii) the measured calibration-independence result (§5.2).

---

## 9. Questions the reviewer is asked to evaluate

Rather than "is Cloud Guardian novel?", the reviewer is asked:

| # | Question | Evidence |
|---|---|---|
| 1 | Does runtime infrastructure/security state change the **membership** of the optimisation decision domain, not merely coefficient values? | §3.1, §4; Experiment 1 (5 structurally distinct problems from one signal); `test_20`, `test_35` |
| 2 | After a variable is removed, are the **structural consequences propagated** and the affected relations and bounds **regenerated**? | §3.2–3.3; `test_02`, `test_05`, `test_31`, `test_35`; Experiment 7 |
| 3 | Is the result represented in a **solver-independent, versioned IR** before any backend formulation exists? | §3.4; `test_06`, `test_07`, `test_08` |
| 4 | Is the IR **certified before solving** — invariants and a constructive feasibility witness — rather than relying on the solver to discover feasibility? | §3.5; `test_13`, `test_27`, `test_28`; Experiment 2 |
| 5 | Is compilation **bound to the certified IR and its state version**, so that a mutated or stale model cannot proceed? | §3.6; tests 09–13, 26, 29, 30; Experiment 8 (0 false accepts / 6 vectors), Experiment 6-D (4/4) |
| 6 | Is the **compiled backend model verified against the certified IR** before the solver runs? | §3.7; tests 17, 24, 25; Experiment 10 |
| 7 | Is the certified decision space **re-checked at the actuation boundary**? | §3.8; `test_37` |
| 8 | Is the safety property **independent of penalty calibration**, in contrast to a parameter-only baseline? | §5.2; Experiment 6 (executed sweep) |

---

## 10. Disclosures the reviewer should have

- **Actuation is simulated.** The four actuator classes construct correct protocol payloads (including a valid IAM key-rotation sequence and an `aws:TokenIssueTime` session-revocation policy) but open no socket; every record is reported `simulated_success`. Claim 7 is supported as an embodiment of payload construction, not as demonstrated device control.
- **The certificate is tamper-evident, not unforgeable.** It uses SHA-256 digests, not asymmetric signatures. A signing embodiment is straightforward but is not implemented.
- **Exact-solver equivalence.** For exact solvers, structural removal and zero-fixing are mathematically equivalent (§5). The claim is positioned on solver independence, calibration independence and attestation, not on the bare removal.
- **Eligibility.** Claim 1 as redrafted is data-domain. Claims 6–7 carry the machine link; the agent should assess whether the independent claim needs an actuation element for the target jurisdiction.
- **Machine-learning metrics are not relied upon.** Detector accuracy figures in other documents are supporting context only and are known to require methodological review; none of the claim elements depends on them.
- **Search limits.** `PRIOR_ART_LAYER5_CORE.md` is a web-based engineering search. No full-text patent database, no CPC classification sweep, and no CN/KR/JP filings were searched. A professional patentability search remains required before filing.

---

## 11. Reference numerals (FIG. 6)

| Numeral | Element | Numeral | Element |
|---|---|---|---|
| 500 | Layer 5 claimed core (trust boundary) | 570 | Safety certificate |
| 510 | Feasibility evaluation | 580 | Certificate-bound gate |
| 520 | Domain transformation | 585 | Multi-target compiler |
| 530 | Fixed-point closure | 590 | Semantic fidelity check |
| 540 | Regeneration (topology, bounds) | 595 | Actuation-boundary re-check (dependent) |
| 550 | Versioned SC-IR | — | Solver, actuation interfaces (unclaimed) |
| 560 | Pre-solve certifier | — | Runtime state, declared policy (inputs) |

*Prepared to fix the scope of the patent assessment. It states what is claimed, what is not, and how each limitation is supported; it does not assert a patentability outcome.*
