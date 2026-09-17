# Prior-Art Analysis — Layer 5 Core Only

**Scope:** the narrow inventive core — the solver-independent Security Constraint IR (SC-IR), the pre-solve safety certifier, the tamper-evident certificate bound to the IR and runtime-state version, and the certificate-bound formulation compiler. Claim 1 elements (f)–(i) of `PATENT_DRAFT_INDIA_V2.md`. The surrounding 9-layer system, the federated detector, and the actuation interfaces are **not** treated as inventive here.

**Method:** web search of academic literature, vendor documentation and Google Patents (September 2026), deliberately in fields the existing `PATENT_INNOVATION.md` matrix does not cover: constraint-programming IRs, proof logging / certified optimisation, safe-RL shielding, pre-deployment network verification, and attestation-gated deployment. This is an engineering search, **not** a professional patentability search; see §6 for what it does not cover.

**Date:** 2026-09-17

---

## 1. Why the existing prior-art file is looking in the wrong place

`PATENT_INNOVATION.md` compares against MARISMA, Boeing, Microsoft, D-Wave, Schneider, Aramco and SOAR patents — all *application-domain* art (security response, quantum hardware). None of those systems has an IR, a certifier or a compiler gate, so the matrix shows the invention winning every row. That is exactly the comparison an examiner will **not** make. The examiner will characterise elements (f)–(i) generically — "a solver-independent model representation, validated before solving, hashed, and refused by a downstream stage if the hash does not match" — and search *those* concepts wherever they occur. Every one of them occurs, individually, in mature prior art below.

---

## 2. Element-by-element prior-art map

### (f) Solver-independent, versioned constraint IR compiled to ≥2 solver targets

| Reference | What it teaches | Overlap |
|---|---|---|
| **MiniZinc → FlatZinc** ([handbook](https://docs.minizinc.dev/en/stable/fzn-spec.html), [flattening](https://docs.minizinc.dev/en/stable/flattening.html)) | A high-level, solver-independent constraint model is compiled to FlatZinc, "a low-level solver input language … designed to be easy to translate into the form required by a solver", then to CP, MIP or SAT back-ends. | **Direct** for "solver-independent IR compiled to multiple solver families". The SC-IR's exactly-one / conflict / budget / objective records all have FlatZinc equivalents. |
| JuMP **MathOptInterface**, Pyomo, CVXPY canonicalisation | Solver-agnostic model objects with pluggable backends. | Same concept, industrial practice for a decade. |
| Canonical IR for LLM-formulated optimisation ([arXiv 2602.02029](https://arxiv.org/pdf/2602.02029)) | 2026 work explicitly naming a "canonical intermediate representation" for optimisation problems. | Shows the phrase itself is now in the literature. |

**Assessment:** (f) is **anticipated generically**. Versioning, provenance records and a hard/soft partition are conventional metadata and will not carry inventive weight on their own. The claim must not rest on the existence of the IR.

### (g) Pre-solve verification of safety invariants + constructive joint-feasible assignment

| Reference | What it teaches | Overlap |
|---|---|---|
| **Google OR-Tools `ValidateCpModel`** | Validates a solver-independent `CpModelProto` for consistency before `Solve()` is ever called and returns an error string. | Pre-solve validation of a solver-independent model — **direct** for the "verify invariants of the IR before formulation" step, though the checks are structural, not policy-semantic, and nothing is emitted. |
| MIP presolve / IIS (Gurobi, CPLEX; e.g. [US6775597B1](https://patents.google.com/patent/US6775597B1/en) infeasibility detection in security-constrained OPF) | Detects infeasibility and tightens bounds *before* the main solve. | Anticipates "determine feasibility before solving" generically. |
| **Dutta et al., *Constraints Satisfiability Driven RL for Autonomous Cyber Defense*, AICA 2021** ([arXiv 2104.08994](https://arxiv.org/abs/2104.08994)) | SMT verification of safety and security requirements inside an autonomous cyber-defence agent's decision loop, steering action selection toward satisfiable actions. | **Same application domain, same idea of formally verifying safety requirements before the response decision.** No IR, no certificate, no compiler gate, no versioning. This is the single most important reference the existing file omits. |
| **Intent-based networking change validation**, [US11539592](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11539592); Batfish ([docs](https://batfish.readthedocs.io/en/stable/notebooks/linked/introduction-to-forwarding-change-validation.html), [SIGCOMM '23](https://dl.acm.org/doi/10.1145/3603269.3604866)) | Verify a planned infrastructure change against network-wide invariants *before* it is pushed; refuse or flag if an invariant would be violated. | Pre-deployment invariant verification of an infrastructure action plan. Anticipates the *purpose* of (g) in the infrastructure domain. |

**Assessment:** pre-solve invariant checking is **known in both the optimisation and the infrastructure domains**. The *constructive feasibility witness* (a concrete joint assignment satisfying exactly-one, conflicts, budget and mandates) is more specific, but an examiner can call it "solving a relaxed feasibility problem", which is routine. (g) contributes limitations, not novelty by itself.

### (h) Tamper-evident certificate bound to the IR digest and the runtime-state version

| Reference | What it teaches | Overlap |
|---|---|---|
| **Proof-carrying code** (Necula & Lee, 1996–97) and certifying compilers | An artefact is shipped with a checkable certificate; the consumer verifies the certificate against the artefact and refuses to run it otherwise. | The **conceptual ancestor** of (h)+(i). Examiner-friendly generic characterisation. |
| **OPA signed bundles** ([docs](https://www.openpolicyagent.org/docs/management-bundles), [PR #2475](https://github.com/open-policy-agent/opa/pull/2475)) | Policy bundle carries a JWT; "for each file the hash of the file must match"; OPA activates the bundle **only if verification succeeds**, otherwise keeps the old one and reports failure. | Hash-bound certificate over a *policy artefact*, refusal on mismatch, staleness handled by keeping the prior version. Very close structurally. |
| **GCP Binary Authorization** ([concepts](https://docs.cloud.google.com/binary-authorization/docs/key-concepts), [attestations](https://docs.cloud.google.com/binary-authorization/docs/attestations)) | An attestation is a signature over the artefact's **digest** asserting that a required check (test, scan) was performed; the enforcer refuses deployment without a valid attestation. | Certificate = "digest + assertion that verification was performed", gate = refuse without it. **Structurally identical to (h)+(i)** in a different domain. |
| **VIPR** (SCIP 10, [arXiv 2511.18580](https://arxiv.org/pdf/2511.18580)), **VeriPB** ([auditable CP solver](https://ciaranm.github.io/papers/cp2022-auditable-solver.pdf), [multi-stage CP proof logging](https://drops.dagstuhl.de/storage/00lipics/lipics-vol307-cp2024/LIPIcs.CP.2024.11/LIPIcs.CP.2024.11.pdf), [formally verified CP certification](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.CP.2026.24)) | Independently checkable certificates for optimisation results, checked *against the FlatZinc model*. | Certificates in optimisation are established — but these certify the **solver's answer after solving**. The invention certifies the **model before solving**. This is a genuine, articulable difference. |
| **Certifying MIP presolve reductions** ([arXiv 2401.09277](https://arxiv.org/abs/2401.09277)) | Certifies that pre-solve *model transformations* preserve feasibility and optimal value. | Closest optimisation-theory art to "certify the transformed model": it certifies transformations of the model, though as a post-hoc proof log, not a gate, and without environment-state binding. |

**Assessment:** "hash the artefact, attach an attestation, refuse downstream without it" is **textbook** across software supply chain, policy engines and PCC. The certificate's *content* — semantic invariant results plus a feasibility witness over a *decision model* — and its binding to a **runtime-state version of live infrastructure** are the only parts not found. Note also that the certificate is a SHA-256 digest, not a signature: it is tamper-*evident*, not unforgeable, and the drafting must not say otherwise (already flagged in the master reference §55).

### (i) Compiler that refuses solver-specific formulation without a valid, current certificate

Covered by the same references as (h): Binary Authorization's enforcer, OPA's activation refusal, and PCC's host check are all "downstream stage refuses to proceed absent a valid certificate over the artefact". What none of them has is (1) the refusing stage being a **model compiler targeting multiple solver families from one certified IR**, and (2) refusal on **runtime-state staleness** (the environment changed since certification), as opposed to artefact mismatch.

### (c)–(e) Domain pruning, fixed-point closure, bound regeneration — *not* claimed as core here, but the examiner will read them

| Reference | Overlap |
|---|---|
| **Safe RL via shielding** — Alshiekh et al., AAAI 2018 ([arXiv 1708.08611](https://arxiv.org/pdf/1708.08611)); preemptive shields "compute a set of all safe actions by removing unsafe actions that would violate the safety specification" ([survey](https://www.emergentmind.com/topics/safe-reinforcement-learning-via-shielding), [online shielding](https://arxiv.org/pdf/2212.01861)) | Removing inadmissible actions from the decision set *before* the decision is made, derived from a formal safety spec. **Direct** for (c). |
| **Action masking in CybORG / autonomous cyber defence** ([entity-based RL](https://arxiv.org/html/2410.17647v3), [survey](https://arxiv.org/html/2310.07745v2)) | Per-entity masks constraining the valid action set at each step, in the cyber-response domain specifically. | Same as above, same domain. |
| Constraint propagation to fixed point (arc consistency; every CP textbook); MIP presolve bound tightening after variable fixing | (d) and (e) are standard CP/MIP machinery. The "typed dependency relations" and "regenerated conflict hyperedges" are a particular encoding of propagation, not a new operation. |

**Assessment:** these elements are fully anticipated as techniques. Their contribution is that they *produce* the certified IR; the claim should say so and no more.

---

## 3. What the search did **not** find

Across all sources examined, no single reference combines:

1. a **versioned, canonicalised model IR** produced by runtime-state-driven structural reconstruction of the decision domain,
2. **pre-solve** verification of policy-semantic invariants **plus a constructive feasibility witness** over that IR,
3. a certificate binding the invariant results and witness to **both** the IR digest **and a version of the live infrastructure state**, such that a state mutation invalidates it, and
4. a **multi-target formulation compiler** that refuses to emit *any* solver-specific model absent a valid, current certificate, followed by
5. exhaustive **semantic-fidelity verification of the emitted backend model against the certified IR** (`semantic_validator.py`) and
6. re-verification of the solved plan against the certified domain **at the actuation boundary** (added 2026-09-17).

Items 3, 5 and 6 are the elements with **no close analogue found**. Item 5 in particular inverts the proof-logging literature: VeriPB/VIPR check a solver's *answer* against the model; this checks the *compiled model* against the certified IR before any answer exists. Item 3 has no analogue in Binary Authorization / OPA, which bind to artefact digests only, nor in IBN verification, which checks current state but emits no certificate.

---

## 4. Realistic risk assessment (core only)

| Ground | Risk | Basis |
|---|---|---|
| **Anticipation (single reference)** | **Low** | No single reference found with items 1–4 together. |
| **Obviousness / inventive step** | **High** | Every element is known; the strongest examiner combination is **Dutta 2021** (SMT safety verification in cyber-defence decision loop) + **MiniZinc/FlatZinc** (solver-independent IR to multiple backends) + **Binary Authorization / OPA signed bundles** (digest-bound attestation gating a downstream stage). Each step is a known technique applied for its known purpose. The rebuttal must show a *non-obvious functional result* of the combination — the strongest candidates are staleness invalidation against runtime state (item 3) and IR↔backend semantic fidelity (item 5), which none of the three teaches or motivates. |
| **Eligibility (India §3(k) / US §101)** | **Medium** | Elements (f)–(i) are entirely data-domain. The core alone is *more* exposed than the full system; the hardware actuation nexus was what mitigated this. Narrowing to the core therefore **trades eligibility risk for inventive-step strength**. Mitigation: tie the certificate to a version of *measured infrastructure state* and the gate to *emission of an executable control formulation*, and keep the actuation-boundary check (item 6) as a dependent claim so the "particular machine" link survives. |
| **Term collision** | Low, but fix now | "Safety certificate" is an established term in control theory (barrier certificates, Lyapunov certificates). Define the term explicitly or use "constraint safety attestation" to avoid an examiner importing the control-theory meaning. |

---

## 5. Drafting recommendations for the narrowed independent claim

Retain (f)–(i) as the independent claim and add the limitations that the search shows are *not* in the art:

1. **Bind the certificate to a runtime-state version and make staleness a refusal ground.** Draft: *"…the certificate further comprising an identifier of the version of the runtime state from which the intermediate representation was generated, and the compiler refusing generation when the current runtime-state version differs from the identifier."* No found reference binds a model certificate to environment state.
2. **Require the feasibility witness in the certificate**, not merely invariant flags. Distinguishes from OR-Tools validation, Batfish and Binary Authorization, none of which emit a constructive assignment.
3. **Require ≥2 solver targets from the same certified IR.** Turns the FlatZinc analogy into a limitation the certificate must satisfy for every target, and sets up item 5.
4. **Add post-compilation semantic-fidelity verification of the emitted formulation against the certified IR** as an element of the independent claim (currently only implied via `semantic_validator.py`). This is the element with no analogue in proof logging, which certifies answers rather than models.
5. **Keep the actuation-boundary re-verification as dependent claim** (new since 2026-09-17): *"…wherein a response plan obtained from the solver is verified against the admissible domain and budget of the certified intermediate representation prior to emission of any control command."* This is the eligibility anchor when the independent claim is data-only.
6. **Demote (c)–(e)** to "wherein the intermediate representation is generated by…" language. They are anticipated by shielding, action masking and constraint propagation and should not be positioned as the invention.
7. **Do not describe the digest as a signature** or the certificate as unforgeable.

---

## 6. Limits of this search — what a professional search must add

- **No full-text patent database search.** Only Google Patents via web search; no Espacenet, Lens, USPTO PatFT/PPUBS full-text, no classification-based (CPC G06F 21/57, G06N 5/01, H04L 63/20, G06Q 10/04) sweep.
- **No non-English patents.** CN, KR and JP filings dominate automated security response and quantum-formulation patents; CN114070629B is already cited in the repo, suggesting more exist.
- **Not reviewed in full:** Dutta 2021 (abstract only — the full paper must be read to establish whether SMT verification gates action *execution*, which would move it from (g)-relevant to (i)-relevant), US11539592 claims, US11750657B2 (cyber digital twin for security-controls requirements).
- **Not searched:** formal-methods work on verified MiniZinc flattening (would bear directly on item 5); runtime-assurance / Simplex-architecture patents (bear on item 6); quantum-formulation verification patents from Zapata, QC Ware, Quantinuum.
- The **19 MB PatentLens report** already in hand should be read specifically against items 3 and 5, since those are the only elements the present search could not find.

---

## 7. References to add to `PATENT_INNOVATION.md` and any IDS

Academic: Alshiekh et al. 2018 (AAAI); Dutta et al. 2021 (AICA); Gocht/McCreesh/Nordström auditable CP solver (CP 2022); multi-stage CP proof logging (CP 2024); certifying MIP presolve (2024); formally verified CP certification (CP 2026).
Systems: MiniZinc/FlatZinc; OR-Tools `ValidateCpModel`; OPA bundle signing; GCP Binary Authorization; Batfish.
Patents: US11539592 (IBN change validation); US6775597B1 (pre-solve infeasibility detection); US11750657B2 (cyber digital twin, security controls); US11563755 (Fortinet SOAR playbook generation, already partly cited).

*Engineering prior-art survey supporting the patent-agent engagement. Not a legal opinion and not a substitute for a professional patentability search.*
