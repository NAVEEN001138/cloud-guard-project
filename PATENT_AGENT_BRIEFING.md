# Cloud Guardian — Patent Agent Briefing Pack

**Prepared for:** the registered patent agent engaged by Naveen Ravi
**Invention:** System and Method for Runtime Security Constraint Compilation and Pre‑Solve Safety Certification for Automated Infrastructure Response
**Prepared:** 17 September 2026
**Status:** Engineering working draft to support the agent meeting. **Not legal advice.** The claim language below is drafted by an engineer/AI to be refined by the agent; the disclosure analysis flags issues for the agent to assess, not conclusions.

---

## PART 1 — Public disclosure timeline (READ FIRST)

The invention was committed to a **public** GitHub repository (`github.com/NAVEEN001138/cloud-guard-project`) before any patent filing. The repository has since been made **private (17 Sept 2026)**, but that does not undo prior public exposure. The agent must assess the grace‑period consequences.

**Earliest public exposure (from git history — author dates, IST):**

| Date | Event |
|---|---|
| **31 Jul 2026, 01:01** | Initial commit — "Cloud Guardian 9‑Layer Incident Response Platform & IEEE Patent Disclosure" (README, `PATENT_INNOVATION.md`). |
| 31 Jul 2026, 23:24 | IEEE research paper added (`IEEE_RESEARCH_PAPER.md`). |
| 31 Jul 2026, 23:26 | "Formal USPTO/IEEE Patent Application & Specification Disclosure" added. |
| 31 Jul 2026, 23:39 | Indian Patent Complete Specification Form 2 added (`PATENT_DRAFT_INDIA.md`). |
| 05 Aug 2026 | Form‑2 completion, compliance guide. |
| **06 Sep 2026** | Hardened Layer‑5 constraint compiler (`dependency_graph.py`, certificate gate, incremental compiler) first appears — the strongest patentable version. |
| 13 Sep 2026 | V2 documentation set. |
| 17 Sep 2026 | Repo made private; taxonomy fix + cleanup committed. |

**Important caveat on dating:** these are git *commit* dates, not the date the repo actually became publicly visible. The true earliest public‑disclosure date is when the repo was first pushed *and* public. **Confirm the actual public date from GitHub** (repo creation date / first public activity). Treat **31 Jul 2026** as the conservative earliest‑disclosure anchor unless GitHub shows the repo was private until later.

**Questions for the agent:**
1. What is the actual date the repository first became publicly visible? (31 Jul 2026, or later?)
2. **US:** The 12‑month grace period under 35 U.S.C. §102(b)(1) for an inventor's own disclosure appears to run to ~**31 Jul 2027**, leaving ~10.5 months. Should we file a US provisional *immediately* to preserve it?
3. **India:** Does the §31 grace period (Patents Act, 1970) apply to a GitHub disclosure and/or the IEEE paper, and if so what is the deadline?
4. **Absolute‑novelty jurisdictions (EPO and others):** the 31 Jul 2026 disclosure likely bars novelty there. Which jurisdictions are still worth pursuing?
5. **Later effective date for improvements:** does the 06 Sep 2026 hardened Layer‑5 version contain inventive matter *not* present on 31 Jul 2026 (e.g., the certificate‑bound compiler gate, fixed‑point closure, incremental compiler), such that those specific improvements enjoy a later disclosure anchor?

**Bottom line for the agent meeting:** the US route looks materially preservable if you file soon; the absolute‑novelty route is likely already impaired. Filing (at minimum a provisional) is time‑sensitive.

---

## PART 2 — Revised claim set (engineering draft)

Three changes versus the current `PATENT_DRAFT_INDIA.md`, all aimed at fixing self‑inflicted weaknesses:
1. **Hardware‑anchored independent claim leads.** The physical actuation and cyber‑physical control are now integral to Claim 1, not a trailing element — the primary defense against §3(k)/§101 "computer program per se / abstract idea."
2. **No experimental numbers or magic constants in claims.** "100.00% Semantic Fidelity," "S = 1000," and "+59.9%" are removed from claim language and belong only in the specification as embodiments. Claims recite *structure*, not *results*.
3. **Objective structural language** throughout.

### Independent Claim 1 (System — hardware‑anchored)

1. An automated incident‑response system for controlling operational states of one or more cyber‑physical assets, the system comprising:
   - one or more hardware processors;
   - one or more actuation interfaces communicatively coupled to physical control interfaces of the cyber‑physical assets, the actuation interfaces comprising at least one of a Modbus TCP register interface, an OPC‑UA industrial command interface, a network switch forwarding‑table interface, or a cloud hypervisor control‑API interface; and
   - a non‑transitory memory storing instructions that cause the one or more processors to:
     (a) receive a runtime security state comprising threat‑detection indicators and operational attributes of the cyber‑physical assets;
     (b) determine, for each asset, an admissible set of response actions by excluding from a set of candidate response actions each action that is physically or statutorily impermissible for that asset given the asset's type and operational state, such that at least one high‑disruption action is excluded from an asset whose continuous operation is availability‑ or safety‑critical;
     (c) propagate the exclusions to a fixed point across a typed dependency graph, whereby a candidate action whose prerequisite action has been excluded is itself excluded, and dependent mutual‑exclusion relations and operational resource bounds are regenerated over the reduced admissible sets;
     (d) synthesize a solver‑independent intermediate representation of the reduced decision problem, the representation partitioning constraints into hard invariants and soft preferences;
     (e) prior to invoking any solver, deterministically certify the intermediate representation by verifying a plurality of safety invariants and constructing a feasibility‑witness assignment that simultaneously satisfies action‑selection, mutual‑exclusion, statutory‑mandate, and resource‑bound constraints, and bind the certified representation with a cryptographic integrity digest;
     (f) permit compilation of the intermediate representation into a solver‑executable optimization problem only upon cryptographic verification of the certificate's status, version alignment, and integrity digest against the representation, and otherwise reject the compilation;
     (g) solve the compiled optimization problem to select a response action for each asset; and
     (h) dispatch, via the one or more actuation interfaces, machine‑executable control commands corresponding to the selected response actions to the physical control interfaces of the cyber‑physical assets;
   - wherein an action excluded in operation (b) is structurally absent from the compiled optimization problem and therefore cannot be selected in operation (g) or dispatched in operation (h), preventing dispatch of a physically unsafe control command to an availability‑ or safety‑critical cyber‑physical asset.

### Dependent Claims (system)

2. The system of claim 1, wherein the fixed‑point propagation terminates in a number of iterations bounded by the number of candidate actions by enforcing monotonic reduction of the admissible sets, and terminates directed dependency cycles by tracking excluded actions in a closure set.

3. The system of claim 1, wherein the feasibility‑witness assignment is constructed by deterministic backtracking over the reduced admissible sets, and certification fails if no such assignment exists.

4. The system of claim 1, wherein permitting compilation comprises recomputing an integrity digest of the intermediate representation and a digest of the dependency‑closure metadata, and rejecting the compilation upon detecting any of: an uncertified status, an intermediate‑representation version mismatch, a runtime‑state version mismatch, an integrity‑digest discrepancy indicating post‑certification modification of the admissible sets, or a closure‑digest discrepancy indicating post‑certification modification of the dependency graph.

5. The system of claim 1, wherein, responsive to a change in the runtime security state, the instructions cause an incremental recompilation comprising identifying an affected sub‑graph by traversing dependency relations intersecting the change, reusing constraint records outside the affected sub‑graph, recomputing constraint records within the affected sub‑graph, and producing an updated intermediate representation having a mathematical fingerprint equivalent to that produced by full recompilation.

6. The system of claim 1, wherein compiling comprises encoding an operational‑budget inequality constraint into a quadratic unconstrained binary optimization form using binary slack variables scaled by an integer scale factor and weighted to span the budget range without residual discretization error, and a penalty multiplier selected to strictly exceed the maximum attainable objective improvement obtainable by violating the budget constraint.

7. The system of claim 1, wherein the compiled optimization problem is selectively expressed as (i) an integer linear program solved by a classical branch‑and‑cut solver, or (ii) a quadratic unconstrained binary optimization problem solved by a variational quantum circuit or a quantum annealer.

8. The system of claim 7, further comprising a validator that evaluates discrete binary assignments against the certified intermediate representation and each compiled form and verifies that each compiled form preserves the feasible set defined by the certified intermediate representation.

9. The system of claim 1, further comprising an experience memory that proposes candidate constraint rules from post‑incident feedback and admits a proposed rule into future decision problems only after re‑certifying, in a sandbox, that the rule does not restrict a failsafe baseline action, does not reintroduce an excluded action on a cyber‑physical asset, and does not produce an empty admissible set.

10. The system of claim 1, wherein the compiled optimization problem includes a switching‑penalty term that disfavors changing the selected action for an asset between consecutive evaluation cycles, thereby suppressing repeated actuation of a physical control interface.

11. The system of claim 1, wherein the availability‑ or safety‑critical asset comprises a programmable logic controller or a medical device, and the excluded high‑disruption action comprises automated network isolation of that asset.

### Independent Claim 12 (Method)

12. A computer‑implemented method of controlling operational states of one or more cyber‑physical assets, comprising, by one or more processors coupled to actuation interfaces of physical control interfaces of the assets: performing operations (a) through (h) recited in claim 1; wherein an action excluded when determining the admissible set is structurally absent from the compiled optimization problem and cannot be dispatched to a physical control interface.

*(Dependent method claims 13–22 mirror system claims 2–11.)*

### Independent Claim 23 (Non‑transitory computer‑readable medium)

23. A non‑transitory computer‑readable medium storing instructions that, when executed by one or more processors coupled to actuation interfaces of physical control interfaces of one or more cyber‑physical assets, cause the processors to perform operations (a) through (h) of claim 1.

*(Dependent medium claims 24–27 mirror the most important system dependents: incremental recompilation, certificate‑gate rejection, feasibility witness, safety‑gated learning.)*

---

## PART 3 — Revised Field of the Invention

Replace the current scattershot statement (which advertises "combinatorial optimization / intermediate compiler representations / mathematical" and invites a §3(k) rejection) with a technical, hardware‑oriented statement:

> This invention relates to automated incident response and to the real‑time control of physical operational states of cyber‑physical, edge, and cloud infrastructure assets. More particularly, it relates to preventing the dispatch of unsafe or non‑compliant automated control commands to availability‑ and safety‑critical assets — such as programmable logic controllers, medical devices, and network control planes — by determining, verifying, and certifying an admissible set of response actions before an automated decision is computed and actuated on the physical control interfaces of those assets.

Keep the IPC classes (G06F 21/55; G06F 9/455; G06N 10/00; H04L 9/40) — those are fine. The change is to lead with the *technical effect on hardware*, not the mathematics.

---

## PART 4 — Applicant / Inventor block (complete before filing)

The current draft says only "Address: India" — insufficient for filing. The agent will need, for IPO Form 1 and Form 2:

- **Inventor legal name:** Naveen Ravi
- **Nationality:** Indian
- **Full residential address:** *(street, city, state, PIN — fill in)*
- **Applicant** (if different from inventor — e.g., a company or institution): *(name, address, nationality/incorporation)*
- **Category of applicant** (natural person / startup / small entity — affects IPO fees): *(fill in; if a student/individual or recognized startup, reduced fees may apply)*
- **Agent details** (registered patent agent name, IN/PA number, address for service): *(agent to supply)*
- **Priority claim, if any:** *(none, unless an earlier application exists)*

---

## PART 5 — What changed and why (summary for the agent)

| Issue in current draft | Fix in this pack | Reason |
|---|---|---|
| Claim 1 heart is mathematical; actuator is a trailing element | Hardware‑anchored Claim 1 leading with cyber‑physical actuation and the technical effect | Defeat §3(k) / §101 subject‑matter rejection |
| "100.00% Semantic Fidelity" recited in a claim | Removed; claim recites feasible‑set preservation as structure | Results/aspirational limitations are narrow and can be indefinite |
| "S = 1000" hard‑coded in claims | Replaced with "an integer scale factor" + structural penalty condition | Avoids trivial design‑around; claims structure, not a constant |
| "+59.9% latency reduction" implied in claims/spec | Removed from claims | Experimental result, not a claim limitation |
| Field of invention advertises the invention as mathematics | Rewritten to lead with technical effect on hardware | Subject‑matter eligibility |
| Applicant block incomplete | Template with required fields | Filing formality |

**Items still to address (outside this pack):** align the specification's fixed‑point‑closure and metric claims with what the shipping code actually does (the default pipeline needs real dependency edges wired in, and the empirical accuracy figures should be reported as a full curve, not cherry‑picked); these are described in `INDEPENDENT_CODE_AUDIT_REFERENCE.md`.

---

*Engineering draft to support a registered patent agent. All claim language is provisional and must be reviewed and finalized by the agent. The disclosure analysis raises questions for the agent to resolve; it is not a legal determination.*
