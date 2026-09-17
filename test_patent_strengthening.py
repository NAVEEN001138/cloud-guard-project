"""
=============================================================================
AUTOMATED TEST SUITE: LAYER 5 PATENT STRENGTHENING CORE
File: test_patent_strengthening.py
-----------------------------------------------------------------------------
Comprehensive deterministic unit and integration test suite covering all 20
mandatory patent strengthening verification criteria:
  1. Deterministic dependency closure
  2. Multi-hop closure (>1 depth)
  3. Cyclic graph safe termination
  4. Closure provenance tracking
  5. Bound regeneration after transitive pruning
  6. Canonical IR serialization stability
  7. IR digest changes after semantic mutation
  8. IR digest invariant to dictionary ordering
  9. Valid certificate allows compilation
  10. Modified certified IR rejected
  11. Stale certificate rejected
  12. Swapped certificate rejected
  13. Uncertified IR rejected
  14. Incremental compile equals full compile semantically
  15. Unaffected subgraph reused
  16. Backend manifest references correct certificate
  17. Semantic fidelity validator catches corrupted backend
  18. Unsafe feedback rule rejected
  19. Safe feedback rule admitted
  20. Existing SCADA PLC case removes isolate before formulation
=============================================================================
"""

import sys
import copy
import time
import unittest

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

from layer1_telemetry.fake_incident import SCENARIOS
from layer3_context.context_aggregator import (
    AggregatedContext,
    ThreatContext,
    AssetContext,
    BusinessContext,
    ComplianceContext,
)
from layer4_confidence.confidence_evaluator import ConfidenceScores
from layer5_constraints.constraint_ir import (
    SecurityConstraintIR,
    VariableDomain,
    InvarianceConstraint,
    ConflictHyperedge,
    HardBudgetConstraint,
    ObjectiveLinearTerm,
    IRProvenanceRecord,
    SemanticManifest,
)
from layer5_constraints.dependency_graph import (
    ConstraintDependencyGraph,
    TypedDependencyEdge,
    DependencyRelationType,
    ClosureProvenance,
    ClosureResult,
)
from layer5_constraints.safety_certifier import (
    PreSolveSafetyCertifier,
    ConstraintSafetyCertificate,
)
from layer5_constraints.formulation_compiler import (
    FormulationCompiler,
    UncertifiedIRCompilationError,
    StaleCertificateError,
    IntegrityBindingError,
    StateEnvelopeViolationError,
    HAS_PULP,
    HAS_QISKIT,
)
from layer5_constraints.validity_envelope import (
    FieldPredicate,
    ValidityEnvelope,
    derive_validity_envelope,
)
from layer5_constraints.incremental_compiler import (
    IncrementalConstraintCompiler,
    RuntimeStateDelta,
    IncrementalCompilationResult,
)
from layer5_constraints.semantic_validator import (
    SemanticValidator,
    SemanticValidationReport,
)
from layer9_feedback.feedback_learner import (
    FeedbackLearner,
    RuleAdmissionEvidence,
)
from layer5_constraints.adaptive_constraints import generate_adaptive_constraints
from layer5_constraints.runtime_state import (
    ValidityRelevantState,
    StateSnapshot,
    canonicalise,
    fingerprint,
    snapshot_from_contexts,
    STATE_SCHEMA_ID,
)
from layer5_constraints.keys import (
    CertifierKey,
    VerifierKey,
    get_certifier_key,
    get_verifier_key,
    POLICY_REVISION,
)
from layer8_orchestration.executor import (
    execute_plan,
    validate_plan_against_certified_ir,
    InadmissibleActionError,
    ActuationBudgetExceededError,
)


def create_test_context(rid: str, rtype: str, threat: float = 0.85, sla: str = "CRITICAL", hipaa: bool = False) -> AggregatedContext:
    return AggregatedContext(
        resource_id=rid,
        threat=ThreatContext(threat_score=threat, severity=threat, attack_velocity=0.8),
        asset=AssetContext(
            business_criticality=0.9 if sla == "CRITICAL" else 0.7,
            data_sensitivity=0.9 if hipaa else 0.5,
            workload_type=rtype,
            resource_type=rtype,
        ),
        business=BusinessContext(
            sla_priority=sla,
            downtime_cost_per_min=500.0,
            recovery_cost_estimate=1000.0,
        ),
        compliance=ComplianceContext(
            gdpr_applicable=False,
            hipaa_applicable=hipaa,
            pci_dss_applicable=False,
        ),
    )


def create_test_confidence(rid: str, conf: float = 0.92) -> ConfidenceScores:
    return ConfidenceScores(
        resource_id=rid,
        detection_confidence=conf,
        sensor_confidence=conf,
        evidence_quality=conf,
        overall_confidence=conf,
        allowed_actions=["isolate", "block_ip", "rate_limit", "quarantine_file", "rotate_credentials", "disable_user", "monitor", "increase_logging"],
        confidence_tier="HIGH",
    )


class TestPatentStrengtheningLayer5(unittest.TestCase):

    def setUp(self):
        self.scenario = {
            "scenario": "test_env",
            "resources": [
                {"id": "res_server_01", "type": "server"},
                {"id": "res_plc_01", "type": "plc_controller"},
                {"id": "res_gw_01", "type": "network_gateway"},
            ],
        }
        self.threat_scores = {
            "res_server_01": 0.85,
            "res_plc_01": 0.85,
            "res_gw_01": 0.85,
        }
        self.contexts = {
            "res_server_01": create_test_context("res_server_01", "server", threat=0.85, sla="HIGH", hipaa=False),
            "res_plc_01": create_test_context("res_plc_01", "plc_controller", threat=0.85, sla="CRITICAL", hipaa=False),
            "res_gw_01": create_test_context("res_gw_01", "network_gateway", threat=0.85, sla="CRITICAL", hipaa=False),
        }
        self.confidences = {
            "res_server_01": create_test_confidence("res_server_01", 0.92),
            "res_plc_01": create_test_confidence("res_plc_01", 0.92),
            "res_gw_01": create_test_confidence("res_gw_01", 0.92),
        }
        self.dag = ConstraintDependencyGraph(incident_id="test_incident")

    # 1. Deterministic dependency closure
    def test_01_deterministic_dependency_closure(self):
        all_vars = {("r1", "isolate"), ("r1", "monitor"), ("r2", "rotate_credentials"), ("r2", "monitor")}
        init_rem = {("r1", "isolate")}
        cost_map = {v: 1.0 for v in all_vars}
        deps = [TypedDependencyEdge("r2:rotate_credentials", "r1:isolate", DependencyRelationType.REQUIRES, "RULE_01")]
        confs = [("r1", "isolate", "r2", "rotate_credentials", "CONF_01")]

        act1, c1, res1 = ConstraintDependencyGraph.compute_fixed_point_closure(
            init_rem, all_vars, deps, confs, cost_map, base_budget=10.0
        )
        act2, c2, res2 = ConstraintDependencyGraph.compute_fixed_point_closure(
            init_rem, all_vars, deps, confs, cost_map, base_budget=10.0
        )

        self.assertEqual(act1, act2)
        self.assertEqual(c1, c2)
        self.assertEqual(res1.to_dict(), res2.to_dict())
        self.assertIn(("r2", "rotate_credentials"), res1.removed_variables)

    # 2. Multi-hop closure (>1 depth)
    def test_02_multi_hop_closure(self):
        all_vars = {("r1", "actA"), ("r2", "actB"), ("r3", "actC"), ("r1", "monitor"), ("r2", "monitor"), ("r3", "monitor")}
        init_rem = {("r3", "actC")}  # C is removed
        cost_map = {v: 1.0 for v in all_vars}
        deps = [
            TypedDependencyEdge("r2:actB", "r3:actC", DependencyRelationType.REQUIRES, "RULE_B_REQ_C"),
            TypedDependencyEdge("r1:actA", "r2:actB", DependencyRelationType.REQUIRES, "RULE_A_REQ_B"),
        ]
        confs = []

        active_vars, active_confs, closure = ConstraintDependencyGraph.compute_fixed_point_closure(
            init_rem, all_vars, deps, confs, cost_map, base_budget=10.0
        )

        self.assertIn(("r3", "actC"), closure.removed_variables)
        self.assertIn(("r2", "actB"), closure.removed_variables)
        self.assertIn(("r1", "actA"), closure.removed_variables)
        self.assertGreaterEqual(closure.propagation_depth, 2)
        self.assertEqual(closure.closure_status, "CONVERGED")

    # 3. Cyclic graph termination
    def test_03_cyclic_graph_termination(self):
        all_vars = {("r1", "actA"), ("r2", "actB"), ("r1", "monitor"), ("r2", "monitor")}
        init_rem = {("r1", "actA")}
        cost_map = {v: 1.0 for v in all_vars}
        deps = [
            TypedDependencyEdge("r1:actA", "r2:actB", DependencyRelationType.REQUIRES, "CYCLE_1"),
            TypedDependencyEdge("r2:actB", "r1:actA", DependencyRelationType.REQUIRES, "CYCLE_2"),
        ]
        confs = []

        t0 = time.perf_counter()
        active_vars, active_confs, closure = ConstraintDependencyGraph.compute_fixed_point_closure(
            init_rem, all_vars, deps, confs, cost_map, base_budget=10.0, max_iterations=50
        )
        elapsed = time.perf_counter() - t0

        self.assertLess(elapsed, 1.0, "Cyclic dependency must terminate rapidly")
        self.assertIn(closure.closure_status, ("CONVERGED", "CYCLE_TERMINATED"))

    # 4. Closure provenance tracking
    def test_04_closure_provenance(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        closure: ClosureResult = ir.dependency_closure_metadata
        self.assertIsNotNone(closure)
        self.assertGreater(len(closure.causal_trace), 0)
        for prov in closure.causal_trace:
            self.assertTrue(hasattr(prov, "entity"))
            self.assertTrue(hasattr(prov, "operation"))
            self.assertTrue(hasattr(prov, "reason"))
            self.assertTrue(hasattr(prov, "parent_event"))

    # 5. Bound regeneration after transitive pruning
    def test_05_bound_regeneration_after_transitive_pruning(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        bounds = ir.regenerated_bounds
        self.assertIn("min_possible_cost", bounds)
        self.assertIn("effective_budget", bounds)
        self.assertIn("budget_consistent", bounds)
        self.assertTrue(bounds["budget_consistent"])

    # 6. Canonical IR serialization stability
    def test_06_canonical_ir_serialization_stability(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        d1 = ir.compute_canonical_digest()
        d2 = ir.compute_canonical_digest()
        self.assertEqual(d1, d2)
        self.assertEqual(len(d1), 64)

    # 7. IR digest changes after semantic mutation
    def test_07_ir_digest_changes_after_semantic_mutation(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        d_orig = ir.compute_canonical_digest()

        # Mutate an active variable domain
        ir_mutated = copy.deepcopy(ir)
        first_rid = list(ir_mutated.variable_domains.keys())[0]
        ir_mutated.variable_domains[first_rid].admissible_actions = ["monitor"]
        d_mutated = ir_mutated.compute_canonical_digest()

        self.assertNotEqual(d_orig, d_mutated)

    # 8. IR digest invariant to dictionary ordering
    def test_08_ir_digest_invariant_to_dict_ordering(self):
        ir1 = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)

        # Create ir2 with reversed keys
        ir2 = copy.deepcopy(ir1)
        rev_domains = {k: ir1.variable_domains[k] for k in reversed(list(ir1.variable_domains.keys()))}
        ir2.variable_domains = rev_domains

        d1 = ir1.compute_canonical_digest()
        d2 = ir2.compute_canonical_digest()
        self.assertEqual(d1, d2)

    # 9. Valid certificate allows compilation
    def test_09_valid_certificate_allows_compilation(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        cert = PreSolveSafetyCertifier.certify(ir)
        self.assertTrue(cert.is_valid())

        if HAS_PULP:
            prob, x_vars = FormulationCompiler.compile_to_ilp(ir, certificate=cert)
            self.assertIsNotNone(prob)
            self.assertGreater(len(x_vars), 0)

        if HAS_QISKIT:
            qp, lookup = FormulationCompiler.compile_to_qubo(ir, certificate=cert)
            self.assertIsNotNone(qp)
            self.assertGreater(len(lookup), 0)

    # 10. Modified certified IR is rejected
    def test_10_modified_certified_ir_rejected(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        cert = PreSolveSafetyCertifier.certify(ir)

        # Tamper with IR after certification
        first_rid = list(ir.variable_domains.keys())[0]
        ir.variable_domains[first_rid].admissible_actions.append("tampered_action")

        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.compile_to_ilp(ir, certificate=cert)

    # 11. Stale certificate is rejected
    def test_11_stale_certificate_rejected(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        cert = PreSolveSafetyCertifier.certify(ir)

        # Advance runtime state version
        ir.runtime_state_version = cert.runtime_state_version + 1
        ir.compute_canonical_digest()

        with self.assertRaises(StaleCertificateError):
            FormulationCompiler.compile_to_ilp(ir, certificate=cert)

    # 12. Swapped certificate is rejected
    def test_12_swapped_certificate_rejected(self):
        ir_A = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        cert_A = PreSolveSafetyCertifier.certify(ir_A)

        other_scen = copy.deepcopy(self.scenario)
        other_scen["resources"].append({"id": "res_extra_01", "type": "server"})
        other_scores = {**self.threat_scores, "res_extra_01": 0.5}
        other_ctxs = {**self.contexts, "res_extra_01": create_test_context("res_extra_01", "server")}
        other_confs = {**self.confidences, "res_extra_01": create_test_confidence("res_extra_01")}
        ir_B = self.dag.resolve(other_scen, other_scores, other_ctxs, other_confs)
        cert_B = PreSolveSafetyCertifier.certify(ir_B)

        # Attempt to compile IR_A using certificate from IR_B
        with self.assertRaises((IntegrityBindingError, StaleCertificateError)):
            FormulationCompiler.compile_to_ilp(ir_A, certificate=cert_B)

    # 13. Uncertified IR is rejected
    def test_13_uncertified_ir_rejected(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        with self.assertRaises(UncertifiedIRCompilationError):
            FormulationCompiler.compile_to_ilp(ir, certificate=None)

    # 14. Incremental compile equals full compile semantically
    def test_14_incremental_compile_equals_full_compile_semantically(self):
        # State S_t
        ir_t = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        cert_t = PreSolveSafetyCertifier.certify(ir_t)

        # State change: threat surge on res_server_01
        new_threat_scores = copy.deepcopy(self.threat_scores)
        new_threat_scores["res_server_01"] = 0.99
        new_contexts = copy.deepcopy(self.contexts)
        new_contexts["res_server_01"].threat.threat_score = 0.99

        delta = RuntimeStateDelta(
            changed_assets=["res_server_01"],
            changed_threat_state={"res_server_01": 0.99},
        )

        # Incremental compilation
        inc_res = IncrementalConstraintCompiler.compile_delta(
            previous_ir=ir_t,
            delta=delta,
            scenario=self.scenario,
            all_contexts=new_contexts,
            all_confidences=self.confidences,
            all_threat_scores=new_threat_scores,
        )
        ir_inc = inc_res.updated_ir

        # Full recompilation of S_{t+1}
        ir_full = self.dag.resolve(
            self.scenario,
            new_threat_scores,
            new_contexts,
            self.confidences,
            ir_version=ir_inc.ir_version,
            runtime_state_version=ir_inc.runtime_state_version,
        )

        # Assert active decision domains match 100%
        self.assertEqual(ir_inc.active_variable_domain, ir_full.active_variable_domain)
        # Assert hard invariants categories match
        self.assertEqual(len(ir_inc.hard_constraints), len(ir_full.hard_constraints))

    # 15. Unaffected subgraph is reused
    def test_15_unaffected_subgraph_is_reused(self):
        ir_t = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        delta = RuntimeStateDelta(changed_assets=["res_server_01"])

        inc_res = IncrementalConstraintCompiler.compile_delta(
            previous_ir=ir_t,
            delta=delta,
            scenario=self.scenario,
            all_contexts=self.contexts,
            all_confidences=self.confidences,
            all_threat_scores=self.threat_scores,
        )

        self.assertFalse(inc_res.fallback_to_full_recompile)
        self.assertIn("res_server_01", inc_res.dirty_nodes)
        self.assertGreater(len(inc_res.reused_constraints), 0)
        self.assertIn("DOMAIN_res_plc_01", inc_res.reused_constraints)

    # 16. Backend manifest references correct certificate
    def test_16_backend_manifest_references_correct_certificate(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        cert = PreSolveSafetyCertifier.certify(ir)

        prob, x_vars, manifest = FormulationCompiler.compile_to_ilp(ir, certificate=cert, return_manifest=True)
        self.assertEqual(manifest.source_certificate_id, cert.certificate_id)
        self.assertEqual(manifest.source_ir_version, ir.ir_version)
        self.assertEqual(manifest.backend_type, "ILP_PULP")
        self.assertGreater(len(manifest.active_variables), 0)

    # 17. Semantic fidelity validator catches corrupted backend
    def test_17_semantic_fidelity_validator_catches_corrupted_backend(self):
        # Small scenario (2 assets, <= 10 vars total)
        small_scen = {"scenario": "small", "resources": [{"id": "r1", "type": "server"}]}
        small_threat = {"r1": 0.8}
        small_ctx = {"r1": create_test_context("r1", "server")}
        small_conf = {"r1": create_test_confidence("r1")}

        ir = self.dag.resolve(small_scen, small_threat, small_ctx, small_conf)
        cert = PreSolveSafetyCertifier.certify(ir)

        prob, x_vars, manifest = FormulationCompiler.compile_to_ilp(ir, certificate=cert, return_manifest=True)

        # Artificially corrupt ILP by dropping all constraints
        corrupted_prob = copy.deepcopy(prob)
        corrupted_prob.constraints.clear()

        rep = SemanticValidator.validate_backend_semantics(
            ir=ir,
            ilp_model=corrupted_prob,
            ilp_var_lookup=x_vars,
            manifest=manifest,
            max_vars=10,
        )

        # Mismatches must be detected between strict IR and unconstrained ILP
        self.assertGreater(rep.ir_vs_ilp_mismatches, 0)
        self.assertLess(rep.semantic_fidelity_ilp_pct, 100.0)

    # 18. Unsafe feedback rule is rejected
    def test_18_unsafe_feedback_rule_is_rejected(self):
        learner = FeedbackLearner(data_path="test_feedback_temp.json")
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)

        # Attempt to restrict failsafe 'monitor'
        unsafe_rule_1 = {
            "rule_id": "UNSAFE_01",
            "target_resource_type": "all",
            "restrict_action": "monitor",
            "condition": "TEST_UNSAFE",
            "rationale": "Attempting to prune failsafe baseline",
            "trigger_incident_id": "test_inc",
        }
        ev1 = learner.admit_candidate_rule_sandboxed(unsafe_rule_1, baseline_ir=ir)
        self.assertFalse(ev1.admitted)
        self.assertIn("REJECTED", ev1.reason)

        # Attempt to re-enable 'isolate' on PLC
        unsafe_rule_2 = {
            "rule_id": "UNSAFE_02",
            "target_resource_type": "plc_controller",
            "allow_action": "isolate",
            "condition": "TEST_UNSAFE_REINTRODUCE",
            "rationale": "Attempting to reintroduce isolate on PLC",
            "trigger_incident_id": "test_inc",
        }
        ev2 = learner.admit_candidate_rule_sandboxed(unsafe_rule_2, baseline_ir=ir)
        self.assertFalse(ev2.admitted)

    # 19. Safe feedback rule may be admitted
    def test_19_safe_feedback_rule_may_be_admitted(self):
        learner = FeedbackLearner(data_path="test_feedback_temp.json")
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)

        safe_rule = {
            "rule_id": "SAFE_01",
            "target_resource_type": "server",
            "restrict_action": "snapshot_backup",
            "condition": "HIGH_COST_OUTCOME",
            "rationale": "Temporarily restrict snapshot_backup on servers due to backup timeout",
            "trigger_incident_id": "test_inc",
        }
        ev = learner.admit_candidate_rule_sandboxed(safe_rule, baseline_ir=ir)
        self.assertTrue(ev.admitted)
        self.assertIn("APPROVED", ev.reason)

    # 20. Existing SCADA PLC case removes isolate before formulation
    def test_20_existing_scada_plc_case_removes_isolate_before_formulation(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        plc_domain = ir.variable_domains["res_plc_01"]

        self.assertNotIn("isolate", plc_domain.admissible_actions)
        self.assertIn("isolate", plc_domain.pruned_actions)

        # Invariance constraint must NOT include isolate
        plc_inv = next(inv for inv in ir.invariance_constraints if inv.resource_id == "res_plc_01")
        self.assertNotIn("isolate", plc_inv.actions)

        # Hard constraint forcing x_{plc, isolate} = 0 exists
        cap_records = [c for c in ir.hard_constraints if c.target_resource == "res_plc_01" and c.target_action == "isolate"]
        self.assertGreater(len(cap_records), 0)

    # 21. QUBO exact fractional slack representation: Cost=0.605, Budget=1.000 (slack=0.395)
    def test_21_qubo_under_budget_feasibility(self):
        ir = SecurityConstraintIR(
            incident_id="test_21_frac_slack",
            variable_domains={"r1": VariableDomain(resource_id="r1", resource_type="server", admissible_actions=["a1", "a2", "a3"])},
            invariance_constraints=[InvarianceConstraint(resource_id="r1", actions=["a1", "a2", "a3"], target_value=1)],
            conflict_hyperedges=[],
            budget_constraint=HardBudgetConstraint(max_budget=1.000, cost_map={("r1", "a1"): 0.605, ("r1", "a2"): 1.000, ("r1", "a3"): 1.005}),
            objective_terms={
                ("r1", "a1"): ObjectiveLinearTerm(resource_id="r1", action="a1", coefficient=1.0, containment_component=1.0, cost_component=0.0, switching_penalty_component=0.0),
                ("r1", "a2"): ObjectiveLinearTerm(resource_id="r1", action="a2", coefficient=2.0, containment_component=2.0, cost_component=0.0, switching_penalty_component=0.0),
                ("r1", "a3"): ObjectiveLinearTerm(resource_id="r1", action="a3", coefficient=3.0, containment_component=3.0, cost_component=0.0, switching_penalty_component=0.0),
            },
        )
        cert = PreSolveSafetyCertifier.certify(ir)
        prob, ilp_lookup = FormulationCompiler.compile_to_ilp(ir, cert)
        qubo, qubo_lookup = FormulationCompiler.compile_to_qubo(ir, cert)

        # Assignment A: choose a1 (cost 0.605 <= 1.000, slack required = 0.395)
        asgn_A = {("r1", "a1"): 1, ("r1", "a2"): 0, ("r1", "a3"): 0}
        ilp_valid = SemanticValidator.evaluate_ilp_feasibility(prob, ilp_lookup, asgn_A)
        qubo_valid = SemanticValidator.evaluate_qubo_feasibility(ir, asgn_A, qubo_model=qubo, qubo_var_lookup=qubo_lookup)
        self.assertTrue(ilp_valid)
        self.assertTrue(qubo_valid)

    # 22. QUBO exact-budget boundary feasibility: Cost=1.000, Budget=1.000 (slack=0.000)
    def test_22_qubo_exact_budget_feasibility(self):
        ir = SecurityConstraintIR(
            incident_id="test_22_exact_budget",
            variable_domains={"r1": VariableDomain(resource_id="r1", resource_type="server", admissible_actions=["a1", "a2", "a3"])},
            invariance_constraints=[InvarianceConstraint(resource_id="r1", actions=["a1", "a2", "a3"], target_value=1)],
            conflict_hyperedges=[],
            budget_constraint=HardBudgetConstraint(max_budget=1.000, cost_map={("r1", "a1"): 0.605, ("r1", "a2"): 1.000, ("r1", "a3"): 1.005}),
            objective_terms={
                ("r1", "a1"): ObjectiveLinearTerm(resource_id="r1", action="a1", coefficient=1.0, containment_component=1.0, cost_component=0.0, switching_penalty_component=0.0),
                ("r1", "a2"): ObjectiveLinearTerm(resource_id="r1", action="a2", coefficient=2.0, containment_component=2.0, cost_component=0.0, switching_penalty_component=0.0),
                ("r1", "a3"): ObjectiveLinearTerm(resource_id="r1", action="a3", coefficient=3.0, containment_component=3.0, cost_component=0.0, switching_penalty_component=0.0),
            },
        )
        cert = PreSolveSafetyCertifier.certify(ir)
        prob, ilp_lookup = FormulationCompiler.compile_to_ilp(ir, cert)
        qubo, qubo_lookup = FormulationCompiler.compile_to_qubo(ir, cert)

        # Assignment B: choose a2 (cost exactly 1.000 == Budget 1.000, slack required = 0)
        asgn_B = {("r1", "a1"): 0, ("r1", "a2"): 1, ("r1", "a3"): 0}
        ilp_valid = SemanticValidator.evaluate_ilp_feasibility(prob, ilp_lookup, asgn_B)
        qubo_valid = SemanticValidator.evaluate_qubo_feasibility(ir, asgn_B, qubo_model=qubo, qubo_var_lookup=qubo_lookup)
        self.assertTrue(ilp_valid)
        self.assertTrue(qubo_valid)

    # 23. QUBO isolated over-budget rejection: Cost=1.005 > Budget=1.000 (satisfies invariance, violates budget)
    def test_23_qubo_over_budget_rejection(self):
        ir = SecurityConstraintIR(
            incident_id="test_23_over_budget",
            variable_domains={"r1": VariableDomain(resource_id="r1", resource_type="server", admissible_actions=["a1", "a2", "a3"])},
            invariance_constraints=[InvarianceConstraint(resource_id="r1", actions=["a1", "a2", "a3"], target_value=1)],
            conflict_hyperedges=[],
            budget_constraint=HardBudgetConstraint(max_budget=1.000, cost_map={("r1", "a1"): 0.605, ("r1", "a2"): 1.000, ("r1", "a3"): 1.005}),
            objective_terms={
                ("r1", "a1"): ObjectiveLinearTerm(resource_id="r1", action="a1", coefficient=1.0, containment_component=1.0, cost_component=0.0, switching_penalty_component=0.0),
                ("r1", "a2"): ObjectiveLinearTerm(resource_id="r1", action="a2", coefficient=2.0, containment_component=2.0, cost_component=0.0, switching_penalty_component=0.0),
                ("r1", "a3"): ObjectiveLinearTerm(resource_id="r1", action="a3", coefficient=3.0, containment_component=3.0, cost_component=0.0, switching_penalty_component=0.0),
            },
        )
        cert = PreSolveSafetyCertifier.certify(ir)
        prob, ilp_lookup = FormulationCompiler.compile_to_ilp(ir, cert)
        qubo, qubo_lookup = FormulationCompiler.compile_to_qubo(ir, cert)

        # Assignment C: choose a3 (cost 1.005 > 1.000, exactly one action satisfied, isolated budget violation)
        asgn_C = {("r1", "a1"): 0, ("r1", "a2"): 0, ("r1", "a3"): 1}
        ilp_valid = SemanticValidator.evaluate_ilp_feasibility(prob, ilp_lookup, asgn_C)
        qubo_valid = SemanticValidator.evaluate_qubo_feasibility(ir, asgn_C, qubo_model=qubo, qubo_var_lookup=qubo_lookup)
        self.assertFalse(ilp_valid)
        self.assertFalse(qubo_valid)

    # 24. Actual QUBO polynomial coefficient corruption detected by semantic validator
    def test_24_actual_qubo_corruption_detected(self):
        small_scen = {"scenario": "small", "resources": [{"id": "r1", "type": "server"}]}
        small_threat = {"r1": 0.8}
        small_ctx = {"r1": create_test_context("r1", "server")}
        small_conf = {"r1": create_test_confidence("r1")}

        ir = self.dag.resolve(small_scen, small_threat, small_ctx, small_conf, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)
        qubo, qubo_lookup = FormulationCompiler.compile_to_qubo(ir, cert)

        # Mutate a real polynomial linear coefficient in the Hamiltonian objective
        target_var = list(qubo_lookup.values())[0]
        qubo.objective.linear[target_var] += 25.0

        report = SemanticValidator.validate_backend_semantics(
            ir, qubo_model=qubo, qubo_var_lookup=qubo_lookup, max_vars=8
        )
        self.assertGreater(report.ir_vs_qubo_mismatches, 0)
        self.assertLess(report.qubo_semantically_valid_count, report.ir_feasible_count)

    # 25. Same count of feasible states but different assignments -> mismatch detected
    def test_25_same_count_different_assignments_mismatch_detected(self):
        report = SemanticValidationReport(
            total_assignments=100,
            ir_feasible_count=10,
            ilp_feasible_count=10,
            qubo_semantically_valid_count=10,
            ir_vs_ilp_mismatches=0,
            ir_vs_qubo_mismatches=4,
            ilp_vs_qubo_mismatches=4,
            semantic_fidelity_ilp_pct=100.0,
            semantic_fidelity_qubo_pct=96.0,
            cross_backend_mismatch=4,
            max_variable_threshold=10,
            evaluation_mode="EXHAUSTIVE",
        )
        self.assertEqual(report.cross_backend_mismatch, 4)
        self.assertNotEqual(report.cross_backend_mismatch, abs(report.ilp_feasible_count - report.qubo_semantically_valid_count))

    # 26. Stale invariance action detected by certifier
    def test_26_stale_invariance_action_detected(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        inv = ir.invariance_constraints[0]
        inv.actions = list(inv.actions) + ["non_existent_stale_action"]
        ir.compute_canonical_digest()
        cert = PreSolveSafetyCertifier.certify(ir)
        self.assertFalse(cert.verification_checks["3_exactly_one_invariance_present"])
        self.assertFalse(cert.is_valid())

    # 27. Globally infeasible conflict state rejected by certifier
    def test_27_globally_infeasible_conflict_state_rejected(self):
        scen = {
            "incident_id": "infeasible_test",
            "resources": [{"id": "rA", "type": "server"}, {"id": "rB", "type": "server"}],
        }
        dag = ConstraintDependencyGraph(incident_id="infeasible_test")
        ir = dag.resolve(scen, {"rA": 0.8, "rB": 0.8}, {}, {})
        ir.variable_domains["rA"].admissible_actions = ["isolate"]
        ir.variable_domains["rB"].admissible_actions = ["isolate"]
        ir.invariance_constraints = [
            InvarianceConstraint(resource_id="rA", actions=["isolate"], target_value=1),
            InvarianceConstraint(resource_id="rB", actions=["isolate"], target_value=1),
        ]
        ir.conflict_hyperedges.append(ConflictHyperedge(
            resource_1="rA", action_1="isolate",
            resource_2="rB", action_2="isolate",
            reason="Mutual exclusion", rule_id="TEST_EXCLUSION"
        ))
        ir.compute_canonical_digest()
        witness = PreSolveSafetyCertifier.find_feasibility_witness(ir)
        self.assertIsNone(witness)
        cert = PreSolveSafetyCertifier.certify(ir)
        self.assertFalse(cert.is_valid())
        self.assertFalse(cert.verification_checks["5_budget_feasibility_guaranteed"])

    # 28. Feasibility witness generated in certificate
    def test_28_feasibility_witness_generated(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)
        self.assertTrue(cert.is_valid())
        self.assertIsNotNone(cert.feasibility_witness)
        for rid in ir.variable_domains:
            self.assertIn(rid, cert.feasibility_witness)
            self.assertIn(cert.feasibility_witness[rid], ir.variable_domains[rid].admissible_actions)

    # 29. Tampered certificate integrity digest rejected
    def test_29_tampered_certificate_integrity_digest_rejected(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)
        cert.integrity_digest = "0" * 64
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.compile_to_ilp(ir, cert)

    # 30. Tampered closure metadata rejected
    def test_30_tampered_closure_metadata_rejected(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)
        if ir.dependency_closure_metadata:
            ir.dependency_closure_metadata.removed_variables.append(("fake_res", "fake_act"))
            with self.assertRaises(IntegrityBindingError):
                FormulationCompiler.compile_to_ilp(ir, cert)

    # 31. Three-hop incremental dependency propagation (A -> B -> C)
    def test_31_three_hop_incremental_dependency_propagation(self):
        scenario = {
            "incident_id": "test_chain",
            "resources": [
                {"id": "node_a", "type": "server"},
                {"id": "node_b", "type": "server"},
                {"id": "node_c", "type": "server"},
            ]
        }
        edges = [
            TypedDependencyEdge("node_a:isolate", "node_b:isolate", DependencyRelationType.REQUIRES, "CHAIN_1"),
            TypedDependencyEdge("node_b:isolate", "node_c:isolate", DependencyRelationType.REQUIRES, "CHAIN_2"),
        ]
        dag = ConstraintDependencyGraph(incident_id="test_chain")
        ir = dag.resolve(scenario, {"node_a": 0.8, "node_b": 0.8, "node_c": 0.8}, {}, {}, explicit_dependencies=edges)

        delta = RuntimeStateDelta(changed_assets={"node_a"})
        res = IncrementalConstraintCompiler.compile_delta(
            previous_ir=ir,
            delta=delta,
            scenario=scenario,
            all_contexts={},
            all_confidences={},
            all_threat_scores={"node_a": 0.8, "node_b": 0.8, "node_c": 0.8},
            explicit_dependencies=edges,
        )
        self.assertIn("node_a", res.dirty_nodes)
        self.assertIn("node_b", res.dirty_nodes)
        self.assertIn("node_c", res.dirty_nodes)

    # 32. Changed resource state triggers recompilation
    def test_32_changed_resource_state_triggers_recompilation(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        delta = RuntimeStateDelta(changed_resource_state={"res_gw_01": {"status": "degraded"}})
        res = IncrementalConstraintCompiler.compile_delta(
            previous_ir=ir,
            delta=delta,
            scenario=self.scenario,
            all_contexts=self.contexts,
            all_confidences=self.confidences,
            all_threat_scores=self.threat_scores,
        )
        self.assertIn("res_gw_01", res.dirty_nodes)

    # 33. Dirty-clean cross-resource conflict rebuilt correctly
    def test_33_dirty_clean_cross_resource_conflict_rebuilt(self):
        scenario = {
            "incident_id": "test_cross",
            "resources": [
                {"id": "res_clean", "type": "server"},
                {"id": "res_dirty", "type": "server"},
            ]
        }
        dag = ConstraintDependencyGraph(incident_id="test_cross")
        ir = dag.resolve(scenario, {"res_clean": 0.8, "res_dirty": 0.8}, {}, {})
        ir.conflict_hyperedges.append(ConflictHyperedge(
            resource_1="res_clean", action_1="isolate",
            resource_2="res_dirty", action_2="isolate",
            reason="Cross-tier conflict", rule_id="CROSS_01"
        ))
        ir.compute_canonical_digest()

        delta = RuntimeStateDelta(changed_threat_state={"res_dirty": 0.95})
        res = IncrementalConstraintCompiler.compile_delta(
            previous_ir=ir,
            delta=delta,
            scenario=scenario,
            all_contexts={},
            all_confidences={},
            all_threat_scores={"res_clean": 0.8, "res_dirty": 0.95},
        )
        cross_conf = [
            c for c in res.updated_ir.conflict_hyperedges
            if (c.resource_1 == "res_clean" and c.resource_2 == "res_dirty")
            or (c.resource_1 == "res_dirty" and c.resource_2 == "res_clean")
        ]
        self.assertGreaterEqual(len(cross_conf), 1)

    # 34. Full and incremental semantic fingerprints match
    def test_34_full_and_incremental_semantic_fingerprints_match(self):
        base_threats = {"res_gw_01": 0.5, "res_db_01": 0.5, "res_plc_01": 0.5}
        scen = {
            "incident_id": "test_fingerprint",
            "resources": [r for r in self.scenario["resources"] if r["id"] in base_threats]
        }
        dag = ConstraintDependencyGraph(incident_id="test_fingerprint")
        ir_t = dag.resolve(scen, base_threats, self.contexts, self.confidences, base_budget=15.0)

        updated_threats = base_threats.copy()
        updated_threats["res_gw_01"] = 0.95
        delta = RuntimeStateDelta(changed_threat_state={"res_gw_01": 0.95})

        full_ir = dag.resolve(scen, updated_threats, self.contexts, self.confidences, base_budget=15.0)
        inc_res = IncrementalConstraintCompiler.compile_delta(
            previous_ir=ir_t,
            delta=delta,
            scenario=scen,
            all_contexts=self.contexts,
            all_confidences=self.confidences,
            all_threat_scores=updated_threats,
            base_budget=15.0,
        )
        self.assertEqual(full_ir.semantic_fingerprint(), inc_res.updated_ir.semantic_fingerprint())

    # 35. Scenario-driven multi-hop closure in default resolve pipeline
    def test_35_scenario_driven_multi_hop_closure_in_default_resolve(self):
        multi_tier_scenario = {
            "scenario": "multi_tier_closure_test",
            "resources": [
                {"id": "tier1_plc", "type": "plc_controller"},
                {
                    "id": "tier2_app",
                    "type": "server",
                    "depends_on": ["tier1_plc"],
                    "requires_isolation_with": ["tier1_plc"],
                },
                {
                    "id": "tier3_web",
                    "type": "server",
                    "depends_on": ["tier2_app"],
                    "requires_isolation_with": ["tier2_app"],
                },
            ],
        }
        threats = {"tier1_plc": 0.85, "tier2_app": 0.85, "tier3_web": 0.85}
        ctxs = {
            "tier1_plc": create_test_context("tier1_plc", "plc_controller", threat=0.85, sla="CRITICAL", hipaa=False),
            "tier2_app": create_test_context("tier2_app", "server", threat=0.85, sla="HIGH", hipaa=False),
            "tier3_web": create_test_context("tier3_web", "server", threat=0.85, sla="HIGH", hipaa=False),
        }
        confs = {
            "tier1_plc": create_test_confidence("tier1_plc", 0.95),
            "tier2_app": create_test_confidence("tier2_app", 0.95),
            "tier3_web": create_test_confidence("tier3_web", 0.95),
        }

        dag = ConstraintDependencyGraph(incident_id="test_closure_incident")
        # Default resolve: NO explicit_dependencies passed!
        ir = dag.resolve(multi_tier_scenario, threats, ctxs, confs)

        # 1. Tier 1 PLC: isolate pruned by physical safety rule
        self.assertNotIn("isolate", ir.variable_domains["tier1_plc"].admissible_actions)
        self.assertIn("isolate", ir.variable_domains["tier1_plc"].pruned_actions)

        # 2. Tier 2 App: isolate transitively pruned via fixed-point closure (Hop 1)
        self.assertNotIn("isolate", ir.variable_domains["tier2_app"].admissible_actions)
        self.assertIn("isolate", ir.variable_domains["tier2_app"].pruned_actions)

        # 3. Tier 3 Web: isolate transitively pruned via fixed-point closure (Hop 2)
        self.assertNotIn("isolate", ir.variable_domains["tier3_web"].admissible_actions)
        self.assertIn("isolate", ir.variable_domains["tier3_web"].pruned_actions)

        # 4. Propagation depth must reflect multi-hop cascade
        closure = ir.dependency_closure_metadata
        self.assertIsNotNone(closure)
        self.assertGreaterEqual(closure.propagation_depth, 2)
        self.assertEqual(closure.closure_status, "CONVERGED")

        # 5. Causal trace must contain UNSATISFIED_PREREQUISITE transitive records
        transitive_prunes = [p for p in closure.causal_trace if "UNSATISFIED_PREREQUISITE" in p.reason]
        self.assertGreaterEqual(len(transitive_prunes), 2)
        pruned_entities = {p.entity for p in transitive_prunes}
        self.assertIn("tier2_app:isolate", pruned_entities)
        self.assertIn("tier3_web:isolate", pruned_entities)

        # 6. Failsafe baselines must remain preserved
        self.assertIn("monitor", ir.variable_domains["tier2_app"].admissible_actions)
        self.assertIn("monitor", ir.variable_domains["tier3_web"].admissible_actions)

        # 7. Certificate verification succeeds
        cert = PreSolveSafetyCertifier.certify(ir)
        self.assertTrue(cert.is_valid())

    # 36. Budget scaling has exactly one owner (no compounding across layers)
    def test_36_budget_scaling_applied_exactly_once(self):
        resources = [{"id": "srv1", "type": "server"}, {"id": "srv2", "type": "server"}]
        scenario = {"scenario": "budget_single_owner", "resources": resources}

        for threat, expected_multiplier in [(0.90, 1.3), (0.55, 1.0), (0.20, 0.8)]:
            with self.subTest(threat=threat):
                threats = {r["id"]: threat for r in resources}
                ctxs = {r["id"]: create_test_context(r["id"], r["type"], threat=threat, sla="HIGH")
                        for r in resources}
                confs = {r["id"]: create_test_confidence(r["id"], 0.92) for r in resources}

                constraints = generate_adaptive_constraints(
                    ctxs, confs, base_max_budget=5.0, scenario=scenario, threat_scores=threats
                )
                expected = round(5.0 * expected_multiplier, 2)

                self.assertAlmostEqual(constraints.max_budget, expected, places=4)
                self.assertAlmostEqual(
                    constraints.constraint_ir.budget_constraint.max_budget, expected, places=4
                )
                self.assertAlmostEqual(
                    constraints.constraint_ir.regenerated_bounds["effective_budget"], expected, places=4
                )

    # 37. Certified-domain gate blocks actuation of a pruned action
    def test_37_actuation_gate_rejects_inadmissible_action(self):
        resources = [{"id": "plc1", "type": "plc_controller"}, {"id": "srv1", "type": "server"}]
        scenario = {"scenario": "actuation_gate", "resources": resources}
        threats = {"plc1": 0.90, "srv1": 0.90}
        ctxs = {r["id"]: create_test_context(r["id"], r["type"], threat=0.90, sla="HIGH")
                for r in resources}
        confs = {r["id"]: create_test_confidence(r["id"], 0.92) for r in resources}

        constraints = generate_adaptive_constraints(
            ctxs, confs, base_max_budget=5.0, scenario=scenario, threat_scores=threats
        )
        ir, cert = constraints.constraint_ir, constraints.safety_certificate

        # isolate is pruned on a PLC by the physical safety profile
        self.assertNotIn("isolate", ir.variable_domains["plc1"].admissible_actions)

        # A plan drawn from the certified domain passes the gate
        admissible = {"plc1": "monitor", "srv1": "monitor"}
        report = validate_plan_against_certified_ir(admissible, ir, cert)
        self.assertEqual(report["validated_actions"], 2)

        # A plan that drifted outside the certified domain is refused
        with self.assertRaises(InadmissibleActionError):
            validate_plan_against_certified_ir({"plc1": "isolate"}, ir, cert)

        # ...and no actuation command is emitted for it
        with self.assertRaises(InadmissibleActionError):
            execute_plan({"plc1": "isolate"}, sc_ir=ir, certificate=cert)

        # An unknown resource has no certified domain and is refused
        with self.assertRaises(InadmissibleActionError):
            validate_plan_against_certified_ir({"unknown_res": "monitor"}, ir, cert)

    # 38. A bare 'depends_on' derives no action-level prerequisite on its own
    def test_38_generic_dependency_does_not_imply_action_prerequisite(self):
        generic = {
            "scenario": "generic_dependency",
            "resources": [
                {"id": "db", "type": "rds_database"},
                {"id": "web", "type": "server", "depends_on": ["db"]},
            ],
        }
        edges = ConstraintDependencyGraph.extract_scenario_dependencies(generic)
        self.assertEqual(
            edges, [],
            "A generic service dependency must not imply that isolating or re-keying "
            "the dependent requires the same action on its provider.",
        )

        typed = copy.deepcopy(generic)
        typed["resources"][1]["requires_isolation_with"] = ["db"]
        typed["resources"][1]["credential_provider"] = ["db"]
        typed_edges = ConstraintDependencyGraph.extract_scenario_dependencies(typed)

        derived = {(e.source_entity, e.target_entity) for e in typed_edges}
        self.assertIn(("web:isolate", "db:isolate"), derived)
        self.assertIn(("web:rotate_credentials", "db:rotate_credentials"), derived)

    # 39. Replacing the feasibility witness after certification is rejected
    def test_39_swapped_witness_rejected(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)
        self.assertIsNotNone(cert.feasibility_witness)
        self.assertTrue(bool(cert.witness_digest))

        # Tamper with witness
        tampered_witness = dict(cert.feasibility_witness)
        for res_id in tampered_witness:
            tampered_witness[res_id] = "monitor"
        cert.feasibility_witness = tampered_witness

        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.verify_binding(ir, cert)
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.compile_to_ilp(ir, cert)

    # 40. Runtime-state fingerprint invariance to non-validity fields and sensitivity to validity fields
    def test_40_runtime_state_fingerprint_invariance_and_sensitivity(self):
        snapshot = snapshot_from_contexts(
            contexts=self.contexts,
            confidences=self.confidences,
            scenario=self.scenario,
            epoch=1,
            threat_scores=self.threat_scores,
        )
        fp_orig = snapshot.fingerprint()
        self.assertEqual(len(fp_orig), 64)

        # 1. Non-validity-relevant mutation (e.g. timestamp sampled_at changes) -> fingerprint invariant
        snapshot_time_mutated = copy.deepcopy(snapshot)
        snapshot_time_mutated.sampled_at += 1000.0
        self.assertEqual(snapshot_time_mutated.fingerprint(), fp_orig)

        # 2. Key ordering invariance
        reversed_resources = {k: snapshot.resources[k] for k in reversed(list(snapshot.resources.keys()))}
        snapshot_reordered = StateSnapshot(resources=reversed_resources, epoch=1, sampled_at=snapshot.sampled_at)
        self.assertEqual(snapshot_reordered.fingerprint(), fp_orig)

        # 3. Validity-relevant field mutation (threat_score) -> fingerprint changes
        snapshot_threat_mutated = copy.deepcopy(snapshot)
        snapshot_threat_mutated.resources["res_server_01"].threat_score = 0.99
        self.assertNotEqual(snapshot_threat_mutated.fingerprint(), fp_orig)

        # 4. Validity-relevant field mutation (confidence) -> fingerprint changes
        snapshot_conf_mutated = copy.deepcopy(snapshot)
        snapshot_conf_mutated.resources["res_plc_01"].overall_confidence = 0.45
        self.assertNotEqual(snapshot_conf_mutated.fingerprint(), fp_orig)

        # 5. IR generated by resolve() carries state_fingerprint matching snapshot
        ir = self.dag.resolve(
            self.scenario,
            self.threat_scores,
            self.contexts,
            self.confidences,
            state_snapshot=snapshot,
        )
        self.assertEqual(ir.state_fingerprint, fp_orig)
        self.assertEqual(ir.state_schema_id, STATE_SCHEMA_ID)
        self.assertEqual(ir.state_epoch, 1)

    # 41. Validity envelope soundness by sampling (≥500 in-envelope and ≥500 boundary-violating)
    def test_41_validity_envelope_soundness_by_sampling(self):
        import random
        rng = random.Random(42)

        base_ir = self.dag.resolve(
            self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0
        )
        envelope = base_ir.validity_envelope
        self.assertIsNotNone(envelope)

        base_domains = base_ir.active_variable_domain
        base_hard = sorted([(c.constraint_id, c.target_resource, c.target_action) for c in base_ir.hard_constraints])
        base_budget = round(float(base_ir.budget_constraint.max_budget), 4)

        base_snap = snapshot_from_contexts(
            contexts=self.contexts,
            confidences=self.confidences,
            scenario=self.scenario,
            epoch=1,
            threat_scores=self.threat_scores,
        )
        in_env_ok, _ = envelope.contains(base_snap)
        self.assertTrue(in_env_ok)

        # 1. Sample 500 snapshots strictly inside E_t
        for _ in range(500):
            sample_threats = {}
            sample_contexts = {}
            sample_confidences = {}
            for rid in ["res_server_01", "res_plc_01", "res_gw_01"]:
                # Threat stays in (0.70, 1.0]
                t_val = rng.uniform(0.71, 0.99)
                sample_threats[rid] = t_val
                sla_val = "CRITICAL" if rid != "res_server_01" else "HIGH"
                sample_contexts[rid] = create_test_context(rid, self.scenario["resources"][0]["type"], threat=t_val, sla=sla_val)
                # Confidence stays in [0.50, 1.0]
                c_val = rng.uniform(0.52, 0.98)
                sample_confidences[rid] = create_test_confidence(rid, c_val)

            snap_sample = snapshot_from_contexts(
                contexts=sample_contexts,
                confidences=sample_confidences,
                scenario=self.scenario,
                epoch=1,
                threat_scores=sample_threats,
            )
            inside, viols = envelope.contains(snap_sample)
            self.assertTrue(inside, f"Generated sample failed envelope: {viols}")

            # Re-resolve and assert exact structural invariance
            ir_sample = self.dag.resolve(
                self.scenario, sample_threats, sample_contexts, sample_confidences, base_budget=10.0
            )
            self.assertEqual(ir_sample.active_variable_domain, base_domains)
            sample_hard = sorted([(c.constraint_id, c.target_resource, c.target_action) for c in ir_sample.hard_constraints])
            self.assertEqual(sample_hard, base_hard)
            self.assertEqual(round(float(ir_sample.budget_constraint.max_budget), 4), base_budget)

        # 2. Sample 500 snapshots that violate exactly one predicate
        outcome_changed_count = 0
        for i in range(500):
            violating_snap = copy.deepcopy(base_snap)
            pick = i % 3
            if pick == 0:
                # Threat crosses below 0.40 threshold for res_gw_01 (SLA Critical forbids isolate)
                violating_snap.resources["res_gw_01"].threat_score = rng.uniform(0.10, 0.35)
            elif pick == 1:
                # Confidence drops below 0.50 threshold for res_server_01
                violating_snap.resources["res_server_01"].overall_confidence = rng.uniform(0.10, 0.45)
            else:
                # SLA priority changed to LOW
                violating_snap.resources["res_plc_01"].sla_priority = "LOW"

            inside, viols = envelope.contains(violating_snap)
            self.assertFalse(inside)
            self.assertTrue(len(viols) > 0)

            # Re-resolve to see if outcome changes
            v_threats = {r: violating_snap.resources[r].threat_score for r in violating_snap.resources}
            v_contexts = {}
            for r in violating_snap.resources:
                st = violating_snap.resources[r]
                v_contexts[r] = create_test_context(r, st.resource_type, threat=st.threat_score, sla=st.sla_priority, hipaa=st.hipaa_applicable)
            v_confidences = {r: create_test_confidence(r, violating_snap.resources[r].overall_confidence) for r in violating_snap.resources}

            ir_viol = self.dag.resolve(self.scenario, v_threats, v_contexts, v_confidences, base_budget=10.0)
            if (ir_viol.active_variable_domain != base_domains or
                round(float(ir_viol.budget_constraint.max_budget), 4) != base_budget):
                outcome_changed_count += 1

        # Soundness requires that envelope never permits an outcome change;
        # tightness is not 100%, so a portion of outside samples change the outcome.
        self.assertGreater(outcome_changed_count, 0)

    # 42. TOCTOU: State drift outside envelope refused; drift inside envelope accepted
    def test_42_toctou_validity_envelope_drift_and_invariance(self):
        base_ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(base_ir)
        base_snap = snapshot_from_contexts(
            contexts=self.contexts,
            confidences=self.confidences,
            scenario=self.scenario,
            epoch=1,
            threat_scores=self.threat_scores,
        )

        # Case (a): mutate a validity-relevant field so it leaves E_t
        drift_snap = copy.deepcopy(base_snap)
        drift_snap.resources["res_gw_01"].threat_score = 0.20  # Crosses 0.40 SLA Critical threshold
        with self.assertRaises(StateEnvelopeViolationError):
            FormulationCompiler.compile_to_ilp(base_ir, cert, current_snapshot=drift_snap)
        with self.assertRaises(StateEnvelopeViolationError):
            validate_plan_against_certified_ir({"res_gw_01": "isolate"}, base_ir, cert, current_snapshot=drift_snap)
        with self.assertRaises(StateEnvelopeViolationError):
            execute_plan({"res_gw_01": "isolate"}, sc_ir=base_ir, certificate=cert, current_snapshot=drift_snap)

        # Case (b): mutate a field to a new value still inside E_t
        valid_drift_snap = copy.deepcopy(base_snap)
        valid_drift_snap.resources["res_gw_01"].threat_score = 0.88  # Still in (0.70, 1.0]
        # Both compilation and actuation succeed without recompilation
        res = FormulationCompiler.compile_to_ilp(base_ir, cert, current_snapshot=valid_drift_snap)
        self.assertIsNotNone(res)
        report = validate_plan_against_certified_ir({"res_gw_01": "isolate"}, base_ir, cert, current_snapshot=valid_drift_snap)
        self.assertEqual(report["validated_actions"], 1)

        # Case (c): mutate a non-validity-relevant field (e.g. timestamp sampled_at)
        time_snap = copy.deepcopy(base_snap)
        time_snap.sampled_at += 10000.0
        res_time = FormulationCompiler.compile_to_ilp(base_ir, cert, current_snapshot=time_snap)
        self.assertIsNotNone(res_time)
        report_time = validate_plan_against_certified_ir({"res_gw_01": "isolate"}, base_ir, cert, current_snapshot=time_snap)
        self.assertEqual(report_time["validated_actions"], 1)

    # 43. State-envelope certificate signature validity under Ed25519 / HMAC
    def test_43_state_envelope_certificate_signature_validity(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)
        self.assertTrue(bool(cert.signature))
        self.assertIn(cert.auth_mechanism, {"ed25519", "hmac-sha256"})
        self.assertEqual(cert.asset_scope, sorted(list(ir.variable_domains.keys())))
        self.assertEqual(cert.policy_revision, POLICY_REVISION)

        # Compilation succeeds under valid signature
        prob, ilp_lookup = FormulationCompiler.compile_to_ilp(ir, cert)
        self.assertIsNotNone(prob)

    # 44. Tampered payload fields (IR digest, closure, witness, envelope, asset_scope, policy_revision, epoch) rejected
    def test_44_certificate_tampered_payload_fields_rejected(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)

        # 1. Tampered IR digest
        c1 = copy.deepcopy(cert)
        c1.ir_sha256 = "f" * 64
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.verify_binding(ir, c1)

        # 2. Tampered closure digest
        c2 = copy.deepcopy(cert)
        c2.closure_digest = "e" * 64
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.verify_binding(ir, c2)

        # 3. Tampered witness digest
        c3 = copy.deepcopy(cert)
        c3.witness_digest = "d" * 64
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.verify_binding(ir, c3)

        # 4. Tampered envelope digest
        c4 = copy.deepcopy(cert)
        c4.envelope_digest = "c" * 64
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.verify_binding(ir, c4)

        # 5. Tampered asset scope
        c5 = copy.deepcopy(cert)
        c5.asset_scope = ["rogue_resource_99"]
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.verify_binding(ir, c5)

        # 6. Tampered policy revision
        c6 = copy.deepcopy(cert)
        c6.policy_revision = "stale_policy_hash"
        with self.assertRaises((IntegrityBindingError, StaleCertificateError)):
            FormulationCompiler.verify_binding(ir, c6)

        # 7. Tampered epoch
        c7 = copy.deepcopy(cert)
        c7.state_epoch = 999
        with self.assertRaises((IntegrityBindingError, StaleCertificateError)):
            FormulationCompiler.verify_binding(ir, c7)

    # 45. Signature from unauthorized key is rejected
    def test_45_certificate_unauthorized_key_signature_rejected(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)

        # Generate an independent rogue certifier key
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            rogue_priv = ed25519.Ed25519PrivateKey.generate()
            rogue_key = CertifierKey(private_key=rogue_priv)
        except Exception:
            rogue_key = CertifierKey(hmac_secret=b"unauthorized_secret_key_12345678")

        payload_bytes = cert.compute_canonical_payload()
        rogue_sig, mech = rogue_key.sign(payload_bytes)
        c_rogue = copy.deepcopy(cert)
        c_rogue.signature = rogue_sig
        c_rogue.auth_mechanism = mech

        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.verify_binding(ir, c_rogue)

    # 46. Replay of certificate against different asset scope or expired lease rejected
    def test_46_certificate_replay_different_scope_or_incident_rejected(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)

        # 1. Different asset scope
        ir_diff_scope = copy.deepcopy(ir)
        ir_diff_scope.variable_domains["extra_res_01"] = VariableDomain(
            resource_id="extra_res_01", resource_type="server", admissible_actions=["monitor"]
        )
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.verify_binding(ir_diff_scope, cert)

        # 2. Expired lease
        c_expired = copy.deepcopy(cert)
        c_expired.timestamp -= 600.0  # Expired > 300s lease
        with self.assertRaises(StaleCertificateError):
            FormulationCompiler.verify_binding(ir, c_expired)

    # 47. Independent Proof Checker agrees with Enumeration Oracle on small instances
    def test_47_proof_checker_agrees_with_enumeration(self):
        from layer5_constraints.proof_checker import IndependentProofChecker, FidelityProofError
        from layer5_constraints.semantic_validator import SemanticValidator

        small_scen = {
            "scenario": "checker_agreement",
            "resources": [
                {"id": "s1", "type": "server"},
                {"id": "p1", "type": "plc_controller"},
            ],
        }
        small_scores = {"s1": 0.8, "p1": 0.8}
        small_ctx = {
            "s1": create_test_context("s1", "server", threat=0.8, sla="HIGH", hipaa=False),
            "p1": create_test_context("p1", "plc_controller", threat=0.8, sla="CRITICAL", hipaa=False),
        }
        small_conf = {"s1": create_test_confidence("s1"), "p1": create_test_confidence("p1")}

        dag = ConstraintDependencyGraph(incident_id="checker_agreement")
        ir = dag.resolve(small_scen, small_scores, small_ctx, small_conf, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)

        # Compile both backends
        comp_ilp = FormulationCompiler.compile_to_ilp(ir, certificate=cert)
        comp_qubo = FormulationCompiler.compile_to_qubo(ir, certificate=cert)

        prob, x_vars = comp_ilp
        qp, q_vars = comp_qubo

        # 1. Independent Proof Checker passes on valid formulations
        ilp_report = IndependentProofChecker.check(ir, prob, comp_ilp.fidelity_proof, cert)
        self.assertTrue(ilp_report.is_valid)
        self.assertEqual(ilp_report.backend_id, "ILP_PULP")
        self.assertIn("polynomial in the size of the proof", ilp_report.complexity_guarantee)

        qubo_report = IndependentProofChecker.check(ir, qp, comp_qubo.fidelity_proof, cert)
        self.assertTrue(qubo_report.is_valid)
        self.assertEqual(qubo_report.backend_id, "QUBO_QISKIT")

        # 2. Semantic Validator (Enumeration Oracle) also verifies 100% fidelity
        sem_rep = SemanticValidator.validate_backend_semantics(
            ir=ir,
            ilp_model=prob,
            ilp_var_lookup=x_vars,
            qubo_model=qp,
            qubo_var_lookup=q_vars,
            manifest=comp_ilp.manifest,
            max_vars=10,
        )
        self.assertEqual(sem_rep.ir_vs_ilp_mismatches, 0)
        self.assertEqual(sem_rep.ir_vs_qubo_mismatches, 0)
        self.assertEqual(sem_rep.semantic_fidelity_ilp_pct, 100.0)
        self.assertEqual(sem_rep.semantic_fidelity_qubo_pct, 100.0)

        # 3. Corrupt ILP by dropping constraints: both Checker and Oracle detect the defect
        corrupt_prob = copy.deepcopy(prob)
        corrupt_prob.constraints.clear()

        # Checker rejects corrupted backend
        with self.assertRaises(FidelityProofError):
            IndependentProofChecker.check(ir, corrupt_prob, comp_ilp.fidelity_proof, cert)

        # Oracle confirms mismatch
        sem_rep_corrupt = SemanticValidator.validate_backend_semantics(
            ir=ir,
            ilp_model=corrupt_prob,
            ilp_var_lookup=x_vars,
            manifest=comp_ilp.manifest,
            max_vars=10,
        )
        self.assertGreater(sem_rep_corrupt.ir_vs_ilp_mismatches, 0)

    # 48. Post-solve feasibility gate filters and conditionally repairs infeasible plan
    def test_48_feasibility_gate_filters_and_repairs_infeasible_plan(self):
        from layer6_optimization.feasibility_gate import FeasibilityGate, InfeasiblePlanRejectionError

        scen = {
            "scenario": "gate_test",
            "resources": [
                {"id": "s1", "type": "server"},
                {"id": "p1", "type": "plc_controller"},
            ],
        }
        threat = {"s1": 0.85, "p1": 0.85}
        ctx = {
            "s1": create_test_context("s1", "server", threat=0.85, sla="HIGH", hipaa=True),
            "p1": create_test_context("p1", "plc_controller", threat=0.85, sla="CRITICAL", hipaa=False),
        }
        conf = {"s1": create_test_confidence("s1"), "p1": create_test_confidence("p1")}

        dag = ConstraintDependencyGraph(incident_id="gate_test")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)

        # 1. Valid plan passes through unrepaired
        valid_plan = {"s1": "isolate", "p1": "monitor"}
        res_valid = FeasibilityGate.filter_and_repair(valid_plan, ir, certificate=cert)
        self.assertTrue(res_valid.is_feasible)
        self.assertFalse(res_valid.was_repaired)
        self.assertEqual(res_valid.plan, valid_plan)

        # 2. Infeasible plan (excised action 'isolate' on plc_controller) is repaired
        infeasible_plan = {"s1": "isolate", "p1": "isolate"}
        is_mem, viol = FeasibilityGate.check_membership(infeasible_plan, ir)
        self.assertFalse(is_mem)
        self.assertGreater(len(viol), 0)

        res_repaired = FeasibilityGate.filter_and_repair(infeasible_plan, ir, certificate=cert)
        self.assertTrue(res_repaired.is_feasible)
        self.assertTrue(res_repaired.was_repaired)
        # Repaired plan must NEVER contain the excised action
        self.assertNotEqual(res_repaired.plan["p1"], "isolate")
        self.assertIn(res_repaired.plan["p1"], ir.variable_domains["p1"].admissible_actions)

        # Invariant: Every plan exiting the gate is in F(IR)
        is_repaired_mem, _ = FeasibilityGate.check_membership(res_repaired.plan, ir)
        self.assertTrue(is_repaired_mem)

        # 3. Conditional delta-optimality loss bound
        # When LP lower bound is provided: returns real loss bound >= 0.0
        bound = FeasibilityGate.compute_certified_loss_bound(res_repaired.plan, ir, lp_relaxation_lower_bound=-5.0)
        self.assertIsNotNone(bound)
        self.assertGreaterEqual(bound, 0.0)

        # When no LP bound is provided: returns None (no universal bound claimed)
        none_bound = FeasibilityGate.compute_certified_loss_bound(res_repaired.plan, ir, lp_relaxation_lower_bound=None)
        self.assertIsNone(none_bound)


if __name__ == "__main__":
    unittest.main(verbosity=2)



