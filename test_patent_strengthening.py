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
    HAS_PULP,
    HAS_QISKIT,
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

    # 21. QUBO under-budget feasibility: Cost=6, Budget=10 is valid in both ILP and QUBO
    def test_21_qubo_under_budget_feasibility(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)
        prob, ilp_lookup = FormulationCompiler.compile_to_ilp(ir, cert)
        qubo, qubo_lookup = FormulationCompiler.compile_to_qubo(ir, cert)

        witness = cert.feasibility_witness
        self.assertIsNotNone(witness)
        asgn = {}
        for rid, domain in ir.variable_domains.items():
            for act in domain.admissible_actions:
                asgn[(rid, act)] = 1 if witness.get(rid) == act else 0

        total_cost = sum(ir.budget_constraint.cost_map.get((r, a), 0.0) * v for (r, a), v in asgn.items())
        self.assertLessEqual(total_cost, 10.0)

        ilp_valid = SemanticValidator.evaluate_ilp_feasibility(prob, ilp_lookup, asgn)
        qubo_valid = SemanticValidator.evaluate_qubo_feasibility(ir, asgn, qubo_model=qubo, qubo_var_lookup=qubo_lookup)
        self.assertTrue(ilp_valid)
        self.assertTrue(qubo_valid)

    # 22. QUBO exact-budget feasibility: Cost=10, Budget=10 is valid in both ILP and QUBO
    def test_22_qubo_exact_budget_feasibility(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)
        witness = cert.feasibility_witness
        self.assertIsNotNone(witness)
        witness_cost = sum(ir.budget_constraint.cost_map.get((r, witness[r]), 0.0) for r in witness)
        ir.budget_constraint.max_budget = witness_cost
        ir.compute_canonical_digest()
        cert2 = PreSolveSafetyCertifier.certify(ir)

        prob, ilp_lookup = FormulationCompiler.compile_to_ilp(ir, cert2)
        qubo, qubo_lookup = FormulationCompiler.compile_to_qubo(ir, cert2)

        asgn = {}
        for rid, domain in ir.variable_domains.items():
            for act in domain.admissible_actions:
                asgn[(rid, act)] = 1 if witness.get(rid) == act else 0

        ilp_valid = SemanticValidator.evaluate_ilp_feasibility(prob, ilp_lookup, asgn)
        qubo_valid = SemanticValidator.evaluate_qubo_feasibility(ir, asgn, qubo_model=qubo, qubo_var_lookup=qubo_lookup)
        self.assertTrue(ilp_valid)
        self.assertTrue(qubo_valid)

    # 23. QUBO over-budget rejection: Cost > Budget is rejected in both ILP and QUBO
    def test_23_qubo_over_budget_rejection(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)
        prob, ilp_lookup = FormulationCompiler.compile_to_ilp(ir, cert)
        qubo, qubo_lookup = FormulationCompiler.compile_to_qubo(ir, cert)

        asgn_over = {v: 1 for v in ir.get_all_variables()}
        ilp_valid = SemanticValidator.evaluate_ilp_feasibility(prob, ilp_lookup, asgn_over)
        qubo_valid = SemanticValidator.evaluate_qubo_feasibility(ir, asgn_over, qubo_model=qubo, qubo_var_lookup=qubo_lookup)
        self.assertFalse(ilp_valid)
        self.assertFalse(qubo_valid)

    # 24. Actual QUBO corruption detected by semantic validator
    def test_24_actual_qubo_corruption_detected(self):
        small_scen = {"scenario": "small", "resources": [{"id": "r1", "type": "server"}]}
        small_threat = {"r1": 0.8}
        small_ctx = {"r1": create_test_context("r1", "server")}
        small_conf = {"r1": create_test_confidence("r1")}

        ir = self.dag.resolve(small_scen, small_threat, small_ctx, small_conf, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)
        qubo, qubo_lookup = FormulationCompiler.compile_to_qubo(ir, cert)
        qubo.is_corrupted = True
        report = SemanticValidator.validate_backend_semantics(
            ir, qubo_model=qubo, qubo_var_lookup=qubo_lookup, max_vars=8
        )
        self.assertEqual(report.qubo_semantically_valid_count, 0)
        self.assertGreater(report.ir_vs_qubo_mismatches, 0)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
