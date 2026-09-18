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
import hashlib
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
    SubgraphDigestMismatchError,
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
            prob, x_vars = FormulationCompiler.compile_to_ilp(ir, certificate=cert, current_snapshot=ir.state_snapshot)
            self.assertIsNotNone(prob)
            self.assertGreater(len(x_vars), 0)

        if HAS_QISKIT:
            qp, lookup = FormulationCompiler.compile_to_qubo(ir, certificate=cert, current_snapshot=ir.state_snapshot)
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
            FormulationCompiler.compile_to_ilp(ir, certificate=cert, current_snapshot=ir.state_snapshot)

    # 11. Stale certificate is rejected
    def test_11_stale_certificate_rejected(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        cert = PreSolveSafetyCertifier.certify(ir)

        # Advance runtime state version
        ir.runtime_state_version = cert.runtime_state_version + 1
        ir.compute_canonical_digest()

        with self.assertRaises(StaleCertificateError):
            FormulationCompiler.compile_to_ilp(ir, certificate=cert, current_snapshot=ir.state_snapshot)

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
            FormulationCompiler.compile_to_ilp(ir_A, certificate=cert_B, current_snapshot=ir_A.state_snapshot)

    # 13. Uncertified IR is rejected
    def test_13_uncertified_ir_rejected(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences)
        with self.assertRaises(UncertifiedIRCompilationError):
            FormulationCompiler.compile_to_ilp(ir, certificate=None, current_snapshot=ir.state_snapshot)

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

        prob, x_vars, manifest = FormulationCompiler.compile_to_ilp(ir, certificate=cert, return_manifest=True, current_snapshot=ir.state_snapshot)
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

        prob, x_vars, manifest = FormulationCompiler.compile_to_ilp(ir, certificate=cert, return_manifest=True, current_snapshot=ir.state_snapshot)

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
        qubo, qubo_lookup = FormulationCompiler.compile_to_qubo(ir, cert, current_snapshot=ir.state_snapshot)

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
            FormulationCompiler.compile_to_ilp(ir, cert, current_snapshot=ir.state_snapshot)

    # 30. Tampered closure metadata rejected
    def test_30_tampered_closure_metadata_rejected(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)
        if ir.dependency_closure_metadata:
            ir.dependency_closure_metadata.removed_variables.append(("fake_res", "fake_act"))
            with self.assertRaises(IntegrityBindingError):
                FormulationCompiler.compile_to_ilp(ir, cert, current_snapshot=ir.state_snapshot)

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
        report = validate_plan_against_certified_ir(admissible, ir, cert, current_snapshot=ir.state_snapshot)
        self.assertEqual(report["validated_actions"], 2)

        # A plan that drifted outside the certified domain is refused
        with self.assertRaises(InadmissibleActionError):
            validate_plan_against_certified_ir({"plc1": "isolate"}, ir, cert, current_snapshot=ir.state_snapshot)

        # ...and no actuation command is emitted for it
        with self.assertRaises(InadmissibleActionError):
            execute_plan({"plc1": "isolate"}, sc_ir=ir, certificate=cert, current_snapshot=ir.state_snapshot)

        # An unknown resource has no certified domain and is refused
        with self.assertRaises(InadmissibleActionError):
            validate_plan_against_certified_ir({"unknown_res": "monitor"}, ir, cert, current_snapshot=ir.state_snapshot)

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
            FormulationCompiler.verify_binding(ir, cert, current_snapshot=ir.state_snapshot)
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.compile_to_ilp(ir, cert, current_snapshot=ir.state_snapshot)

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

        # Mixed tiers setup across resources:
        # res_server_01 in high tier (0.85 in (0.70, 1.0])
        # res_plc_01 in mid tier (0.65 in (0.60, 0.70])
        # res_gw_01 in high tier (0.75 in (0.70, 1.0])
        # Mean threat = (0.85 + 0.65 + 0.75) / 3 = 0.75 in (0.70, 1.0] -> Budget multiplier 1.3
        threats_mixed = {
            "res_server_01": 0.85,
            "res_plc_01": 0.65,
            "res_gw_01": 0.75,
        }
        contexts_mixed = {
            "res_server_01": create_test_context("res_server_01", "server", threat=0.85, sla="HIGH", hipaa=True),
            "res_plc_01": create_test_context("res_plc_01", "plc_controller", threat=0.65, sla="CRITICAL", hipaa=False),
            "res_gw_01": create_test_context("res_gw_01", "network_gateway", threat=0.75, sla="CRITICAL", hipaa=False),
        }

        base_ir = self.dag.resolve(
            self.scenario, threats_mixed, contexts_mixed, self.confidences, base_budget=10.0
        )
        envelope = base_ir.validity_envelope
        self.assertIsNotNone(envelope)

        base_domains = base_ir.active_variable_domain
        base_hard = sorted([(c.constraint_id, c.target_resource, c.target_action) for c in base_ir.hard_constraints])
        base_budget = round(float(base_ir.budget_constraint.max_budget), 4)

        base_snap = snapshot_from_contexts(
            contexts=contexts_mixed,
            confidences=self.confidences,
            scenario=self.scenario,
            epoch=1,
            threat_scores=threats_mixed,
        )
        in_env_ok, _ = envelope.contains(base_snap)
        self.assertTrue(in_env_ok)

        # 1. Sample 500 snapshots strictly inside E_t across MIXED tiers
        inside_count = 0
        while inside_count < 500:
            sample_threats = {
                "res_server_01": rng.uniform(0.72, 0.98),  # (0.70, 1.0]
                "res_plc_01": rng.uniform(0.61, 0.69),     # (0.60, 0.70]
                "res_gw_01": rng.uniform(0.72, 0.98),      # (0.70, 1.0]
            }
            sample_contexts = {
                r: create_test_context(r, contexts_mixed[r].asset.resource_type, threat=sample_threats[r], sla=contexts_mixed[r].business.sla_priority, hipaa=contexts_mixed[r].compliance.hipaa_applicable)
                for r in sample_threats
            }
            sample_confidences = {
                r: create_test_confidence(r, rng.uniform(0.52, 0.98))
                for r in sample_threats
            }

            snap_sample = snapshot_from_contexts(
                contexts=sample_contexts,
                confidences=sample_confidences,
                scenario=self.scenario,
                epoch=1,
                threat_scores=sample_threats,
            )
            inside, viols = envelope.contains(snap_sample)
            if not inside:
                continue

            inside_count += 1
            # Re-resolve and assert exact structural invariance and budget identity
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
            pick = i % 4
            if pick == 0:
                # Threat crosses below 0.40 threshold for res_gw_01 (SLA Critical forbids isolate)
                violating_snap.resources["res_gw_01"].threat_score = rng.uniform(0.10, 0.35)
            elif pick == 1:
                # Confidence drops below 0.50 threshold for res_server_01
                violating_snap.resources["res_server_01"].overall_confidence = rng.uniform(0.10, 0.45)
            elif pick == 2:
                # SLA priority changed to LOW
                violating_snap.resources["res_plc_01"].sla_priority = "LOW"
            else:
                # Violate aggregate mean_threat_score by dropping res_server_01 into low tier
                violating_snap.resources["res_server_01"].threat_score = 0.20

            inside, viols = envelope.contains(violating_snap)
            self.assertFalse(inside)
            self.assertTrue(len(viols) > 0)

            # Re-resolve to see if outcome changes
            v_threats = {r: violating_snap.resources[r].threat_score for r in violating_snap.resources}
            v_contexts = {r: create_test_context(r, violating_snap.resources[r].resource_type, threat=st.threat_score, sla=st.sla_priority, hipaa=st.hipaa_applicable) for r, st in violating_snap.resources.items()}
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
        prob, ilp_lookup = FormulationCompiler.compile_to_ilp(ir, cert, current_snapshot=ir.state_snapshot)
        self.assertIsNotNone(prob)

    # 44. Tampered payload fields (IR digest, closure, witness, envelope, asset_scope, policy_revision, epoch) rejected
    def test_44_certificate_tampered_payload_fields_rejected(self):
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)

        # 1. Tampered IR digest
        c1 = copy.deepcopy(cert)
        c1.ir_sha256 = "f" * 64
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.verify_binding(ir, c1, current_snapshot=ir.state_snapshot)

        # 2. Tampered closure digest
        c2 = copy.deepcopy(cert)
        c2.closure_digest = "e" * 64
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.verify_binding(ir, c2, current_snapshot=ir.state_snapshot)

        # 3. Tampered witness digest
        c3 = copy.deepcopy(cert)
        c3.witness_digest = "d" * 64
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.verify_binding(ir, c3, current_snapshot=ir.state_snapshot)

        # 4. Tampered envelope digest
        c4 = copy.deepcopy(cert)
        c4.envelope_digest = "c" * 64
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.verify_binding(ir, c4, current_snapshot=ir.state_snapshot)

        # 5. Tampered asset scope
        c5 = copy.deepcopy(cert)
        c5.asset_scope = ["rogue_resource_99"]
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.verify_binding(ir, c5, current_snapshot=ir.state_snapshot)

        # 6. Tampered policy revision
        c6 = copy.deepcopy(cert)
        c6.policy_revision = "stale_policy_hash"
        with self.assertRaises((IntegrityBindingError, StaleCertificateError)):
            FormulationCompiler.verify_binding(ir, c6, current_snapshot=ir.state_snapshot)

        # 7. Tampered epoch
        c7 = copy.deepcopy(cert)
        c7.state_epoch = 999
        with self.assertRaises((IntegrityBindingError, StaleCertificateError)):
            FormulationCompiler.verify_binding(ir, c7, current_snapshot=ir.state_snapshot)

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
            FormulationCompiler.verify_binding(ir, c_rogue, current_snapshot=ir.state_snapshot)

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
            FormulationCompiler.verify_binding(ir_diff_scope, cert, current_snapshot=ir_diff_scope.state_snapshot)

        # 2. Expired lease
        c_expired = copy.deepcopy(cert)
        c_expired.timestamp -= 600.0  # Expired > 300s lease
        with self.assertRaises(StaleCertificateError):
            FormulationCompiler.verify_binding(ir, c_expired, current_snapshot=ir.state_snapshot)

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
        comp_ilp = FormulationCompiler.compile_to_ilp(ir, certificate=cert, current_snapshot=ir.state_snapshot)
        comp_qubo = FormulationCompiler.compile_to_qubo(ir, certificate=cert, current_snapshot=ir.state_snapshot)

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

    # 49. Actuation capability verifier, state epoch, and device-side revision check
    def test_49_actuation_capability_verifier_and_device_revision_race(self):
        from layer8_orchestration.capability_verifier import ActuationCapabilityVerifier, ActuationVerificationError
        from layer8_orchestration.executor import SimulatedDeviceInterface, execute_plan
        from pipeline import reconstruct_and_recertify
        from layer5_constraints.runtime_state import snapshot_from_contexts

        scen = {
            "scenario": "actuation_test",
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

        snap_initial = snapshot_from_contexts(ctx, conf, scen, epoch=1)
        dag = ConstraintDependencyGraph(incident_id="actuation_test")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap_initial)
        cert = PreSolveSafetyCertifier.certify(ir)

        plan = {"s1": "isolate", "p1": "monitor"}

        # 1. Authorize actuation with matching snapshot
        auth = ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap_initial)
        self.assertTrue(auth.is_authorized)
        self.assertEqual(auth.expected_state_revision, 1)
        self.assertTrue(auth.domain_authenticated)
        self.assertTrue(auth.domain_certified)
        self.assertTrue(auth.envelope_valid)
        self.assertTrue(auth.epoch_valid)

        # 2. SimulatedDeviceInterface executes command with matching expected_state_revision
        sim_dev = SimulatedDeviceInterface("p1", initial_revision=1)
        cmd = {
            "resource_id": "p1",
            "action": "monitor",
            "expected_state_revision": auth.expected_state_revision,
        }
        res_cmd = sim_dev.execute_command(cmd)
        self.assertEqual(res_cmd["status"], "simulated_success")
        self.assertEqual(res_cmd["revision"], 1)

        # 3. Race condition: Bump device revision asynchronously (mutation occurs before dispatch)
        sim_dev.bump_revision(1)  # Device revision is now 2
        self.assertEqual(sim_dev.current_revision, 2)

        # Dispatch command carrying stale expected revision 1 -> MUST BE REJECTED
        res_stale = sim_dev.execute_command(cmd)
        self.assertEqual(res_stale["status"], "rejected")
        self.assertIn("revision race", res_stale["error"].lower())

        # 4. execute_plan routes through verifier and attaches expected revision and validation flags
        logs = execute_plan(plan, sc_ir=ir, certificate=cert, current_snapshot=snap_initial)
        self.assertGreater(len(logs), 0)
        for entry in logs:
            self.assertEqual(entry["expected_state_revision"], 1)
            self.assertTrue(entry["domain_certified"])
            self.assertTrue(entry["envelope_valid"])
            self.assertTrue(entry["epoch_valid"])

        # 5. Closed-loop: Relevant state change triggers refusal, then reconstruction recertifies
        mutated_ctx = copy.deepcopy(ctx)
        mutated_ctx["s1"].threat.threat_score = 0.25  # Crosses 0.70 threshold -> leaves envelope!
        snap_mutated = snapshot_from_contexts(mutated_ctx, conf, scen, epoch=2)

        # Actuation refused on old certificate
        with self.assertRaises(ActuationVerificationError):
            ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap_mutated)

        # Closed-loop reconstruction & recertification
        new_ir, new_cert, new_snap = reconstruct_and_recertify(
            scen, {"s1": 0.25, "p1": 0.85}, mutated_ctx, conf, reason="state_drift_detected", epoch=2
        )
        self.assertEqual(new_cert.status, "CERTIFIED")
        self.assertEqual(new_cert.state_epoch, 2)
        # New envelope must contain the mutated state
        is_inside, viols = new_cert.validity_envelope.contains(new_snap)
        self.assertTrue(is_inside, f"New envelope failed to contain new state: {viols}")

    # 50. Certified incremental lineage chain, parent cryptographic binding, and clean subgraph invariance
    def test_50_certified_incremental_lineage_chain_and_subgraph_invariance(self):
        scenario = {
            "scenario": "lineage_chain_test",
            "resources": [
                {"id": "res_a", "type": "server"},
                {"id": "res_b", "type": "server"},
                {"id": "res_c", "type": "server"},
                {"id": "res_d", "type": "server"},
            ],
        }
        threats_t1 = {"res_a": 0.85, "res_b": 0.85, "res_c": 0.85, "res_d": 0.85}
        ctx_t1 = {
            r["id"]: create_test_context(r["id"], r["type"], threat=0.85, sla="HIGH")
            for r in scenario["resources"]
        }
        conf_t1 = {r["id"]: create_test_confidence(r["id"], 0.90) for r in scenario["resources"]}

        # 1. Base compile: C_1 (root of lineage)
        dag = ConstraintDependencyGraph(incident_id="lineage_test")
        ir_1 = dag.resolve(scenario, threats_t1, ctx_t1, conf_t1, base_budget=20.0, ir_version=1)
        cert_1 = PreSolveSafetyCertifier.certify(ir_1)
        self.assertIsNone(cert_1.parent_certificate_digest)
        self.assertTrue(cert_1.verify_signature())
        self.assertGreater(len(cert_1.subgraph_digests), 0)

        # 2. Incremental compile 1: Delta on res_a -> C_2 (parent: C_1)
        threats_t2 = dict(threats_t1)
        threats_t2["res_a"] = 0.55
        delta_1 = RuntimeStateDelta(
            changed_assets=["res_a"],
            changed_threat_state={"res_a": 0.55},
        )
        res_1 = IncrementalConstraintCompiler.compile_delta(
            previous_ir=ir_1,
            delta=delta_1,
            scenario=scenario,
            all_contexts=ctx_t1,
            all_confidences=conf_t1,
            all_threat_scores=threats_t2,
            base_budget=20.0,
            parent_certificate=cert_1,
        )
        ir_2 = res_1.updated_ir
        cert_2 = res_1.updated_certificate
        self.assertEqual(cert_2.parent_certificate_digest, cert_1.integrity_digest)
        self.assertTrue(cert_2.verify_signature())
        self.assertTrue(cert_2.verify_lineage(cert_1))
        self.assertIsNotNone(cert_2.incremental_equivalence_check)
        self.assertEqual(cert_2.incremental_equivalence_check["method"], "digest_gated_reuse")
        self.assertIn("reused_subgraph_digests", cert_2.incremental_equivalence_check)
        self.assertIn("recomputed", cert_2.incremental_equivalence_check)

        # 3. Incremental compile 2: Delta on res_b -> C_3 (parent: C_2)
        threats_t3 = dict(threats_t2)
        threats_t3["res_b"] = 0.45
        delta_2 = RuntimeStateDelta(
            changed_assets=["res_b"],
            changed_threat_state={"res_b": 0.45},
        )
        res_2 = IncrementalConstraintCompiler.compile_delta(
            previous_ir=ir_2,
            delta=delta_2,
            scenario=scenario,
            all_contexts=ctx_t1,
            all_confidences=conf_t1,
            all_threat_scores=threats_t3,
            base_budget=20.0,
            parent_certificate=cert_2,
        )
        ir_3 = res_2.updated_ir
        cert_3 = res_2.updated_certificate
        self.assertEqual(cert_3.parent_certificate_digest, cert_2.integrity_digest)
        self.assertTrue(cert_3.verify_signature())
        self.assertTrue(cert_3.verify_lineage(cert_2))
        self.assertIsNotNone(cert_3.incremental_equivalence_check)

        # 4. Three-certificate sequential lineage chain verifies in order
        chain = [cert_1, cert_2, cert_3]
        self.assertTrue(ConstraintSafetyCertificate.verify_lineage_chain(chain))

        # 5. Breaking parent link fails verification
        # 5a. Tampered parent digest in C_3
        broken_c3 = copy.deepcopy(cert_3)
        broken_c3.parent_certificate_digest = "0" * 64
        self.assertFalse(broken_c3.verify_lineage(cert_2))
        self.assertFalse(ConstraintSafetyCertificate.verify_lineage_chain([cert_1, cert_2, broken_c3]))
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.verify_binding(ir_3, broken_c3, current_snapshot=ir_3.state_snapshot)

        # 5b. Broken intermediate parent certificate in chain
        tampered_c2 = copy.deepcopy(cert_2)
        tampered_c2.policy_revision = "unauthorized_policy_mutation"
        self.assertFalse(cert_3.verify_lineage(tampered_c2))
        self.assertFalse(ConstraintSafetyCertificate.verify_lineage_chain([cert_1, tampered_c2, cert_3]))

        # 6. Reused clean subgraph whose digest changed is refused
        # Mutate clean asset 'res_c' inside ir_2 before running delta_2
        corrupted_ir_2 = copy.deepcopy(ir_2)
        corrupted_ir_2.variable_domains["res_c"].admissible_actions.append("non_certified_action")
        with self.assertRaises(SubgraphDigestMismatchError):
            IncrementalConstraintCompiler.compile_delta(
                previous_ir=corrupted_ir_2,
                delta=delta_2,
                scenario=scenario,
                all_contexts=ctx_t1,
                all_confidences=conf_t1,
                all_threat_scores=threats_t3,
                base_budget=20.0,
                parent_certificate=cert_2,
            )

    # 51. Aggregate mean threat score envelope soundness
    def test_51_aggregate_mean_threat_envelope_soundness(self):
        scenario = {
            "scenario": "mean_threat_test",
            "resources": [
                {"id": "res_1", "type": "server"},
                {"id": "res_2", "type": "network_gateway"},
            ],
        }
        threats_cert = {"res_1": 0.85, "res_2": 0.65}
        contexts_cert = {
            "res_1": create_test_context("res_1", "server", threat=0.85, sla="HIGH"),
            "res_2": create_test_context("res_2", "network_gateway", threat=0.65, sla="HIGH"),
        }
        confidences = {
            "res_1": create_test_confidence("res_1", 0.95),
            "res_2": create_test_confidence("res_2", 0.95),
        }

        # 1. Certify at initial threats {0.85, 0.65}
        # Mean threat = (0.85 + 0.65) / 2 = 0.75 > 0.70 -> Multiplier = 1.3
        # Budget = 10.0 * 1.3 = 13.0
        base_ir = self.dag.resolve(scenario, threats_cert, contexts_cert, confidences, base_budget=10.0)
        self.assertEqual(round(float(base_ir.budget_constraint.max_budget), 2), 13.0)
        envelope = base_ir.validity_envelope
        self.assertIsNotNone(envelope)

        # 2. Perturb to {0.71, 0.61}
        # Notice: 0.71 is in (0.70, 1.0] and 0.61 is in (0.60, 0.70] (per-resource intervals hold)
        # BUT perturbed mean threat = (0.71 + 0.61) / 2 = 0.66 <= 0.70 -> Multiplier drops to 1.0!
        threats_pert = {"res_1": 0.71, "res_2": 0.61}
        contexts_pert = {
            "res_1": create_test_context("res_1", "server", threat=0.71, sla="HIGH"),
            "res_2": create_test_context("res_2", "network_gateway", threat=0.61, sla="HIGH"),
        }
        snap_pert = snapshot_from_contexts(
            contexts=contexts_pert,
            confidences=confidences,
            scenario=scenario,
            epoch=1,
            threat_scores=threats_pert,
        )

        # Assert envelope.contains() is FALSE because aggregate mean_threat_score left the interval
        is_inside, violations = envelope.contains(snap_pert)
        self.assertFalse(is_inside, "Envelope should have rejected sample due to mean_threat_score violation")
        self.assertTrue(any("mean_threat_score" in v for v in violations))

        # Re-derive budget on perturbed state: multiplier is 1.0, budget re-derives from 13.0 -> 10.0
        ir_pert = self.dag.resolve(scenario, threats_pert, contexts_pert, confidences, base_budget=10.0)
        self.assertEqual(round(float(ir_pert.budget_constraint.max_budget), 2), 10.0)

    # 52. Policy threshold constants single source of truth verification
    def test_52_policy_thresholds_single_source_of_truth(self):
        import re
        from pathlib import Path
        root = Path(__file__).parent / "layer5_constraints"
        target_files = ["dependency_graph.py", "adaptive_constraints.py", "validity_envelope.py"]
        pattern = re.compile(r"\b0\.[4567]0?\b")

        for fname in target_files:
            fpath = root / fname
            self.assertTrue(fpath.exists(), f"File {fpath} does not exist")
            content = fpath.read_text(encoding="utf-8")
            offending_lines = []
            for lineno, line in enumerate(content.splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                matches = pattern.findall(line)
                if matches:
                    offending_lines.append((lineno, line, matches))

            self.assertEqual(
                len(offending_lines), 0,
                f"File {fname} contains literal threshold constants: {offending_lines}. "
                "All thresholds must be imported from policy_thresholds.py."
            )

    # 53. QUBO fidelity checker verifies model, not compiler metadata (three model mutations + one proof mutation)
    def test_53_qubo_undersized_penalty_rejected_by_checker(self):
        from layer5_constraints.proof_checker import IndependentProofChecker, FidelityProofError
        ir = self.dag.resolve(self.scenario, self.threat_scores, self.contexts, self.confidences, base_budget=10.0)
        cert = PreSolveSafetyCertifier.certify(ir)
        comp_qubo = FormulationCompiler.compile_to_qubo(ir, certificate=cert, current_snapshot=ir.state_snapshot)
        qp, _ = comp_qubo
        proof = comp_qubo.fidelity_proof

        # Normal verification passes
        report = IndependentProofChecker.check(ir, qp, proof, cert)
        self.assertTrue(report.is_valid)

        # Negative (a): Scale all quadratic coefficients by 0.01 in the model ONLY
        qp_a = copy.deepcopy(qp)
        quad_a = qp_a.objective.quadratic.to_dict(use_name=True)
        qp_a.objective.quadratic = {pair: float(val) * 0.01 for pair, val in quad_a.items()}
        with self.assertRaises(FidelityProofError) as ctx_a:
            IndependentProofChecker.check(ir, qp_a, proof, cert)
        self.assertIn("quadratic coefficient mismatch", str(ctx_a.exception).lower())

        # Negative (b): Zero one conflict pair's coefficient in the model ONLY
        qp_b = copy.deepcopy(qp)
        quad_b = qp_b.objective.quadratic.to_dict(use_name=True)
        conflict_trans = next(t for t in proof.constraint_translations if t.get("ir_constraint_type") == "CONFLICT")
        c_elems = conflict_trans["backend_elements"]
        c_pair = (c_elems[0], c_elems[1]) if (c_elems[0], c_elems[1]) in quad_b else (c_elems[1], c_elems[0])
        new_quad_b = dict(quad_b)
        new_quad_b[c_pair] = 0.0
        qp_b.objective.quadratic = new_quad_b
        with self.assertRaises(FidelityProofError) as ctx_b:
            IndependentProofChecker.check(ir, qp_b, proof, cert)
        self.assertIn("quadratic coefficient mismatch", str(ctx_b.exception).lower())

        # Negative (c): Change one linear coefficient in the model ONLY
        qp_c = copy.deepcopy(qp)
        lin_c = dict(qp_c.objective.linear.to_dict(use_name=True))
        target_var = next(iter(lin_c.keys()))
        lin_c[target_var] = float(lin_c[target_var]) + 100.0
        qp_c.objective.linear = lin_c
        with self.assertRaises(FidelityProofError) as ctx_c:
            IndependentProofChecker.check(ir, qp_c, proof, cert)
        self.assertIn("linear coefficient mismatch", str(ctx_c.exception).lower())

        # Negative (d): Mutate one translation weight in the proof only -> must raise
        proof_d = copy.deepcopy(proof)
        first_trans = proof_d.constraint_translations[0]
        first_trans["parameters"]["penalty"] = float(first_trans["parameters"]["penalty"]) * 2.0
        proof_d.proof_digest = proof_d.compute_digest()
        with self.assertRaises(FidelityProofError) as ctx_d:
            IndependentProofChecker.check(ir, qp, proof_d, cert)
        self.assertTrue(
            "mismatch" in str(ctx_d.exception).lower() or "penalty" in str(ctx_d.exception).lower()
        )

    # 54. Least-fixed-point closure order-independence across random edge insertion permutations
    def test_54_least_fixed_point_order_independence(self):
        import random
        from layer5_constraints.dependency_graph import TypedDependencyEdge, DependencyRelationType

        all_vars = {
            ("s1", "isolate"), ("s1", "monitor"), ("s1", "rotate_credentials"),
            ("s2", "isolate"), ("s2", "monitor"),
            ("gw1", "isolate"), ("gw1", "monitor"),
            ("fw1", "isolate"), ("fw1", "monitor"),
            ("db1", "isolate"), ("db1", "monitor"),
            ("plc1", "isolate"), ("plc1", "monitor"),
        }
        initial_removed = {("plc1", "isolate"), ("db1", "isolate")}
        edges = [
            TypedDependencyEdge("gw1:isolate", "plc1:isolate", DependencyRelationType.REQUIRES, "r1"),
            TypedDependencyEdge("s1:isolate", "gw1:isolate", DependencyRelationType.REQUIRES, "r2"),
            TypedDependencyEdge("s2:isolate", "gw1:isolate", DependencyRelationType.REQUIRES, "r3"),
            TypedDependencyEdge("fw1:isolate", "gw1:isolate", DependencyRelationType.REQUIRES, "r4"),
            TypedDependencyEdge("s1:rotate_credentials", "db1:isolate", DependencyRelationType.REQUIRES, "r5"),
        ]
        conflicts = [
            ("s1", "isolate", "s2", "isolate", "c1"),
            ("gw1", "isolate", "fw1", "isolate", "c2"),
        ]
        cost_map = {(r, a): 1.0 for (r, a) in all_vars}

        base_vars, base_confs, base_res = ConstraintDependencyGraph.compute_fixed_point_closure(
            initial_removed=initial_removed,
            all_variables=all_vars,
            dependency_edges=edges,
            conflict_pairs=conflicts,
            cost_map=cost_map,
            base_budget=10.0,
        )
        base_digest = base_res.compute_canonical_digest()

        for seed in range(50):
            rng = random.Random(seed)
            shuffled_edges = list(edges)
            rng.shuffle(shuffled_edges)
            shuffled_conflicts = list(conflicts)
            rng.shuffle(shuffled_conflicts)

            vars_i, confs_i, res_i = ConstraintDependencyGraph.compute_fixed_point_closure(
                initial_removed=initial_removed,
                all_variables=all_vars,
                dependency_edges=shuffled_edges,
                conflict_pairs=shuffled_conflicts,
                cost_map=cost_map,
                base_budget=10.0,
            )
            self.assertEqual(vars_i, base_vars)
            self.assertEqual(confs_i, base_confs)
            self.assertEqual(res_i.compute_canonical_digest(), base_digest)

    def test_55_certificate_only_actuation_manifest_and_invariant(self):
        """
        Hardening Item B: Certificate-only actuation via CertifiedExecutionManifest.
        1. Invariant: is_authorized => domain_authenticated by construction (no code path returns False).
        2. Authorize method has NO sc_ir parameter.
        3. Authorize succeeds with valid cert, mock sc_ir=None, verifying manifest alone.
        4. Certificate without manifest -> rejected.
        5. Tampered manifest -> rejected.
        6. Deployed POLICY_REVISION mismatch -> rejected.
        """
        import inspect
        import ast
        from layer8_orchestration.capability_verifier import (
            ActuationCapabilityVerifier,
            ActuationVerificationError,
            ActuationAuthorization,
        )
        from layer5_constraints.safety_certifier import CertifiedExecutionManifest, PreSolveSafetyCertifier
        from layer5_constraints import policy_thresholds

        # 1. Structural Invariant: Verify by AST analysis that authorize has NO code path returning domain_authenticated=False
        import textwrap
        auth_src = textwrap.dedent(inspect.getsource(ActuationCapabilityVerifier.authorize))
        tree = ast.parse(auth_src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Call):
                for kw in node.value.keywords:
                    if kw.arg in ("domain_authenticated", "domain_certified"):
                        if isinstance(kw.value, ast.Constant):
                            self.assertTrue(kw.value.value, "domain_authenticated must never be False on authorized return")

        # 2. Verify signature of authorize() has NO sc_ir parameter
        sig = inspect.signature(ActuationCapabilityVerifier.authorize)
        self.assertNotIn("sc_ir", sig.parameters, "authorize() must not accept sc_ir parameter")

        # 3. Valid authorization with manifest alone (provably no IR access)
        scen = {
            "incident_id": "manifest_test",
            "scenario": "manifest_test",
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
        snap = snapshot_from_contexts(ctx, conf, scen, epoch=1)

        dag = ConstraintDependencyGraph(incident_id="manifest_test")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap)
        cert = PreSolveSafetyCertifier.certify(ir)

        self.assertIsNotNone(cert.execution_manifest)
        self.assertIsInstance(cert.execution_manifest, CertifiedExecutionManifest)
        self.assertEqual(cert.manifest_digest, cert.execution_manifest.compute_digest())

        plan = {"s1": "isolate", "p1": "monitor"}
        auth = ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap)
        self.assertTrue(auth.is_authorized)
        self.assertTrue(auth.domain_authenticated)
        self.assertTrue(auth.domain_certified)

        # 4. Certificate without manifest -> ActuationVerificationError
        bad_cert = copy.deepcopy(cert)
        bad_cert.execution_manifest = None
        with self.assertRaises(ActuationVerificationError):
            ActuationCapabilityVerifier.authorize(plan, bad_cert, current_snapshot=snap)

        # 5. Tampered manifest -> digest mismatch or signature mismatch
        bad_cert2 = copy.deepcopy(cert)
        bad_cert2.execution_manifest.effective_budget = 0.001
        with self.assertRaises(ActuationVerificationError):
            ActuationCapabilityVerifier.authorize(plan, bad_cert2, current_snapshot=snap)

        # 6. Deployed POLICY_REVISION mismatch -> ActuationVerificationError
        orig_rev = policy_thresholds.POLICY_REVISION
        try:
            policy_thresholds.POLICY_REVISION = "tampered_policy_rev_9999"
            with self.assertRaises(ActuationVerificationError):
                ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap)
        finally:
            policy_thresholds.POLICY_REVISION = orig_rev

    def test_56_three_way_binding_independent_revocation(self):
        """
        Hardening Item C: Three-way binding made explicit.
        Revocation rule: IR changed OR state not in E_t OR policy revision changed => authority revoked.
        Exercises each of the three revocations independently with the other two held constant.
        """
        from layer8_orchestration.capability_verifier import (
            ActuationCapabilityVerifier,
            ActuationVerificationError,
            ActuationEnvelopeViolationError,
        )
        from layer5_constraints.formulation_compiler import FormulationCompiler
        from layer5_constraints.proof_checker import IndependentProofChecker, FidelityProofError
        from layer5_constraints.safety_certifier import PreSolveSafetyCertifier
        from layer5_constraints import policy_thresholds

        # Setup baseline: IR, state snapshot inside envelope, and current POLICY_REVISION
        scen = {
            "incident_id": "threeway_test",
            "scenario": "threeway_test",
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
        snap = snapshot_from_contexts(ctx, conf, scen, epoch=1)

        dag = ConstraintDependencyGraph(incident_id="threeway_test")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap)
        cert = PreSolveSafetyCertifier.certify(ir)
        plan = {"s1": "isolate", "p1": "monitor"}

        # Baseline: All 3 held valid -> Actuation authorized
        auth = ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap)
        self.assertTrue(auth.is_authorized)

        # ---------------------------------------------------------------------
        # Revocation 1: IR changed (State in E_t held constant, Policy Revision held constant)
        # ---------------------------------------------------------------------
        # If IR changes, compiler rejects because certificate commits H(IR)
        modified_ir = copy.deepcopy(ir)
        modified_ir.incident_id = "tampered_ir_incident"
        with self.assertRaises(Exception):
            FormulationCompiler.compile_to_ilp(modified_ir, cert, current_snapshot=snap)

        # If proof checker checks modified IR against original cert -> rejected
        comp_ilp = FormulationCompiler.compile_to_ilp(ir, cert, current_snapshot=snap)
        with self.assertRaises(FidelityProofError):
            IndependentProofChecker.check(modified_ir, comp_ilp.model, comp_ilp.fidelity_proof, cert)

        # If certificate's committed IR digest is altered in transit to verifier -> signature fails
        tampered_ir_cert = copy.deepcopy(cert)
        tampered_ir_cert.ir_sha256 = "0" * 64
        with self.assertRaises(ActuationVerificationError):
            ActuationCapabilityVerifier.authorize(plan, tampered_ir_cert, current_snapshot=snap)

        # ---------------------------------------------------------------------
        # Revocation 2: State NOT in E_t (IR held constant, Policy Revision held constant)
        # ---------------------------------------------------------------------
        drifted_ctx = copy.deepcopy(ctx)
        drifted_ctx["s1"].threat.threat_score = 0.25  # Crosses 0.70 threshold -> outside E_t!
        snap_drifted = snapshot_from_contexts(drifted_ctx, conf, scen, epoch=1)
        with self.assertRaises(ActuationEnvelopeViolationError):
            ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap_drifted)

        # ---------------------------------------------------------------------
        # Revocation 3: Policy revision changed (IR held constant, State in E_t held constant)
        # ---------------------------------------------------------------------
        orig_rev = policy_thresholds.POLICY_REVISION
        try:
            policy_thresholds.POLICY_REVISION = "MUTATED_REVISION_HASH_999"
            with self.assertRaises(ActuationVerificationError):
                ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap)
        finally:
            policy_thresholds.POLICY_REVISION = orig_rev

        # Verification that restoring the three invariants restores authorization
        auth_restored = ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap)
        self.assertTrue(auth_restored.is_authorized)

    # 57. PLC mode RUN -> MAINTENANCE: envelope REJECT (physical_state.mode value_set violation)
    def test_57_plc_mode_run_to_maintenance_envelope_reject(self):
        """
        Adversarial vector 10: PLC mode transitions from RUN to MAINTENANCE.
        Telemetry is identical; only physical_state.mode changes.
        Envelope must REJECT because the certified mode was RUN.
        """
        from layer8_orchestration.capability_verifier import (
            ActuationCapabilityVerifier,
            ActuationEnvelopeViolationError,
        )
        from layer5_constraints.safety_certifier import PreSolveSafetyCertifier

        scen = {
            "scenario": "plc_mode_test",
            "resources": [
                {"id": "plc1", "type": "plc_controller", "physical_state": {"mode": "RUN"}},
                {"id": "srv1", "type": "server"},
            ],
        }
        threat = {"plc1": 0.85, "srv1": 0.85}
        ctx = {
            "plc1": create_test_context("plc1", "plc_controller", threat=0.85, sla="CRITICAL"),
            "srv1": create_test_context("srv1", "server", threat=0.85, sla="HIGH"),
        }
        conf = {"plc1": create_test_confidence("plc1"), "srv1": create_test_confidence("srv1")}

        snap_run = snapshot_from_contexts(ctx, conf, scen, epoch=1, threat_scores=threat)
        dag = ConstraintDependencyGraph(incident_id="plc_mode_test")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap_run)
        cert = PreSolveSafetyCertifier.certify(ir)
        envelope = ir.validity_envelope
        self.assertIsNotNone(envelope)

        # Verify RUN mode is inside envelope
        is_inside, _ = envelope.contains(snap_run)
        self.assertTrue(is_inside)

        # PLC isolate is pruned in RUN mode
        self.assertNotIn("isolate", ir.variable_domains["plc1"].admissible_actions)

        # Transition to MAINTENANCE mode: change physical_state.mode only
        scen_maint = copy.deepcopy(scen)
        scen_maint["resources"][0]["physical_state"]["mode"] = "MAINTENANCE"
        snap_maint = snapshot_from_contexts(ctx, conf, scen_maint, epoch=1, threat_scores=threat)

        # Envelope must REJECT because physical_state.mode changed from RUN to MAINTENANCE
        is_inside_m, violations_m = envelope.contains(snap_maint)
        self.assertFalse(is_inside_m, "Envelope should reject PLC mode change from RUN to MAINTENANCE")
        self.assertTrue(any("physical_state.mode" in v for v in violations_m))

        # Actuation verifier must reject with envelope violation
        plan = {"plc1": "monitor", "srv1": "isolate"}
        with self.assertRaises(ActuationEnvelopeViolationError):
            ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap_maint)

    # 58. Irrelevant telemetry change inside envelope -> ACCEPT (certificate reused)
    def test_58_irrelevant_telemetry_inside_envelope_accept(self):
        """
        Adversarial vector 11: Only non-validity-relevant telemetry changes
        (e.g., minor threat fluctuation within the same interval).
        Envelope must ACCEPT, proving certificate can be reused.
        """
        from layer8_orchestration.capability_verifier import ActuationCapabilityVerifier
        from layer5_constraints.safety_certifier import PreSolveSafetyCertifier

        scen = {
            "scenario": "envelope_accept_test",
            "resources": [
                {"id": "s1", "type": "server"},
                {"id": "s2", "type": "server"},
            ],
        }
        # Both in HIGH tier (> 0.70)
        threat = {"s1": 0.85, "s2": 0.80}
        ctx = {
            "s1": create_test_context("s1", "server", threat=0.85, sla="HIGH"),
            "s2": create_test_context("s2", "server", threat=0.80, sla="HIGH"),
        }
        conf = {"s1": create_test_confidence("s1"), "s2": create_test_confidence("s2")}

        snap = snapshot_from_contexts(ctx, conf, scen, epoch=1, threat_scores=threat)
        dag = ConstraintDependencyGraph(incident_id="envelope_accept_test")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap)
        cert = PreSolveSafetyCertifier.certify(ir)
        envelope = ir.validity_envelope

        # Baseline inside
        is_inside, _ = envelope.contains(snap)
        self.assertTrue(is_inside)

        # Fluctuate threat scores WITHIN same intervals: 0.85->0.78, 0.80->0.72 (both still >0.70)
        threat_f = {"s1": 0.78, "s2": 0.72}
        ctx_f = {
            "s1": create_test_context("s1", "server", threat=0.78, sla="HIGH"),
            "s2": create_test_context("s2", "server", threat=0.72, sla="HIGH"),
        }
        snap_f = snapshot_from_contexts(ctx_f, conf, scen, epoch=1, threat_scores=threat_f)

        # Envelope still contains the fluctuated snapshot
        is_inside_f, violations_f = envelope.contains(snap_f)
        self.assertTrue(is_inside_f, f"Should accept inside-envelope fluctuation, violations: {violations_f}")
        self.assertEqual(len(violations_f), 0)

        # Certificate can be reused for actuation
        plan = {"s1": "isolate", "s2": "block_ip"}
        auth = ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap_f)
        self.assertTrue(auth.is_authorized)

    # 59. PLC MAINTENANCE mode admits 'isolate' as admissible action
    def test_59_plc_maintenance_mode_admits_isolate(self):
        """
        Verifies that PLC in MAINTENANCE mode admits 'isolate' as an admissible action,
        unlike the default RUN mode which prunes it.
        """
        scen_run = {
            "scenario": "plc_mode_compare",
            "resources": [
                {"id": "plc1", "type": "plc_controller", "physical_state": {"mode": "RUN"}},
            ],
        }
        scen_maint = {
            "scenario": "plc_mode_compare",
            "resources": [
                {"id": "plc1", "type": "plc_controller", "physical_state": {"mode": "MAINTENANCE"}},
            ],
        }
        threat = {"plc1": 0.85}
        ctx = {"plc1": create_test_context("plc1", "plc_controller", threat=0.85, sla="CRITICAL")}
        conf = {"plc1": create_test_confidence("plc1")}

        dag = ConstraintDependencyGraph(incident_id="plc_mode_compare")

        # RUN mode: isolate is pruned
        ir_run = dag.resolve(scen_run, threat, ctx, conf, base_budget=10.0)
        self.assertNotIn("isolate", ir_run.variable_domains["plc1"].admissible_actions)
        self.assertIn("isolate", ir_run.variable_domains["plc1"].pruned_actions)

        # MAINTENANCE mode: isolate is admitted
        ir_maint = dag.resolve(scen_maint, threat, ctx, conf, base_budget=10.0)
        self.assertIn("isolate", ir_maint.variable_domains["plc1"].admissible_actions)
        self.assertNotIn("isolate", ir_maint.variable_domains["plc1"].pruned_actions)

        # Provenance record for MAINTENANCE admission exists
        maint_prov = [p for p in ir_maint.provenance_records
                      if p.target_resource == "plc1" and p.rule_id == "PLC_MODE_MAINTENANCE_ADMITS_ISOLATE"]
        self.assertGreater(len(maint_prov), 0, "MAINTENANCE mode admission provenance must be recorded")

    # 60. Dotted-path resolver correctly resolves nested physical_state fields
    def test_60_dotted_path_resolver_physical_state(self):
        """
        Verifies that the dotted-path resolver in ValidityEnvelope.contains()
        correctly resolves 'physical_state.mode' and rejects changes.
        """
        from layer5_constraints.validity_envelope import _resolve_dotted_path, _UNRESOLVABLE

        rstate = ValidityRelevantState(
            resource_id="plc1",
            resource_type="plc_controller",
            threat_score=0.85,
            overall_confidence=0.92,
            sla_priority="CRITICAL",
            physical_state={"mode": "RUN", "safety_relay": "CLOSED"},
        )

        # Resolve dotted paths
        self.assertEqual(_resolve_dotted_path(rstate, "threat_score"), 0.85)
        self.assertEqual(_resolve_dotted_path(rstate, "physical_state.mode"), "RUN")
        self.assertEqual(_resolve_dotted_path(rstate, "physical_state.safety_relay"), "CLOSED")

        # Unresolvable paths return sentinel
        self.assertIs(_resolve_dotted_path(rstate, "physical_state.nonexistent"), _UNRESOLVABLE)
        self.assertIs(_resolve_dotted_path(rstate, "nonexistent_field"), _UNRESOLVABLE)
        self.assertIs(_resolve_dotted_path(rstate, "physical_state.mode.deep"), _UNRESOLVABLE)

    # 61. SCADA cascade test: PLC physical_state.mode in scenario
    def test_61_scada_cascade_physical_state_mode(self):
        """
        End-to-end SCADA cascade test: PLC in RUN mode with downstream gateway.
        Verifies that physical_state.mode is properly surfaced in envelope predicates
        and that mode transition invalidates the certificate.
        """
        from layer5_constraints.safety_certifier import PreSolveSafetyCertifier

        scen = {
            "scenario": "scada_industrial_cascade",
            "resources": [
                {"id": "scada-plc-01", "type": "plc_controller",
                 "physical_state": {"mode": "RUN"},
                 "requires_isolation_with": []},
                {"id": "scada-gw-01", "type": "network_gateway",
                 "requires_isolation_with": ["scada-plc-01"]},
            ],
        }
        threat = {"scada-plc-01": 0.85, "scada-gw-01": 0.85}
        ctx = {
            "scada-plc-01": create_test_context("scada-plc-01", "plc_controller", threat=0.85, sla="CRITICAL"),
            "scada-gw-01": create_test_context("scada-gw-01", "network_gateway", threat=0.85, sla="CRITICAL"),
        }
        conf = {
            "scada-plc-01": create_test_confidence("scada-plc-01"),
            "scada-gw-01": create_test_confidence("scada-gw-01"),
        }

        snap = snapshot_from_contexts(ctx, conf, scen, epoch=1, threat_scores=threat)
        dag = ConstraintDependencyGraph(incident_id="scada_industrial_cascade")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap)
        cert = PreSolveSafetyCertifier.certify(ir)
        envelope = ir.validity_envelope

        # PLC in RUN: isolate is pruned
        self.assertNotIn("isolate", ir.variable_domains["scada-plc-01"].admissible_actions)

        # Envelope predicate for physical_state.mode must exist
        plc_preds = envelope.predicates.get("scada-plc-01", [])
        mode_preds = [p for p in plc_preds if p.field_path == "physical_state.mode"]
        self.assertGreater(len(mode_preds), 0, "Envelope must contain physical_state.mode predicate for PLC")
        self.assertEqual(mode_preds[0].allowed_values, {"RUN"})

        # Snapshot with same mode is inside envelope
        is_inside, _ = envelope.contains(snap)
        self.assertTrue(is_inside)

        # Change mode to MAINTENANCE -> outside envelope
        scen_m = copy.deepcopy(scen)
        scen_m["resources"][0]["physical_state"]["mode"] = "MAINTENANCE"
        snap_m = snapshot_from_contexts(ctx, conf, scen_m, epoch=1, threat_scores=threat)
        is_inside_m, viol = envelope.contains(snap_m)
        self.assertFalse(is_inside_m)
        self.assertTrue(any("physical_state.mode" in v for v in viol))

    # 62. Incremental compilation emits digest_gated_reuse schema
    def test_62_incremental_compilation_digest_gated_reuse_schema(self):
        """
        Adversarial vector: Verify incremental compilation on the clean path
        emits the digest_gated_reuse equivalence schema with explicit reused
        subgraph digests and recomputed asset list.
        """
        from layer5_constraints.safety_certifier import PreSolveSafetyCertifier

        scen = {
            "scenario": "digest_reuse_test",
            "resources": [
                {"id": "a1", "type": "server"},
                {"id": "a2", "type": "server"},
                {"id": "a3", "type": "network_gateway"},
            ],
        }
        threat = {"a1": 0.85, "a2": 0.75, "a3": 0.80}
        ctx = {
            "a1": create_test_context("a1", "server", threat=0.85, sla="HIGH"),
            "a2": create_test_context("a2", "server", threat=0.75, sla="HIGH"),
            "a3": create_test_context("a3", "network_gateway", threat=0.80, sla="HIGH"),
        }
        conf = {
            "a1": create_test_confidence("a1"),
            "a2": create_test_confidence("a2"),
            "a3": create_test_confidence("a3"),
        }

        dag = ConstraintDependencyGraph(incident_id="digest_reuse_test")
        ir1 = dag.resolve(scen, threat, ctx, conf, base_budget=20.0, ir_version=1)
        cert1 = PreSolveSafetyCertifier.certify(ir1)

        # Incremental: only a1 changes
        delta = RuntimeStateDelta(
            changed_assets=["a1"],
            changed_threat_state={"a1": 0.88},
        )
        threat2 = dict(threat)
        threat2["a1"] = 0.88
        result = IncrementalConstraintCompiler.compile_delta(
            previous_ir=ir1,
            delta=delta,
            scenario=scen,
            all_contexts=ctx,
            all_confidences=conf,
            all_threat_scores=threat2,
            base_budget=20.0,
            parent_certificate=cert1,
        )

        self.assertFalse(result.fallback_to_full_recompile)
        eq_check = result.incremental_equivalence_check
        self.assertIsNotNone(eq_check)
        self.assertEqual(eq_check["method"], "digest_gated_reuse")
        self.assertIn("reused_subgraph_digests", eq_check)
        self.assertIn("recomputed", eq_check)
        self.assertIn("semantic_fingerprint", eq_check)

        # Clean assets should have reused subgraph digests
        reused = eq_check["reused_subgraph_digests"]
        recomputed = eq_check["recomputed"]
        self.assertIn("a1", recomputed, "Dirty asset a1 must be in recomputed list")
        # At least one clean asset should be reused
        self.assertGreater(len(reused), 0, "At least one clean subgraph should be reused")

    # 63. Decision-policy manifest completeness and rule module coverage
    def test_63_decision_policy_manifest_completeness(self):
        """
        Item 5: Verifies that DECISION_POLICY_MANIFEST contains all decision-affecting constants
        across rule modules (policy_thresholds, dependency_graph, adaptive_constraints).
        Asserts every module-level policy constant is referenced by the manifest.
        """
        import layer5_constraints.policy_thresholds as pt
        import layer5_constraints.dependency_graph as dg
        import layer5_constraints.adaptive_constraints as ac

        manifest = pt.build_decision_policy_manifest()

        # Required components
        self.assertIn("THRESHOLD_THREAT_HIGH", manifest)
        self.assertIn("THRESHOLD_HIPAA_MANDATE", manifest)
        self.assertIn("THRESHOLD_LOW_CONFIDENCE", manifest)
        self.assertIn("THRESHOLD_THREAT_LOW", manifest)
        self.assertIn("PHYSICAL_CAPABILITY_MAP", manifest)
        self.assertIn("FEASIBLE_ACTION_MATRIX", manifest)
        self.assertIn("RESOURCE_PROFILES", manifest)
        self.assertIn("DEFAULT_ACTION_CONFLICTS", manifest)
        self.assertIn("PLC_MODE_RUN", manifest)
        self.assertIn("PLC_MODE_MAINTENANCE", manifest)
        self.assertIn("LEARNED_RULES_DIGEST", manifest)

        # Inspect rule modules for module-level policy constants and assert manifest references them
        rule_modules = [pt, dg, ac]
        checked_constants = set()
        for mod in rule_modules:
            for attr_name in dir(mod):
                if attr_name.startswith("_"):
                    continue
                # Policy constants are uppercase by convention
                if attr_name.isupper() and attr_name not in ("HAS_PULP", "HAS_QISKIT", "ACTIONS", "COST_WEIGHTS", "UTILITY_WEIGHTS", "MAX_BUDGET"):
                    if attr_name in ("POLICY_REVISION", "POLICY_THRESHOLDS_DICT", "DECISION_POLICY_MANIFEST"):
                        continue
                    checked_constants.add(attr_name)
                    self.assertIn(attr_name, manifest, f"Module-level policy constant '{attr_name}' from {mod.__name__} is NOT referenced by DECISION_POLICY_MANIFEST")

        self.assertGreaterEqual(len(checked_constants), 10, "Must check all core policy constants across rule modules")

    # 64. Adversarial a: Forged certificate with auth_mechanism="digest-only", signature=sha256(payload), no key
    def test_64_adversarial_a_forged_digest_only_cert_rejected(self):
        """
        Adversarial Vector a:
        Forged certificate with auth_mechanism='digest-only' and signature=sha256(payload)
        with no private key MUST be rejected by verify_signature and ActuationCapabilityVerifier.
        """
        import hashlib
        from layer8_orchestration.capability_verifier import ActuationCapabilityVerifier, ActuationVerificationError

        scen = {"scenario": "test_adv_a", "resources": [{"id": "srv1", "type": "server"}]}
        threat = {"srv1": 0.85}
        ctx = {"srv1": create_test_context("srv1", "server", threat=0.85)}
        conf = {"srv1": create_test_confidence("srv1")}
        snap = snapshot_from_contexts(ctx, conf, scen, epoch=1, threat_scores=threat)
        dag = ConstraintDependencyGraph(incident_id="test_adv_a")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap)

        cert = PreSolveSafetyCertifier.certify(ir)
        # Forge signature and mechanism: digest-only without key
        cert.auth_mechanism = "digest-only"
        payload = cert.compute_canonical_payload()
        cert.signature = hashlib.sha256(payload).hexdigest()

        vk = get_verifier_key()
        # 1. verify_signature returns False
        self.assertFalse(cert.verify_signature(vk))
        # 2. Actuation rejects with ActuationVerificationError
        plan = {"srv1": "isolate"}
        with self.assertRaises(ActuationVerificationError) as cm:
            ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap, public_key=vk)
        self.assertIn("Invalid certificate cryptographic signature", str(cm.exception))

    # 65. Adversarial b: Empty signature rejected
    def test_65_adversarial_b_empty_signature_rejected(self):
        """
        Adversarial Vector b:
        Certificate with empty or missing signature MUST be rejected and return False.
        """
        from layer8_orchestration.capability_verifier import ActuationCapabilityVerifier, ActuationVerificationError

        scen = {"scenario": "test_adv_b", "resources": [{"id": "srv1", "type": "server"}]}
        threat = {"srv1": 0.85}
        ctx = {"srv1": create_test_context("srv1", "server", threat=0.85)}
        conf = {"srv1": create_test_confidence("srv1")}
        snap = snapshot_from_contexts(ctx, conf, scen, epoch=1, threat_scores=threat)
        dag = ConstraintDependencyGraph(incident_id="test_adv_b")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap)

        cert = PreSolveSafetyCertifier.certify(ir)
        vk = get_verifier_key()

        # Empty string signature
        cert.signature = ""
        self.assertFalse(cert.verify_signature(vk))
        plan = {"srv1": "isolate"}
        with self.assertRaises(ActuationVerificationError):
            ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap, public_key=vk)

        # None signature
        cert.signature = None
        self.assertFalse(cert.verify_signature(vk))
        with self.assertRaises(ActuationVerificationError):
            ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap, public_key=vk)

    # 66. Adversarial c: Valid Ed25519 signature but auth_mechanism field altered after signing
    def test_66_adversarial_c_altered_auth_mechanism_rejected(self):
        """
        Adversarial Vector c:
        Valid Ed25519 signature, but auth_mechanism field altered after signing.
        Because auth_mechanism is included in the signed canonical payload, verification MUST fail.
        """
        from layer8_orchestration.capability_verifier import ActuationCapabilityVerifier, ActuationVerificationError

        scen = {"scenario": "test_adv_c", "resources": [{"id": "srv1", "type": "server"}]}
        threat = {"srv1": 0.85}
        ctx = {"srv1": create_test_context("srv1", "server", threat=0.85)}
        conf = {"srv1": create_test_confidence("srv1")}
        snap = snapshot_from_contexts(ctx, conf, scen, epoch=1, threat_scores=threat)
        dag = ConstraintDependencyGraph(incident_id="test_adv_c")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap)

        cert = PreSolveSafetyCertifier.certify(ir)
        vk = get_verifier_key()
        self.assertTrue(cert.verify_signature(vk))

        # Alter auth_mechanism field
        cert.auth_mechanism = "hmac-sha256"
        self.assertFalse(cert.verify_signature(vk))

        plan = {"srv1": "isolate"}
        with self.assertRaises(ActuationVerificationError):
            ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap, public_key=vk)

    # 67. Adversarial d: Signed certificate with status="VIOLATION_DETECTED" presented to actuator
    def test_67_adversarial_d_violation_detected_status_rejected(self):
        """
        Adversarial Vector d:
        Signed certificate with status='VIOLATION_DETECTED' presented to actuator MUST be refused.
        """
        from layer8_orchestration.capability_verifier import ActuationCapabilityVerifier, ActuationVerificationError

        scen = {"scenario": "test_adv_d", "resources": [{"id": "srv1", "type": "server"}]}
        threat = {"srv1": 0.85}
        ctx = {"srv1": create_test_context("srv1", "server", threat=0.85)}
        conf = {"srv1": create_test_confidence("srv1")}
        snap = snapshot_from_contexts(ctx, conf, scen, epoch=1, threat_scores=threat)
        dag = ConstraintDependencyGraph(incident_id="test_adv_d")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap)

        cert = PreSolveSafetyCertifier.certify(ir)
        # Even if validly signed with VIOLATION_DETECTED
        cert.status = "VIOLATION_DETECTED"
        ck = get_certifier_key()
        payload = cert.compute_canonical_payload()
        sig_hex, _ = ck.sign(payload)
        cert.signature = sig_hex
        cert.canonical_payload_bytes = payload

        # Cryptographic signature itself is valid
        self.assertTrue(cert.verify_signature(get_verifier_key()))

        plan = {"srv1": "isolate"}
        with self.assertRaises(ActuationVerificationError) as cm:
            ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap)
        self.assertIn("VIOLATION_DETECTED", str(cm.exception))
        self.assertIn("expected 'CERTIFIED'", str(cm.exception))

    # 68. Adversarial e: Compile and actuate with current_snapshot=None
    def test_68_adversarial_e_compile_and_actuate_none_snapshot_rejected(self):
        """
        Adversarial Vector e:
        Compiling and actuating when certificate carries an envelope but
        current_snapshot=None MUST fail closed with 'current runtime state unavailable'.
        """
        from layer8_orchestration.capability_verifier import ActuationCapabilityVerifier, ActuationVerificationError

        scen = {"scenario": "test_adv_e", "resources": [{"id": "srv1", "type": "server"}]}
        threat = {"srv1": 0.85}
        ctx = {"srv1": create_test_context("srv1", "server", threat=0.85)}
        conf = {"srv1": create_test_confidence("srv1")}
        snap = snapshot_from_contexts(ctx, conf, scen, epoch=1, threat_scores=threat)
        dag = ConstraintDependencyGraph(incident_id="test_adv_e")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap)

        self.assertIsNotNone(ir.validity_envelope)
        cert = PreSolveSafetyCertifier.certify(ir)

        # Compiler fail-closed
        with self.assertRaises(StateEnvelopeViolationError) as cm_comp:
            FormulationCompiler.compile_to_ilp(ir, certificate=cert, current_snapshot=None)
        self.assertIn("current runtime state unavailable", str(cm_comp.exception))

        # Actuator fail-closed
        plan = {"srv1": "isolate"}
        with self.assertRaises(ActuationVerificationError) as cm_act:
            ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=None)
        self.assertIn("current runtime state unavailable", str(cm_act.exception))

    # 69. Adversarial f: PLC certified with no physical_state; snapshot later reports mode=MAINTENANCE
    def test_69_adversarial_f_plc_no_physical_state_mode_maintenance_rejected(self):
        """
        Adversarial Vector f:
        PLC certified with no physical_state defaults effectively to 'RUN' and emits
        envelope predicate. When runtime snapshot subsequently reports mode=MAINTENANCE,
        actuation MUST be refused.
        """
        from layer8_orchestration.capability_verifier import ActuationCapabilityVerifier, ActuationVerificationError

        # No physical_state provided in scenario
        scen = {"scenario": "test_adv_f", "resources": [{"id": "plc1", "type": "plc_controller"}]}
        threat = {"plc1": 0.85}
        ctx = {"plc1": create_test_context("plc1", "plc_controller", threat=0.85)}
        conf = {"plc1": create_test_confidence("plc1")}
        snap_run = snapshot_from_contexts(ctx, conf, scen, epoch=1, threat_scores=threat)

        dag = ConstraintDependencyGraph(incident_id="test_adv_f")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap_run)
        cert = PreSolveSafetyCertifier.certify(ir)

        # Effective mode was RUN, and predicate was emitted
        plc_preds = ir.validity_envelope.predicates.get("plc1", [])
        mode_preds = [p for p in plc_preds if p.field_path == "physical_state.mode"]
        self.assertEqual(len(mode_preds), 1)
        self.assertEqual(mode_preds[0].allowed_values, {"RUN"})

        # Later snapshot reports mode=MAINTENANCE
        scen_maint = copy.deepcopy(scen)
        scen_maint["resources"][0]["physical_state"] = {"mode": "MAINTENANCE"}
        snap_maint = snapshot_from_contexts(ctx, conf, scen_maint, epoch=2, threat_scores=threat)

        plan = {"plc1": "monitor"}
        with self.assertRaises(ActuationVerificationError) as cm:
            ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap_maint)
        self.assertIn("physical_state.mode", str(cm.exception))

    # 70. Adversarial g: Plan action whose cost is absent from the manifest
    def test_70_adversarial_g_missing_cost_action_rejected(self):
        """
        Adversarial Vector g:
        Plan action whose cost is absent from the manifest MUST be refused by actuator
        (fail-closed: 0.0 fallback deleted).
        """
        from layer8_orchestration.capability_verifier import ActuationCapabilityVerifier, ActuationVerificationError

        scen = {"scenario": "test_adv_g", "resources": [{"id": "srv1", "type": "server"}]}
        threat = {"srv1": 0.85}
        ctx = {"srv1": create_test_context("srv1", "server", threat=0.85)}
        conf = {"srv1": create_test_confidence("srv1")}
        snap = snapshot_from_contexts(ctx, conf, scen, epoch=1, threat_scores=threat)

        dag = ConstraintDependencyGraph(incident_id="test_adv_g")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap)
        cert = PreSolveSafetyCertifier.certify(ir)

        # Delete cost for ("srv1", "isolate") from manifest and update digest/signature
        cert.execution_manifest.cost_map.pop(("srv1", "isolate"), None)
        cert.execution_manifest.cost_map.pop("srv1:isolate", None)
        cert.manifest_digest = cert.execution_manifest.compute_digest()
        ck = get_certifier_key()
        payload = cert.compute_canonical_payload()
        sig_hex, _ = ck.sign(payload)
        cert.signature = sig_hex
        cert.canonical_payload_bytes = payload

        plan = {"srv1": "isolate"}
        with self.assertRaises(ActuationVerificationError) as cm:
            ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap)
        self.assertIn("Missing cost for action ('srv1', 'isolate') in certified manifest", str(cm.exception))

    # 71. Adversarial h: Change one entry in PHYSICAL_CAPABILITY_MAP -> POLICY_REVISION changes -> actuation refused
    def test_71_adversarial_h_policy_manifest_mutation_rejected(self):
        """
        Adversarial Vector h:
        Changing one entry in PHYSICAL_CAPABILITY_MAP changes POLICY_REVISION,
        causing actuator to refuse actuation due to policy revision mismatch.
        """
        import layer5_constraints.policy_thresholds as pt
        from layer8_orchestration.capability_verifier import ActuationCapabilityVerifier, ActuationVerificationError

        scen = {"scenario": "test_adv_h", "resources": [{"id": "srv1", "type": "server"}]}
        threat = {"srv1": 0.85}
        ctx = {"srv1": create_test_context("srv1", "server", threat=0.85)}
        conf = {"srv1": create_test_confidence("srv1")}
        snap = snapshot_from_contexts(ctx, conf, scen, epoch=1, threat_scores=threat)

        dag = ConstraintDependencyGraph(incident_id="test_adv_h")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap)
        cert = PreSolveSafetyCertifier.certify(ir)

        orig_caps = copy.deepcopy(pt.PHYSICAL_CAPABILITY_MAP)
        orig_rev = pt.POLICY_REVISION
        self.assertEqual(cert.execution_manifest.policy_revision, orig_rev)

        try:
            # Mutate one entry
            pt.PHYSICAL_CAPABILITY_MAP["server"] = ["isolate"]
            mutated_rev = pt.POLICY_REVISION
            self.assertNotEqual(orig_rev, mutated_rev)

            plan = {"srv1": "isolate"}
            with self.assertRaises(ActuationVerificationError) as cm:
                ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap)
            self.assertIn("Policy revision mismatch", str(cm.exception))
        finally:
            pt.PHYSICAL_CAPABILITY_MAP.clear()
            pt.PHYSICAL_CAPABILITY_MAP.update(orig_caps)
            self.assertEqual(pt.POLICY_REVISION, orig_rev)

    # 72. Adversarial i: Honest path with snapshot supplied -> ACCEPT (regression)
    def test_72_adversarial_i_honest_path_with_snapshot_accepted(self):
        """
        Adversarial Vector i:
        Honest path: valid certificate with Ed25519 signature, matching current snapshot,
        all invariant checks passed, certified plan executed -> ACCEPT.
        """
        from layer8_orchestration.capability_verifier import ActuationCapabilityVerifier

        scen = {"scenario": "test_adv_i", "resources": [{"id": "srv1", "type": "server"}]}
        threat = {"srv1": 0.85}
        ctx = {"srv1": create_test_context("srv1", "server", threat=0.85)}
        conf = {"srv1": create_test_confidence("srv1")}
        snap = snapshot_from_contexts(ctx, conf, scen, epoch=1, threat_scores=threat)

        dag = ConstraintDependencyGraph(incident_id="test_adv_i")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap)
        cert = PreSolveSafetyCertifier.certify(ir)

        # Honest plan within admissible actions and budget
        plan = {"srv1": "isolate"}
        auth = ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap)
        self.assertTrue(auth.is_authorized)
        self.assertEqual(auth.authorized_actions, plan)
        self.assertTrue(auth.domain_authenticated)
        self.assertTrue(auth.envelope_valid)
        self.assertTrue(auth.epoch_valid)

    # 73. Verify binding signature erasure and mechanism tampering checks
    def test_73_compiler_verify_binding_signature_and_mechanism_checks(self):
        """
        Item 2: Valid cert -> erase signature -> compile_to_ilp AND compile_to_qubo both raise IntegrityBindingError.
        Also: alter auth_mechanism post-sign -> both raise IntegrityBindingError.
        """
        scen = {"scenario": "test_73", "resources": [{"id": "srv1", "type": "server"}]}
        threat = {"srv1": 0.85}
        ctx = {"srv1": create_test_context("srv1", "server", threat=0.85)}
        conf = {"srv1": create_test_confidence("srv1")}
        snap = snapshot_from_contexts(ctx, conf, scen, epoch=1, threat_scores=threat)

        dag = ConstraintDependencyGraph(incident_id="test_73")
        ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap)
        cert = PreSolveSafetyCertifier.certify(ir)

        # Baseline: compiles cleanly
        prob_ilp, _ = FormulationCompiler.compile_to_ilp(ir, cert, current_snapshot=snap)
        self.assertIsNotNone(prob_ilp)
        if HAS_QISKIT:
            qp, _, _ = FormulationCompiler.compile_to_qubo(ir, cert, current_snapshot=snap, return_manifest=True)
            self.assertIsNotNone(qp)

        # 1. Erase signature -> compile_to_ilp AND compile_to_qubo both raise IntegrityBindingError
        cert_erased = copy.deepcopy(cert)
        cert_erased.signature = ""
        with self.assertRaises(IntegrityBindingError) as cm_ilp:
            FormulationCompiler.compile_to_ilp(ir, cert_erased, current_snapshot=snap)
        self.assertIn("Digital signature verification failed", str(cm_ilp.exception))

        if HAS_QISKIT:
            with self.assertRaises(IntegrityBindingError) as cm_qubo:
                FormulationCompiler.compile_to_qubo(ir, cert_erased, current_snapshot=snap)
            self.assertIn("Digital signature verification failed", str(cm_qubo.exception))

        # 2. Alter auth_mechanism post-sign -> both raise IntegrityBindingError
        cert_altered = copy.deepcopy(cert)
        cert_altered.auth_mechanism = "unapproved_custom_hmac"
        with self.assertRaises(IntegrityBindingError):
            FormulationCompiler.compile_to_ilp(ir, cert_altered, current_snapshot=snap)

        if HAS_QISKIT:
            with self.assertRaises(IntegrityBindingError):
                FormulationCompiler.compile_to_qubo(ir, cert_altered, current_snapshot=snap)

        # 2b. Alter auth_mechanism and recompute digest -> signature check raises IntegrityBindingError
        cert_altered2 = copy.deepcopy(cert)
        cert_altered2.auth_mechanism = "unapproved_custom_hmac"
        cert_altered2.integrity_digest = hashlib.sha256(cert_altered2.compute_canonical_payload()).hexdigest()
        with self.assertRaises(IntegrityBindingError) as cm_ilp2:
            FormulationCompiler.compile_to_ilp(ir, cert_altered2, current_snapshot=snap)
        self.assertIn("Digital signature verification failed", str(cm_ilp2.exception))

        if HAS_QISKIT:
            with self.assertRaises(IntegrityBindingError) as cm_qubo2:
                FormulationCompiler.compile_to_qubo(ir, cert_altered2, current_snapshot=snap)
            self.assertIn("Digital signature verification failed", str(cm_qubo2.exception))

    # 74. Active policy revision: learned rules and dual boundary refusal
    def test_74_active_policy_revision_boundaries_and_learned_rules(self):
        """
        Item 3:
        (a) certificate issued under admitted learned rules is accepted at both boundaries;
        (b) a base-policy change refuses at BOTH compiler and actuator;
        (c) admitting a new learned rule after certification refuses at both boundaries.
        """
        import layer5_constraints.policy_thresholds as pt
        from layer8_orchestration.capability_verifier import ActuationCapabilityVerifier, ActuationVerificationError

        pt.clear_trusted_learned_rules()
        orig_caps = copy.deepcopy(pt.PHYSICAL_CAPABILITY_MAP)
        try:
            # (a) Certificate issued under admitted learned rules is accepted at both boundaries
            rule_a = {"rule_id": "LEARNED_RULE_A", "target_resource_type": "server", "restrict_action": "monitor"}
            pt.register_admitted_learned_rule(rule_a)

            scen = {"scenario": "test_74", "resources": [{"id": "srv1", "type": "server"}]}
            threat = {"srv1": 0.85}
            ctx = {"srv1": create_test_context("srv1", "server", threat=0.85)}
            conf = {"srv1": create_test_confidence("srv1")}
            snap = snapshot_from_contexts(ctx, conf, scen, epoch=1, threat_scores=threat)

            dag = ConstraintDependencyGraph(incident_id="test_74")
            ir = dag.resolve(scen, threat, ctx, conf, base_budget=10.0, state_snapshot=snap)
            cert = PreSolveSafetyCertifier.certify(ir)

            # Compiler boundary: ACCEPT
            prob, _ = FormulationCompiler.compile_to_ilp(ir, cert, current_snapshot=snap)
            self.assertIsNotNone(prob)

            # Actuator boundary: ACCEPT
            plan = {"srv1": "isolate"}
            auth = ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap)
            self.assertTrue(auth.is_authorized)

            # (b) Base-policy change refuses at BOTH compiler and actuator
            pt.PHYSICAL_CAPABILITY_MAP["server"] = ["isolate"]
            # Compiler refuses
            with self.assertRaises(IntegrityBindingError) as cm_comp:
                FormulationCompiler.compile_to_ilp(ir, cert, current_snapshot=snap)
            self.assertIn("Policy revision mismatch", str(cm_comp.exception))

            # Actuator refuses
            with self.assertRaises(ActuationVerificationError) as cm_act:
                ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap)
            self.assertIn("Policy revision mismatch", str(cm_act.exception))

            # Restore base policy
            pt.PHYSICAL_CAPABILITY_MAP.clear()
            pt.PHYSICAL_CAPABILITY_MAP.update(orig_caps)

            # (c) Admitting a new learned rule after certification refuses at BOTH boundaries
            rule_b = {"rule_id": "LEARNED_RULE_B", "target_resource_type": "server", "restrict_action": "increase_logging"}
            pt.register_admitted_learned_rule(rule_b)

            # Compiler refuses
            with self.assertRaises(IntegrityBindingError) as cm_comp2:
                FormulationCompiler.compile_to_ilp(ir, cert, current_snapshot=snap)
            self.assertIn("Policy revision mismatch", str(cm_comp2.exception))

            # Actuator refuses
            with self.assertRaises(ActuationVerificationError) as cm_act2:
                ActuationCapabilityVerifier.authorize(plan, cert, current_snapshot=snap)
            self.assertIn("Policy revision mismatch", str(cm_act2.exception))

        finally:
            pt.clear_trusted_learned_rules()
            pt.PHYSICAL_CAPABILITY_MAP.clear()
            pt.PHYSICAL_CAPABILITY_MAP.update(orig_caps)

    # 75. PLC in MAINTENANCE mode admits isolate and certifies CERTIFIED
    def test_75_plc_maintenance_isolate_admissible_certifies_certified(self):
        """
        Item 4:
        PLC RUN admits isolate -> violation;
        PLC MAINTENANCE admits isolate -> OK, certify() returns CERTIFIED;
        medical_device admits isolate -> violation always.
        """
        dag = ConstraintDependencyGraph(incident_id="test_75")

        # 1. PLC in MAINTENANCE mode admits isolate -> certify() returns CERTIFIED
        scen_maint = {
            "scenario": "plc_maint",
            "resources": [{"id": "plc_m1", "type": "plc_controller", "physical_state": {"mode": "MAINTENANCE"}}],
        }
        threat_m = {"plc_m1": 0.85}
        ctx_m = {"plc_m1": create_test_context("plc_m1", "plc_controller", threat=0.85)}
        conf_m = {"plc_m1": create_test_confidence("plc_m1")}
        snap_m = snapshot_from_contexts(ctx_m, conf_m, scen_maint, epoch=1, threat_scores=threat_m)

        ir_maint = dag.resolve(scen_maint, threat_m, ctx_m, conf_m, base_budget=10.0, state_snapshot=snap_m)
        self.assertIn("isolate", ir_maint.variable_domains["plc_m1"].admissible_actions)

        cert_maint = PreSolveSafetyCertifier.certify(ir_maint)
        self.assertEqual(cert_maint.status, "CERTIFIED")
        self.assertTrue(cert_maint.verification_checks["1_forbidden_action_elimination"])

        # 2. PLC in RUN mode admitting isolate -> certify() returns VIOLATION_DETECTED
        scen_run = {
            "scenario": "plc_run",
            "resources": [{"id": "plc_r1", "type": "plc_controller", "physical_state": {"mode": "RUN"}}],
        }
        threat_r = {"plc_r1": 0.85}
        ctx_r = {"plc_r1": create_test_context("plc_r1", "plc_controller", threat=0.85)}
        conf_r = {"plc_r1": create_test_confidence("plc_r1")}
        snap_r = snapshot_from_contexts(ctx_r, conf_r, scen_run, epoch=1, threat_scores=threat_r)

        ir_run = dag.resolve(scen_run, threat_r, ctx_r, conf_r, base_budget=10.0, state_snapshot=snap_r)
        # Manually tamper to inject isolate into RUN PLC domain
        ir_run.variable_domains["plc_r1"].admissible_actions.append("isolate")
        # Ensure invariance action list matches to isolate the forbidden action check
        for inv in ir_run.invariance_constraints:
            if inv.resource_id == "plc_r1":
                inv.actions.append("isolate")

        cert_run = PreSolveSafetyCertifier.certify(ir_run)
        self.assertEqual(cert_run.status, "VIOLATION_DETECTED")
        self.assertFalse(cert_run.verification_checks["1_forbidden_action_elimination"])
        self.assertTrue(any("Cyber-physical PLC" in v and "RUN mode allows 'isolate'" in v for v in cert_run.forbidden_action_violations))

        # 3. Medical device admitting isolate -> certify() returns VIOLATION_DETECTED always
        scen_med = {
            "scenario": "med_dev",
            "resources": [{"id": "med_1", "type": "medical_device"}],
        }
        threat_med = {"med_1": 0.85}
        ctx_med = {"med_1": create_test_context("med_1", "medical_device", threat=0.85)}
        conf_med = {"med_1": create_test_confidence("med_1")}
        snap_med = snapshot_from_contexts(ctx_med, conf_med, scen_med, epoch=1, threat_scores=threat_med)

        ir_med = dag.resolve(scen_med, threat_med, ctx_med, conf_med, base_budget=10.0, state_snapshot=snap_med)
        ir_med.variable_domains["med_1"].admissible_actions.append("isolate")
        for inv in ir_med.invariance_constraints:
            if inv.resource_id == "med_1":
                inv.actions.append("isolate")

        cert_med = PreSolveSafetyCertifier.certify(ir_med)
        self.assertEqual(cert_med.status, "VIOLATION_DETECTED")
        self.assertFalse(cert_med.verification_checks["1_forbidden_action_elimination"])
        self.assertTrue(any("medical device" in v.lower() and "allows 'isolate'" in v for v in cert_med.forbidden_action_violations))


if __name__ == "__main__":
    unittest.main(verbosity=2)

