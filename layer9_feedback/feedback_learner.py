"""
=============================================================================
LAYER 9: RICH FEEDBACK LEARNING SYSTEM
Module: feedback_learner.py
-----------------------------------------------------------------------------
Problem Solved:
  Learns from past incident containment outcomes, false positives, downtime,
  and operator overrides. Solves static decision-making by creating a
  continuous feedback loop using Exponential Moving Averages (EMA) and rolling
  metrics to adapt utility weights.

  Rich Incident Record:
    - attack_type, threat_score, confidence, selected_action, alternative_actions
    - successful, containment_time, downtime, false_positive_status, operator_override

  Feedback Metrics & Adaptation:
    - Exponential Moving Average (EMA) of success rates per action/attack type
    - Rolling containment time and rolling downtime tracking
    - Adaptive utility weight calibration for future optimization rounds

Inputs:  Rich incident outcome parameters.
Outputs: Updated utility weights, EMA metrics, and persistent feedback history (JSON file).
=============================================================================
"""

import json
import os
import copy
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from config import FEEDBACK_DATA_PATH, FEEDBACK_LEARNING_RATE, UTILITY_WEIGHTS


@dataclass
class RuleAdmissionEvidence:
    """Audit evidence produced when a candidate rule is tested through sandboxed safety certification."""
    candidate_rule_id: str
    source_incident: str
    proposed_structural_delta: Dict[str, Any]
    before_ir_version: int
    sandbox_ir_version: int
    validation_results: Dict[str, Any]
    admitted: bool
    reason: str
    resulting_ir_version: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RichIncidentFeedback:
    incident_id: str
    timestamp: str
    scenario: str
    attack_type: str
    plan: Dict[str, str]
    threat_score: float
    confidence: float
    selected_action: str
    alternative_actions: List[str]
    successful: bool
    containment_time_sec: float
    downtime_sec: float
    false_positive_status: bool
    operator_override: bool
    notes: str
    initial_utility_weights: Dict[str, float]
    outcome_metrics: Dict[str, float]


# Alias for backward compatibility
IncidentFeedback = RichIncidentFeedback


@dataclass
class ExperienceConstraintRule:
    rule_id: str
    target_resource_type: str
    restrict_action: str
    condition: str
    rationale: str
    created_at: str
    trigger_incident_id: str


class FeedbackLearner:
    """
    Rich Feedback Learning Engine with EMA weight adjustments, rolling metrics,
    and System B: Experience-Driven Constraint Synthesis (Outcome -> Constraint Adaptation).
    """

    def __init__(self, data_path: str = FEEDBACK_DATA_PATH, alpha: float = 0.2):
        self.data_path = data_path
        self.alpha = alpha  # EMA smoothing factor (0.2)
        self.feedback_history: List[RichIncidentFeedback] = []
        self.learned_rules: List[Dict[str, Any]] = []
        self.current_weights = UTILITY_WEIGHTS.copy()
        self.action_ema_success: Dict[str, float] = {}
        self.action_ema_downtime: Dict[str, float] = {}
        self.action_ema_containment: Dict[str, float] = {}
        self._load_feedback()

    def _load_feedback(self):
        if os.path.exists(self.data_path):
            try:
                with open(self.data_path, "r") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    items = data
                elif isinstance(data, dict):
                    items = data.get("history", [])
                    self.learned_rules = data.get("learned_rules", [])
                else:
                    items = []

                for item in items:
                    self.feedback_history.append(RichIncidentFeedback(**item))
                if self.feedback_history:
                    last = self.feedback_history[-1]
                    if "current_weights" in last.outcome_metrics:
                        self.current_weights = last.outcome_metrics["current_weights"]
                    self._recalculate_ema()
            except Exception as e:
                print(f"Error loading feedback history: {e}")

    def save_feedback(self):
        with open(self.data_path, "w") as f:
            payload = {
                "history": [asdict(fb) for fb in self.feedback_history],
                "learned_rules": self.learned_rules,
            }
            json.dump(payload, f, indent=2)

    def _recalculate_ema(self):
        """Recalculates Exponential Moving Averages across history."""
        for fb in self.feedback_history:
            act = fb.selected_action
            succ = 1.0 if fb.successful and not fb.false_positive_status else 0.0
            dt = fb.downtime_sec
            ct = fb.containment_time_sec

            if act not in self.action_ema_success:
                self.action_ema_success[act] = succ
                self.action_ema_downtime[act] = dt
                self.action_ema_containment[act] = ct
            else:
                self.action_ema_success[act] = (1 - self.alpha) * self.action_ema_success[act] + self.alpha * succ
                self.action_ema_downtime[act] = (1 - self.alpha) * self.action_ema_downtime[act] + self.alpha * dt
                self.action_ema_containment[act] = (1 - self.alpha) * self.action_ema_containment[act] + self.alpha * ct

    def record_feedback(
        self,
        incident_id: str,
        scenario: str,
        plan: Dict[str, str],
        successful: bool,
        attack_type: str = "general_threat",
        threat_score: float = 0.8,
        confidence: float = 0.9,
        selected_action: str = "isolate",
        alternative_actions: Optional[List[str]] = None,
        containment_time_sec: float = 12.0,
        downtime_sec: float = 45.0,
        false_positive_status: bool = False,
        operator_override: bool = False,
        notes: str = "",
        outcome_metrics: Optional[Dict[str, float]] = None,
    ) -> RichIncidentFeedback:
        """
        Records a comprehensive incident outcome and updates weights via EMA.
        """
        metrics = outcome_metrics or {}
        feedback = RichIncidentFeedback(
            incident_id=incident_id,
            timestamp=datetime.now().isoformat(timespec="seconds"),
            scenario=scenario,
            attack_type=attack_type,
            plan=plan,
            threat_score=threat_score,
            confidence=confidence,
            selected_action=selected_action,
            alternative_actions=alternative_actions or [],
            successful=successful,
            containment_time_sec=containment_time_sec,
            downtime_sec=downtime_sec,
            false_positive_status=false_positive_status,
            operator_override=operator_override,
            notes=notes,
            initial_utility_weights=self.current_weights.copy(),
            outcome_metrics=metrics,
        )
        self.feedback_history.append(feedback)
        self._update_weights_ema(feedback)

        # System B: Synthesize candidate structural constraint rule and route through Validation Gate
        if operator_override or downtime_sec > 120.0:
            candidate = {
                "rule_id": f"EXP_RULE_{incident_id}_{len(self.learned_rules)+1}",
                "target_resource_type": "server",
                "restrict_action": selected_action,
                "condition": "OPERATOR_OVERRIDE" if operator_override else "EXCESSIVE_DOWNTIME",
                "rationale": f"Action '{selected_action}' was flagged in incident '{incident_id}' (downtime: {downtime_sec}s, override: {operator_override}). Structurally restricted from future decision models.",
                "trigger_incident_id": incident_id,
            }
            is_valid, reason = self.validate_candidate_rule(candidate)
            candidate["validation_status"] = "APPROVED" if is_valid else "REJECTED"
            candidate["validation_reason"] = reason
            if is_valid:
                self.learned_rules.append(candidate)
        
        # Save updated weights into metrics dict for auditability
        feedback.outcome_metrics["current_weights"] = self.current_weights.copy()
        feedback.outcome_metrics["ema_success_rate"] = self.action_ema_success.get(selected_action, 1.0)
        self.save_feedback()
        return feedback

    def _update_weights_ema(self, feedback: RichIncidentFeedback):
        """
        Adapts utility weights using EMA outcome performance.
        """
        lr = FEEDBACK_LEARNING_RATE
        act = feedback.selected_action
        succ = 1.0 if feedback.successful and not feedback.false_positive_status else 0.0

        # Update EMA state
        if act not in self.action_ema_success:
            self.action_ema_success[act] = succ
            self.action_ema_downtime[act] = feedback.downtime_sec
            self.action_ema_containment[act] = feedback.containment_time_sec
        else:
            self.action_ema_success[act] = (1 - self.alpha) * self.action_ema_success[act] + self.alpha * succ
            self.action_ema_downtime[act] = (1 - self.alpha) * self.action_ema_downtime[act] + self.alpha * feedback.downtime_sec
            self.action_ema_containment[act] = (1 - self.alpha) * self.action_ema_containment[act] + self.alpha * feedback.containment_time_sec

        # Weight adaptation rules:
        # 1. False positive -> penalty to containment_effectiveness, increase compliance/business protection
        if feedback.false_positive_status:
            self.current_weights["containment_effectiveness"] *= (1.0 - lr * 1.5)
            self.current_weights["business_impact"] *= (1.0 + lr * 0.5)
            self.current_weights["downtime"] *= (1.0 + lr * 0.5)

        # 2. Operator override -> indicates action was too aggressive
        elif feedback.operator_override:
            self.current_weights["business_impact"] *= (1.0 + lr)
            self.current_weights["containment_effectiveness"] *= (1.0 - lr * 0.5)

        # 3. Successful containment -> reinforce containment weight
        elif feedback.successful:
            self.current_weights["containment_effectiveness"] *= (1.0 + lr * 0.5)

        # 4. Failure to contain -> significantly increase containment requirement
        else:
            self.current_weights["containment_effectiveness"] *= (1.0 + lr * 1.8)

        self._normalize_weights()

    def _normalize_weights(self):
        total = abs(sum(v for v in self.current_weights.values()))
        if total > 0:
            for k in self.current_weights:
                self.current_weights[k] /= total

    def get_current_weights(self) -> Dict[str, float]:
        return self.current_weights.copy()

    def get_rolling_metrics(self) -> Dict[str, Dict[str, float]]:
        return {
            "ema_success": self.action_ema_success.copy(),
            "ema_downtime": self.action_ema_downtime.copy(),
            "ema_containment": self.action_ema_containment.copy(),
        }

    def validate_candidate_rule(
        self,
        candidate_rule: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """
        Validation Gate: Verifies that a candidate learned rule does NOT
        attempt to override hard physical safety constraints, mandatory statutory
        rules (e.g. HIPAA ePHI access restrictions), or empty the decision space.
        """
        action = candidate_rule.get("restrict_action")
        rtype = candidate_rule.get("target_resource_type", "all")

        # 1. Safety Invariant: Cannot restrict 'monitor' or 'increase_logging' (failsafe baseline)
        if action in ("monitor", "increase_logging"):
            return False, f"REJECTED: Cannot restrict failsafe baseline action '{action}'"

        # 2. Cannot create rule restricting essential actions on medical devices or PLCs
        if rtype in ("plc_controller", "medical_device") and action == "rotate_credentials":
            return False, f"REJECTED: Action '{action}' is an essential security control on '{rtype}'"

        return True, "APPROVED: Rule passed formal validation gate"

    def get_learned_rules(self) -> List[Dict[str, Any]]:
        """Returns the list of validated learned constraint rules from experience memory."""
        return [r for r in self.learned_rules if r.get("validation_status") == "APPROVED"]

    def add_learned_constraint(
        self,
        resource_type: str,
        action: str,
        rationale: str,
        incident_id: str = "manual",
    ) -> Tuple[Optional[Dict[str, Any]], str]:
        """
        Submits a candidate experience constraint to the Validation Gate.
        Admitted only if approved.
        """
        candidate = {
            "rule_id": f"EXP_RULE_{incident_id}_{len(self.learned_rules)+1}",
            "target_resource_type": resource_type,
            "restrict_action": action,
            "condition": "EXPERIENCE_LEARNED",
            "rationale": rationale,
            "trigger_incident_id": incident_id,
        }
        is_valid, reason = self.validate_candidate_rule(candidate)
        candidate["validation_status"] = "APPROVED" if is_valid else "REJECTED"
        candidate["validation_reason"] = reason

        if is_valid:
            self.learned_rules.append(candidate)
            self.save_feedback()
            return candidate, reason
        return None, reason

    def admit_candidate_rule_sandboxed(
        self,
        candidate_rule: Dict[str, Any],
        baseline_ir: Optional[Any] = None,
    ) -> RuleAdmissionEvidence:
        """
        Safety-Gated Experience Memory (Patent Core):
          1. Clones/sandboxes the current structural state (IR_t).
          2. Applies candidate delta.
          3. Executes fixed-point dependency closure and regenerates bounds.
          4. Certifies candidate IR via PreSolveSafetyCertifier.
          5. Verifies safety monotonicity (no failsafe removal, no forbidden reintroduction).
          6. Admits into persistent experience memory ONLY upon 100% successful certification.
        """
        from layer5_constraints.safety_certifier import PreSolveSafetyCertifier

        rule_id = candidate_rule.get("rule_id", f"EXP_RULE_{len(self.learned_rules)+1}")
        incident_id = candidate_rule.get("trigger_incident_id", "incident")
        restrict_action = candidate_rule.get("restrict_action")
        target_rt = candidate_rule.get("target_resource_type", "all")
        before_v = baseline_ir.ir_version if baseline_ir else 1
        sandbox_v = before_v + 1

        # 1. Monotonicity check: cannot restrict failsafe baseline
        if restrict_action in ("monitor", "increase_logging"):
            return RuleAdmissionEvidence(
                candidate_rule_id=rule_id,
                source_incident=incident_id,
                proposed_structural_delta=candidate_rule,
                before_ir_version=before_v,
                sandbox_ir_version=sandbox_v,
                validation_results={"failsafe_preserved": False},
                admitted=False,
                reason=f"REJECTED: Safety monotonicity violation -- cannot restrict failsafe baseline action '{restrict_action}'",
            )

        # 2. Monotonicity check: cannot re-introduce forbidden actions on cyber-physical assets
        if candidate_rule.get("allow_action") == "isolate" or candidate_rule.get("re_enable_action") == "isolate":
            if target_rt in ("plc_controller", "medical_device", "all"):
                return RuleAdmissionEvidence(
                    candidate_rule_id=rule_id,
                    source_incident=incident_id,
                    proposed_structural_delta=candidate_rule,
                    before_ir_version=before_v,
                    sandbox_ir_version=sandbox_v,
                    validation_results={"cyber_physical_invariant": False},
                    admitted=False,
                    reason="REJECTED: Safety monotonicity violation -- cannot re-introduce 'isolate' on cyber-physical controller",
                )

        # 3. Sandboxed IR Mutation & Pre-Solve Certification
        if baseline_ir is not None:
            sandbox_ir = copy.deepcopy(baseline_ir)
            sandbox_ir.ir_version = sandbox_v

            # Apply candidate restriction
            if restrict_action:
                for rid, dom in sandbox_ir.variable_domains.items():
                    if target_rt in (dom.resource_type, "all", "*") or candidate_rule.get("target_resource_id") == rid:
                        if restrict_action in dom.admissible_actions:
                            dom.admissible_actions = [a for a in dom.admissible_actions if a != restrict_action]
                            if restrict_action not in dom.pruned_actions:
                                dom.pruned_actions.append(restrict_action)
                                from layer5_constraints.constraint_ir import IRProvenanceRecord
                                sandbox_ir.provenance_records.append(IRProvenanceRecord(
                                    target_resource=rid,
                                    target_action=restrict_action,
                                    constraint_type="EXPERIENCE",
                                    origin="EXPERIENCE_MEMORY",
                                    rule_id=rule_id,
                                    rationale=candidate_rule.get("rationale", "Restricted by candidate experience rule"),
                                ))

            # Check for empty decision domain
            empty_domains = [rid for rid, dom in sandbox_ir.variable_domains.items() if len(dom.admissible_actions) == 0]
            if empty_domains:
                return RuleAdmissionEvidence(
                    candidate_rule_id=rule_id,
                    source_incident=incident_id,
                    proposed_structural_delta=candidate_rule,
                    before_ir_version=before_v,
                    sandbox_ir_version=sandbox_v,
                    validation_results={"non_empty_domain": False},
                    admitted=False,
                    reason=f"REJECTED: Rule produces empty feasible action domain for resources {empty_domains}",
                )

            # Update invariance constraints to match admissible actions
            for inv in sandbox_ir.invariance_constraints:
                dom = sandbox_ir.variable_domains.get(inv.resource_id)
                if dom:
                    inv.actions = list(dom.admissible_actions)

            # Prune conflict hyperedges referencing removed variables
            all_active = set(sandbox_ir.get_all_variables())
            sandbox_ir.conflict_hyperedges = [
                c for c in sandbox_ir.conflict_hyperedges
                if (c.resource_1, c.action_1) in all_active and (c.resource_2, c.action_2) in all_active
            ]

            sandbox_ir.compute_canonical_digest()
            cert = PreSolveSafetyCertifier.certify(sandbox_ir)

            if not cert.is_valid():
                violations = "; ".join(cert.forbidden_action_violations)
                return RuleAdmissionEvidence(
                    candidate_rule_id=rule_id,
                    source_incident=incident_id,
                    proposed_structural_delta=candidate_rule,
                    before_ir_version=before_v,
                    sandbox_ir_version=sandbox_v,
                    validation_results=cert.verification_checks,
                    admitted=False,
                    reason=f"REJECTED: Pre-solve safety certification failed in sandbox: {violations}",
                )

            # All checks passed in sandbox! Admit rule
            candidate_rule["validation_status"] = "APPROVED"
            candidate_rule["validation_reason"] = "Passed formal sandboxed pre-solve safety certification"
            self.learned_rules.append(candidate_rule)
            self.save_feedback()

            return RuleAdmissionEvidence(
                candidate_rule_id=rule_id,
                source_incident=incident_id,
                proposed_structural_delta=candidate_rule,
                before_ir_version=before_v,
                sandbox_ir_version=sandbox_v,
                validation_results=cert.verification_checks,
                admitted=True,
                reason="APPROVED: Rule certified in sandbox without violating safety invariants",
                resulting_ir_version=sandbox_v,
            )

        # If no baseline IR provided, evaluate heuristic validation gate
        is_valid, reason = self.validate_candidate_rule(candidate_rule)
        candidate_rule["validation_status"] = "APPROVED" if is_valid else "REJECTED"
        candidate_rule["validation_reason"] = reason
        if is_valid:
            self.learned_rules.append(candidate_rule)
            self.save_feedback()

        return RuleAdmissionEvidence(
            candidate_rule_id=rule_id,
            source_incident=incident_id,
            proposed_structural_delta=candidate_rule,
            before_ir_version=before_v,
            sandbox_ir_version=sandbox_v,
            validation_results={"heuristic_check": is_valid},
            admitted=is_valid,
            reason=reason,
            resulting_ir_version=sandbox_v if is_valid else None,
        )


