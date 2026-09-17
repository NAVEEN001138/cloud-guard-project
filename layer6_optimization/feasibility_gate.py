"""
=============================================================================
LAYER 6: POST-SOLVE FEASIBILITY GATE & CONDITIONAL REPAIR
Module: feasibility_gate.py
-----------------------------------------------------------------------------
Problem Solved:
  Acts as an untrusted-solver guardrail. Verifies whether solver output x*
  strictly belongs to F(IR). If x* in F(IR), it passes through unchanged.
  If x* not in F(IR), attempts a greedy projection onto F(IR) with the
  constructive feasibility witness W_t as a fallback. If repair fails,
  REJECTS the plan.

Invariant Guarantee:
  Every plan exiting this gate is strictly in F(IR).

Conditional Optimality Guarantee:
  The delta-optimality bound is CONDITIONAL: certified_loss_bound(x_repaired)
  is implemented only where an independently verifiable lower bound exists
  (e.g., ILP LP relaxation). Returns None otherwise; universal optimality
  bounds are not claimed.
=============================================================================
"""

import copy
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any

from layer5_constraints.constraint_ir import SecurityConstraintIR
from layer5_constraints.safety_certifier import ConstraintSafetyCertificate


class InfeasiblePlanRejectionError(Exception):
    """Raised when solver plan cannot be repaired to satisfy F(IR)."""
    pass


@dataclass
class FeasibilityGateResult:
    """Result of passing a candidate plan through the feasibility gate."""
    plan: Dict[str, str]
    is_feasible: bool
    was_repaired: bool
    original_plan: Dict[str, str]
    certified_loss_bound: Optional[float] = None
    violations: List[str] = field(default_factory=list)
    rejection_reason: str = ""


class FeasibilityGate:
    """
    Post-solve safety gate enforcing that all emitted response plans
    strictly satisfy F(IR).
    """

    @classmethod
    def check_membership(
        cls,
        plan: Dict[str, str],
        ir: SecurityConstraintIR,
    ) -> Tuple[bool, List[str]]:
        """
        Tests whether candidate plan strictly belongs to F(IR).
        Returns (is_member, list_of_violations).
        """
        violations = []

        # 1. Variable Domain Admissibility & Coverage
        for rid, domain in ir.variable_domains.items():
            if rid not in plan:
                violations.append(f"Missing action for resource '{rid}'")
                continue
            act = plan[rid]
            if act not in domain.admissible_actions:
                violations.append(
                    f"Action '{act}' on '{rid}' is inadmissible (excised/pruned from certified domain)"
                )

        # 2. Invariance Constraints (Exactly-one active per resource group)
        for inv in ir.invariance_constraints:
            act = plan.get(inv.resource_id)
            if act not in inv.actions:
                violations.append(
                    f"Invariance violation on '{inv.resource_id}': action '{act}' not in invariance set"
                )

        # 3. Conflict Hyperedges
        for conf in ir.conflict_hyperedges:
            a1 = plan.get(conf.resource_1)
            a2 = plan.get(conf.resource_2)
            if a1 == conf.action_1 and a2 == conf.action_2:
                violations.append(
                    f"Conflict hyperedge violation: ({conf.resource_1}={a1}) conflicts with ({conf.resource_2}={a2})"
                )

        # 4. Hard Budget Constraint
        if ir.budget_constraint and ir.budget_constraint.max_budget > 0:
            total_cost = 0.0
            for rid, act in plan.items():
                total_cost += ir.budget_constraint.cost_map.get((rid, act), 0.0)
            if total_cost > ir.budget_constraint.max_budget + 1e-5:
                violations.append(
                    f"Budget ceiling exceeded: cost {total_cost:.3f} > max {ir.budget_constraint.max_budget:.3f}"
                )

        return (len(violations) == 0, violations)

    @classmethod
    def evaluate_objective(cls, plan: Dict[str, str], ir: SecurityConstraintIR) -> float:
        """Evaluates linear objective cost of a response plan under the IR."""
        total = 0.0
        for (r, a), term in ir.objective_terms.items():
            if plan.get(r) == a:
                total += term.coefficient
        return total

    @classmethod
    def compute_certified_loss_bound(
        cls,
        repaired_plan: Dict[str, str],
        ir: SecurityConstraintIR,
        lp_relaxation_lower_bound: Optional[float] = None,
    ) -> Optional[float]:
        """
        Computes conditional delta-optimality loss bound delta = C(x_repaired) - Z_LP.
        Returns None when no independently verifiable lower bound is supplied.
        """
        if lp_relaxation_lower_bound is None:
            return None
        obj_repaired = cls.evaluate_objective(repaired_plan, ir)
        # Loss bound against independent LP relaxation lower bound
        delta = max(0.0, obj_repaired - lp_relaxation_lower_bound)
        return float(delta)

    @classmethod
    def filter_and_repair(
        cls,
        plan: Dict[str, str],
        ir: SecurityConstraintIR,
        certificate: Optional[ConstraintSafetyCertificate] = None,
        lp_relaxation_lower_bound: Optional[float] = None,
    ) -> FeasibilityGateResult:
        """
        Gates untrusted solver plan:
          1. If plan in F(IR), pass through.
          2. Else greedily project onto F(IR).
          3. If greedy projection fails, fall back to certified witness W_t.
          4. If still invalid, raise InfeasiblePlanRejectionError.
        """
        is_member, violations = cls.check_membership(plan, ir)
        if is_member:
            return FeasibilityGateResult(
                plan=plan,
                is_feasible=True,
                was_repaired=False,
                original_plan=plan,
                certified_loss_bound=None,
                violations=[],
            )

        # Attempt Greedy Projection onto F(IR)
        repaired_plan = copy.deepcopy(plan)

        # Fix inadmissible actions first (replace with failsafe 'monitor' or first admissible)
        for rid, domain in ir.variable_domains.items():
            if rid not in repaired_plan or repaired_plan[rid] not in domain.admissible_actions:
                if "monitor" in domain.admissible_actions:
                    repaired_plan[rid] = "monitor"
                elif domain.admissible_actions:
                    repaired_plan[rid] = domain.admissible_actions[0]

        # Fix conflict violations greedily
        for conf in ir.conflict_hyperedges:
            if repaired_plan.get(conf.resource_1) == conf.action_1 and repaired_plan.get(conf.resource_2) == conf.action_2:
                # Demote one to monitor or alternate admissible action
                domain2 = ir.variable_domains.get(conf.resource_2)
                if domain2:
                    alts = [a for a in domain2.admissible_actions if a != conf.action_2]
                    if "monitor" in alts:
                        repaired_plan[conf.resource_2] = "monitor"
                    elif alts:
                        repaired_plan[conf.resource_2] = alts[0]

        # Fix budget violation greedily (demote to lowest-cost action)
        if ir.budget_constraint and ir.budget_constraint.max_budget > 0:
            cost_map = ir.budget_constraint.cost_map
            curr_cost = sum(cost_map.get((r, a), 0.0) for r, a in repaired_plan.items())
            if curr_cost > ir.budget_constraint.max_budget:
                for rid, domain in ir.variable_domains.items():
                    cheapest_act = min(domain.admissible_actions, key=lambda a: cost_map.get((rid, a), 0.0))
                    repaired_plan[rid] = cheapest_act
                    curr_cost = sum(cost_map.get((r, a), 0.0) for r, a in repaired_plan.items())
                    if curr_cost <= ir.budget_constraint.max_budget:
                        break

        # Verify whether greedy projection succeeded
        is_rep_feasible, rep_violations = cls.check_membership(repaired_plan, ir)
        if is_rep_feasible:
            loss_bound = cls.compute_certified_loss_bound(repaired_plan, ir, lp_relaxation_lower_bound)
            return FeasibilityGateResult(
                plan=repaired_plan,
                is_feasible=True,
                was_repaired=True,
                original_plan=plan,
                certified_loss_bound=loss_bound,
                violations=violations,
            )

        # Fallback to Constructive Feasibility Witness W_t
        witness = getattr(certificate, "feasibility_witness", None) if certificate else None
        if witness:
            w_plan = witness if isinstance(witness, dict) and "assignment" not in witness else witness.get("assignment", {})
            w_feasible, _ = cls.check_membership(w_plan, ir)
            if w_feasible:
                loss_bound = cls.compute_certified_loss_bound(w_plan, ir, lp_relaxation_lower_bound)
                return FeasibilityGateResult(
                    plan=w_plan,
                    is_feasible=True,
                    was_repaired=True,
                    original_plan=plan,
                    certified_loss_bound=loss_bound,
                    violations=violations,
                )

        raise InfeasiblePlanRejectionError(
            f"Feasibility gate rejected plan: Inadmissible solution cannot be projected onto F(IR). "
            f"Violations: {'; '.join(violations)}"
        )
