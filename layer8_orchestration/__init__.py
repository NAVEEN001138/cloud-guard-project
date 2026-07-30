"""
=============================================================================
LAYER 8: RESPONSE ORCHESTRATION & EXECUTION
Package Initialization
=============================================================================
"""

from .executor import execute_plan, execute_strategy
from .explainability import DecisionExplainer, RoleBasedExplanation

# Alias for backward compatibility
ResourceDecisionExplanation = RoleBasedExplanation

__all__ = [
    "execute_plan",
    "execute_strategy",
    "DecisionExplainer",
    "RoleBasedExplanation",
    "ResourceDecisionExplanation",
]
