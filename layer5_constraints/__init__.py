"""
=============================================================================
LAYER 5: ADAPTIVE CONSTRAINTS & COMPILER ENGINE
Package Initialization
=============================================================================
"""

from .adaptive_constraints import (
    generate_adaptive_constraints,
    OptimizationConstraints,
    ConstraintProvenance,
    ResourceProfile,
    FEASIBLE_ACTION_MATRIX,
    RESOURCE_PROFILES,
)
from .constraint_ir import (
    SecurityConstraintIR,
    VariableDomain,
    InvarianceConstraint,
    ConflictHyperedge,
    HardBudgetConstraint,
    ObjectiveLinearTerm,
    IRProvenanceRecord,
    TopologyMetadata,
)
from .dependency_graph import ConstraintDependencyGraph
from .safety_certifier import PreSolveSafetyCertifier, ConstraintSafetyCertificate
from .formulation_compiler import FormulationCompiler
