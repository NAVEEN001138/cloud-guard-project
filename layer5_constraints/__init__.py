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
    SemanticManifest,
    ConstraintRecord,
    ConstraintHardness,
)
from .dependency_graph import (
    ConstraintDependencyGraph,
    TypedDependencyEdge,
    DependencyRelationType,
    ClosureProvenance,
    ClosureResult,
    calculate_action_cost,
    PHYSICAL_CAPABILITY_MAP,
    DEFAULT_ACTION_CONFLICTS,
)
from .safety_certifier import PreSolveSafetyCertifier, ConstraintSafetyCertificate
from .formulation_compiler import (
    FormulationCompiler,
    UncertifiedIRCompilationError,
    StaleCertificateError,
    IntegrityBindingError,
    CompilationResult,
)
from .incremental_compiler import (
    IncrementalConstraintCompiler,
    RuntimeStateDelta,
    IncrementalCompilationResult,
)
from .semantic_validator import (
    SemanticValidator,
    SemanticValidationReport,
)
