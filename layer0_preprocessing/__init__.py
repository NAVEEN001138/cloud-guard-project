"""
=============================================================================
LAYER 0: DATA PREPROCESSING
Package Initialization
=============================================================================
Sits before Layer 1 (Telemetry) in the pipeline. Provides a consistent,
reproducible fit→transform pipeline that is shared across all FL clients
so that FedAvg weight aggregation remains numerically compatible.

Usage:
    from layer0_preprocessing import DataPreprocessor
    preprocessor = DataPreprocessor()
    X_clean = preprocessor.fit_transform(X_raw_df)
    X_new   = preprocessor.transform(X_new_df)
=============================================================================
"""

from .preprocessor import DataPreprocessor
from .cache_manager import save_preprocessor, load_preprocessor

__all__ = [
    "DataPreprocessor",
    "save_preprocessor",
    "load_preprocessor",
]
