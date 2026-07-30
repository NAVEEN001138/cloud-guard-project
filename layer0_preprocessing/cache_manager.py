"""
=============================================================================
LAYER 0: DATA PREPROCESSING
Module: cache_manager.py
-----------------------------------------------------------------------------
Problem Solved:
  Saves and loads the fitted DataPreprocessor state to/from disk so that:
    - The preprocessing pipeline is fitted ONCE on the full training data
    - All 11 FL domain clients share the SAME fitted scaler (critical for
      FedAvg weight compatibility — weights trained on identically-scaled
      features can be safely averaged)
    - Re-running the system does not re-fit (faster cold-start)

Inputs:  A fitted DataPreprocessor instance
Outputs: .pkl file at PREPROCESSING_CACHE_PATH (from config.py)
=============================================================================
"""

import os
import pickle
from typing import Optional

from config import PREPROCESSING_CACHE_PATH


def save_preprocessor(preprocessor, path: Optional[str] = None) -> str:
    """
    Serialize a fitted DataPreprocessor to disk.

    Parameters
    ----------
    preprocessor : DataPreprocessor
        A fitted preprocessor instance (fit_transform already called).
    path : str, optional
        Override the default cache path from config.py.

    Returns
    -------
    str
        Absolute path where the cache was saved.
    """
    save_path = path or PREPROCESSING_CACHE_PATH
    os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)

    with open(save_path, "wb") as f:
        pickle.dump(preprocessor, f, protocol=pickle.HIGHEST_PROTOCOL)

    return os.path.abspath(save_path)


def load_preprocessor(path: Optional[str] = None):
    """
    Deserialize a fitted DataPreprocessor from disk.

    Parameters
    ----------
    path : str, optional
        Override the default cache path from config.py.

    Returns
    -------
    DataPreprocessor or None
        The fitted preprocessor, or None if the cache file does not exist.
    """
    load_path = path or PREPROCESSING_CACHE_PATH
    if not os.path.exists(load_path):
        return None

    with open(load_path, "rb") as f:
        obj = pickle.load(f)

    return obj


def cache_exists(path: Optional[str] = None) -> bool:
    """Return True if a preprocessor cache file exists at the given path."""
    return os.path.exists(path or PREPROCESSING_CACHE_PATH)


def invalidate_cache(path: Optional[str] = None) -> bool:
    """
    Delete the preprocessor cache file (forces re-fitting on next run).

    Returns True if a file was deleted, False if nothing existed.
    """
    target = path or PREPROCESSING_CACHE_PATH
    if os.path.exists(target):
        os.remove(target)
        return True
    return False
