"""
=============================================================================
LAYER 2: GLOBAL FEDERATED SERVER
Module: fedavg_server.py
-----------------------------------------------------------------------------
Problem Solved:
  Coordinates central model aggregation across distributed IoT Edge clients
  using Federated Averaging (FedAvg). Solves model centralization risks by
  updating a global threat detection neural network without accessing raw data.

Formula:  w_global = sum_{k=1}^K (n_k / N) * w_k
Inputs:   Client state dict list [w_1, w_2, ..., w_K] and sample sizes [n_1, n_2, ..., n_K].
Outputs: Aggregated global model state dict (w_global).
=============================================================================
"""

import copy
from typing import List, Dict

try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


class GlobalFedAvgServer:
    """Central Federated Learning Server performing FedAvg weight aggregation."""
    def __init__(self, global_state_dict: Dict = None):
        self.global_state_dict = global_state_dict

    def aggregate_weights(self, client_state_dicts: List[Dict], client_sample_sizes: List[int]) -> Dict:
        """
        Executes FedAvg weighted averaging:
        w_global = sum_{k=1}^K (n_k / N) * w_k
        """
        if not client_state_dicts or not HAS_TORCH:
            return self.global_state_dict

        total_samples = sum(client_sample_sizes)
        if total_samples == 0:
            return self.global_state_dict

        # Initialize global accumulator with zeros matching tensor shapes
        new_global_weights = copy.deepcopy(client_state_dicts[0])
        for key in new_global_weights.keys():
            new_global_weights[key] = torch.zeros_like(new_global_weights[key], dtype=torch.float32)

        # Weighted sum across all participating IoT edge nodes
        for state_dict, n_k in zip(client_state_dicts, client_sample_sizes):
            weight_factor = n_k / total_samples
            for key in new_global_weights.keys():
                new_global_weights[key] += weight_factor * state_dict[key].to(torch.float32)

        self.global_state_dict = new_global_weights
        return self.global_state_dict
