"""
=============================================================================
LAYER 2: GLOBAL FEDERATED SERVER
Module: fedprox_server.py
-----------------------------------------------------------------------------
Problem Solved:
  FedProx (Federated Proximal) addresses the statistical heterogeneity
  (non-IID data) problem in standard FedAvg. It adds a proximal term
  μ‖w_k − w_global‖² to each client's local objective, preventing local
  models from drifting too far from the global model during local training.

  This is critical for IoT edge environments where different sensor nodes
  (Smart Factory, Medical IoT, Smart Grid) observe completely different
  traffic distributions (non-IID).

Algorithm:
  Client side: min F_k(w) + (μ/2)‖w − w_global‖²
  Server side: Same weighted average as FedAvg (aggregation is identical)

Reference: Li et al., "Federated Optimization in Heterogeneous Networks"
           (ICLR 2020) — https://arxiv.org/abs/1812.06127

Inputs:   Client state dict list + sample sizes + mu (proximal strength)
Outputs:  Aggregated global model state dict
=============================================================================
"""

import copy
from typing import List, Dict

try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


class GlobalFedProxServer:
    """
    FedProx Server — aggregation is identical to FedAvg.
    The proximal term is enforced on the CLIENT side (see edge_client.py).

    Parameters
    ----------
    global_state_dict : dict
        Initial global model state dict.
    mu : float
        Proximal term coefficient. Higher mu → clients stay closer to global.
        Typical values: 0.001 (weak), 0.01 (moderate), 0.1 (strong).
    """

    def __init__(self, global_state_dict: Dict = None, mu: float = 0.01):
        self.global_state_dict = global_state_dict
        self.mu = mu
        self.round_num = 0

    def aggregate_weights(
        self,
        client_state_dicts: List[Dict],
        client_sample_sizes: List[int],
    ) -> Dict:
        """
        FedProx aggregation:  w_global = Σ_k (n_k / N) · w_k

        The proximal regularisation happens on the client during local training.
        Server-side aggregation is the same weighted mean as FedAvg.
        """
        if not client_state_dicts or not HAS_TORCH:
            return self.global_state_dict

        total_samples = sum(client_sample_sizes)
        if total_samples == 0:
            return self.global_state_dict

        new_global = copy.deepcopy(client_state_dicts[0])
        for key in new_global:
            new_global[key] = torch.zeros_like(new_global[key], dtype=torch.float32)

        for state_dict, n_k in zip(client_state_dicts, client_sample_sizes):
            factor = n_k / total_samples
            for key in new_global:
                new_global[key] += factor * state_dict[key].to(torch.float32)

        self.global_state_dict = new_global
        self.round_num += 1
        return self.global_state_dict
