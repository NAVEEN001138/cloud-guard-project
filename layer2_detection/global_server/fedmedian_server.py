"""
=============================================================================
LAYER 2: GLOBAL FEDERATED SERVER
Module: fedmedian_server.py
-----------------------------------------------------------------------------
Problem Solved:
  FedMedian replaces the weighted mean aggregation of FedAvg with a
  coordinate-wise median. This makes the server robust to Byzantine
  (malicious or corrupted) clients — a critical property for IoT security
  systems where edge nodes may be compromised by the very attacks they are
  trying to detect.

  In the IoT threat detection context:
    - A node infected with a Backdoor attack may send poisoned gradients
    - A node running Ransomware may behave erratically
    - Median aggregation naturally ignores extreme outlier weight values

  Aggregation:
      w_global[j] = median({w_k[j] : k = 1..K})   for each parameter j

  Note: FedMedian does NOT use sample-size weighting (every client has
  equal vote), which is its key difference from FedAvg and FedProx.

Reference: Yin et al., "Byzantine-Robust Distributed Learning: Towards
           Optimal Statistical Rates" (ICML 2018)
           https://arxiv.org/abs/1803.01498

Inputs:   Client state dict list
Outputs:  Aggregated global model state dict (coordinate-wise median)
=============================================================================
"""

import copy
from typing import List, Dict

try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


class GlobalFedMedianServer:
    """
    FedMedian Server — coordinate-wise median aggregation for Byzantine
    robustness. Each parameter is set to the median value across clients,
    rather than the mean, making it resistant to poisoned/outlier clients.

    Parameters
    ----------
    global_state_dict : dict
        Initial global model weights.
    """

    def __init__(self, global_state_dict: Dict = None):
        self.global_state_dict = global_state_dict
        self.round_num = 0

    def aggregate_weights(
        self,
        client_state_dicts: List[Dict],
        client_sample_sizes: List[int] = None,   # unused — median ignores weights
    ) -> Dict:
        """
        FedMedian aggregation:
          w_global[j] = median({w_1[j], w_2[j], ..., w_K[j]})

        Each coordinate is the median across all participating clients.
        Sample sizes are intentionally ignored (equal client voting).
        """
        if not client_state_dicts or not HAS_TORCH:
            return self.global_state_dict

        if len(client_state_dicts) == 1:
            self.global_state_dict = copy.deepcopy(client_state_dicts[0])
            return self.global_state_dict

        new_global = copy.deepcopy(client_state_dicts[0])

        for key in new_global:
            # Stack all client tensors along a new dimension → (K, *param_shape)
            stacked = torch.stack(
                [sd[key].to(torch.float32) for sd in client_state_dicts],
                dim=0,
            )
            # Coordinate-wise median across clients (dim=0)
            new_global[key] = torch.median(stacked, dim=0).values

        self.global_state_dict = new_global
        self.round_num += 1
        return self.global_state_dict
