"""
=============================================================================
LAYER 2: GLOBAL FEDERATED SERVER
Module: fednova_server.py
-----------------------------------------------------------------------------
Problem Solved:
  FedNova (Federated Normalised Averaging) corrects the "objective
  inconsistency" in FedAvg caused by clients performing different numbers
  of local gradient steps. In non-IID IoT settings, clients with smaller
  local datasets take fewer steps, creating a bias in the global update.

  FedNova normalises each client's update by the number of local steps
  taken (τ_k) before aggregating:

      d_k = (w_k_init − w_k_final) / τ_k       (normalised gradient)
      w_global ← w_global − η · Σ_k (n_k/N) · d_k

  This ensures all clients contribute equally per gradient step regardless
  of dataset size, which is critical when IoT sensor nodes have very
  different amounts of data (e.g., MITM: 1,229 rows vs DDoS UDP: 3.2M rows).

Reference: Wang et al., "Tackling the Objective Inconsistency Problem in
           Heterogeneous Federated Optimization" (NeurIPS 2020)
           https://arxiv.org/abs/2007.07481

Inputs:   Client (state_dict, initial_state_dict, local_steps) tuples
Outputs:  Aggregated global model state dict
=============================================================================
"""

import copy
from typing import List, Dict, Tuple

try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


class GlobalFedNovaServer:
    """
    FedNova Server — normalises client updates by local step count
    before aggregating to fix objective inconsistency in non-IID FL.

    Parameters
    ----------
    global_state_dict : dict
        Initial global model weights.
    server_lr : float
        Server-side learning rate η applied to the aggregated normalised gradient.
    """

    def __init__(self, global_state_dict: Dict = None, server_lr: float = 1.0):
        self.global_state_dict = global_state_dict
        self.server_lr = server_lr
        self.round_num = 0

    def aggregate_weights(
        self,
        client_state_dicts: List[Dict],
        client_initial_dicts: List[Dict],
        client_sample_sizes: List[int],
        client_local_steps: List[int],
    ) -> Dict:
        """
        FedNova aggregation:
          d_k  = (w_k_init − w_k_final) / τ_k    (normalised per-step update)
          d_agg = Σ_k (n_k / N) · d_k             (weighted aggregate)
          w_global ← w_global − η · d_agg

        Parameters
        ----------
        client_state_dicts   : final weights from each client  [w_k_final]
        client_initial_dicts : weights sent TO each client     [w_k_init]
        client_sample_sizes  : number of samples per client    [n_k]
        client_local_steps   : number of local SGD steps taken [τ_k]
        """
        if not client_state_dicts or not HAS_TORCH:
            return self.global_state_dict

        total_samples = sum(client_sample_sizes)
        if total_samples == 0:
            return self.global_state_dict

        # Accumulate the normalised global gradient direction
        agg_grad = copy.deepcopy(client_state_dicts[0])
        for key in agg_grad:
            agg_grad[key] = torch.zeros_like(agg_grad[key], dtype=torch.float32)

        for w_final, w_init, n_k, tau_k in zip(
            client_state_dicts,
            client_initial_dicts,
            client_sample_sizes,
            client_local_steps,
        ):
            factor = n_k / total_samples
            tau_k  = max(tau_k, 1)   # avoid divide-by-zero if no steps taken
            for key in agg_grad:
                # Normalised update: (w_init - w_final) / τ_k
                delta = (w_init[key].to(torch.float32) - w_final[key].to(torch.float32)) / tau_k
                agg_grad[key] += factor * delta

        # Apply aggregated normalised gradient to global model
        new_global = copy.deepcopy(self.global_state_dict)
        for key in new_global:
            new_global[key] = (
                new_global[key].to(torch.float32) - self.server_lr * agg_grad[key]
            )

        self.global_state_dict = new_global
        self.round_num += 1
        return self.global_state_dict
