"""
=============================================================================
LAYER 2: GLOBAL FEDERATED SERVER
Module: fedadam_server.py
-----------------------------------------------------------------------------
Problem Solved:
  FedAdam applies the Adam optimiser on the SERVER side to the aggregated
  pseudo-gradient received from clients. While FedAvg uses a fixed server
  learning rate (effectively η=1), FedAdam uses adaptive moment estimates
  to accelerate convergence and improve final accuracy.

  The server treats the aggregated client update Δw as a pseudo-gradient
  and applies:
      m_t = β1·m_{t-1} + (1−β1)·Δw          (first moment)
      v_t = β2·v_{t-1} + (1−β2)·Δw²          (second moment)
      w_global ← w_global + η · m_t / (√v_t + ε)

  Benefit: Server-side adaptivity compensates for non-IID client gradient
  noise — especially valuable when IoT nodes have heterogeneous attack
  distributions (DDoS-heavy nodes vs password-attack-heavy nodes).

Reference: Reddi et al., "Adaptive Federated Optimization" (ICLR 2021)
           https://arxiv.org/abs/2003.00295

Inputs:   Client state dicts + sample sizes + Adam hyperparameters
Outputs:  Aggregated global model state dict
=============================================================================
"""

import copy
from typing import List, Dict, Optional

try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


class GlobalFedAdamServer:
    """
    FedAdam Server — applies server-side Adam optimisation on
    aggregated client pseudo-gradients for faster, more stable convergence.

    Parameters
    ----------
    global_state_dict : dict
        Initial global model weights.
    server_lr : float
        Server learning rate η (default 0.01 — smaller than FedAvg's 1.0).
    beta1 : float
        Exponential decay rate for first moment (default 0.9).
    beta2 : float
        Exponential decay rate for second moment (default 0.999).
    epsilon : float
        Numerical stability constant (default 1e-8).
    """

    def __init__(
        self,
        global_state_dict: Dict = None,
        server_lr: float = 0.01,
        beta1: float = 0.9,
        beta2: float = 0.999,
        epsilon: float = 1e-8,
    ):
        self.global_state_dict = global_state_dict
        self.server_lr = server_lr
        self.beta1 = beta1
        self.beta2 = beta2
        self.epsilon = epsilon
        self.round_num = 0

        # Adam moment accumulators — initialised lazily on first round
        self._m: Optional[Dict] = None   # first moment
        self._v: Optional[Dict] = None   # second moment

    def aggregate_weights(
        self,
        client_state_dicts: List[Dict],
        client_sample_sizes: List[int],
    ) -> Dict:
        """
        FedAdam aggregation:
          Δw   = Σ_k (n_k/N)·w_k − w_global       (pseudo-gradient)
          m_t  = β1·m + (1−β1)·Δw
          v_t  = β2·v + (1−β2)·Δw²
          w_global ← w_global + η · m_t / (√v_t + ε)
        """
        if not client_state_dicts or not HAS_TORCH:
            return self.global_state_dict

        total_samples = sum(client_sample_sizes)
        if total_samples == 0:
            return self.global_state_dict

        self.round_num += 1

        # Step 1: Compute weighted average of client weights (same as FedAvg)
        avg_weights = copy.deepcopy(client_state_dicts[0])
        for key in avg_weights:
            avg_weights[key] = torch.zeros_like(avg_weights[key], dtype=torch.float32)
        for state_dict, n_k in zip(client_state_dicts, client_sample_sizes):
            factor = n_k / total_samples
            for key in avg_weights:
                avg_weights[key] += factor * state_dict[key].to(torch.float32)

        # Step 2: Compute pseudo-gradient Δw = avg_weights − w_global
        delta = {}
        for key in avg_weights:
            delta[key] = avg_weights[key] - self.global_state_dict[key].to(torch.float32)

        # Step 3: Initialise moment accumulators on first round
        if self._m is None:
            self._m = {k: torch.zeros_like(delta[k]) for k in delta}
            self._v = {k: torch.zeros_like(delta[k]) for k in delta}

        # Step 4: Adam update
        new_global = copy.deepcopy(self.global_state_dict)
        for key in delta:
            self._m[key] = self.beta1 * self._m[key] + (1 - self.beta1) * delta[key]
            self._v[key] = self.beta2 * self._v[key] + (1 - self.beta2) * (delta[key] ** 2)

            # Bias-corrected estimates
            m_hat = self._m[key] / (1 - self.beta1 ** self.round_num)
            v_hat = self._v[key] / (1 - self.beta2 ** self.round_num)

            new_global[key] = (
                new_global[key].to(torch.float32)
                + self.server_lr * m_hat / (torch.sqrt(v_hat) + self.epsilon)
            )

        self.global_state_dict = new_global
        return self.global_state_dict
