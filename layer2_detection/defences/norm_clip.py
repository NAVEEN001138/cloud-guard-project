"""
=============================================================================
LAYER 2 DEFENCE: SERVER-SIDE UPDATE-NORM CLIPPING
Module: norm_clip.py
-----------------------------------------------------------------------------
Problem Solved:
  Mitigates model poisoning, backdoor attacks, and malicious parameter
  manipulation (e.g., sign-flip and large-magnitude malicious perturbations)
  by clipping each client's model delta norm to a robust data-driven bound.

Algorithm:
  For each client k:
    1. Compute update delta: d_k = w_k - w_global (floating-point tensors).
    2. Compute total update norm: ||d_k||_2 = sqrt(sum_p ||d_k[p]||_2^2).
    3. Compute adaptive clipping threshold B = median(||d_1||_2, ..., ||d_K||_2).
    4. Clip update delta: d_k_clipped = d_k * min(1.0, B / ||d_k||_2).
    5. Aggregate clipped updates via sample-weighted average:
         w_global = w_global + sum_k (n_k / N) * d_k_clipped.
    6. Non-floating buffers (e.g. BatchNorm num_batches_tracked) pass through
       unchanged from client updates.

Reference:
  Sun et al., "Can you really backdoor federated learning?",
  NeurIPS Workshop on Federated Learning for Data Privacy and Confidentiality, 2019.
  https://arxiv.org/abs/1911.07963
=============================================================================
"""

import copy
import numpy as np
from typing import List, Dict, Optional

try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

from layer2_detection.global_server.fedavg_server import GlobalFedAvgServer


class NormClipServer(GlobalFedAvgServer):
    """
    Central Federated Learning Server performing server-side update-norm clipping
    prior to FedAvg aggregation.

    Parameters
    ----------
    global_state_dict : dict, optional
        Initial global model weights.
    """

    def __init__(self, global_state_dict: Optional[Dict] = None):
        super().__init__(global_state_dict)
        self.round_num = 0
        self.last_clipped_count = 0
        self.last_bound_B = 0.0
        self.round_clipped_counts: List[int] = []

    @property
    def clipped_history(self) -> List[int]:
        """Alias for round_clipped_counts."""
        return self.round_clipped_counts

    def aggregate_weights(
        self, client_state_dicts: List[Dict], client_sample_sizes: List[int]
    ) -> Dict:
        """
        Executes sample-weighted averaging of norm-clipped client updates:
          B = median(||d_1||_2, ..., ||d_K||_2)
          d_k_clipped = d_k * min(1, B / ||d_k||_2)
          w_global = w_global + sum_k (n_k / N) * d_k_clipped
        """
        if not client_state_dicts or not HAS_TORCH:
            return self.global_state_dict

        total_samples = sum(client_sample_sizes)
        if total_samples == 0:
            return self.global_state_dict

        if self.global_state_dict is None:
            self.global_state_dict = copy.deepcopy(client_state_dicts[0])
            return self.global_state_dict

        K = len(client_state_dicts)

        # 1. Identify floating-point parameter keys vs integer/buffer keys
        float_keys = [
            k for k, v in self.global_state_dict.items() if v.is_floating_point()
        ]
        non_float_keys = [
            k for k, v in self.global_state_dict.items() if not v.is_floating_point()
        ]

        # 2. Compute client deltas and their global L2 norms
        client_deltas: List[Dict[str, torch.Tensor]] = []
        client_norms: List[float] = []

        for w_k in client_state_dicts:
            d_k = {}
            sum_sq = 0.0
            for k in float_keys:
                delta = w_k[k].to(torch.float32) - self.global_state_dict[k].to(torch.float32)
                d_k[k] = delta
                sum_sq += float(torch.sum(delta ** 2).item())
            norm_k = float(np.sqrt(sum_sq))
            client_deltas.append(d_k)
            client_norms.append(norm_k)

        # 3. Compute clipping threshold B = median of delta norms
        B = float(np.median(client_norms))
        self.last_bound_B = B

        # 4. Scale deltas and record clipping count
        clipped_count = 0
        scaled_deltas: List[Dict[str, torch.Tensor]] = []

        for d_k, norm_k in zip(client_deltas, client_norms):
            if norm_k > B and B > 0.0:
                scale = B / norm_k
                clipped_count += 1
            else:
                scale = 1.0

            s_k = {k: d_k[k] * scale for k in float_keys}
            scaled_deltas.append(s_k)

        self.last_clipped_count = clipped_count
        self.round_clipped_counts.append(clipped_count)
        self.round_num += 1

        # 5. Weighted average of clipped deltas + add to global model
        new_global_weights = copy.deepcopy(self.global_state_dict)

        # Initialize floating point accumulators with current global weights
        for k in float_keys:
            # sum_k (n_k / total_samples) * s_k[k]
            weighted_delta = torch.zeros_like(new_global_weights[k], dtype=torch.float32)
            for s_k, n_k in zip(scaled_deltas, client_sample_sizes):
                weight_factor = n_k / total_samples
                weighted_delta += weight_factor * s_k[k]
            new_global_weights[k] = self.global_state_dict[k].to(torch.float32) + weighted_delta

        # Non-floating buffers (e.g. BatchNorm num_batches_tracked) pass through unchanged
        for k in non_float_keys:
            new_global_weights[k] = copy.deepcopy(client_state_dicts[0][k])

        self.global_state_dict = new_global_weights
        return self.global_state_dict
