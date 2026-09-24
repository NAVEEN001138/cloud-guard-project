"""
=============================================================================
LAYER 2 DEFENCE: COMMUNICATION REDUCTION VIA 8-BIT UPDATE QUANTISATION
Module: quantize.py
-----------------------------------------------------------------------------
Problem Solved:
  Mitigates uplink bandwidth bottlenecks in constrained IoT Edge networks
  (cellular, satellite, LPWAN) by compressing client model update deltas
  from 32-bit floats to 8-bit uniform integers.

Algorithm:
  For each client k:
    1. Compute update delta: d_k = w_k - w_global (floating-point tensors).
    2. Per-tensor min/max uniform 8-bit quantisation:
         scale = (v_max - v_min) / 255.0
         q = round((d_k - v_min) / scale), clamped to [0, 255] as uint8.
    3. Transmission payload:
         uint8 data (1 byte/param) + float32 v_min (4 bytes) + float32 scale (4 bytes).
         Non-floating buffers pass through unquantised.
    4. Server reconstruction:
         d_k_rec = v_min + q * scale
         w_k_rec = w_global + d_k_rec
    5. Aggregation via standard sample-weighted FedAvg.

Guarantees & Limits:
  - Theoretical reconstruction error bound: max |d - d_rec| <= scale / 2 per tensor.
  - Incompatibility: Quantisation cannot be combined with secure aggregation,
    because pairwise masking operates on exact fixed-point integers across all clients.
    Requesting both raises an explicit ValueError.
=============================================================================
"""

import copy
from typing import Dict, List, Tuple, Optional, Any

try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

from layer2_detection.global_server.fedavg_server import GlobalFedAvgServer


def check_defence_compatibility(enable_quantize: bool, enable_secagg: bool) -> None:
    """Raises ValueError if mutually incompatible defences are requested."""
    if enable_quantize and enable_secagg:
        raise ValueError(
            "Incompatible defence configuration: 8-bit quantisation cannot be combined "
            "with secure aggregation because pairwise masking requires exact fixed-point "
            "arithmetic over unquantised updates."
        )


def quantize_tensor(tensor: "torch.Tensor") -> Tuple["torch.Tensor", float, float]:
    """
    Applies uniform min/max 8-bit quantisation to a floating-point PyTorch tensor.

    Returns
    -------
    quantized_uint8 : torch.Tensor
        Byte tensor with values in [0, 255].
    v_min : float
        Original minimum value (float32).
    scale : float
        Quantisation step size (float32).
    """
    if not tensor.is_floating_point():
        raise TypeError("Quantisation can only be applied to floating-point tensors.")

    t_float = tensor.detach().to(torch.float32)
    v_min = float(t_float.min().item())
    v_max = float(t_float.max().item())

    val_range = v_max - v_min
    if val_range < 1e-12:
        # Constant tensor: all zeros, scale 0.0
        q = torch.zeros_like(t_float, dtype=torch.uint8)
        return q, v_min, 0.0

    scale = val_range / 255.0
    q = torch.clamp(torch.round((t_float - v_min) / scale), 0, 255).to(torch.uint8)
    return q, v_min, scale


def dequantize_tensor(
    quantized_uint8: "torch.Tensor", v_min: float, scale: float, original_dtype=torch.float32
) -> "torch.Tensor":
    """Reconstructs floating-point tensor from uint8 values, min, and scale."""
    if scale == 0.0:
        return torch.full_like(quantized_uint8, fill_value=v_min, dtype=original_dtype)
    return (v_min + quantized_uint8.to(torch.float32) * scale).to(original_dtype)


def quantize_state_dict_delta(
    client_state_dict: Dict[str, Any], global_state_dict: Dict[str, Any]
) -> Tuple[Dict[str, Tuple["torch.Tensor", float, float]], Dict[str, Any], int]:
    """
    Computes delta d = w_k - w_global and quantises float tensors to uint8.

    Returns
    -------
    quantized_deltas : dict
        name -> (uint8_tensor, v_min, scale)
    integer_buffers : dict
        name -> unquantised buffer tensor
    exact_payload_bytes : int
        Exact payload byte count.
    """
    quantized_deltas = {}
    integer_buffers = {}
    total_bytes = 0

    for name, client_val in client_state_dict.items():
        global_val = global_state_dict[name]
        if client_val.is_floating_point():
            delta = client_val.to(torch.float32) - global_val.to(torch.float32)
            q, v_min, scale = quantize_tensor(delta)
            quantized_deltas[name] = (q, v_min, scale)
            # uint8 values (1 byte each) + float32 v_min (4 bytes) + float32 scale (4 bytes)
            total_bytes += q.numel() * 1 + 8
        else:
            integer_buffers[name] = copy.deepcopy(client_val)
            total_bytes += client_val.element_size() * client_val.numel()

    return quantized_deltas, integer_buffers, total_bytes


def dequantize_state_dict_delta(
    quantized_deltas: Dict[str, Tuple["torch.Tensor", float, float]],
    integer_buffers: Dict[str, Any],
    global_state_dict: Dict[str, Any],
) -> Dict[str, Any]:
    """Reconstructs client state dict: w_k = w_global + dequantize(delta)."""
    reconstructed = copy.deepcopy(global_state_dict)

    for name, (q, v_min, scale) in quantized_deltas.items():
        delta_rec = dequantize_tensor(q, v_min, scale, original_dtype=global_state_dict[name].dtype)
        reconstructed[name] = global_state_dict[name].to(torch.float32) + delta_rec

    for name, buf in integer_buffers.items():
        reconstructed[name] = copy.deepcopy(buf)

    return reconstructed


def calculate_quantized_payload_bytes(state_dict: Dict[str, Any]) -> int:
    """Calculates exact transmission byte count for a state dict under 8-bit delta quantisation."""
    total_bytes = 0
    for name, tensor in state_dict.items():
        if tensor.is_floating_point():
            total_bytes += tensor.numel() * 1 + 8  # 1 byte per element + 8 bytes min/scale
        else:
            total_bytes += tensor.element_size() * tensor.numel()
    return total_bytes


class QuantizedClient:
    """Client helper for compressing model updates before transmission."""

    def __init__(self, client_id: int):
        self.client_id = client_id

    def compress_update(
        self, local_weights: Dict[str, Any], global_weights: Dict[str, Any]
    ) -> Tuple[Dict[str, Tuple["torch.Tensor", float, float]], Dict[str, Any], int]:
        return quantize_state_dict_delta(local_weights, global_weights)


class QuantizedServer(GlobalFedAvgServer):
    """
    Central server that receives 8-bit quantised client deltas,
    reconstructs client weights w_k = w_global + dequantize(d_k),
    and executes sample-weighted FedAvg aggregation.
    """

    def __init__(self, global_state_dict: Optional[Dict] = None):
        super().__init__(global_state_dict)
        self.round_num = 0
        self.last_payload_bytes = 0

    def aggregate_quantized_updates(
        self,
        quantized_payloads: List[Tuple[Dict[str, Tuple["torch.Tensor", float, float]], Dict[str, Any]]],
        client_sample_sizes: List[int],
    ) -> Dict[str, "torch.Tensor"]:
        """Reconstructs client models from quantised payloads and aggregates with FedAvg."""
        if not quantized_payloads or not HAS_TORCH:
            return self.global_state_dict

        reconstructed_clients = [
            dequantize_state_dict_delta(q_deltas, int_bufs, self.global_state_dict)
            for q_deltas, int_bufs in quantized_payloads
        ]

        self.global_state_dict = super().aggregate_weights(
            reconstructed_clients, client_sample_sizes
        )
        self.round_num += 1
        return self.global_state_dict
