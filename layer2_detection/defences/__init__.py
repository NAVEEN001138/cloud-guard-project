"""
Layer 2 Federated Learning Defences Package.

Opt-in defences against adversarial attacks, statistical snooping,
and communication bottlenecks in IoT threat detection:
1. NormClipServer: Server-side update-norm clipping (Sun et al., 2019)
2. SecureAggregationServer / SecureAggregationClient: Pairwise masking (Bonawitz et al., 2017)
3. QuantizedServer / QuantizedClient: 8-bit uniform update quantisation
"""

from layer2_detection.defences.norm_clip import NormClipServer
from layer2_detection.defences.secure_aggregation import (
    SecureAggregationServer,
    SecureAggregationClient,
    simulate_secure_aggregation_round,
)
from layer2_detection.defences.quantize import (
    QuantizedServer,
    QuantizedClient,
    quantize_state_dict_delta,
    dequantize_state_dict_delta,
    calculate_quantized_payload_bytes,
)

__all__ = [
    "NormClipServer",
    "SecureAggregationServer",
    "SecureAggregationClient",
    "simulate_secure_aggregation_round",
    "QuantizedServer",
    "QuantizedClient",
    "quantize_state_dict_delta",
    "dequantize_state_dict_delta",
    "calculate_quantized_payload_bytes",
]
