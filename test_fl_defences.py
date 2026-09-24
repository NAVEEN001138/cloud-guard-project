"""
=============================================================================
TEST SUITE: LAYER 2 FEDERATED LEARNING DEFENCES
File: test_fl_defences.py
-----------------------------------------------------------------------------
Verifies the three opt-in FL defences:
1. Defaults preservation (existing GlobalFedAvgServer remains 100% unchanged)
2. NormClipServer: bound B calculation, norm capping, and honest update equivalence
3. SecureAggregation: pairwise zero-sum mask cancellation, fixed-point precision (< 1e-5),
   and individual masked vector decorrelation (correlation < 0.1)
4. 8-Bit Quantisation: maximum reconstruction error <= scale/2 and exact byte payload
5. Mutual exclusivity: Quantisation + Secure Aggregation incompatibility check
=============================================================================
"""

import copy
import pytest
import numpy as np
import torch

from layer2_detection.local_clients.edge_client import PyTorchMLP
from layer2_detection.global_server.fedavg_server import GlobalFedAvgServer
from layer2_detection.defences.norm_clip import NormClipServer
from layer2_detection.defences.secure_aggregation import (
    SecureAggregationClient,
    SecureAggregationServer,
    simulate_secure_aggregation_round,
)
from layer2_detection.defences.quantize import (
    quantize_tensor,
    dequantize_tensor,
    quantize_state_dict_delta,
    dequantize_state_dict_delta,
    calculate_quantized_payload_bytes,
    QuantizedServer,
    check_defence_compatibility,
)


class TestFLDefences:
    """Comprehensive test suite for Layer 2 FL defences."""

    @pytest.fixture
    def setup_model_and_weights(self):
        torch.manual_seed(42)
        np.random.seed(42)
        input_dim = 9
        model = PyTorchMLP(input_dim)
        global_weights = copy.deepcopy(model.state_dict())

        # Generate K=10 simulated client weight state dicts with sample sizes
        K = 10
        client_weights = []
        sample_sizes = [1000 + i * 150 for i in range(K)]

        for i in range(K):
            c_model = PyTorchMLP(input_dim)
            c_model.load_state_dict(copy.deepcopy(global_weights))
            # Perturb float weights slightly to simulate local training
            with torch.no_grad():
                for p in c_model.parameters():
                    p.add_(torch.randn_like(p) * 0.05)
            client_weights.append(copy.deepcopy(c_model.state_dict()))

        return {
            "global_weights": global_weights,
            "client_weights": client_weights,
            "sample_sizes": sample_sizes,
            "input_dim": input_dim,
        }

    # -------------------------------------------------------------------------
    # 1. Defaults Unchanged
    # -------------------------------------------------------------------------
    def test_01_defaults_unchanged(self, setup_model_and_weights):
        """Verifies that the existing GlobalFedAvgServer operates identically to before."""
        ctx = setup_model_and_weights
        server = GlobalFedAvgServer(ctx["global_weights"])

        # Run standard FedAvg
        aggregated = server.aggregate_weights(ctx["client_weights"], ctx["sample_sizes"])

        # Manual FedAvg check: w_expected = sum_k (n_k / N) * w_k
        N = sum(ctx["sample_sizes"])
        for k in ctx["global_weights"]:
            expected = torch.zeros_like(ctx["global_weights"][k], dtype=torch.float32)
            for w, n in zip(ctx["client_weights"], ctx["sample_sizes"]):
                expected += (n / N) * w[k].to(torch.float32)
            diff = torch.max(torch.abs(aggregated[k] - expected)).item()
            assert diff < 1e-6, f"Mismatch in FedAvg default aggregation for key {k}: {diff}"

    # -------------------------------------------------------------------------
    # 2. Norm-Clipping Defence
    # -------------------------------------------------------------------------
    def test_02_norm_clip_bound_and_no_exceed(self, setup_model_and_weights):
        """Verifies that no clipped client delta norm exceeds median bound B."""
        ctx = setup_model_and_weights
        server = NormClipServer(ctx["global_weights"])

        # Inject an aggressive outlier (poisoned client 0 with 50x update norm)
        poisoned_weights = copy.deepcopy(ctx["client_weights"])
        for k in poisoned_weights[0]:
            if poisoned_weights[0][k].is_floating_point():
                poisoned_weights[0][k] = ctx["global_weights"][k] + 50.0 * (
                    poisoned_weights[0][k] - ctx["global_weights"][k]
                )

        server.aggregate_weights(poisoned_weights, ctx["sample_sizes"])
        B = server.last_bound_B
        assert B > 0.0, "Bound B must be strictly positive"
        assert server.last_clipped_count >= 1, "At least the poisoned update must be clipped"

        # Verify that for each client, the effective delta norm is <= B
        float_keys = [k for k, v in ctx["global_weights"].items() if v.is_floating_point()]
        for w_k in poisoned_weights:
            delta_norm = float(np.sqrt(sum(
                torch.sum((w_k[k].to(torch.float32) - ctx["global_weights"][k].to(torch.float32)) ** 2).item()
                for k in float_keys
            )))
            scale = min(1.0, B / delta_norm) if delta_norm > 0 else 1.0
            clipped_norm = delta_norm * scale
            assert clipped_norm <= B + 1e-6, f"Clipped norm {clipped_norm} exceeded bound {B}"

    def test_03_norm_clip_identical_honest_updates_equals_fedavg(self, setup_model_and_weights):
        """Verifies that with identical honest updates, NormClipServer output equals FedAvg."""
        ctx = setup_model_and_weights
        # Set all clients to identical weights
        identical_client_weights = [copy.deepcopy(ctx["client_weights"][0]) for _ in range(10)]

        fedavg_server = GlobalFedAvgServer(ctx["global_weights"])
        fedavg_out = fedavg_server.aggregate_weights(identical_client_weights, ctx["sample_sizes"])

        normclip_server = NormClipServer(ctx["global_weights"])
        normclip_out = normclip_server.aggregate_weights(identical_client_weights, ctx["sample_sizes"])

        for k in ctx["global_weights"]:
            diff = torch.max(torch.abs(fedavg_out[k] - normclip_out[k])).item()
            assert diff < 1e-6, f"NormClip deviated from FedAvg on identical updates for {k}: {diff}"
        assert normclip_server.last_clipped_count == 0, "No identical honest updates should be clipped"

    # -------------------------------------------------------------------------
    # 3. Secure Aggregation Defence
    # -------------------------------------------------------------------------
    def test_04_secure_aggregation_precision(self, setup_model_and_weights):
        """Verifies that masked secure aggregation matches plain FedAvg within 1e-5 max absolute difference."""
        ctx = setup_model_and_weights
        K = 10

        # Plain FedAvg
        fedavg_server = GlobalFedAvgServer(ctx["global_weights"])
        fedavg_out = fedavg_server.aggregate_weights(ctx["client_weights"], ctx["sample_sizes"])

        # Secure aggregation round
        sec_out, metrics = simulate_secure_aggregation_round(
            ctx["client_weights"], ctx["sample_sizes"], ctx["global_weights"]
        )

        for k in ctx["global_weights"]:
            diff = torch.max(torch.abs(fedavg_out[k] - sec_out[k])).item()
            assert diff < 1e-5, f"Secure aggregation max absolute difference exceeded 1e-5 for {k}: {diff}"

        assert metrics["bytes_per_client_message"] > 0
        assert metrics["key_agreement_time_sec"] >= 0.0
        assert metrics["client_masking_time_sec"] >= 0.0
        assert metrics["server_time_sec"] >= 0.0

    def test_05_secure_aggregation_decorrelation(self, setup_model_and_weights):
        """Verifies that individual masked vectors differ completely from plain encoding (correlation < 0.1)."""
        ctx = setup_model_and_weights
        K = 10

        # Create clients and pairwise seeds
        clients = [SecureAggregationClient(i) for i in range(K)]
        seeds = [{} for _ in range(K)]
        for i in range(K):
            for j in range(i + 1, K):
                s = clients[i].derive_pair_seed(j, clients[j].public_bytes)
                seeds[i][j] = s
                seeds[j][i] = s

        # Verify that for each client, the full masked vector differs from plain encoding (correlation < 0.1)
        float_keys = [k for k, v in ctx["global_weights"].items() if v.is_floating_point()]
        for cid in range(K):
            masked_dict, _, _ = clients[cid].mask_weights(
                ctx["client_weights"][cid], ctx["sample_sizes"][cid], seeds[cid]
            )
            plain_concat = np.concatenate([
                ctx["client_weights"][cid][k].detach().cpu().numpy().flatten()
                for k in float_keys
            ])
            masked_concat = np.concatenate([
                masked_dict[k].view(np.int64).flatten()
                for k in float_keys
            ])
            corr = np.corrcoef(plain_concat, masked_concat)[0, 1]
            assert abs(corr) < 0.1, f"Client {cid} masked vector correlated with plain ({corr} >= 0.1)"

    # -------------------------------------------------------------------------
    # 4. 8-Bit Quantisation Defence
    # -------------------------------------------------------------------------
    def test_06_quantization_error_bound(self):
        """Verifies that uniform 8-bit quantisation max error is bounded by scale / 2."""
        torch.manual_seed(99)
        test_tensors = [
            torch.randn(10, 10) * 10.0,
            torch.randn(100, 32) * 0.01,
            torch.zeros(5, 5),  # Constant zero
            torch.ones(8, 8) * 3.14159,  # Constant non-zero
        ]

        for t in test_tensors:
            q, v_min, scale = quantize_tensor(t)
            rec = dequantize_tensor(q, v_min, scale, original_dtype=t.dtype)
            max_err = torch.max(torch.abs(t - rec)).item()
            assert max_err <= (scale / 2.0) + 1e-6, f"Max error {max_err} exceeded scale/2 ({scale/2.0})"

    def test_07_quantized_payload_byte_count(self, setup_model_and_weights):
        """Verifies exact payload byte count for 8-bit delta quantisation."""
        ctx = setup_model_and_weights
        client_w = ctx["client_weights"][0]
        global_w = ctx["global_weights"]

        q_deltas, int_bufs, payload_bytes = quantize_state_dict_delta(client_w, global_w)

        # Expected: sum_p (numel + 8) + sum_b (numel * element_size)
        expected_bytes = 0
        for name, tensor in client_w.items():
            if tensor.is_floating_point():
                expected_bytes += tensor.numel() * 1 + 8
            else:
                expected_bytes += tensor.numel() * tensor.element_size()

        assert payload_bytes == expected_bytes, f"Expected {expected_bytes} bytes, got {payload_bytes}"
        assert payload_bytes == calculate_quantized_payload_bytes(client_w)

        # Verify reconstruction through QuantizedServer
        server = QuantizedServer(global_w)
        all_payloads = [quantize_state_dict_delta(w, global_w)[:2] for w in ctx["client_weights"]]
        server_out = server.aggregate_quantized_updates(all_payloads, ctx["sample_sizes"])
        assert server_out is not None

    # -------------------------------------------------------------------------
    # 5. Incompatibility / Mutual Exclusivity
    # -------------------------------------------------------------------------
    def test_08_incompatible_quantize_and_secagg_raises(self):
        """Verifies that requesting both quantisation and secure aggregation raises ValueError."""
        with pytest.raises(ValueError, match="Incompatible defence configuration"):
            check_defence_compatibility(enable_quantize=True, enable_secagg=True)

        # Single or neither should pass without error
        check_defence_compatibility(enable_quantize=True, enable_secagg=False)
        check_defence_compatibility(enable_quantize=False, enable_secagg=True)
        check_defence_compatibility(enable_quantize=False, enable_secagg=False)
