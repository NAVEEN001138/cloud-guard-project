"""
=============================================================================
LAYER 2 DEFENCE: SIMULATED SECURE AGGREGATION VIA PAIRWISE MASKING
Module: secure_aggregation.py
-----------------------------------------------------------------------------
Problem Solved:
  Protects client parameter privacy against an honest-but-curious central server
  by ensuring the server only ever observes the sum of all client updates,
  never any individual client's model weights or gradients.

Algorithm:
  1. Key Agreement: Each client generates an ephemeral X25519 keypair.
     Every client pair (i, j) with i < j computes an ECDH shared secret,
     expanded via HKDF-SHA256 into a shared 256-bit PRG seed.
  2. Fixed-Point Encoding: Client k scales n_k * w_k (float tensors) by 2^20
     into 64-bit signed integers (int64), interpreted as uint64.
  3. Pairwise Zero-Sum Masking:
     - Client i (lower index) adds PRG_seed_ij mask to its vector (mod 2^64).
     - Client j (higher index) subtracts PRG_seed_ij mask from its vector (mod 2^64).
  4. Server Aggregation:
     - The server sums all received masked vectors modulo 2^64.
     - All pairwise masks cancel identically to zero.
     - The server decodes the accumulated int64 fixed-point vector and divides
       by total samples N = sum_k n_k.
     - Integer buffers (e.g., BatchNorm num_batches_tracked) pass through directly.
  5. Metrics Recorded:
     - Payload bytes per client message
     - Key agreement duration
     - Client masking duration
     - Server summation and decoding duration

Limitations & Assumptions:
  - No dropout recovery: All clients must participate in each round (any dropout
    prevents mask cancellation).
  - Honest-but-curious server: Protects against passive eavesdropping by the server,
    but does not protect against malicious client collusion.
  - Mutual exclusivity: Cannot be combined with coordinate-wise median or
    update-norm clipping, because those defences require inspecting individual
    unmasked client updates.

Reference:
  Bonawitz et al., "Practical Secure Aggregation for Privacy-Preserving
  Machine Learning", ACM CCS 2017. https://doi.org/10.1145/3133956.3133982
=============================================================================
"""

import time
import copy
import numpy as np
from typing import List, Dict, Tuple, Optional, Any

try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from layer2_detection.global_server.fedavg_server import GlobalFedAvgServer

FIXED_POINT_SCALE = 2 ** 20  # 1,048,576


class SecureAggregationClient:
    """Simulated secure aggregation client node using X25519 key exchange."""

    def __init__(self, client_id: int):
        self.client_id = client_id
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.public_bytes = self.public_key.public_bytes_raw()

    def derive_pair_seed(self, peer_id: int, peer_public_bytes: bytes) -> int:
        """Derives a deterministic 64-bit PRG seed with peer using ECDH and HKDF."""
        peer_pk = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = self.private_key.exchange(peer_pk)

        # Consistent pair info regardless of caller order
        low, high = min(self.client_id, peer_id), max(self.client_id, peer_id)
        info = f"SecAgg-Pair-{low}-{high}".encode("utf-8")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        )
        derived = hkdf.derive(shared_secret)
        # Use first 16 bytes as integer seed for PCG64
        return int.from_bytes(derived[:16], "big")

    def mask_weights(
        self,
        state_dict: Dict[str, Any],
        sample_size: int,
        pair_seeds: Dict[int, int],
    ) -> Tuple[Dict[str, np.ndarray], Dict[str, Any], int]:
        """
        Encodes n_k * w_k into fixed-point uint64 and applies zero-sum pairwise masks.

        Returns
        -------
        masked_tensors : dict
            Dict mapping float parameter names to masked uint64 numpy arrays.
        integer_buffers : dict
            Dict mapping non-float parameter names to raw buffer tensors.
        payload_bytes : int
            Total transmission payload size in bytes.
        """
        masked_tensors = {}
        integer_buffers = {}
        total_bytes = len(self.public_bytes)  # 32 bytes for public key

        for name, tensor in state_dict.items():
            if tensor.is_floating_point():
                flat_data = tensor.detach().cpu().numpy().astype(np.float64).flatten()
                scaled = np.round(sample_size * flat_data * FIXED_POINT_SCALE).astype(np.int64)
                uint_vec = scaled.view(np.uint64)

                # Apply pairwise masks with all other participating clients
                for peer_id, seed in pair_seeds.items():
                    rng = np.random.default_rng(np.random.PCG64(seed))
                    mask = rng.integers(0, 2**64, size=uint_vec.shape, dtype=np.uint64)
                    if self.client_id < peer_id:
                        uint_vec = uint_vec + mask  # Lower index adds
                    else:
                        uint_vec = uint_vec - mask  # Higher index subtracts

                masked_tensors[name] = uint_vec
                total_bytes += uint_vec.nbytes  # 8 bytes per element
            else:
                integer_buffers[name] = copy.deepcopy(tensor)
                total_bytes += tensor.element_size() * tensor.numel()

        return masked_tensors, integer_buffers, total_bytes


class SecureAggregationServer(GlobalFedAvgServer):
    """
    Secure Aggregation Server:
    Receives only pairwise-masked client vectors mod 2^64,
    sums them to cancel masks, decodes fixed-point arithmetic, and divides by N.
    """

    def __init__(self, global_state_dict: Optional[Dict] = None):
        super().__init__(global_state_dict)
        self.round_num = 0
        self.last_overhead: Dict[str, float] = {}

    def aggregate_masked_updates(
        self,
        masked_client_payloads: List[Tuple[Dict[str, np.ndarray], Dict[str, Any]]],
        client_sample_sizes: List[int],
    ) -> Dict[str, torch.Tensor]:
        """
        Sums incoming masked vectors mod 2^64, decodes, and updates global model.
        """
        if not masked_client_payloads or not HAS_TORCH:
            return self.global_state_dict

        total_samples = sum(client_sample_sizes)
        if total_samples == 0:
            return self.global_state_dict

        t0_server = time.time()
        new_global_weights = copy.deepcopy(self.global_state_dict)

        sample_masked_tensors, sample_int_buffers = masked_client_payloads[0]

        # 1. Sum floating-point parameters mod 2^64
        for name in sample_masked_tensors.keys():
            shape = self.global_state_dict[name].shape
            acc = np.zeros_like(sample_masked_tensors[name], dtype=np.uint64)

            for masked_tensors, _ in masked_client_payloads:
                acc = acc + masked_tensors[name]

            # Decode fixed-point int64: sum_k (n_k * w_k)
            acc_int64 = acc.view(np.int64)
            unscaled = acc_int64.astype(np.float64) / FIXED_POINT_SCALE
            averaged = unscaled / total_samples

            new_global_weights[name] = torch.tensor(
                averaged.reshape(shape), dtype=torch.float32
            )

        # 2. Integer buffers (BatchNorm counters) pass through from clients
        for name in sample_int_buffers.keys():
            new_global_weights[name] = copy.deepcopy(sample_int_buffers[name])

        self.last_overhead["server_time_sec"] = time.time() - t0_server
        self.global_state_dict = new_global_weights
        self.round_num += 1
        return self.global_state_dict


def simulate_secure_aggregation_round(
    client_state_dicts: List[Dict],
    client_sample_sizes: List[int],
    global_state_dict: Dict,
) -> Tuple[Dict, Dict[str, Any]]:
    """
    Executes a complete simulated round of Secure Aggregation:
    1. Key generation & agreement (X25519 + HKDF-SHA256)
    2. Client-side fixed-point encoding & pairwise zero-sum masking
    3. Server-side accumulation mod 2^64 and decoding
    4. Measurement of payload bytes, agreement time, masking time, and server time.
    """
    K = len(client_state_dicts)
    server = SecureAggregationServer(global_state_dict)

    # Step 1: Client key generation
    t0_keys = time.time()
    clients = [SecureAggregationClient(cid) for cid in range(K)]

    # Step 2: Key agreement (derive pairwise PRG seeds)
    client_seeds: List[Dict[int, int]] = [{} for _ in range(K)]
    for i in range(K):
        for j in range(i + 1, K):
            seed_i = clients[i].derive_pair_seed(j, clients[j].public_bytes)
            seed_j = clients[j].derive_pair_seed(i, clients[i].public_bytes)
            assert seed_i == seed_j, "ECDH derived seeds must match"
            client_seeds[i][j] = seed_i
            client_seeds[j][i] = seed_j
    key_agreement_time = time.time() - t0_keys

    # Step 3: Client masking
    t0_mask = time.time()
    payloads = []
    message_bytes_list = []
    for cid in range(K):
        masked_tensors, int_buffers, msg_bytes = clients[cid].mask_weights(
            state_dict=client_state_dicts[cid],
            sample_size=client_sample_sizes[cid],
            pair_seeds=client_seeds[cid],
        )
        payloads.append((masked_tensors, int_buffers))
        message_bytes_list.append(msg_bytes)
    client_masking_time = time.time() - t0_mask

    # Step 4: Server aggregation
    t0_server = time.time()
    aggregated_weights = server.aggregate_masked_updates(payloads, client_sample_sizes)
    server_time = time.time() - t0_server

    metrics = {
        "key_agreement_time_sec": key_agreement_time,
        "client_masking_time_sec": client_masking_time,
        "server_time_sec": server_time,
        "bytes_per_client_message": int(np.mean(message_bytes_list)),
        "total_round_bytes_uploaded": int(sum(message_bytes_list)),
    }
    return aggregated_weights, metrics
