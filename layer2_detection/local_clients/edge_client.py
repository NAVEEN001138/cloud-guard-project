"""
=============================================================================
LAYER 2: LOCAL IOT EDGE CLIENTS
Module: edge_client.py
-----------------------------------------------------------------------------
Problem Solved:
  Implements localized PyTorch neural network model training (MLP and 1D-CNN)
  on isolated IoT Edge devices (Smart Factory, Smart Grid, Medical IoT).
  Ensures raw telemetry data NEVER leaves the local edge node.

Inputs:  Local Non-IID telemetry data shard (X_local, y_local), global model weights.
Outputs: Updated local neural network model state dict (weights & biases).
=============================================================================
"""

import copy
import numpy as np
from typing import Dict, Tuple

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


if HAS_TORCH:
    class PyTorchMLP(nn.Module):
        """Edge Node Multi-Layer Perceptron (MLP) Model"""
        def __init__(self, input_dim: int, hidden_dim: int = 64):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(input_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(hidden_dim, 32),
                nn.BatchNorm1d(32),
                nn.ReLU(),
                nn.Dropout(0.1),
                nn.Linear(32, 2)
            )

        def forward(self, x):
            return self.net(x)

    class PyTorch1DCNN(nn.Module):
        """Edge Node 1D Convolutional Neural Network Model"""
        def __init__(self, input_dim: int):
            super().__init__()
            self.conv1 = nn.Conv1d(1, 16, kernel_size=3, padding=1)
            self.relu = nn.ReLU()
            self.pool = nn.MaxPool1d(2)
            self.conv2 = nn.Conv1d(16, 32, kernel_size=3, padding=1)
            self.fc1 = nn.Linear(32 * (input_dim // 2), 32)
            self.fc2 = nn.Linear(32, 2)

        def forward(self, x):
            x = x.unsqueeze(1)
            x = self.pool(self.relu(self.conv1(x)))
            x = self.relu(self.conv2(x))
            x = x.view(x.size(0), -1)
            x = self.relu(self.fc1(x))
            return self.fc2(x)
else:
    class PyTorchMLP:
        """Fallback Edge Node MLP Model when PyTorch is missing"""
        def __init__(self, input_dim: int = 10, hidden_dim: int = 64):
            self.input_dim = input_dim
        def state_dict(self):
            return {}
        def load_state_dict(self, state_dict):
            pass

    class PyTorch1DCNN:
        """Fallback Edge Node 1D-CNN Model when PyTorch is missing"""
        def __init__(self, input_dim: int = 10):
            self.input_dim = input_dim
        def state_dict(self):
            return {}
        def load_state_dict(self, state_dict):
            pass



class IoTEdgeNodeClient:
    """Represents an isolated IoT Edge Node running local model training."""
    def __init__(self, client_id: int, X_local: np.ndarray, y_local: np.ndarray, name: str = "Edge Node"):
        self.client_id = client_id
        self.name = name
        self.X_local = X_local
        self.y_local = y_local
        self.sample_count = len(y_local)

    def train_local_epoch(self, global_state_dict: dict, epochs: int = 2, lr: float = 0.01) -> Tuple[dict, float]:
        """Trains local neural network on locked local data; returns updated weights."""
        if not HAS_TORCH or self.sample_count == 0:
            return global_state_dict, 0.0

        input_dim = self.X_local.shape[1]
        local_model = PyTorchMLP(input_dim)
        local_model.load_state_dict(copy.deepcopy(global_state_dict))
        local_model.train()

        optimizer = optim.Adam(local_model.parameters(), lr=lr)

        # Class-weighted loss to prevent majority-class bias on imbalanced IoT shards
        n_0 = max(1, int(np.sum(self.y_local == 0)))
        n_1 = max(1, int(np.sum(self.y_local == 1)))
        w0 = len(self.y_local) / (2.0 * n_0)
        w1 = len(self.y_local) / (2.0 * n_1)
        class_weights = torch.tensor([w0, w1], dtype=torch.float32)
        criterion = nn.CrossEntropyLoss(weight=class_weights)

        dataset = TensorDataset(
            torch.tensor(self.X_local, dtype=torch.float32),
            torch.tensor(self.y_local, dtype=torch.long)
        )
        loader = DataLoader(dataset, batch_size=32, shuffle=True)

        total_loss = 0.0
        batches = 0
        for _ in range(epochs):
            for bx, by in loader:
                optimizer.zero_grad()
                out = local_model(bx)
                loss = criterion(out, by)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
                batches += 1

        avg_loss = total_loss / max(1, batches)
        return copy.deepcopy(local_model.state_dict()), avg_loss

    def train_local_epoch_prox(
        self,
        global_state_dict: dict,
        epochs: int = 2,
        lr: float = 0.01,
        mu: float = 0.01,
    ) -> Tuple[dict, float]:
        """
        FedProx local training — adds proximal term μ/2·‖w − w_global‖² to loss.

        The proximal term prevents the local model from drifting too far from
        the global model, which is especially important on non-IID IoT shards
        where some nodes see only DDoS traffic and others only sensor anomalies.

        Parameters
        ----------
        global_state_dict : dict  Global weights received from server (w_global)
        epochs            : int   Local training epochs
        lr                : float Local learning rate
        mu                : float Proximal strength (0 → same as FedAvg, >0 → regularised)
        """
        if not HAS_TORCH or self.sample_count == 0:
            return global_state_dict, 0.0

        input_dim = self.X_local.shape[1]
        local_model = PyTorchMLP(input_dim)
        local_model.load_state_dict(copy.deepcopy(global_state_dict))
        local_model.train()

        # Keep a frozen copy of the global weights for the proximal term
        global_model_ref = PyTorchMLP(input_dim)
        global_model_ref.load_state_dict(copy.deepcopy(global_state_dict))
        global_model_ref.eval()
        for p in global_model_ref.parameters():
            p.requires_grad_(False)

        optimizer = optim.Adam(local_model.parameters(), lr=lr)

        # Class-weighted loss to prevent majority-class bias on imbalanced IoT shards
        n_0 = max(1, int(np.sum(self.y_local == 0)))
        n_1 = max(1, int(np.sum(self.y_local == 1)))
        w0 = len(self.y_local) / (2.0 * n_0)
        w1 = len(self.y_local) / (2.0 * n_1)
        class_weights = torch.tensor([w0, w1], dtype=torch.float32)
        criterion = nn.CrossEntropyLoss(weight=class_weights)

        dataset = TensorDataset(
            torch.tensor(self.X_local, dtype=torch.float32),
            torch.tensor(self.y_local, dtype=torch.long),
        )
        loader = DataLoader(dataset, batch_size=32, shuffle=True)

        total_loss = 0.0
        batches = 0
        for _ in range(epochs):
            for bx, by in loader:
                optimizer.zero_grad()
                out  = local_model(bx)
                loss = criterion(out, by)

                # Proximal regularisation: μ/2 · Σ_j ‖w_j − w_global_j‖²
                prox_loss = torch.tensor(0.0)
                for w_local, w_global in zip(
                    local_model.parameters(), global_model_ref.parameters()
                ):
                    prox_loss = prox_loss + torch.norm(w_local - w_global) ** 2
                loss = loss + (mu / 2.0) * prox_loss

                loss.backward()
                optimizer.step()
                total_loss += loss.item()
                batches += 1

        avg_loss = total_loss / max(1, batches)
        return copy.deepcopy(local_model.state_dict()), avg_loss

    def train_local_epoch_with_step_count(
        self,
        global_state_dict: dict,
        epochs: int = 2,
        lr: float = 0.01,
    ) -> Tuple[dict, dict, int, float]:
        """
        FedNova local training — returns (final_weights, initial_weights, steps_taken, avg_loss).
        The caller (FedNova training loop) uses initial_weights and steps_taken
        to compute the normalised update: (w_init − w_final) / steps_taken.
        """
        if not HAS_TORCH or self.sample_count == 0:
            return global_state_dict, global_state_dict, 1, 0.0

        input_dim = self.X_local.shape[1]
        local_model = PyTorchMLP(input_dim)
        initial_state = copy.deepcopy(global_state_dict)
        local_model.load_state_dict(initial_state)
        local_model.train()

        optimizer = optim.SGD(local_model.parameters(), lr=lr)  # SGD for step counting
        criterion = nn.CrossEntropyLoss()

        dataset = TensorDataset(
            torch.tensor(self.X_local, dtype=torch.float32),
            torch.tensor(self.y_local, dtype=torch.long),
        )
        loader = DataLoader(dataset, batch_size=32, shuffle=True)

        total_loss = 0.0
        steps = 0
        for _ in range(epochs):
            for bx, by in loader:
                optimizer.zero_grad()
                out = local_model(bx)
                loss = criterion(out, by)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
                steps += 1

        avg_loss = total_loss / max(1, steps)
        return copy.deepcopy(local_model.state_dict()), initial_state, steps, avg_loss
