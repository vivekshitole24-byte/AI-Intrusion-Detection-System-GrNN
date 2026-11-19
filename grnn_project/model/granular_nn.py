"""
Granular Neural Network (GrNN) for Network Intrusion Detection
=============================================================
Architecture:
  - Micro-Granule Subnet  : Packet-level feature processor (flags, sizes, headers)
  - Meso-Granule Subnet   : Flow/session-level feature processor (rates, volumes)
  - Macro-Granule Subnet  : Temporal/IAT-level feature processor (timing patterns)
  - Cross-Granule Fusion  : Attention-based dynamic weighting of the 3 subnets
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


# ─────────────────────────────────────────────────────────────────────────────
# Feature split indices (from the 78 dataset features, excluding Label)
# ─────────────────────────────────────────────────────────────────────────────
MICRO_FEATURES = [
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Header Length.1',
    'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
]  # 31 features — what each packet LOOKS LIKE

MESO_FEATURES = [
    'Destination Port', 'Flow Duration',
    'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Flow Bytes/s', 'Flow Packets/s',
    'Fwd Packets/s', 'Bwd Packets/s',
    'Down/Up Ratio',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes',
    'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
]  # 25 features — how the FLOW behaves

MACRO_FEATURES = [
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
]  # 22 features — TEMPORAL TIMING patterns

MICRO_DIM = len(MICRO_FEATURES)   # 31
MESO_DIM  = len(MESO_FEATURES)    # 25
MACRO_DIM = len(MACRO_FEATURES)   # 22
NUM_CLASSES = 6   # BENIGN, DDoS, PortScan, BruteForce, Botnet, DoS


# ─────────────────────────────────────────────────────────────────────────────
# Individual Granule Subnets
# ─────────────────────────────────────────────────────────────────────────────

class MicroGranuleNet(nn.Module):
    """
    Processes packet-level features (flags, lengths, header byte patterns).
    Catches: DDoS floods, SYN floods, SQL Injection, buffer overflows.
    Uses narrow but deep layers — precise, fast detection.
    """
    def __init__(self, input_dim=MICRO_DIM, embed_dim=64):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 96),
            nn.ReLU(),
            nn.Linear(96, embed_dim),
            nn.ReLU(),
        )

    def forward(self, x):
        return self.net(x)


class MesoGranuleNet(nn.Module):
    """
    Processes flow/session-level features (rates, volumes, ratios, window sizes).
    Catches: Port scans, fast brute force, session hijacking.
    Uses medium-width layers — balances detail and context.
    """
    def __init__(self, input_dim=MESO_DIM, embed_dim=64):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 96),
            nn.BatchNorm1d(96),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(96, 80),
            nn.ReLU(),
            nn.Linear(80, embed_dim),
            nn.ReLU(),
        )

    def forward(self, x):
        return self.net(x)


class MacroGranuleNet(nn.Module):
    """
    Processes temporal/IAT features (inter-arrival timings, active/idle periods).
    Catches: Low-and-slow APTs, C2 beaconing, stealthy lateral movement.
    Uses residual connections — preserves subtle long-range temporal signals.
    """
    def __init__(self, input_dim=MACRO_DIM, embed_dim=64):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, 80)
        self.bn1 = nn.BatchNorm1d(80)
        self.fc2 = nn.Linear(80, 64)
        self.fc3 = nn.Linear(64, embed_dim)
        self.skip = nn.Linear(input_dim, embed_dim)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.2)

    def forward(self, x):
        residual = self.skip(x)
        out = self.relu(self.bn1(self.fc1(x)))
        out = self.dropout(out)
        out = self.relu(self.fc2(out))
        out = self.fc3(out)
        return self.relu(out + residual)


# ─────────────────────────────────────────────────────────────────────────────
# Cross-Granule Attention Fusion
# ─────────────────────────────────────────────────────────────────────────────

class GranularFusionLayer(nn.Module):
    """
    Dynamically weights which granule (micro/meso/macro) detected the threat.
    Uses a learned attention gate: alpha1, alpha2, alpha3 sum to 1.
    The output alpha values tell you WHICH level caught the attack.
    """
    def __init__(self, embed_dim=64):
        super().__init__()
        # Attention gate: takes concatenated granule embeddings → 3 weights
        self.attention_gate = nn.Sequential(
            nn.Linear(embed_dim * 3, 48),
            nn.ReLU(),
            nn.Linear(48, 3),
            nn.Softmax(dim=-1)  # outputs [alpha_micro, alpha_meso, alpha_macro]
        )
        self.fusion_proj = nn.Sequential(
            nn.Linear(embed_dim * 3, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
        )

    def forward(self, g_micro, g_meso, g_macro):
        concat = torch.cat([g_micro, g_meso, g_macro], dim=-1)  # [B, 192]
        alphas = self.attention_gate(concat)                      # [B, 3]

        # Weighted sum of granule embeddings
        alpha_m = alphas[:, 0:1]
        alpha_s = alphas[:, 1:2]
        alpha_c = alphas[:, 2:3]
        fused = alpha_m * g_micro + alpha_s * g_meso + alpha_c * g_macro  # [B, 64]

        # Also process the raw concat for richer features
        proj = self.fusion_proj(concat)  # [B, 128]
        final = torch.cat([fused, proj], dim=-1)  # [B, 192]
        return final, alphas


# ─────────────────────────────────────────────────────────────────────────────
# Full GrNN Model
# ─────────────────────────────────────────────────────────────────────────────

class GrNN(nn.Module):
    """
    Granular Neural Network — Full 3-Scale Intrusion Detection Model.

    Input: 3 separate feature vectors (micro, meso, macro)
    Output: (class_probabilities, granule_attention_weights)

    The attention weights tell you which granule caught the attack:
      - High alpha_micro → Fast packet-level attack (DDoS, SQLi)
      - High alpha_meso  → Flow-level attack (Port Scan, Brute Force)
      - High alpha_macro → Temporal stealthy attack (APT, C2 Beacon)
    """
    def __init__(self, num_classes=NUM_CLASSES, embed_dim=64):
        super().__init__()
        self.micro_net  = MicroGranuleNet(embed_dim=embed_dim)
        self.meso_net   = MesoGranuleNet(embed_dim=embed_dim)
        self.macro_net  = MacroGranuleNet(embed_dim=embed_dim)
        self.fusion     = GranularFusionLayer(embed_dim=embed_dim)
        self.classifier = nn.Sequential(
            nn.Linear(192, 96),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(96, num_classes),
        )

    def forward(self, x_micro, x_meso, x_macro):
        g_micro = self.micro_net(x_micro)
        g_meso  = self.meso_net(x_meso)
        g_macro = self.macro_net(x_macro)
        fused, alphas = self.fusion(g_micro, g_meso, g_macro)
        logits = self.classifier(fused)
        return logits, alphas

