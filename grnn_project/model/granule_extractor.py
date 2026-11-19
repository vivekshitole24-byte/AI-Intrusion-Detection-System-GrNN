"""
Granule Extractor — Feature Engineering for 3-Scale Granulation
===============================================================
Converts a raw network traffic CSV (CICIDS format) into
Micro, Meso, and Macro granule feature matrices for GrNN inference.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import os

# Feature group definitions (must match granular_nn.py)
MICRO_FEATURES = [
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Header Length.1',
    'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
]

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
]

MACRO_FEATURES = [
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
]

ALL_FEATURES = MICRO_FEATURES + MESO_FEATURES + MACRO_FEATURES

# Attack label mapping — covers CICIDS label variants
LABEL_MAP = {
    'BENIGN': 'Benign',
    'Benign': 'Benign',
    'benign': 'Benign',
    'DDoS': 'DDoS',
    'ddos': 'DDoS',
    'DoS Hulk': 'DoS',
    'DoS GoldenEye': 'DoS',
    'DoS slowloris': 'DoS',
    'DoS Slowhttptest': 'DoS',
    'Heartbleed': 'DoS',
    'PortScan': 'Port Scan',
    'Port Scan': 'Port Scan',
    'FTP-Patator': 'Brute Force',
    'SSH-Patator': 'Brute Force',
    'Brute Force': 'Brute Force',
    'Web Attack – Brute Force': 'Brute Force',
    'Web Attack – XSS': 'Web Attack',
    'Web Attack – Sql Injection': 'Web Attack',
    'Bot': 'Botnet',
    'Botnet': 'Botnet',
    'Infiltration': 'Infiltration',
}

CLASS_NAMES = ['Benign', 'DDoS', 'DoS', 'Port Scan', 'Brute Force', 'Web Attack', 'Botnet', 'Infiltration']
NUM_CLASSES = len(CLASS_NAMES)


class GranuleExtractor:
    """
    Loads a CICIDS CSV and splits features into 3 granule matrices.
    Also handles scaling/normalisation and label encoding.
    """

    def __init__(self):
        self.micro_scaler = StandardScaler()
        self.meso_scaler  = StandardScaler()
        self.macro_scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.fitted = False

    # ------------------------------------------------------------------
    def _clean_df(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardise column names, remove inf/nan, map labels."""
        # Strip whitespace from column names (CICIDS files have leading spaces)
        df.columns = [c.strip() for c in df.columns]

        # Replace inf values with NaN then fill with 0
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)

        # Map raw labels to canonical names
        if 'Label' in df.columns:
            df['Label'] = df['Label'].map(lambda x: LABEL_MAP.get(str(x).strip(), 'Other'))

        # Ensure all required feature columns exist; fill missing with 0
        for col in ALL_FEATURES:
            if col not in df.columns:
                df[col] = 0.0

        return df

    # ------------------------------------------------------------------
    def fit_transform(self, csv_path: str):
        """Read CSV, fit scalers, return (X_micro, X_meso, X_macro, y)."""
        df = pd.read_csv(csv_path)
        df = self._clean_df(df)

        X_micro = df[MICRO_FEATURES].values.astype(np.float32)
        X_meso  = df[MESO_FEATURES].values.astype(np.float32)
        X_macro = df[MACRO_FEATURES].values.astype(np.float32)

        X_micro = self.micro_scaler.fit_transform(X_micro).astype(np.float32)
        X_meso  = self.meso_scaler.fit_transform(X_meso).astype(np.float32)
        X_macro = self.macro_scaler.fit_transform(X_macro).astype(np.float32)

        y = None
        if 'Label' in df.columns:
            labels = df['Label'].values
            self.label_encoder.fit(sorted(set(labels)))
            y = self.label_encoder.transform(labels)

        self.fitted = True
        return X_micro, X_meso, X_macro, y

    # ------------------------------------------------------------------
    def transform(self, csv_path: str):
        """Transform a new CSV using fitted scalers (inference mode)."""
        df = pd.read_csv(csv_path)
        df = self._clean_df(df)

        X_micro = self.micro_scaler.transform(df[MICRO_FEATURES].values.astype(np.float32))
        X_meso  = self.meso_scaler.transform(df[MESO_FEATURES].values.astype(np.float32))
        X_macro = self.macro_scaler.transform(df[MACRO_FEATURES].values.astype(np.float32))

        y = None
        if 'Label' in df.columns:
            labels = df['Label'].map(lambda x: LABEL_MAP.get(str(x).strip(), 'Other')).values
            y = self.label_encoder.transform(labels)

        return X_micro.astype(np.float32), X_meso.astype(np.float32), X_macro.astype(np.float32), y

    # ------------------------------------------------------------------
    def transform_df(self, df: pd.DataFrame):
        """Transform an already-loaded DataFrame (for live inference)."""
        df = self._clean_df(df.copy())
        X_micro = self.micro_scaler.transform(df[MICRO_FEATURES].values.astype(np.float32))
        X_meso  = self.meso_scaler.transform(df[MESO_FEATURES].values.astype(np.float32))
        X_macro = self.macro_scaler.transform(df[MACRO_FEATURES].values.astype(np.float32))
        return X_micro.astype(np.float32), X_meso.astype(np.float32), X_macro.astype(np.float32)

    # ------------------------------------------------------------------
    def save(self, path='model/grnn_scalers.pkl'):
        """Persist scalers and label encoder to disk."""
        joblib.dump({
            'micro': self.micro_scaler,
            'meso':  self.meso_scaler,
            'macro': self.macro_scaler,
            'le':    self.label_encoder,
        }, path)
        print(f"[GranuleExtractor] Saved to {path}")

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, path='model/grnn_scalers.pkl'):
        """Restore from disk."""
        obj = cls()
        data = joblib.load(path)
        obj.micro_scaler  = data['micro']
        obj.meso_scaler   = data['meso']
        obj.macro_scaler  = data['macro']
        obj.label_encoder = data['le']
        obj.fitted = True
        return obj

