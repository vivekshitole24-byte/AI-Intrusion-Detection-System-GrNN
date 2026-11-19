"""
GrNN Training Script
====================
Trains the Granular Neural Network on CICIDS-format datasets.
Produces: grnn_model.pt  +  grnn_scalers.pkl

Usage:
    python model/train_grnn.py
"""

import os
import sys
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from model.granular_nn import GrNN, NUM_CLASSES
from model.granule_extractor import GranuleExtractor, CLASS_NAMES

# ── Config ────────────────────────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, '..', 'ids_web', 'ids_app', 'cleaned_dataset.csv')
EXTRA_CSV = os.path.join(BASE_DIR, '..', 'ids_web', 'media', 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv')
SAVE_DIR  = os.path.join(BASE_DIR, 'model')

BATCH_SIZE = 512
EPOCHS     = 30
LR         = 1e-3
DEVICE     = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

print(f"[GrNN Training] Device: {DEVICE}")


# ── Load & Extract Granules ───────────────────────────────────────────────────
extractor = GranuleExtractor()
print("[GrNN Training] Loading primary dataset...")
X_micro, X_meso, X_macro, y = extractor.fit_transform(DATA_PATH)

# Try to merge additional dataset for more attack diversity
if os.path.exists(EXTRA_CSV):
    try:
        print("[GrNN Training] Loading extra dataset for Port Scan labels...")
        Xm2, Xs2, Xc2, y2 = extractor.transform(EXTRA_CSV)
        X_micro = np.vstack([X_micro, Xm2])
        X_meso  = np.vstack([X_meso,  Xs2])
        X_macro = np.vstack([X_macro, Xc2])
        y       = np.concatenate([y, y2])
        print(f"[GrNN Training] Combined dataset size: {len(y)} samples")
    except Exception as e:
        print(f"[WARNING] Could not merge extra dataset: {e}")

print(f"[GrNN Training] Classes: {extractor.label_encoder.classes_}")
print(f"[GrNN Training] Samples per class: {np.unique(y, return_counts=True)}")

# ── Train/Test Split ──────────────────────────────────────────────────────────
X_mi_tr, X_mi_te, X_ms_tr, X_ms_te, X_mc_tr, X_mc_te, y_tr, y_te = train_test_split(
    X_micro, X_meso, X_macro, y,
    test_size=0.2, random_state=42, stratify=y
)

# ── Class Weights (handles imbalance) ────────────────────────────────────────
classes = np.unique(y_tr)
weights = compute_class_weight('balanced', classes=classes, y=y_tr)
class_weights = torch.tensor(weights, dtype=torch.float32).to(DEVICE)

num_classes_actual = len(extractor.label_encoder.classes_)

# ── DataLoaders ───────────────────────────────────────────────────────────────
def to_tensor(*arrays):
    return [torch.tensor(a) for a in arrays]

tr_micro, tr_meso, tr_macro, tr_y = to_tensor(X_mi_tr, X_ms_tr, X_mc_tr, y_tr.astype(np.int64))
te_micro, te_meso, te_macro, te_y = to_tensor(X_mi_te, X_ms_te, X_mc_te, y_te.astype(np.int64))

train_ds = TensorDataset(tr_micro, tr_meso, tr_macro, tr_y)
test_ds  = TensorDataset(te_micro, te_meso, te_macro, te_y)

train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True,  num_workers=0)
test_loader  = DataLoader(test_ds,  batch_size=BATCH_SIZE, shuffle=False, num_workers=0)

# ── Model, Optimizer, Loss ────────────────────────────────────────────────────
model     = GrNN(num_classes=num_classes_actual).to(DEVICE)
optimizer = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=1e-4)
scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=EPOCHS)
criterion = nn.CrossEntropyLoss(weight=class_weights[:num_classes_actual]
                                 if len(class_weights) >= num_classes_actual
                                 else None)

# ── Training Loop ─────────────────────────────────────────────────────────────
best_acc = 0.0
best_path = os.path.join(SAVE_DIR, 'grnn_model.pt')

print("\n[GrNN Training] Starting training...")
for epoch in range(1, EPOCHS + 1):
    model.train()
    total_loss, correct, total = 0.0, 0, 0

    for xm, xs, xc, yb in train_loader:
        xm, xs, xc, yb = xm.to(DEVICE), xs.to(DEVICE), xc.to(DEVICE), yb.to(DEVICE)
        optimizer.zero_grad()
        logits, alphas = model(xm, xs, xc)
        loss = criterion(logits, yb)
        loss.backward()
        optimizer.step()

        total_loss += loss.item() * yb.size(0)
        preds = logits.argmax(dim=1)
        correct += (preds == yb).sum().item()
        total   += yb.size(0)

    scheduler.step()
    train_acc = 100.0 * correct / total
    avg_loss  = total_loss / total

    # Validation
    model.eval()
    val_correct, val_total = 0, 0
    with torch.no_grad():
        for xm, xs, xc, yb in test_loader:
            xm, xs, xc, yb = xm.to(DEVICE), xs.to(DEVICE), xc.to(DEVICE), yb.to(DEVICE)
            logits, _ = model(xm, xs, xc)
            preds = logits.argmax(dim=1)
            val_correct += (preds == yb).sum().item()
            val_total   += yb.size(0)

    val_acc = 100.0 * val_correct / val_total
    print(f"Epoch {epoch:02d}/{EPOCHS}  Loss: {avg_loss:.4f}  Train: {train_acc:.2f}%  Val: {val_acc:.2f}%")

    if val_acc > best_acc:
        best_acc = val_acc
        torch.save({
            'model_state': model.state_dict(),
            'num_classes': num_classes_actual,
            'class_names': list(extractor.label_encoder.classes_),
        }, best_path, _use_new_zipfile_serialization=True)
        print(f"  >> Saved best model ({val_acc:.2f}%)")

# ── Final Report ──────────────────────────────────────────────────────────────
print(f"\n[GrNN Training] Best Validation Accuracy: {best_acc:.2f}%")
model.load_state_dict(torch.load(best_path, weights_only=False)['model_state'])
model.eval()

all_preds, all_true = [], []
with torch.no_grad():
    for xm, xs, xc, yb in test_loader:
        xm, xs, xc = xm.to(DEVICE), xs.to(DEVICE), xc.to(DEVICE)
        logits, _ = model(xm, xs, xc)
        all_preds.extend(logits.argmax(1).cpu().numpy())
        all_true.extend(yb.numpy())

print("\n[GrNN Training] Classification Report:")
print(classification_report(all_true, all_preds,
                             target_names=list(extractor.label_encoder.classes_)))

# Save scalers
scaler_path = os.path.join(SAVE_DIR, 'grnn_scalers.pkl')
extractor.save(scaler_path)
print(f"\n[GrNN Training] Done. Model → {best_path}  Scalers → {scaler_path}")
