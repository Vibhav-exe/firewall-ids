import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnx
import os

# ── Column names for NSL-KDD dataset ─────────────────────────────────────────
COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]

# ── 6 features matching feature_extractor.py exactly ─────────────────────────
FEATURE_COLS = [
    "protocol_type",  # → proto
    "src_bytes",      # → src_port proxy
    "dst_bytes",      # → dst_port proxy
    "duration",       # → pkt_len proxy
    "count",          # → ttl proxy
    "flag"            # → tcp_flags
]

DATA_PATH  = os.path.join("data", "KDDTrain+.txt")
MODEL_PATH = os.path.join("model", "ids_model.onnx")


def load_data():
    print("[*] Loading dataset...")
    df = pd.read_csv(DATA_PATH, header=None, names=COLUMNS)

    # Encode categorical string columns → integers
    le = LabelEncoder()
    for col in ["protocol_type", "service", "flag"]:
        df[col] = le.fit_transform(df[col])

    # Binary label: normal=0, any attack=1
    df["binary_label"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)

    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df["binary_label"].values

    print(f"[*] Samples: {len(df)}")
    print(f"[*] Benign: {(y == 0).sum()} | Attack: {(y == 1).sum()}")
    return X, y


def train(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("[*] Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=50,   # Low count = smaller model, faster on Pi
        max_depth=10,      # Prevents RAM bloat
        n_jobs=-1,         # Use all CPU cores on Windows for training speed
        random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n[*] Evaluation:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Attack"]))

    return model


def export_onnx(model, num_features):
    os.makedirs("model", exist_ok=True)
    initial_type = [("float_input", FloatTensorType([None, num_features]))]
    onnx_model = convert_sklearn(model, initial_types=initial_type)
    onnx.save(onnx_model, MODEL_PATH)
    size_kb = os.path.getsize(MODEL_PATH) / 1024
    print(f"[*] Saved: {MODEL_PATH} ({size_kb:.1f} KB)")


if __name__ == "__main__":
    X, y = load_data()
    model = train(X, y)
    export_onnx(model, X.shape[1])
    print("\n[✓] Done! ids_model.onnx is ready.")
