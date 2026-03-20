import onnxruntime as ort
import numpy as np
import os
import platform

# ✅ Auto-detect hardware for thread optimization
PI_MODEL = platform.machine()

# ✅ Use relative path instead of absolute
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "model", "ids_model.onnx")

# ✅ Configure session options based on hardware
session_options = ort.SessionOptions()

if 'armv7' in PI_MODEL:  # Raspberry Pi 3B (32-bit ARM)
    session_options.intra_op_num_threads = 2  # Limit threads (less CPU cores)
    session_options.inter_op_num_threads = 1
    print("[*] ML Model: Optimized for Raspberry Pi 3B (2 threads)")
else:  # Raspberry Pi 4 or better (64-bit ARM)
    session_options.intra_op_num_threads = 4  # More threads available
    session_options.inter_op_num_threads = 2
    print("[*] ML Model: Optimized for Raspberry Pi 4+ (4 threads)")

# ✅ Additional optimizations for both
session_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
session_options.enable_mem_pattern = True
session_options.enable_cpu_mem_arena = False

# ✅ Load model with error handling
session = None
input_name = None

try:
    session = ort.InferenceSession(
        MODEL_PATH,
        sess_options=session_options,
        providers=['CPUExecutionProvider']
    )
    input_name = session.get_inputs()[0].name
    print(f"[*] ML Model loaded successfully from {MODEL_PATH}")

except FileNotFoundError:
    print(f"[WARN] Model file not found at {MODEL_PATH}")
    print("[WARN] Running in DUMMY mode — all packets will be marked benign (score 0.0)")
    session = None

except Exception as e:
    print(f"[ERROR] Failed to load ML model: {e}")
    print("[WARN] Running in DUMMY mode — all packets will be marked benign (score 0.0)")
    session = None


def predict(features: np.ndarray) -> float:
    """
    Run inference on the ONNX model.

    Args:
        features: numpy array of shape (1, 6) with packet features

    Returns:
        float: Attack probability (0.0 = normal, 1.0 = attack)
    """
    # ✅ Dummy mode if model not loaded
    if session is None:
        return 0.0

    try:
        outputs = session.run(None, {input_name: features})
        probabilities = outputs[0][0]

        # Return attack probability (1 = attack, 0 = normal)
        return float(probabilities[1])

    except Exception as e:
        print(f"[ERROR] Inference failed: {e}")
        return 0.0  # Treat as benign on error