import numpy as np
import os

# Graceful fallback if model file doesn't exist yet (during development)
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "model", "ids_model.onnx")

sess = None

def load_model():
    global sess
    try:
        import onnxruntime as rt

        sess_options = rt.SessionOptions()
        sess_options.intra_op_num_threads = 2
        sess_options.graph_optimization_level = rt.GraphOptimizationLevel.ORT_ENABLE_ALL
        sess_options.enable_mem_pattern = True
        sess_options.enable_cpu_mem_arena = False

        sess = rt.InferenceSession(
            MODEL_PATH,
            sess_options=sess_options,
            providers=["CPUExecutionProvider"]
        )
        print(f"[*] Model loaded from {MODEL_PATH}")

    except FileNotFoundError:
        print(f"[WARN] Model file not found at {MODEL_PATH}")
        print("[WARN] Running in DUMMY mode — all packets will be marked benign.")
        sess = None

    except Exception as e:
        print(f"[WARN] Model not trained yet — running in dummy mode.")
        sess = None


def predict(features: np.ndarray) -> float:
    """
    Takes shape (1, 6) float32 array.
    Returns a float score between 0.0 and 1.0.
    1.0 = malicious, 0.0 = benign.
    """
    if sess is None:
        return 0.0   # Dummy mode — treat as benign

    input_name  = sess.get_inputs()[0].name
    output_name = sess.get_outputs()[0].name

    result = sess.run([output_name], {input_name: features})
    return float(result[0][0])


# Load model once at import time
load_model()
