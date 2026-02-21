import json
import os
import datetime

LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "alerts.jsonl")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def log_alert(src_ip: str, dst_ip: str, proto: str, score: float, action="BLOCKED"):
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "protocol":  proto,
        "score":     round(float(score), 3),
        "action":    action
    }
    with open(LOG_FILE, "a", buffering=1) as f:   # line-buffered, no RAM buildup
        f.write(json.dumps(entry) + "\n")
    print(f"[LOG] {entry['timestamp']} | {src_ip} → {dst_ip} | {proto} | {score:.2f} | {action}")


def get_recent_alerts(n=20) -> list:
    """Read last N alerts from log file."""
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
    return [json.loads(l) for l in lines[-n:] if l.strip()]


def clear_logs():
    open(LOG_FILE, "w").close()
    print("[*] Alert log cleared.")
