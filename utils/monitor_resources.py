import psutil
import threading
import time


def monitor_resources(interval=5):
    """Monitor CPU and memory usage - useful for debugging on Pi 3B."""
    while True:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()

        print(f"[SYSTEM] CPU: {cpu_percent:.1f}% | "
              f"RAM: {memory.percent:.1f}% ({memory.used // (1024 ** 2)}MB used)")

        time.sleep(interval)


def start_monitoring():
    """Start resource monitoring in background thread."""
    monitor_thread = threading.Thread(target=monitor_resources, daemon=True)
    monitor_thread.start()
    print("[*] Resource monitoring started")