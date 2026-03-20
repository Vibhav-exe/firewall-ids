"""
Configuration file for IDS
Adjust these settings based on your hardware
"""

# Hardware detection
import platform
PI_MODEL = platform.machine()

# Network settings
INTERFACE = "eth0"
WHITELIST = {
    "192.168.30.1",
    "192.168.29.171",
    "192.168.29.1",
}

# Detection thresholds
SYN_THRESHOLD = 50
SYN_WINDOW = 3
ML_THRESHOLD = 0.40

# ✅ Performance tuning for Pi 3B vs Pi 4
if 'armv7' in PI_MODEL:  # Pi 3B
    ML_SAMPLE_RATE = 20      # Check every 20th packet
    MAX_TRACKED_IPS = 300    # Lower memory usage
    CLEANUP_INTERVAL = 50
    print("[*] Detected: Raspberry Pi 3B - Using optimized settings")
else:  # Pi 4 or better
    ML_SAMPLE_RATE = 10
    MAX_TRACKED_IPS = 500
    CLEANUP_INTERVAL = 100
    print("[*] Detected: Raspberry Pi 4 or better - Using standard settings")

# Memory management
ENABLE_RESOURCE_MONITORING = False  # Set True to debug performance