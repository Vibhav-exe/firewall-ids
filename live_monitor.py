import sys
import pcap
import dpkt
import numpy as np
from datetime import datetime
from collections import defaultdict
import time
from socket import inet_ntoa
import platform
# Replace hardcoded values with config imports
from config import (
    INTERFACE, WHITELIST, SYN_THRESHOLD, SYN_WINDOW,
    ML_THRESHOLD, ML_SAMPLE_RATE, MAX_TRACKED_IPS,
    CLEANUP_INTERVAL, ENABLE_RESOURCE_MONITORING
)

THRESHOLD = ML_THRESHOLD
try:
    from utils.monitor_resources import start_monitoring
    ENABLE_MONITORING = True
except ImportError:
    ENABLE_MONITORING = False


# ✅ Auto-detect hardware and optimize
PI_MODEL = platform.machine()
if 'armv7' in PI_MODEL:  # Pi 3B
    ML_SAMPLE_RATE = 20
    MAX_TRACKED_IPS = 300
    CLEANUP_INTERVAL = 50
    print("[*] Detected: Raspberry Pi 3B - Using optimized settings")
else:  # Pi 4+
    ML_SAMPLE_RATE = 10
    MAX_TRACKED_IPS = 500
    CLEANUP_INTERVAL = 100
    print("[*] Detected: Raspberry Pi 4+ - Using standard settings")

syn_tracker = defaultdict(list)
blocked_ips_cache = set()
packet_counter = 0

SYN_THRESHOLD = 50
SYN_WINDOW = 3

WHITELIST = {
    "192.168.30.1",
    "192.168.29.171",
    "192.168.29.1",
}

if sys.platform == "linux":
    from core.rule_engine import block_ip, initialize_nftables
else:
    from mock.mock_nft import block_ip


    def initialize_nftables():
        pass

from core.feature_extractor import extract_features
from core.inference import predict
from monitor.alert_logger import log_alert

INTERFACE = "eth0"
THRESHOLD = 0.40


def cleanup_trackers():
    """Clean up old tracking data to prevent memory growth."""
    global syn_tracker

    now = time.time()
    for ip in list(syn_tracker.keys()):
        syn_tracker[ip] = [t for t in syn_tracker[ip] if now - t < SYN_WINDOW]
        if not syn_tracker[ip]:
            del syn_tracker[ip]

    if len(syn_tracker) > MAX_TRACKED_IPS:
        oldest_ips = sorted(syn_tracker.items(),
                            key=lambda x: max(x[1]) if x[1] else 0)[:50]
        for ip, _ in oldest_ips:
            del syn_tracker[ip]


def process_packet(ip, timestamp):
    global packet_counter

    try:
        # Periodic cleanup
        packet_counter += 1
        if packet_counter % CLEANUP_INTERVAL == 0:
            cleanup_trackers()

        src_ip = inet_ntoa(ip.src)
        dst_ip = inet_ntoa(ip.dst)

        if src_ip in WHITELIST or dst_ip in WHITELIST:
            return

        if src_ip in blocked_ips_cache:
            return

        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip.p, str(ip.p))

        # Rule-based SYN flood detection (always run)
        if ip.p == 6:
            tcp = ip.data
            if isinstance(tcp, dpkt.tcp.TCP) and (tcp.flags & dpkt.tcp.TH_SYN):
                now = time.time()
                syn_tracker[src_ip].append(now)
                syn_tracker[src_ip] = [
                    t for t in syn_tracker[src_ip]
                    if now - t < SYN_WINDOW
                ]

                if len(syn_tracker[src_ip]) > SYN_THRESHOLD:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"[ALERT] SYN FLOOD from {src_ip} → {dst_ip} | "
                          f"Count: {len(syn_tracker[src_ip])}")
                    block_ip(src_ip)
                    blocked_ips_cache.add(src_ip)
                    log_alert(src_ip, dst_ip, proto, 1.0)
                    del syn_tracker[src_ip]
                    return

        # ML-based detection (sampled)
        if packet_counter % ML_SAMPLE_RATE == 0:
            features = extract_features(ip)
            score = predict(features)

            if score > THRESHOLD:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"[ALERT] {src_ip} → {dst_ip} | {proto} | Score: {score:.2f}")
                block_ip(src_ip)
                blocked_ips_cache.add(src_ip)
                log_alert(src_ip, dst_ip, proto, score)

    except AttributeError:
        pass
    except Exception as e:
        print(f"[ERROR] process_packet: {e}")


def start_capture():
    print("[*] Initializing nftables...")
    initialize_nftables()

    if ENABLE_MONITORING:
        start_monitoring()


    try:
        pc = pcap.pcap(
            name=INTERFACE,
            promisc=True,
            immediate=True,
            timeout_ms=50
        )
        pc.setfilter("ip")

        print(f"[*] Starting capture on interface: {INTERFACE}")
        print(f"[*] Platform: {sys.platform}")
        print(f"[*] ML Detection threshold: {THRESHOLD}")
        print(f"[*] ML Sampling rate: 1 in {ML_SAMPLE_RATE} packets")
        print(f"[*] Whitelisted IPs: {WHITELIST}")
        print(f"[*] SYN flood threshold: {SYN_THRESHOLD} packets in {SYN_WINDOW}s")
        print(f"[*] Mode: Gateway (monitoring LAN traffic)")
        print("-" * 50)

        for timestamp, raw in pc:
            try:
                eth = dpkt.ethernet.Ethernet(raw)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                process_packet(eth.data, timestamp)
            except dpkt.dpkt.NeedData:
                continue
            except dpkt.dpkt.UnpackError:
                continue
            except Exception:
                pass

    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo for packet capture.")
    except Exception as e:
        print(f"[FATAL] Capture error: {e}")
    finally:
        print("[*] Closing capture.")


if __name__ == "__main__":
    start_capture()