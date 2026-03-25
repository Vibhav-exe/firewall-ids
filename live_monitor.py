import sys
import pcap
import dpkt
import numpy as np
from datetime import datetime
from collections import defaultdict
import time
from socket import inet_ntoa
import platform


led = None
try:
    from hardware.led_controller import LEDController
    LED_AVAILABLE = True
except ImportError:
    LED_AVAILABLE = False
    print("[INFO] LED module not found - Running without LED indicators")
# ✅ Auto-detect hardware and optimize
# platform.machine() returns:
#   - 'armv7l' for Raspberry Pi 3B (32-bit ARM)
#   - 'aarch64' for Raspberry Pi 4 (64-bit ARM)
PI_MODEL = platform.machine()

if 'armv7' in PI_MODEL:  # Raspberry Pi 3B detected
    ML_SAMPLE_RATE = 20      # Check ML every 20th packet (reduced CPU load)
    MAX_TRACKED_IPS = 300    # Track fewer IPs (limited to 1GB RAM)
    CLEANUP_INTERVAL = 50    # Clean memory more frequently
    print("[*] Detected: Raspberry Pi 3B - Using optimized settings")
else:  # Raspberry Pi 4 or better detected
    ML_SAMPLE_RATE = 10      # Check ML every 10th packet (more frequent detection)
    MAX_TRACKED_IPS = 500    # Track more IPs (4GB RAM available)
    CLEANUP_INTERVAL = 100   # Clean memory less frequently
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
try:
    from hardware.led_controller import LEDController
    USE_LEDS = True
except ImportError:
    print("[WARN] LED controller not available (not on Pi or GPIO not installed)")
    USE_LEDS = False


from core.feature_extractor import extract_features
from core.inference import predict
from monitor.alert_logger import log_alert

INTERFACE = "wlan0"
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

        # ✅ DEBUG: Print every 10th packet
        if packet_counter % 10 == 0:
            print(f"[DEBUG] Packet #{packet_counter}: {src_ip} → {dst_ip} | Proto: {ip.p}")

        # Whitelist check
        if src_ip in WHITELIST or dst_ip in WHITELIST:
            if packet_counter % 10 == 0:
                print(f"[DEBUG] Packet skipped (whitelist)")
            return

        if src_ip in blocked_ips_cache:
            if packet_counter % 10 == 0:
                print(f"[DEBUG] Packet skipped (already blocked)")
            return

        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip.p, str(ip.p))

        # Rule-based SYN flood detection (always run)
        if ip.p == 6:
            tcp = ip.data
            if isinstance(tcp, dpkt.tcp.TCP) and (tcp.flags & dpkt.tcp.TH_SYN):
                now = time.time()
                
                # ✅ DEBUG: Show SYN packet count
                print(f"[DEBUG] SYN from {src_ip}, current count: {len(syn_tracker[src_ip])}")
                
                syn_tracker[src_ip].append(now)
                syn_tracker[src_ip] = [
                    t for t in syn_tracker[src_ip]
                    if now - t < SYN_WINDOW
                ]
                if led and led.enabled and len(syn_tracker[src_ip]) > SYN_THRESHOLD * 0.8:
                    led.flash_yellow(times=1, duration=0.1)

                # ✅ DEBUG: Show count after cleanup
                print(f"[DEBUG] After cleanup, count: {len(syn_tracker[src_ip])} (threshold: {SYN_THRESHOLD})")

                if len(syn_tracker[src_ip]) > SYN_THRESHOLD:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"[ALERT] SYN FLOOD from {src_ip} → {dst_ip} | "
                          f"Count: {len(syn_tracker[src_ip])}")
                    # ✅ Flash red LED for SYN flood alert
                    if led and led.enabled:
                        led.flash_red(times=5, duration=0.2)
                    block_ip(src_ip)
                    blocked_ips_cache.add(src_ip)
                    log_alert(src_ip, dst_ip, proto, 1.0)
                    del syn_tracker[src_ip]
                    # ✅ Set LED to blocked state
                    if led and led.enabled:
                        led.set_blocked()
                    return

        # ML-based detection (sampled)
        if packet_counter % ML_SAMPLE_RATE == 0:
            features = extract_features(ip)
            score = predict(features)

            if score > THRESHOLD:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"[ALERT] {src_ip} → {dst_ip} | {proto} | Score: {score:.2f}")
                # ✅ Flash red LED for ML detection alert
                if led and led.enabled:
                    led.flash_red(times=3, duration=0.3)
                block_ip(src_ip)
                blocked_ips_cache.add(src_ip)
                log_alert(src_ip, dst_ip, proto, score)
                # ✅ Set LED to blocked state
                if led and led.enabled:
                    led.set_blocked()
        
    except AttributeError as e:
        print(f"[DEBUG] AttributeError: {e}")
        pass
    except Exception as e:
        print(f"[ERROR] process_packet: {e}")


def start_capture():
    print("[*] Initializing nftables...")
    initialize_nftables()
    if LED_AVAILABLE:
        try:
            led = LEDController()
            if led.enabled:
                led.startup_sequence()
                print("[*] ✓ LED indicators active")
            else:
                print("[*] Running without LED indicators")
                led = None
        except Exception as e:
            print(f"[WARN] LED controller error: {e}")
            print("[*] Continuing without LED support")
            led = None
    else:
        print("[*] LED controller not available - Running in standard mode")
    
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
        
        # ✅ Dynamic mode description based on interface
        if INTERFACE == "eth0":
            print(f"[*] Mode: Gateway (monitoring LAN traffic)")
        elif INTERFACE == "wlan0":
            print(f"[*] Mode: WiFi monitoring (interface: {INTERFACE})")
        else:
            print(f"[*] Mode: Monitoring {INTERFACE}")
            
        print("-" * 50)
        print("[*] DEBUG MODE ENABLED - Showing packet details")
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
            except Exception as e:
                print(f"[DEBUG] Capture exception: {e}")
                pass

    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo for packet capture.")
    except Exception as e:
        print(f"[FATAL] Capture error: {e}")
    finally:
         if led and led.enabled:
            led.cleanup()
            print("[*] Closing capture.")
            print("[*] Closing capture.")


if __name__ == "__main__":
    start_capture()