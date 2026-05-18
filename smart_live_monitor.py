import sys
import pcap
import dpkt
import numpy as np
from datetime import datetime
from collections import defaultdict
import time
from socket import inet_ntoa
import platform
import subprocess
import re

# ✅ Try to import LED Controller (only once)
led = None
try:
    from hardware.led_controller import LEDController
    LED_AVAILABLE = True
except ImportError:
    LED_AVAILABLE = False
    print("[INFO] LED module not found - Running without LED indicators")

# ═══════════════════════════════════════════════════════════════════════════
# AUTO-DETECT HARDWARE (Pi 3B vs Pi 4)
# ═══════════════════════════════════════════════════════════════════════════
PI_MODEL = platform.machine()

def get_total_ram_mb():
    """Get total RAM in MB"""
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal'):
                    # Extract number (in kB)
                    ram_kb = int(line.split()[1])
                    return ram_kb // 1024  # Convert to MB
    except:
        return 0

total_ram = get_total_ram_mb()

# Detect Pi model based on architecture and RAM
if 'armv7' in PI_MODEL or total_ram < 2048:  # Pi 3B: 32-bit OR less than 2GB RAM
    ML_SAMPLE_RATE = 20
    MAX_TRACKED_IPS = 300
    CLEANUP_INTERVAL = 50
    print(f"[*] Detected: Raspberry Pi 3B (RAM: {total_ram}MB) - Using optimized settings")
    print("[*] Performance mode: Low resource (ML samples every 20th packet)")
else:  # Pi 4 or better: 64-bit AND 2GB+ RAM
    ML_SAMPLE_RATE = 10
    MAX_TRACKED_IPS = 500
    CLEANUP_INTERVAL = 100
    print(f"[*] Detected: Raspberry Pi 4+ (RAM: {total_ram}MB) - Using standard settings")
    print("[*] Performance mode: High performance (ML samples every 10th packet)")

# ═══════════════════════════════════════════════════════════════════════════
# AUTO-DETECT NETWORK INTERFACE (eth0 vs wlan0)
# ═══════════════════════════════════════════════════════════════════════════
def get_active_interface():
    """Auto-detect active network interface with IP assigned"""
    try:
        # Get all network interfaces
        result = subprocess.run(['ip', 'addr', 'show'], 
                              capture_output=True, text=True, timeout=5)
        output = result.stdout
        
        # Priority order: eth0 > wlan0 > others
        interfaces = []
        current_iface = None
        
        for line in output.split('\n'):
            # Check for interface name
            if_match = re.match(r'^\d+:\s+(\w+):', line)
            if if_match:
                current_iface = if_match.group(1)
            
            # Check if interface has an IP (is UP and has address)
            if current_iface and 'inet ' in line and 'scope global' in line:
                # Skip loopback
                if current_iface != 'lo':
                    interfaces.append(current_iface)
        
        # Return first active interface (prefer eth0, then wlan0)
        for preferred in ['eth0', 'wlan0']:
            if preferred in interfaces:
                return preferred
        
        # If neither eth0 nor wlan0, return first available
        if interfaces:
            return interfaces[0]
        
        # Default fallback
        return 'wlan0'
        
    except Exception as e:
        print(f"[WARN] Interface detection failed: {e}")
        return 'wlan0'  # Default fallback

INTERFACE = get_active_interface()
print(f"[*] Auto-detected interface: {INTERFACE}")

# ═══════════════════════════════════════════════════════════════════════════
# DETECTION THRESHOLDS (Adjusted for Pi 3B if needed)
# ═══════════════════════════════════════════════════════════════════════════
# All trackers
syn_tracker = defaultdict(list)
blocked_ips_cache = set()
packet_counter = 0

port_scan_tracker = defaultdict(set)
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW = 10

icmp_tracker = defaultdict(list)
ICMP_THRESHOLD = 100
ICMP_WINDOW = 5

udp_tracker = defaultdict(list)
UDP_THRESHOLD = 200
UDP_WINDOW = 5

connection_tracker = defaultdict(list)
CONN_THRESHOLD = 10
CONN_WINDOW = 60

SYN_THRESHOLD = 50
SYN_WINDOW = 3

THRESHOLD = 0.40

# Auto-detect local IP and add to whitelist
def get_local_ip():
    """Get the Pi's IP address on the active interface"""
    try:
        result = subprocess.run(['ip', 'addr', 'show', INTERFACE],
                              capture_output=True, text=True, timeout=5)
        for line in result.stdout.split('\n'):
            if 'inet ' in line and 'scope global' in line:
                # Extract IP address
                ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    return ip_match.group(1)
    except:
        pass
    return None

local_ip = get_local_ip()

# Build whitelist with auto-detected local IP
WHITELIST = {
    "192.168.8.235",   # Gateway LAN
    "192.168.8.1",   # Router
    "192.168.8.89",
    "192.168.8.51",
    "192.168.8.255",
    "239.255.255.250",
    "192.168.8.151",
    "192.168.8.255",
    "192.168.1.45",
    "192.168.1.144",
    "192.168.8.11",
    "192.168.8.234",
    "192.168.8.65",
    "192.168.8.17",
    "192.168.30.1",
    "192.168.29.171",
    "192.168.29.1",
    "192.168.8.30",
    "192.168.8.29",
    "192.168.5.31",
    "192.168.3.188",
    "192.168.8.71",
    "192.168.8.77",
    "192.168.1.48",
    "192.168.2.83",



}

if local_ip:
    WHITELIST.add(local_ip)
    print(f"[*] Local IP detected: {local_ip} (added to whitelist)")
else:
    print("[WARN] Could not detect local IP - using default whitelist")

# ═══════════════════════════════════════════════════════════════════════════
# IMPORT MODULES
# ═══════════════════════════════════════════════════════════════════════════
if sys.platform == "linux":
    from core.rule_engine import block_ip, initialize_nftables
else:
    from mock.mock_nft import block_ip
    def initialize_nftables():
        pass

from core.feature_extractor import extract_features
from core.inference import predict
from monitor.alert_logger import log_alert


def cleanup_trackers():
    """Clean up old tracking data to prevent memory growth."""
    global syn_tracker, port_scan_tracker, icmp_tracker, udp_tracker, connection_tracker
    
    now = time.time()
    
    # ✅ Clean SYN tracker
    for ip in list(syn_tracker.keys()):
        syn_tracker[ip] = [t for t in syn_tracker[ip] if now - t < SYN_WINDOW]
        if not syn_tracker[ip]:
            del syn_tracker[ip]
    
    # ✅ Clean port scan tracker
    for ip in list(port_scan_tracker.keys()):
        port_scan_tracker[ip] = {
            (port, ts) for port, ts in port_scan_tracker[ip]
            if now - ts < PORT_SCAN_WINDOW
        }
        if not port_scan_tracker[ip]:
            del port_scan_tracker[ip]
    
    # ✅ Clean ICMP tracker
    for ip in list(icmp_tracker.keys()):
        icmp_tracker[ip] = [t for t in icmp_tracker[ip] if now - t < ICMP_WINDOW]
        if not icmp_tracker[ip]:
            del icmp_tracker[ip]
    
    # ✅ Clean UDP tracker
    for ip in list(udp_tracker.keys()):
        udp_tracker[ip] = [t for t in udp_tracker[ip] if now - t < UDP_WINDOW]
        if not udp_tracker[ip]:
            del udp_tracker[ip]
    
    # ✅ Clean connection tracker
    for ip in list(connection_tracker.keys()):
        connection_tracker[ip] = [t for t in connection_tracker[ip] if now - t < CONN_WINDOW]
        if not connection_tracker[ip]:
            del connection_tracker[ip]
    
    # ✅ Limit total tracked IPs
    if len(syn_tracker) > MAX_TRACKED_IPS:
        oldest_ips = sorted(syn_tracker.items(), 
                           key=lambda x: max(x[1]) if x[1] else 0)[:50]
        for ip, _ in oldest_ips:
            del syn_tracker[ip]


def process_packet(ip, timestamp):
    global packet_counter, led
    
    try:
        # Periodic cleanup
        packet_counter += 1
        if packet_counter % CLEANUP_INTERVAL == 0:
            cleanup_trackers()
        
        src_ip = inet_ntoa(ip.src)
        dst_ip = inet_ntoa(ip.dst)

        # ✅ Only check source IP in whitelist
        if src_ip in WHITELIST:
            return

        if src_ip in blocked_ips_cache:
            return

        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip.p, str(ip.p))

        # ======================================================================
        # TCP-based detections (SYN flood, Port scan, Brute force)
        # ======================================================================
        if ip.p == 6:  # TCP
            tcp = ip.data
            if isinstance(tcp, dpkt.tcp.TCP) and (tcp.flags & dpkt.tcp.TH_SYN):
                now = time.time()
                dst_port = tcp.dport
                
                # ✅ 1. Brute Force Detection (SSH, FTP, Telnet, RDP)
                if dst_port in [21, 22, 23, 3389]:
                    connection_tracker[src_ip].append(now)
                    connection_tracker[src_ip] = [
                        t for t in connection_tracker[src_ip]
                        if now - t < CONN_WINDOW
                    ]
                    
                    if len(connection_tracker[src_ip]) > CONN_THRESHOLD:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                              f"[ALERT] BRUTE FORCE from {src_ip} | Port: {dst_port} | "
                              f"Attempts: {len(connection_tracker[src_ip])}")
                        
                        if led and led.enabled:
                            led.flash_yellow(times=3, duration=0.2)
                            led.flash_red(times=3, duration=0.3)
                            led.set_blocked()
                        
                        block_ip(src_ip)
                        blocked_ips_cache.add(src_ip)
                        log_alert(src_ip, dst_ip, proto, 1.0)
                        del connection_tracker[src_ip]
                        return
                
                # ✅ 2. Port Scan Detection
                port_scan_tracker[src_ip].add((dst_port, now))
                port_scan_tracker[src_ip] = {
                    (port, ts) for port, ts in port_scan_tracker[src_ip]
                    if now - ts < PORT_SCAN_WINDOW
                }
                
                unique_ports = len(set(port for port, _ in port_scan_tracker[src_ip]))
                
                if unique_ports > PORT_SCAN_THRESHOLD:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"[ALERT] PORT SCAN from {src_ip} → {dst_ip} | "
                          f"Scanned {unique_ports} ports")
                    
                    if led and led.enabled:
                        led.flash_red(times=4, duration=0.25)
                        led.set_blocked()
                    
                    block_ip(src_ip)
                    blocked_ips_cache.add(src_ip)
                    log_alert(src_ip, dst_ip, proto, 1.0)
                    del port_scan_tracker[src_ip]
                    return
                
                # ✅ 3. SYN Flood Detection
                syn_tracker[src_ip].append(now)
                syn_tracker[src_ip] = [
                    t for t in syn_tracker[src_ip]
                    if now - t < SYN_WINDOW
                ]
                
                # Flash yellow when approaching threshold
                if led and led.enabled and len(syn_tracker[src_ip]) > SYN_THRESHOLD * 0.8:
                    led.flash_yellow(times=1, duration=0.1)
                
                if len(syn_tracker[src_ip]) > SYN_THRESHOLD:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"[ALERT] SYN FLOOD from {src_ip} → {dst_ip} | "
                          f"Count: {len(syn_tracker[src_ip])}")
                    
                    if led and led.enabled:
                        led.flash_red(times=5, duration=0.2)
                        led.set_blocked()
                    
                    block_ip(src_ip)
                    blocked_ips_cache.add(src_ip)
                    log_alert(src_ip, dst_ip, proto, 1.0)
                    del syn_tracker[src_ip]
                    return
        
        # ======================================================================
        # ICMP Flood Detection
        # ======================================================================
        if ip.p == 1:  # ICMP
            now = time.time()
            icmp_tracker[src_ip].append(now)
            icmp_tracker[src_ip] = [
                t for t in icmp_tracker[src_ip]
                if now - t < ICMP_WINDOW
            ]
            
            if len(icmp_tracker[src_ip]) > ICMP_THRESHOLD:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"[ALERT] ICMP FLOOD from {src_ip} → {dst_ip} | "
                      f"Count: {len(icmp_tracker[src_ip])}")
                
                if led and led.enabled:
                    led.flash_red(times=3, duration=0.2)
                    led.set_blocked()
                
                block_ip(src_ip)
                blocked_ips_cache.add(src_ip)
                log_alert(src_ip, dst_ip, proto, 1.0)
                del icmp_tracker[src_ip]
                return
        
        # ======================================================================
        # UDP Flood Detection
        # ======================================================================
        if ip.p == 17:  # UDP
            now = time.time()
            udp_tracker[src_ip].append(now)
            udp_tracker[src_ip] = [
                t for t in udp_tracker[src_ip]
                if now - t < UDP_WINDOW
            ]
            
            if len(udp_tracker[src_ip]) > UDP_THRESHOLD:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"[ALERT] UDP FLOOD from {src_ip} → {dst_ip} | "
                      f"Count: {len(udp_tracker[src_ip])}")
                
                if led and led.enabled:
                    led.flash_red(times=3, duration=0.2)
                    led.set_blocked()
                
                block_ip(src_ip)
                blocked_ips_cache.add(src_ip)
                log_alert(src_ip, dst_ip, proto, 1.0)
                del udp_tracker[src_ip]
                return
        
        # ======================================================================
        # ML-based detection (sampled)
        # ======================================================================
        if packet_counter % ML_SAMPLE_RATE == 0:
            features = extract_features(ip)
            score = predict(features)

            if score > THRESHOLD:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"[ALERT-ML] {src_ip} → {dst_ip} | {proto} | Score: {score:.2f}")
                
                if led and led.enabled:
                    led.flash_red(times=3, duration=0.3)
                    led.set_blocked()
                
                block_ip(src_ip)
                blocked_ips_cache.add(src_ip)
                log_alert(src_ip, dst_ip, proto, score)
        
    except AttributeError:
        pass
    except Exception as e:
        print(f"[ERROR] process_packet: {e}")


def start_capture():
    global led
    
    print("[*] Initializing nftables...")
    initialize_nftables()
    
    # ✅ Initialize LED controller
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
        print(f"[*] Detection thresholds:")
        print(f"    - SYN flood: {SYN_THRESHOLD} packets in {SYN_WINDOW}s")
        print(f"    - Port scan: {PORT_SCAN_THRESHOLD} ports in {PORT_SCAN_WINDOW}s")
        print(f"    - Brute force: {CONN_THRESHOLD} attempts in {CONN_WINDOW}s")
        print(f"    - ICMP flood: {ICMP_THRESHOLD} packets in {ICMP_WINDOW}s")
        print(f"    - UDP flood: {UDP_THRESHOLD} packets in {UDP_WINDOW}s")
        
        # Auto-describe mode based on interface
        if INTERFACE == "eth0":
            print(f"[*] Mode: Ethernet (wired connection)")
        elif INTERFACE == "wlan0":
            print(f"[*] Mode: WiFi (wireless connection)")
        else:
            print(f"[*] Mode: Custom interface ({INTERFACE})")
        
        if led and led.enabled:
            led.set_normal()
            
        print("=" * 50)

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
        if led and led.enabled:
            led.cleanup()
        print("[*] Closing capture.")


if __name__ == "__main__":
    start_capture()