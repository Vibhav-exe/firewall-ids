import sys
import pcap  # pypcap library
import dpkt
import numpy as np
from datetime import datetime
from collections import defaultdict
import time
from socket import inet_ntoa

syn_tracker = defaultdict(list)
blocked_ips_cache = set()
SYN_THRESHOLD = 50
SYN_WINDOW = 3

WHITELIST = {
    "192.168.29.171",  # Your Raspberry Pi
    #"192.168.29.171"   #PC
    "192.168.29.1",  # Router
    "192.168.29.234" #phone
    "192.168.29.224"
    "192.168.29.169"
}

# Platform guard
if sys.platform == "linux":
    from core.rule_engine import block_ip
else:
    from mock.mock_nft import block_ip

from core.feature_extractor import extract_features
from core.inference import predict
from monitor.alert_logger import log_alert

INTERFACE = "wlan0"
THRESHOLD = 0.40


def process_packet(ip, timestamp):
    try:
        # Convert IP addresses using socket.inet_ntoa (works with dpkt)
        src_ip = inet_ntoa(ip.src)
        dst_ip = inet_ntoa(ip.dst)

        # Skip if EITHER source OR destination is whitelisted
        if src_ip in WHITELIST or dst_ip in WHITELIST:
            return

        # ✅ Skip already blocked IPs (check early)
        if src_ip in blocked_ips_cache:
            return

        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip.p, str(ip.p))

        # SYN flood detection
        if ip.p == 6:  # TCP
            tcp = ip.data
            # Check if it's actually TCP and has SYN flag
            if isinstance(tcp, dpkt.tcp.TCP) and (tcp.flags & dpkt.tcp.TH_SYN):
                now = time.time()
                syn_tracker[src_ip].append(now)

                # Clean old entries within window
                syn_tracker[src_ip] = [
                    t for t in syn_tracker[src_ip]
                    if now - t < SYN_WINDOW
                ]

                if len(syn_tracker[src_ip]) > SYN_THRESHOLD:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"[ALERT] SYN FLOOD from {src_ip} → {dst_ip} | "
                          f"Count: {len(syn_tracker[src_ip])}")
                    block_ip(src_ip)
                    blocked_ips_cache.add(src_ip)  # ✅ Add to cache
                    log_alert(src_ip, dst_ip, proto, 1.0)
                    del syn_tracker[src_ip]  # Remove from tracker after blocking
                    return

        # ML-based detection
        features = extract_features(ip)
        score = predict(features)

        if score > THRESHOLD:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"[ALERT] {src_ip} → {dst_ip} | {proto} | Score: {score:.2f}")
            block_ip(src_ip)
            blocked_ips_cache.add(src_ip)  # ✅ Add to cache
            log_alert(src_ip, dst_ip, proto, score)
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"[OK]    {src_ip} → {dst_ip} | {proto} | len={ip.len}")

    except AttributeError as e:
        # Packet structure issues
        pass
    except Exception as e:
        # Log unexpected errors in production
        print(f"[ERROR] process_packet: {e}")


def start_capture():
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
        print(f"[*] Block threshold: {THRESHOLD}")
        print(f"[*] Whitelisted IPs: {WHITELIST}")
        print(f"[*] SYN flood threshold: {SYN_THRESHOLD} packets in {SYN_WINDOW}s")
        print("-" * 50)

        for timestamp, raw in pc:
            try:
                eth = dpkt.ethernet.Ethernet(raw)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                process_packet(eth.data, timestamp)
            except dpkt.dpkt.NeedData:
                # Incomplete packet, skip
                continue
            except dpkt.dpkt.UnpackError:
                # Malformed packet, skip
                continue
            except Exception as e:
                # Don't crash on individual packet errors
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