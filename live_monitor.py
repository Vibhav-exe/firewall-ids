import sys
import pcap
import dpkt
import numpy as np
from datetime import datetime


WHITELIST = {
    #"192.168.29.171",   # Pi's own IP
    "192.168.29.54",    # Your Windows machine
    "192.168.29.1",     # Router
}


# Platform guard — these only exist on Linux/Pi
if sys.platform == "linux":
    from core.rule_engine import block_ip
else:
    from mock.mock_nft import block_ip

from core.feature_extractor import extract_features
from core.inference import predict
from monitor.alert_logger import log_alert


INTERFACE = "wlan0"
THRESHOLD = 0.95


def process_packet(ip, timestamp):
    try:
        src_ip = pcap.ntoa(ip.src) if isinstance(ip.src, int) else \
                 ".".join(str(b) for b in ip.src)

        dst_ip = ".".join(str(b) for b in ip.dst) \
                 if hasattr(ip.dst, '__iter__') else str(ip.dst)

        # ✅ Whitelist check BEFORE ML inference
        if src_ip in WHITELIST or dst_ip in WHITELIST:
            return

        features = extract_features(ip)
        score = predict(features)

        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip.p, str(ip.p))

        if score > THRESHOLD:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"[ALERT] {src_ip} → {dst_ip} | {proto} | Score: {score:.2f}")
            block_ip(src_ip)
            log_alert(src_ip, dst_ip, proto, score)
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"[OK]    {src_ip} → {dst_ip} | {proto} | len={ip.len}")

    except Exception as e:
        pass


def start_capture():
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
    print("-" * 50)

    try:
        for timestamp, raw in pc:
            try:
                eth = dpkt.ethernet.Ethernet(raw)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                process_packet(eth.data, timestamp)
            except dpkt.dpkt.NeedData:
                pass
            except Exception:
                pass

    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")
    finally:
        print("[*] Closing capture.")


if __name__ == "__main__":
    start_capture()
