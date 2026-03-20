"""Test IDS performance on different hardware."""

import time
import psutil
from live_monitor import process_packet
import dpkt
from socket import inet_aton


def generate_test_packet(src="192.168.30.10", dst="192.168.29.50"):
    """Generate a test packet."""
    ip = dpkt.ip.IP(
        src=inet_aton(src),
        dst=inet_aton(dst),
        p=dpkt.ip.IP_PROTO_TCP
    )
    tcp = dpkt.tcp.TCP(sport=12345, dport=80, flags=dpkt.tcp.TH_SYN)
    ip.data = tcp
    return ip


def test_throughput(num_packets=1000):
    """Test how many packets/second can be processed."""
    print(f"Testing with {num_packets} packets...")

    start_time = time.time()
    start_cpu = psutil.cpu_percent()
    start_mem = psutil.virtual_memory().percent

    for i in range(num_packets):
        packet = generate_test_packet()
        process_packet(packet, time.time())

    elapsed = time.time() - start_time
    end_cpu = psutil.cpu_percent()
    end_mem = psutil.virtual_memory().percent

    print(f"\n=== Performance Results ===")
    print(f"Packets processed: {num_packets}")
    print(f"Time elapsed: {elapsed:.2f} seconds")
    print(f"Throughput: {num_packets / elapsed:.0f} packets/second")
    print(f"CPU usage: {end_cpu:.1f}%")
    print(f"Memory usage: {end_mem:.1f}%")
    print(f"=========================\n")


if __name__ == "__main__":
    test_throughput(1000)