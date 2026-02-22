

import dpkt
import numpy as np

TCP_PROTO = 6
UDP_PROTO = 17
ICMP_PROTO = 1


def extract_features(ip: dpkt.ip.IP) -> np.ndarray:

    proto = ip.p
    pkt_len = ip.len
    ttl = ip.ttl
    src_port = 0  # Source port (default 0 for non-TCP/UDP)
    dst_port = 0  # Destination port (default 0 for non-TCP/UDP)
    tcp_flags = 0  # TCP flags (default 0 for non-TCP)

    try:
        if ip.p == TCP_PROTO and isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            src_port = tcp.sport  # TCP source port
            dst_port = tcp.dport  # TCP destination port
            tcp_flags = tcp.flags  # TCP flags (SYN, ACK, FIN, etc.)

        # Extract UDP-specific features
        elif ip.p == UDP_PROTO and isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            src_port = udp.sport  # UDP source port
            dst_port = udp.dport  # UDP destination port

    except (AttributeError, dpkt.dpkt.UnpackError):

        pass


    return np.array(
        [[proto, src_port, dst_port, pkt_len, ttl, tcp_flags]],
        dtype=np.float32
    )