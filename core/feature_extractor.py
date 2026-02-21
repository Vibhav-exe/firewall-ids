import dpkt
import numpy as np


def extract_features(ip: dpkt.ip.IP) -> np.ndarray:
    proto     = ip.p
    pkt_len   = ip.len
    ttl       = ip.ttl
    src_port  = 0
    dst_port  = 0
    tcp_flags = 0

    if ip.p == dpkt.ip.IP_PROTO_TCP and isinstance(ip.data, dpkt.tcp.TCP):
        tcp       = ip.data
        src_port  = tcp.sport
        dst_port  = tcp.dport
        tcp_flags = tcp.flags

    elif ip.p == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
        udp      = ip.data
        src_port = udp.sport
        dst_port = udp.dport

    return np.array(
        [[proto, src_port, dst_port, pkt_len, ttl, tcp_flags]],
        dtype=np.float32
    )
