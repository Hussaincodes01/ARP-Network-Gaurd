"""Frame builders shared by the tests (re-exported from the capture generator)."""
from make_synthetic_capture import (ACK, SYN, IPv4, arp_frame, dhcp_payload, eth,  # noqa: F401
                                    tcp, udp)

from arpguard.core.parser import decode_frame

GW_IP, GW_MAC = "192.168.1.1", "50:c7:bf:3a:1c:01"
HOST_IP, HOST_MAC = "192.168.1.10", "b8:ac:6f:52:7e:10"
EVIL_IP, EVIL_MAC = "192.168.1.66", "00:0c:29:7d:e1:66"
ZERO_MAC = "00:00:00:00:00:00"


def pkt(frame: bytes, ts: float, index: int = 0):
    return decode_frame(frame, ts, len(frame), index=index)


def arp(op, sha, spa, tha, tpa, ts, index=0, eth_src=None):
    return pkt(arp_frame(op, sha, spa, tha, tpa, eth_src=eth_src), ts, index)


def ip_packet(src_ip, dst_ip, src_mac, dst_mac, ts, index=0):
    l3 = IPv4.build(src_ip, dst_ip, 6, tcp(src_ip, dst_ip, 50000, 443, 1, 0, ACK, b"x" * 100))
    return pkt(eth(dst_mac, src_mac, 0x0800, l3), ts, index)


def dhcp_ack(client_mac, ip, ts, index=0):
    l3 = IPv4.build(GW_IP, ip, 17, udp(GW_IP, ip, 67, 68, dhcp_payload(2, 1234, client_mac, 5, ip, GW_IP, GW_IP)))
    return pkt(eth(client_mac, GW_MAC, 0x0800, l3), ts, index)
