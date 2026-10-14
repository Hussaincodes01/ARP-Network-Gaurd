import gzip
import struct

from helpers import GW_IP, GW_MAC, HOST_IP, HOST_MAC, arp_frame, dhcp_ack, eth

from arpguard.core.parser import ETH_P_ARP, decode_frame, read_packets, write_pcap


def test_arp_request_and_reply_decode():
    p = decode_frame(arp_frame(1, HOST_MAC, HOST_IP, "00:00:00:00:00:00", GW_IP), 1.0, 60)
    assert p.ethertype == ETH_P_ARP and p.eth_dst == "ff:ff:ff:ff:ff:ff" and p.eth_src == HOST_MAC
    assert (p.arp.op, p.arp.sha, p.arp.spa, p.arp.tpa, p.arp.kind) == (1, HOST_MAC, HOST_IP, GW_IP, "request")
    r = decode_frame(arp_frame(2, GW_MAC, GW_IP, HOST_MAC, HOST_IP), 1.1, 60)
    assert r.arp.kind == "reply" and r.eth_dst == HOST_MAC


def test_gratuitous_and_probe_kinds():
    g = decode_frame(arp_frame(1, HOST_MAC, HOST_IP, "00:00:00:00:00:00", HOST_IP), 0, 60)
    pr = decode_frame(arp_frame(1, HOST_MAC, "0.0.0.0", "00:00:00:00:00:00", HOST_IP), 0, 60)
    assert g.arp.kind == "gratuitous" and pr.arp.kind == "probe"


def test_vlan_tag_is_skipped():
    frame = arp_frame(1, HOST_MAC, HOST_IP, "00:00:00:00:00:00", GW_IP)
    tagged = frame[:12] + b"\x81\x00\x00\x0a" + frame[12:]
    p = decode_frame(tagged, 0, len(tagged))
    assert p.vlan == 10 and p.arp is not None and p.arp.tpa == GW_IP


def test_dhcp_ack_options():
    p = dhcp_ack(HOST_MAC, HOST_IP, 5.0)
    assert p.dhcp.msg_type == "ACK" and p.dhcp.yiaddr == HOST_IP
    assert p.dhcp.client_mac == HOST_MAC and p.dhcp.router == GW_IP


def test_pcap_roundtrip_keeps_original_length(tmp_path):
    big = eth(GW_MAC, HOST_MAC, 0x0800, b"\x45" + b"\0" * 1400)
    path = tmp_path / "t.pcap"
    write_pcap(path, [(100.25, big, len(big)), (100.5, arp_frame(1, HOST_MAC, HOST_IP, "00:00:00:00:00:00", GW_IP), 60)], snaplen=96)
    pk = list(read_packets(path))
    assert len(pk) == 2 and pk[0].length == len(big) and abs(pk[0].ts - 100.25) < 1e-6
    assert pk[1].arp.spa == HOST_IP
    # gzip transparently
    gz = tmp_path / "t.pcap.gz"
    gz.write_bytes(gzip.compress(path.read_bytes()))
    assert [p.index for p in read_packets(gz)] == [0, 1]
    # bytes input, slice
    assert [p.index for p in read_packets(path.read_bytes(), start=1)] == [1]


def _block(btype: int, body: bytes) -> bytes:
    body += b"\0" * ((4 - len(body) % 4) % 4)
    ln = 12 + len(body)
    return struct.pack("<II", btype, ln) + body + struct.pack("<I", ln)


def test_pcapng_with_nanosecond_resolution():
    frame = arp_frame(2, GW_MAC, GW_IP, HOST_MAC, HOST_IP)
    shb = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    opts = struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)    # if_tsresol = 10^-9
    idb = _block(1, struct.pack("<HHI", 1, 0, 65535) + opts)
    ts_ns = 1_700_000_000_123_456_789
    epb = _block(6, struct.pack("<IIIII", 0, ts_ns >> 32, ts_ns & 0xFFFFFFFF, len(frame), len(frame)) + frame)
    pk = list(read_packets(shb + idb + epb))
    assert len(pk) == 1 and pk[0].arp.spa == GW_IP
    assert abs(pk[0].ts - 1_700_000_000.123456789) < 1e-6
