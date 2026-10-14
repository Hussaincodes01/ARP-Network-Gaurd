"""Packet parser: pcap / pcapng / raw frames -> `Packet` records.

Written from scratch (no Scapy needed) so the same decoder runs in the
serverless API, in batch evaluation and behind the live sniffer.

Layers decoded:
  * Ethernet II header (dst MAC, src MAC, EtherType), including one 802.1Q tag
  * ARP (EtherType 0x0806): opcode, sender/target hardware + protocol address
  * IPv4 (0x0800): addresses, protocol, TCP/UDP ports, ICMP
  * DHCP (UDP 67/68) inside IPv4: message type, client MAC, assigned IP, router
  * IPv6 (0x86DD): addresses and next header, enough for Kitsune's features
"""
from __future__ import annotations

import gzip
import io
import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator, Optional, Union

ETH_P_IPV4 = 0x0800
ETH_P_ARP = 0x0806
ETH_P_VLAN = 0x8100
ETH_P_IPV6 = 0x86DD

LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
ZERO_IP = "0.0.0.0"

DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
              5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


@dataclass(slots=True)
class ArpInfo:
    op: int            # 1 = request ("who-has"), 2 = reply ("is-at")
    sha: str           # sender hardware (MAC) address
    spa: str           # sender protocol (IPv4) address
    tha: str           # target hardware address
    tpa: str           # target protocol address

    @property
    def kind(self) -> str:
        if self.spa == ZERO_IP:
            return "probe"          # RFC 5227 address-conflict probe
        if self.spa == self.tpa:
            return "gratuitous"     # announcement of the sender's own binding
        return "request" if self.op == 1 else "reply" if self.op == 2 else f"op{self.op}"


@dataclass(slots=True)
class DhcpInfo:
    msg_type: str
    client_mac: str
    yiaddr: str        # "your" (assigned) IP address
    router: Optional[str] = None
    requested_ip: Optional[str] = None


@dataclass(slots=True)
class Packet:
    index: int
    ts: float
    length: int                    # original length on the wire
    eth_src: str
    eth_dst: str
    ethertype: int
    vlan: Optional[int] = None
    arp: Optional[ArpInfo] = None
    ip_version: Optional[int] = None
    ip_src: str = ""
    ip_dst: str = ""
    ip_proto: Optional[int] = None
    sport: Optional[int] = None
    dport: Optional[int] = None
    icmp: bool = False
    dhcp: Optional[DhcpInfo] = None

    @property
    def is_broadcast(self) -> bool:
        return self.eth_dst == BROADCAST_MAC


def mac_str(b: bytes) -> str:
    return b.hex(":")


def ip4_str(b: bytes) -> str:
    return socket.inet_ntoa(b)


def decode_frame(data: bytes, ts: float, length: int, index: int = 0,
                 linktype: int = LINKTYPE_ETHERNET) -> Optional[Packet]:
    """Decode one link-layer frame. Returns None for frames we can't use."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        eth_dst = mac_str(data[0:6])
        eth_src = mac_str(data[6:12])
        ethertype = (data[12] << 8) | data[13]
        off = 14
    elif linktype == LINKTYPE_LINUX_SLL:
        # Linux "cooked" capture: no destination MAC, 16-byte header
        if len(data) < 16:
            return None
        halen = (data[4] << 8) | data[5]
        eth_src = mac_str(data[6:6 + min(halen, 6)]) if halen >= 6 else ZERO_MAC
        pkttype = (data[0] << 8) | data[1]
        eth_dst = BROADCAST_MAC if pkttype == 1 else ZERO_MAC
        ethertype = (data[14] << 8) | data[15]
        off = 16
    else:
        return None

    vlan = None
    if ethertype == ETH_P_VLAN and len(data) >= off + 4:
        vlan = ((data[off] << 8) | data[off + 1]) & 0x0FFF
        ethertype = (data[off + 2] << 8) | data[off + 3]
        off += 4

    pkt = Packet(index=index, ts=ts, length=length, eth_src=eth_src,
                 eth_dst=eth_dst, ethertype=ethertype, vlan=vlan)

    if ethertype == ETH_P_ARP:
        _decode_arp(pkt, data, off)
    elif ethertype == ETH_P_IPV4:
        _decode_ipv4(pkt, data, off)
    elif ethertype == ETH_P_IPV6:
        _decode_ipv6(pkt, data, off)
    return pkt


def _decode_arp(pkt: Packet, data: bytes, off: int) -> None:
    if len(data) < off + 28:
        return
    htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", data, off)
    if htype != 1 or ptype != ETH_P_IPV4 or hlen != 6 or plen != 4:
        return  # not Ethernet/IPv4 ARP
    b = off + 8
    pkt.arp = ArpInfo(op=op,
                      sha=mac_str(data[b:b + 6]), spa=ip4_str(data[b + 6:b + 10]),
                      tha=mac_str(data[b + 10:b + 16]), tpa=ip4_str(data[b + 16:b + 20]))
    # Kitsune keys ARP traffic on the ARP addresses
    pkt.ip_src, pkt.ip_dst = pkt.arp.spa, pkt.arp.tpa


def _decode_ipv4(pkt: Packet, data: bytes, off: int) -> None:
    if len(data) < off + 20:
        return
    ihl = (data[off] & 0x0F) * 4
    pkt.ip_version = 4
    pkt.ip_proto = data[off + 9]
    pkt.ip_src = ip4_str(data[off + 12:off + 16])
    pkt.ip_dst = ip4_str(data[off + 16:off + 20])
    frag_off = ((data[off + 6] & 0x1F) << 8) | data[off + 7]
    l4 = off + ihl
    if frag_off != 0:
        return  # non-first fragment: no transport header
    if pkt.ip_proto in (6, 17) and len(data) >= l4 + 4:
        pkt.sport, pkt.dport = struct.unpack_from("!HH", data, l4)
        if pkt.ip_proto == 17 and {pkt.sport, pkt.dport} <= {67, 68}:
            pkt.dhcp = _decode_dhcp(data, l4 + 8)
    elif pkt.ip_proto == 1:
        pkt.icmp = True


def _decode_ipv6(pkt: Packet, data: bytes, off: int) -> None:
    if len(data) < off + 40:
        return
    pkt.ip_version = 6
    nh = data[off + 6]
    pkt.ip_proto = nh
    pkt.ip_src = socket.inet_ntop(socket.AF_INET6, data[off + 8:off + 24])
    pkt.ip_dst = socket.inet_ntop(socket.AF_INET6, data[off + 24:off + 40])
    l4 = off + 40
    if nh in (6, 17) and len(data) >= l4 + 4:
        pkt.sport, pkt.dport = struct.unpack_from("!HH", data, l4)
    elif nh == 58:
        pkt.icmp = True


def _decode_dhcp(data: bytes, off: int) -> Optional[DhcpInfo]:
    # BOOTP fixed header is 236 bytes, then the magic cookie and options
    if len(data) < off + 240 or data[off + 236:off + 240] != b"\x63\x82\x53\x63":
        return None
    yiaddr = ip4_str(data[off + 16:off + 20])
    chaddr = mac_str(data[off + 28:off + 34])
    msg_type, router, requested = None, None, None
    i = off + 240
    while i < len(data):
        code = data[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(data):
            break
        ln = data[i + 1]
        val = data[i + 2:i + 2 + ln]
        if code == 53 and ln >= 1:
            msg_type = DHCP_TYPES.get(val[0], str(val[0]))
        elif code == 3 and ln >= 4:
            router = ip4_str(val[:4])
        elif code == 50 and ln >= 4:
            requested = ip4_str(val[:4])
        i += 2 + ln
    if msg_type is None:
        return None
    return DhcpInfo(msg_type=msg_type, client_mac=chaddr, yiaddr=yiaddr,
                    router=router, requested_ip=requested)


# --------------------------------------------------------------------------
# Capture file readers
# --------------------------------------------------------------------------

Source = Union[str, Path, bytes, bytearray, BinaryIO]


def _open(source: Source) -> BinaryIO:
    if isinstance(source, (bytes, bytearray)):
        fh: BinaryIO = io.BytesIO(bytes(source))
    elif isinstance(source, (str, Path)):
        fh = open(source, "rb")
    else:
        fh = source
    head = fh.read(2)
    fh.seek(0)
    if head == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=fh)  # type: ignore[return-value]
    return fh


def iter_frames(source: Source) -> Iterator[tuple[float, bytes, int, int]]:
    """Yield (timestamp, captured bytes, original length, linktype)."""
    fh = _open(source)
    try:
        magic = fh.read(4)
        if len(magic) < 4:
            return
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _iter_pcapng(fh, magic)
        else:
            yield from _iter_pcap(fh, magic)
    finally:
        if isinstance(source, (str, Path)):
            fh.close()


def _iter_pcap(fh: BinaryIO, magic: bytes) -> Iterator[tuple[float, bytes, int, int]]:
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
    }
    if magic not in formats:
        raise ValueError("not a pcap or pcapng file")
    endian, scale = formats[magic]
    hdr = fh.read(20)
    if len(hdr) < 20:
        return
    linktype = struct.unpack(endian + "HHiIII", hdr)[5] & 0x0FFFFFFF
    rec = struct.Struct(endian + "IIII")
    while True:
        h = fh.read(16)
        if len(h) < 16:
            return
        sec, frac, caplen, origlen = rec.unpack(h)
        data = fh.read(caplen)
        if len(data) < caplen:
            return  # truncated file
        yield sec + frac * scale, data, origlen, linktype


def _iter_pcapng(fh: BinaryIO, first: bytes) -> Iterator[tuple[float, bytes, int, int]]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, seconds per tick)
    buf = first
    while True:
        head = buf + fh.read(8 - len(buf))
        buf = b""
        if len(head) < 8:
            return
        btype_raw, blen_raw = head[:4], head[4:8]
        if btype_raw == b"\x0a\x0d\x0d\x0a":  # Section Header Block
            bom = fh.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", blen_raw)[0]
            fh.read(blen - 12)
            interfaces = []
            continue
        btype = struct.unpack(endian + "I", btype_raw)[0]
        blen = struct.unpack(endian + "I", blen_raw)[0]
        if blen < 12:
            return
        body = fh.read(blen - 8)
        if len(body) < blen - 8:
            return
        if btype == 1:  # Interface Description Block
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            interfaces.append((linktype, _pcapng_tsresol(body[8:-4], endian)))
        elif btype == 6:  # Enhanced Packet Block
            iface, ts_hi, ts_lo, caplen, origlen = struct.unpack_from(endian + "IIIII", body, 0)
            linktype, tick = interfaces[iface] if iface < len(interfaces) else (1, 1e-6)
            ts = ((ts_hi << 32) | ts_lo) * tick
            yield ts, body[20:20 + caplen], origlen, linktype
        elif btype == 3:  # Simple Packet Block (no timestamp)
            origlen = struct.unpack_from(endian + "I", body, 0)[0]
            linktype = interfaces[0][0] if interfaces else 1
            yield 0.0, body[4:4 + min(origlen, len(body) - 8)], origlen, linktype


def _pcapng_tsresol(opts: bytes, endian: str) -> float:
    i = 0
    while i + 4 <= len(opts):
        code, ln = struct.unpack_from(endian + "HH", opts, i)
        if code == 0:
            break
        if code == 9 and ln >= 1:
            v = opts[i + 4]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        i += 4 + ((ln + 3) & ~3)
    return 1e-6


def read_packets(source: Source, limit: Optional[int] = None,
                 start: int = 0) -> Iterator[Packet]:
    """Parse a capture into `Packet`s. `start`/`limit` select a slice."""
    n = 0
    for i, (ts, data, origlen, linktype) in enumerate(iter_frames(source)):
        if i < start:
            continue
        if limit is not None and n >= limit:
            return
        pkt = decode_frame(data, ts, origlen, index=i, linktype=linktype)
        if pkt is not None:
            n += 1
            yield pkt


def write_pcap(path: Union[str, Path], frames: Iterable[tuple[float, bytes, int]],
               snaplen: int = 65535) -> int:
    """Write (ts, frame bytes, original length) records as a classic pcap.

    Frames longer than `snaplen` are truncated but keep their original length,
    like the Kitsune dataset's truncated captures.
    """
    n = 0
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, LINKTYPE_ETHERNET))
        for ts, data, origlen in frames:
            data = data[:snaplen]
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            if usec >= 1_000_000:
                sec, usec = sec + 1, usec - 1_000_000
            fh.write(struct.pack("<IIII", sec, usec, len(data), max(origlen, len(data))))
            fh.write(data)
            n += 1
    return n
