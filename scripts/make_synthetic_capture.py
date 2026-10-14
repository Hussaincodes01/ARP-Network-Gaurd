#!/usr/bin/env python3
"""Generate labelled synthetic LAN captures for demos and tests.

The real benchmark is the Kitsune "ARP MitM" capture (see
scripts/fetch_kitsune.py); this script builds a smaller, fully labelled
stand-in that runs anywhere and fits in the repo. Both are analysed by the
same pipeline.

Network 192.168.1.0/24, captured on a switch mirror port:
  .1  gateway / DHCP server (TP-Link)      .20 IP camera (Hikvision) -> streams to .25
  .10 laptop (Dell)                         .25 NVR (Raspberry Pi)
  .11 MacBook (Apple)                       .30 printer (Brother)
  .12 phone (Google), later a smart plug    .66 Kali VM (VMware), the attacker

Timeline of the attack capture (seconds):
  0-450    normal traffic (Kitsune learns on roughly the first 300 s)
  60       attacker VM joins via DHCP (benign until 450)
  320-330  phone leaves; a smart plug takes .12 via DHCP          -> legitimate change
  375-385  printer NIC replaced, same static IP, new MAC          -> legitimate change
  410-418  MacBook port-scans the NVR                              -> anomaly, not ARP
  450-690  Ettercap-style ARP MitM: host scan, then poison replies every
           10 s between {gateway, NVR} and {laptop, MacBook, camera};
           intercepted traffic is relayed through the attacker
  690-693  attacker restores the real bindings and stops
  693-780  normal traffic

Labels: 1 for every frame sent to or from the attacker's MAC during the
attack (scan, poison, relayed traffic, restore), else 0.

Usage:
  python scripts/make_synthetic_capture.py            # writes data/*.pcap + labels
  python scripts/make_synthetic_capture.py --benign   # only the benign home capture
"""
from __future__ import annotations

import argparse
import random
import socket
import struct
import sys
from array import array
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from arpguard.core.parser import write_pcap  # noqa: E402

SNAPLEN = 96
BCAST = "ff:ff:ff:ff:ff:ff"


def mac_b(m: str) -> bytes:
    return bytes.fromhex(m.replace(":", ""))


def ip_b(ip: str) -> bytes:
    return socket.inet_aton(ip)


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(array("H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return socket.htons(~s & 0xFFFF)


def eth(dst: str, src: str, etype: int, payload: bytes) -> bytes:
    frame = mac_b(dst) + mac_b(src) + struct.pack("!H", etype) + payload
    return frame + b"\0" * max(0, 60 - len(frame))


def arp_frame(op: int, sha: str, spa: str, tha: str, tpa: str,
              eth_dst: str | None = None, eth_src: str | None = None) -> bytes:
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mac_b(sha) + ip_b(spa) + mac_b(tha) + ip_b(tpa)
    return eth(eth_dst or (BCAST if op == 1 else tha), eth_src or sha, 0x0806, body)


class IPv4:
    ident = 1

    @classmethod
    def build(cls, src: str, dst: str, proto: int, l4: bytes, ttl: int = 64) -> bytes:
        cls.ident = (cls.ident + 1) & 0xFFFF
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), cls.ident, 0x4000, ttl, proto, 0,
                          ip_b(src), ip_b(dst))
        hdr = hdr[:10] + struct.pack("H", csum(hdr)) + hdr[12:]
        return hdr + l4


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    pseudo = ip_b(src) + ip_b(dst) + struct.pack("!BBH", 0, 17, len(seg))
    c = csum(pseudo + seg) or 0xFFFF
    return seg[:6] + struct.pack("H", c) + seg[8:]


def tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int,
        payload: bytes = b"", window: int = 64240) -> bytes:
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4,
                      flags, window, 0, 0) + payload
    pseudo = ip_b(src) + ip_b(dst) + struct.pack("!BBH", 0, 6, len(seg))
    return seg[:16] + struct.pack("H", csum(pseudo + seg)) + seg[18:]


SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04


def dhcp_payload(op: int, xid: int, chaddr: str, msg_type: int, yiaddr: str = "0.0.0.0",
                 router: str | None = None, server: str | None = None,
                 requested: str | None = None) -> bytes:
    p = struct.pack("!BBBBIHH4s4s4s4s", op, 1, 6, 0, xid, 0, 0x8000, ip_b("0.0.0.0"),
                    ip_b(yiaddr), ip_b(server or "0.0.0.0"), ip_b("0.0.0.0"))
    p += mac_b(chaddr) + b"\0" * 10 + b"\0" * 192 + b"\x63\x82\x53\x63"
    p += bytes([53, 1, msg_type])
    if requested:
        p += bytes([50, 4]) + ip_b(requested)
    if server:
        p += bytes([54, 4]) + ip_b(server)
    if router:
        p += bytes([1, 4]) + ip_b("255.255.255.0") + bytes([3, 4]) + ip_b(router)
        p += bytes([51, 4]) + struct.pack("!I", 86400) + bytes([6, 4]) + ip_b(router)
    return p + b"\xff"


# ---------------------------------------------------------------------------

GW = ("192.168.1.1", "50:c7:bf:3a:1c:01")
LAPTOP = ("192.168.1.10", "b8:ac:6f:52:7e:10")
MACBOOK = ("192.168.1.11", "00:25:00:a1:b2:11")
PHONE = ("192.168.1.12", "f4:f5:d8:6e:21:12")
PLUG = ("192.168.1.12", "24:0a:c4:9d:33:12")
CAMERA = ("192.168.1.20", "44:19:b6:0c:55:20")
NVR = ("192.168.1.25", "b8:27:eb:44:aa:25")
PRINTER_OLD = ("192.168.1.30", "00:80:77:5b:10:30")
PRINTER_NEW = ("192.168.1.30", "00:80:77:5b:99:30")
ATTACKER = ("192.168.1.66", "00:0c:29:7d:e1:66")
BACKUP_GW_MAC = "20:4e:7f:c4:08:01"

INTERNET = ["142.250.183.14", "104.16.132.229", "151.101.1.69", "52.84.150.12",
            "13.107.42.14", "140.82.112.4", "35.186.224.25", "17.253.144.10"]
CLOUD_STORAGE = "34.120.54.55"
MQTT_BROKER = "3.120.181.40"
NTP = "162.159.200.1"


class World:
    def __init__(self, seed: int, duration: float, plug_at: float | None = None,
                 printer_swap_at: float | None = None, gateway_swap_at: float | None = None):
        self.rng = random.Random(seed)
        self.duration = duration
        self.frames: list[tuple[float, bytes, int]] = []   # (ts, frame, label)
        self.base = 1_760_000_000.0                      # capture start epoch
        self.attack: tuple[float, float] | None = None
        self.attacker_mac = ATTACKER[1]
        self.plug_at = plug_at
        self.printer_swap_at = printer_swap_at
        self.gateway_swap_at = gateway_swap_at

    # Which device holds a role at time t
    def phone(self, t: float) -> tuple:
        return PLUG if self.plug_at is not None and t >= self.plug_at else PHONE

    def phone_gone(self, t: float) -> bool:
        """The phone has left and the plug hasn't finished joining yet."""
        return self.plug_at is not None and self.plug_at - 10 <= t < self.plug_at + 2

    def printer(self, t: float) -> tuple:
        return PRINTER_NEW if self.printer_swap_at is not None and t >= self.printer_swap_at else PRINTER_OLD

    def printer_gone(self, t: float) -> bool:
        return self.printer_swap_at is not None and self.printer_swap_at - 10 <= t < self.printer_swap_at + 1

    def gw(self, t: float) -> tuple:
        if self.gateway_swap_at is not None and t >= self.gateway_swap_at:
            return (GW[0], BACKUP_GW_MAC)
        return GW

    def add(self, t: float, frame: bytes, label: int = 0) -> None:
        if 0 <= t <= self.duration:
            self.frames.append((t, frame, label))

    # Where does a frame from `src_ip` to `dst_ip` go at time t (ARP cache view)?
    def next_hop(self, t: float, src_ip: str, dst_ip: str) -> str:
        local = dst_ip.startswith("192.168.1.")
        target = dst_ip if local else GW[0]
        if self.poisoned(t, src_ip, target):
            return self.attacker_mac
        return self.owner(t, target)

    def owner(self, t: float, ip: str) -> str:
        if ip == GW[0]:
            return self.gw(t)[1]
        if ip == PHONE[0]:
            return self.phone(t)[1]
        if ip == PRINTER_OLD[0]:
            return self.printer(t)[1]
        return {LAPTOP[0]: LAPTOP[1], MACBOOK[0]: MACBOOK[1], CAMERA[0]: CAMERA[1],
                NVR[0]: NVR[1], ATTACKER[0]: ATTACKER[1]}[ip]

    def poisoned(self, t: float, src_ip: str, target_ip: str) -> bool:
        if not self.attack:
            return False
        a0, a1 = self.attack
        if not (a0 + 3.0 <= t < a1):
            return False
        victims = {LAPTOP[0], MACBOOK[0], CAMERA[0]}
        group2 = {GW[0], NVR[0]}
        return (src_ip in victims and target_ip in group2) or (src_ip in group2 and target_ip in victims)

    def send_ip(self, t: float, src: tuple, dst_ip: str, l3: bytes, external_src: str | None = None) -> None:
        """Emit an IP packet from host `src` (or from the internet via the gateway when
        external_src is set), relaying it through the attacker if caches are poisoned."""
        if external_src is not None:
            # Inbound from the internet: the gateway forwards to the LAN host
            hop = self.next_hop(t, GW[0], dst_ip)
            frame = eth(hop, self.gw(t)[1], 0x0800, l3)
            if hop == self.attacker_mac and dst_ip != ATTACKER[0]:
                self.add(t, frame, 1)
                d = self.rng.uniform(0.0003, 0.002)
                self.add(t + d, eth(self.owner(t, dst_ip), self.attacker_mac, 0x0800, l3), 1)
            else:
                self.add(t, frame)
            return
        hop = self.next_hop(t, src[0], dst_ip)
        frame = eth(hop, src[1], 0x0800, l3)
        if hop == self.attacker_mac and src[1] != self.attacker_mac and dst_ip != ATTACKER[0]:
            self.add(t, frame, 1)
            local = dst_ip.startswith("192.168.1.")
            real = self.owner(t, dst_ip) if local else self.gw(t)[1]
            d = self.rng.uniform(0.0003, 0.002)
            self.add(t + d, eth(real, self.attacker_mac, 0x0800, l3), 1)
        else:
            self.add(t, frame)

    # ------------------------------------------------------------ behaviours
    def tcp_session(self, t: float, host: tuple, server: str, port: int, down_pkts: int,
                    up_pkts: int = 2, rtt: float = 0.03) -> float:
        r = self.rng
        sport = r.randint(49152, 65000)
        seq, sseq = r.getrandbits(32), r.getrandbits(32)
        c, s = host[0], server
        self.send_ip(t, host, s, IPv4.build(c, s, 6, tcp(c, s, sport, port, seq, 0, SYN)))
        t += rtt
        if s.startswith("192.168.1."):
            self.send_ip(t, self.host_by_ip(s, t), c, IPv4.build(s, c, 6, tcp(s, c, port, sport, sseq, seq + 1, SYN | ACK)))
        else:
            self.send_ip(t, None, c, IPv4.build(s, c, 6, tcp(s, c, port, sport, sseq, seq + 1, SYN | ACK), ttl=57),
                         external_src=s)
        t += 0.0005
        self.send_ip(t, host, s, IPv4.build(c, s, 6, tcp(c, s, sport, port, seq + 1, sseq + 1, ACK)))
        for _ in range(up_pkts):
            t += r.uniform(0.001, 0.01)
            n = r.randint(200, 700)
            self.send_ip(t, host, s, IPv4.build(c, s, 6, tcp(c, s, sport, port, seq + 1, sseq + 1, PSH | ACK, b"\x17" * n)))
            seq += n
        t += rtt
        for i in range(down_pkts):
            t += r.expovariate(400)
            n = 1448 if i < down_pkts - 1 else r.randint(100, 1448)
            l3 = IPv4.build(s, c, 6, tcp(s, c, port, sport, sseq + 1, seq + 1, ACK, b"\x17" * n), ttl=57)
            if s.startswith("192.168.1."):
                self.send_ip(t, self.host_by_ip(s, t), c, l3)
            else:
                self.send_ip(t, None, c, l3, external_src=s)
            sseq += n
            if i % 2 == 1:
                self.send_ip(t + 0.0002, host, s, IPv4.build(c, s, 6, tcp(c, s, sport, port, seq + 1, sseq + 1, ACK)))
        t += 0.002
        self.send_ip(t, host, s, IPv4.build(c, s, 6, tcp(c, s, sport, port, seq + 1, sseq + 1, FIN | ACK)))
        return t

    def host_by_ip(self, ip: str, t: float) -> tuple:
        return (ip, self.owner(t, ip))

    def dns(self, t: float, host: tuple) -> None:
        r = self.rng
        sport = r.randint(30000, 60000)
        q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x07example\x03com\x00\x00\x01\x00\x01"
        self.send_ip(t, host, GW[0], IPv4.build(host[0], GW[0], 17, udp(host[0], GW[0], sport, 53, q)))
        ans = q + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04" + ip_b(r.choice(INTERNET))
        self.send_ip(t + r.uniform(0.004, 0.02), self.gw(t), host[0],
                     IPv4.build(GW[0], host[0], 17, udp(GW[0], host[0], 53, sport, ans)))

    def arp_exchange(self, t: float, asker: tuple, target_ip: str) -> None:
        owner_mac = self.owner(t, target_ip)
        self.add(t, arp_frame(1, asker[1], asker[0], "00:00:00:00:00:00", target_ip))
        self.add(t + self.rng.uniform(0.0005, 0.004),
                 arp_frame(2, owner_mac, target_ip, asker[1], asker[0]))
        # Ettercap answers requests for poisoned IPs too, racing the real owner
        if self.poisoned(t, asker[0], target_ip):
            self.add(t + self.rng.uniform(0.002, 0.01),
                     arp_frame(2, self.attacker_mac, target_ip, asker[1], asker[0]), 1)

    def dhcp_join(self, t: float, host: tuple) -> float:
        xid = self.rng.getrandbits(32)
        c = host[1]

        def bootp(src_ip, dst_ip, sport, dport, payload, src_mac, dst_mac):
            return eth(dst_mac, src_mac, 0x0800,
                       IPv4.build(src_ip, dst_ip, 17, udp(src_ip, dst_ip, sport, dport, payload)))
        self.add(t, bootp("0.0.0.0", "255.255.255.255", 68, 67, dhcp_payload(1, xid, c, 1), c, BCAST))
        t += 0.01
        self.add(t, bootp(GW[0], host[0], 67, 68, dhcp_payload(2, xid, c, 2, host[0], GW[0], GW[0]), self.gw(t)[1], c))
        t += 0.02
        self.add(t, bootp("0.0.0.0", "255.255.255.255", 68, 67,
                          dhcp_payload(1, xid, c, 3, requested=host[0], server=GW[0]), c, BCAST))
        t += 0.01
        self.add(t, bootp(GW[0], host[0], 67, 68, dhcp_payload(2, xid, c, 5, host[0], GW[0], GW[0]), self.gw(t)[1], c))
        # RFC 5227: probe the address, then announce it
        for i in range(3):
            t += self.rng.uniform(0.2, 0.5)
            self.add(t, arp_frame(1, c, "0.0.0.0", "00:00:00:00:00:00", host[0]))
        for i in range(2):
            t += 1.0
            self.add(t, arp_frame(1, c, host[0], "00:00:00:00:00:00", host[0]))
        return t


def build(attack: bool, seed: int, duration: float, plug_at: float | None = None,
          printer_swap_at: float | None = None, gateway_swap_at: float | None = None,
          port_scan_at: float | None = None) -> World:
    w = World(seed, duration, plug_at, printer_swap_at, gateway_swap_at)
    r = w.rng
    if attack:
        w.attack = (450.0, 690.0)

    # --- camera -> NVR RTP stream (~20 pps) and RTCP
    t = 0.5
    while t < duration:
        size = r.randint(900, 1400) if r.random() < 0.9 else r.randint(200, 600)
        w.send_ip(t, CAMERA, NVR[0], IPv4.build(CAMERA[0], NVR[0], 17,
                                               udp(CAMERA[0], NVR[0], 5004, 5004, b"\x80" * size)))
        t += r.gauss(1 / 20, 0.005)
    t = 1.0
    while t < duration:
        w.send_ip(t, NVR, CAMERA[0], IPv4.build(NVR[0], CAMERA[0], 17, udp(NVR[0], CAMERA[0], 5005, 5005, b"\x81" * 52)))
        w.send_ip(t + 0.01, CAMERA, NVR[0], IPv4.build(CAMERA[0], NVR[0], 17, udp(CAMERA[0], NVR[0], 5005, 5005, b"\x81" * 60)))
        t += r.gauss(1.0, 0.02)

    # --- laptop / MacBook / phone / attacker browsing
    def browsing(host, mean_gap, start, stop, heavy=1.0):
        t = start + r.uniform(0, 3)
        while t < stop:
            w.dns(t, host)
            server = r.choice(INTERNET)
            w.tcp_session(t + 0.03, host, server, 443, down_pkts=int(r.randint(6, 40) * heavy))
            t += r.expovariate(1 / mean_gap)

    browsing(LAPTOP, 5.0, 0, duration)
    browsing(MACBOOK, 9.0, 0, duration)
    browsing(PHONE, 15.0, 0, plug_at - 10 if plug_at else duration, heavy=0.4)
    browsing(ATTACKER, 25.0, 62, 440 if attack else duration, heavy=0.5)

    # --- NVR uploads a clip to the cloud every ~60 s
    t = 20.0
    while t < duration:
        w.tcp_session(t, NVR, CLOUD_STORAGE, 443, down_pkts=8, up_pkts=r.randint(80, 140))
        t += r.gauss(60, 3)

    # --- laptop polls the printer (IPP) every ~30 s; mDNS chatter; NTP
    t = 7.0
    while t < duration:
        if not w.printer_gone(t):
            w.tcp_session(t, LAPTOP, w.printer(t)[0], 631, down_pkts=3, up_pkts=1, rtt=0.004)
        t += r.gauss(30, 2)
    for host, period in ((MACBOOK, 20), (PRINTER_OLD, 30), (PHONE, 25)):
        t = r.uniform(0, period)
        while t < duration:
            h = host
            if host is PRINTER_OLD:
                if w.printer_gone(t):
                    t += period
                    continue
                h = w.printer(t)
            if host is PHONE:
                if w.phone_gone(t):
                    t += period
                    continue
                h = w.phone(t)
            mdns = IPv4.build(h[0], "224.0.0.251", 17, udp(h[0], "224.0.0.251", 5353, 5353, b"\0" * r.randint(40, 300)), ttl=255)
            w.add(t, eth("01:00:5e:00:00:fb", h[1], 0x0800, mdns))
            t += r.gauss(period, 1)
    for host in (LAPTOP, MACBOOK, CAMERA, NVR):
        t = r.uniform(0, 64)
        while t < duration:
            w.send_ip(t, host, NTP, IPv4.build(host[0], NTP, 17, udp(host[0], NTP, 123, 123, b"\x23" + b"\0" * 47)))
            w.send_ip(t + 0.02, None, host[0], IPv4.build(NTP, host[0], 17, udp(NTP, host[0], 123, 123, b"\x24" + b"\0" * 47), ttl=57), external_src=NTP)
            t += r.gauss(64, 2)

    # --- smart plug (after it joins) keeps an MQTT session alive
    if plug_at is not None:
        t = plug_at + 5
        while t < duration:
            w.tcp_session(t, PLUG, MQTT_BROKER, 8883, down_pkts=1, up_pkts=1, rtt=0.05)
            t += r.gauss(30, 1)

    # --- ARP cache refreshes (every host re-resolves its peers every 60-120 s)
    pairs = [(LAPTOP, GW[0]), (MACBOOK, GW[0]), (CAMERA, NVR[0]), (NVR, CAMERA[0]), (NVR, GW[0]),
             (GW, LAPTOP[0]), (GW, MACBOOK[0]), (GW, NVR[0]), (LAPTOP, PRINTER_OLD[0]),
             (PHONE, GW[0]), (GW, PHONE[0]), (ATTACKER, GW[0]), (GW, CAMERA[0])]
    for asker, target in pairs:
        t = r.uniform(2, 60)
        while t < duration:
            a = asker
            if asker is PHONE:
                if w.phone_gone(t):
                    t += 30
                    continue
                a = w.phone(t)
            if asker is GW:
                a = w.gw(t)
            if asker is ATTACKER and t < 61:
                t += 30
                continue
            if (target == PRINTER_OLD[0] and w.printer_gone(t)) or (target == PHONE[0] and w.phone_gone(t)):
                t += 15
                continue
            w.arp_exchange(t, a, target)
            t += r.uniform(60, 120)

    # --- the attacker VM joins the network
    w.dhcp_join(60.0, ATTACKER)

    if plug_at is not None:
        # phone leaves; smart plug gets .12 from DHCP
        w.dhcp_join(plug_at, PLUG)
    if printer_swap_at is not None:
        # printer NIC swap: static IP, new board announces itself
        for i in range(2):
            w.add(printer_swap_at + i, arp_frame(1, PRINTER_NEW[1], PRINTER_NEW[0], "00:00:00:00:00:00", PRINTER_NEW[0]))
    if gateway_swap_at is not None:
        # the ISP router is replaced by a backup router with a new MAC
        for i in range(2):
            w.add(gateway_swap_at + i, arp_frame(1, BACKUP_GW_MAC, GW[0], "00:00:00:00:00:00", GW[0]))
    if port_scan_at is not None:
        # MacBook port-scans the NVR (unrelated to ARP)
        t = port_scan_at
        for port in r.sample(range(1, 10000), 1000):
            sp = r.randint(40000, 60000)
            w.send_ip(t, MACBOOK, NVR[0], IPv4.build(MACBOOK[0], NVR[0], 6, tcp(MACBOOK[0], NVR[0], sp, port, r.getrandbits(32), 0, SYN, window=1024)))
            w.send_ip(t + 0.0004, NVR, MACBOOK[0], IPv4.build(NVR[0], MACBOOK[0], 6, tcp(NVR[0], MACBOOK[0], port, sp, 0, 1, RST | ACK, window=0)))
            t += r.expovariate(125)
    if attack:
        _ettercap(w)
    return w


def _ettercap(w: World) -> None:
    r = w.rng
    a0, a1 = w.attack
    A = ATTACKER
    # 1. host discovery: ARP request for every address in the /24
    t = a0
    live = {GW[0], LAPTOP[0], MACBOOK[0], PHONE[0], CAMERA[0], NVR[0], PRINTER_OLD[0]}  # by IP
    for i in range(1, 255):
        ip = f"192.168.1.{i}"
        if ip == A[0]:
            continue
        w.add(t, arp_frame(1, A[1], A[0], "00:00:00:00:00:00", ip), 1)
        if ip in live:
            owner = w.owner(t, ip)
            w.add(t + r.uniform(0.0005, 0.003), arp_frame(2, owner, ip, A[1], A[0]), 1)
        t += 0.01
    # 2. poisoning: warm-up at 1 s intervals, then every 10 s
    group1 = [LAPTOP, MACBOOK, CAMERA]
    group2 = [GW, NVR]
    times = [a0 + 3 + i for i in range(3)]
    t = times[-1] + 10
    while t < a1:
        times.append(t)
        t += 10
    for t in times:
        for v in group1:
            for g in group2:
                w.add(t, arp_frame(2, A[1], g[0], v[1], v[0]), 1)              # tell v: g is at A
                w.add(t + 0.001, arp_frame(2, A[1], v[0], g[1], g[0]), 1)      # tell g: v is at A
                t += 0.002
    # 3. restore real bindings on exit (sent from the attacker, real MACs as source)
    for i in range(3):
        t = a1 + i
        for v in group1:
            for g in group2:
                w.add(t, arp_frame(2, g[1], g[0], v[1], v[0]), 1)
                w.add(t + 0.001, arp_frame(2, v[1], v[0], g[1], g[0]), 1)
                t += 0.002


def is_dhcp(frame: bytes) -> bool:
    return frame[12:14] == b"\x08\x00" and frame[23] == 17 and frame[34:38] in (
        b"\x00\x44\x00\x43", b"\x00\x43\x00\x44")


def write(w: World, pcap: Path, labels: Path | None) -> None:
    frames = sorted(w.frames, key=lambda f: f[0])
    # Truncate like the Kitsune captures, but keep DHCP whole: the rule engine
    # reads the DHCP options (lease, router) the way DHCP snooping does.
    n = write_pcap(pcap, ((w.base + t, data if is_dhcp(data) else data[:SNAPLEN], len(data))
                          for t, data, _ in frames), snaplen=65535)
    if labels is not None:
        with open(labels, "w") as fh:
            fh.write("index,label\n")
            for i, (_, _, lab) in enumerate(frames):
                fh.write(f"{i},{lab}\n")
    mal = sum(f[2] for f in frames)
    print(f"wrote {pcap.relative_to(ROOT)}: {n} packets, {mal} labelled malicious, "
          f"{pcap.stat().st_size / 1e6:.1f} MB")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benign", action="store_true", help="only write the benign home capture")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    out = ROOT / "data"
    out.mkdir(exist_ok=True)
    if not args.benign:
        # The rebuilds of build() re-seed the RNG, so the attack capture is reproducible
        write(build(True, args.seed, 780.0, plug_at=330.0, printer_swap_at=385.0, port_scan_at=410.0),
              out / "arp_mitm_synthetic.pcap", out / "arp_mitm_synthetic_labels.csv")
    # A different day on the same LAN: no attack; the smart plug joins and the
    # ISP router is swapped for a backup router (a one-off gateway MAC change)
    write(build(False, args.seed + 1, 600.0, plug_at=260.0, gateway_swap_at=400.0),
          out / "home_benign_synthetic.pcap", out / "home_benign_synthetic_labels.csv")


if __name__ == "__main__":
    main()
