"""Rule engine: an IP->MAC binding table plus explainable ARP spoofing checks.

Rules
-----
gateway_mac_change  (critical)  the gateway's IP is claimed by a MAC that is not its trusted owner
ip_mac_conflict     (medium)    any other IP is claimed by a MAC that is not its trusted owner
binding_flip_flop   (high)      an IP's binding keeps alternating between MACs (poisoner vs. real owner)
mac_multiple_ips    (medium/high) one MAC claims several IPs, at least one owned by someone else
unsolicited_reply   (low)       an ARP reply nobody asked for (the usual poisoning vehicle)
eth_arp_mismatch    (medium)    Ethernet source MAC differs from the ARP sender MAC
arp_scan            (medium)    one MAC asks for many different IPs in a few seconds
arp_flood           (medium)    ARP broadcast overhead: too many ARP frames per second from one MAC
ip_mac_change       (low)       an IP moved to a new MAC right after a DHCP ACK (DHCP-snooping style)
binding_restored    (info)      the trusted owner reclaimed its IP

"Trusted owner" is the first MAC seen for an IP, or the MAC a DHCP ACK handed
the IP to. Besides alerts, every packet gets an optional per-packet flag
(`spoofed_claim`, `arp_scan`, `eth_arp_mismatch` or `mitm_path`) used for
evaluation and for the "traffic rerouted through the attacker" view.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

from .oui import vendor
from .parser import ZERO_IP, ZERO_MAC, Packet

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class RuleConfig:
    gateway_ip: Optional[str] = None
    request_timeout: float = 5.0      # a reply is "solicited" if asked for within this many seconds
    flipflop_window: float = 120.0
    flipflop_min_changes: int = 3
    multi_ip_window: float = 300.0
    scan_window: float = 5.0
    scan_min_targets: int = 20
    flood_window: float = 1.0
    flood_rate: int = 50
    dhcp_grace: float = 300.0         # a DHCP ACK this recent explains a binding change
    suspect_timeout: float = 120.0
    alert_cooldown: float = 60.0      # repeats of the same (rule, actor, ip) are counted, not re-raised


@dataclass
class Alert:
    id: int
    ts: float
    packet_index: int
    rule: str
    severity: str
    actor: str                    # the MAC this alert is about (claimant / suspect)
    ip: Optional[str] = None
    mac: Optional[str] = None
    old_mac: Optional[str] = None
    message: str = ""
    evidence: dict = field(default_factory=dict)
    repeats: int = 1
    last_ts: float = 0.0

    def to_dict(self, t0: float = 0.0) -> dict:
        return {
            "id": self.id, "t": round(self.ts - t0, 3), "last_t": round(self.last_ts - t0, 3),
            "packet": self.packet_index, "rule": self.rule, "severity": self.severity,
            "actor": self.actor, "ip": self.ip, "mac": self.mac, "old_mac": self.old_mac,
            "message": self.message, "evidence": self.evidence, "repeats": self.repeats,
        }


@dataclass
class Binding:
    ip: str
    mac: str                      # MAC most recently claiming this IP on the wire
    trusted_mac: str              # MAC we believe really owns it
    first_seen: float
    last_seen: float
    history: list = field(default_factory=list)   # [ts, mac, via] on every change
    changes: int = 0


@dataclass
class PacketResult:
    alerts: list
    flag: Optional[str] = None
    actor: Optional[str] = None


def _prefix24(ip: str) -> str:
    return ip.rsplit(".", 1)[0]


class ArpRuleEngine:
    def __init__(self, config: Optional[RuleConfig] = None):
        self.cfg = config or RuleConfig()
        self.bindings: dict[str, Binding] = {}
        self.mac_ips: dict[str, dict[str, float]] = defaultdict(dict)
        self.mac_last_seen: dict[str, float] = {}
        self.pending: dict[tuple[str, str], float] = {}         # (asker ip, wanted ip) -> ts
        self.leases: dict[str, tuple[str, float]] = {}          # ip -> (mac, ts) from DHCP ACK
        self.suspects: dict[str, dict] = {}                     # mac -> {first, last, ips}
        self.arp_times: dict[str, deque] = defaultdict(deque)
        self.req_targets: dict[str, deque] = defaultdict(deque)
        self.local_prefixes: set[str] = set()
        self.next_hops: Counter = Counter()
        self.gateway_ip: Optional[str] = self.cfg.gateway_ip
        self.gateway_source = "configured" if self.gateway_ip else None
        self.alerts: list[Alert] = []
        self._last_alert: dict[tuple, Alert] = {}
        self.arp_packets = 0

    # ------------------------------------------------------------------ API
    def process(self, pkt: Packet) -> PacketResult:
        res = PacketResult(alerts=[])
        self.mac_last_seen[pkt.eth_src] = pkt.ts
        if pkt.dhcp is not None:
            self._on_dhcp(pkt)
        if pkt.arp is not None:
            self._on_arp(pkt, res)
        elif pkt.ip_version == 4:
            self._learn_next_hop(pkt)
            if self.suspects:
                self._mitm_check(pkt, res)
        return res

    def accept_binding(self, ip: str, mac: str) -> None:
        """Operator/fusion decided a change is legitimate: trust the new MAC."""
        b = self.bindings.get(ip)
        if b is not None:
            b.trusted_mac = mac
        s = self.suspects.get(mac)
        if s is not None:
            s["ips"].discard(ip)
            if not s["ips"]:
                del self.suspects[mac]

    def gateway(self) -> tuple[Optional[str], Optional[str]]:
        ip = self.gateway_ip or self._inferred_gateway_ip()
        b = self.bindings.get(ip) if ip else None
        return ip, (b.trusted_mac if b else None)

    def is_local(self, ip: str) -> bool:
        return _prefix24(ip) in self.local_prefixes

    # ---------------------------------------------------------------- rules
    def _emit(self, res: PacketResult, pkt: Packet, rule: str, severity: str, actor: str,
              message: str, ip: Optional[str] = None, mac: Optional[str] = None,
              old_mac: Optional[str] = None, evidence: Optional[dict] = None) -> None:
        key = (rule, actor, ip)
        prev = self._last_alert.get(key)
        if prev is not None and pkt.ts - prev.last_ts <= self.cfg.alert_cooldown:
            prev.repeats += 1
            prev.last_ts = pkt.ts
            return
        alert = Alert(id=len(self.alerts) + 1, ts=pkt.ts, packet_index=pkt.index, rule=rule,
                      severity=severity, actor=actor, ip=ip, mac=mac, old_mac=old_mac,
                      message=message, evidence=evidence or {}, last_ts=pkt.ts)
        self._last_alert[key] = alert
        self.alerts.append(alert)
        res.alerts.append(alert)

    def _on_dhcp(self, pkt: Packet) -> None:
        d = pkt.dhcp
        if d.msg_type == "ACK" and d.yiaddr != ZERO_IP:
            self.leases[d.yiaddr] = (d.client_mac, pkt.ts)
        if d.router and d.msg_type in ("ACK", "OFFER") and self.gateway_source != "configured":
            self.gateway_ip, self.gateway_source = d.router, "dhcp"

    def _on_arp(self, pkt: Packet, res: PacketResult) -> None:
        a, t, cfg = pkt.arp, pkt.ts, self.cfg
        self.arp_packets += 1

        # Broadcast overhead: ARP frames per second from one sender
        times = self.arp_times[a.sha]
        times.append(t)
        while times and t - times[0] > cfg.flood_window:
            times.popleft()
        if len(times) >= cfg.flood_rate:
            self._emit(res, pkt, "arp_flood", "medium", a.sha,
                       f"{a.sha} sent {len(times)} ARP frames in {cfg.flood_window:g}s",
                       mac=a.sha, evidence={"rate": len(times), "vendor": vendor(a.sha)})

        if a.op == 1:
            targets = self.req_targets[a.sha]
            targets.append((t, a.tpa))
            while targets and t - targets[0][0] > cfg.scan_window:
                targets.popleft()
            distinct = len({ip for _, ip in targets})
            if distinct >= cfg.scan_min_targets:
                self._emit(res, pkt, "arp_scan", "medium", a.sha,
                           f"{a.sha} asked for {distinct} different IPs in {cfg.scan_window:g}s (host discovery)",
                           ip=a.spa, mac=a.sha,
                           evidence={"distinct_targets": distinct, "vendor": vendor(a.sha)})
                res.flag, res.actor = "arp_scan", a.sha
            if a.spa != ZERO_IP:
                self.pending[(a.spa, a.tpa)] = t

        if pkt.eth_src != a.sha and a.sha != ZERO_MAC:
            self._emit(res, pkt, "eth_arp_mismatch", "medium", pkt.eth_src,
                       f"frame from {pkt.eth_src} carries an ARP claim for {a.sha} ({a.spa})",
                       ip=a.spa, mac=a.sha, old_mac=pkt.eth_src,
                       evidence={"eth_src": pkt.eth_src, "arp_sha": a.sha})
            res.flag, res.actor = "eth_arp_mismatch", pkt.eth_src

        if a.spa == ZERO_IP:
            return  # address probe: no binding claimed
        self.local_prefixes.add(_prefix24(a.spa))

        unsolicited = False
        if a.op == 2 and a.kind != "gratuitous":
            asked = self.pending.get((a.tpa, a.spa))
            unsolicited = asked is None or t - asked > cfg.request_timeout
        flag = self._claim(pkt, a.spa, a.sha, a.kind, unsolicited, res)
        if flag and res.flag is None:
            res.flag, res.actor = flag, a.sha

    def _claim(self, pkt: Packet, ip: str, mac: str, via: str, unsolicited: bool,
               res: PacketResult) -> Optional[str]:
        t, cfg = pkt.ts, self.cfg
        b = self.bindings.get(ip)
        if b is None:
            lease = self.leases.get(ip)
            trusted = lease[0] if lease and t - lease[1] <= cfg.dhcp_grace else mac
            b = self.bindings[ip] = Binding(ip, mac, trusted, t, t, [[t, mac, via]])
            prev_mac = None
        else:
            prev_mac = b.mac
            b.last_seen = t
            if mac != b.mac:
                b.history.append([t, mac, via])
                b.changes += 1
                b.mac = mac
        self._track_mac_ips(pkt, mac, ip, res)

        if mac == b.trusted_mac:
            if prev_mac is not None and prev_mac != mac:
                self._emit(res, pkt, "binding_restored", "info", prev_mac,
                           f"{ip} is back at its trusted MAC {mac} (was {prev_mac})",
                           ip=ip, mac=mac, old_mac=prev_mac, evidence={"via": via})
                self._check_flipflop(pkt, b, actor=prev_mac, res=res)
            return None

        # The claimant is not the trusted owner. A fresh DHCP lease explains it.
        lease = self.leases.get(ip)
        if lease and lease[0] == mac and t - lease[1] <= cfg.dhcp_grace:
            old = b.trusted_mac
            b.trusted_mac = mac
            self._emit(res, pkt, "ip_mac_change", "low", mac,
                       f"{ip} moved from {old} to {mac} {t - lease[1]:.0f}s after a DHCP ACK",
                       ip=ip, mac=mac, old_mac=old,
                       evidence={"dhcp_ack_age_s": round(t - lease[1], 1), "via": via,
                                 "new_vendor": vendor(mac), "old_vendor": vendor(old),
                                 "old_mac_last_seen_s_ago": self._ago(old, t)})
            return None

        is_gw = self._is_gateway(ip, b.trusted_mac)
        s = self.suspects.setdefault(mac, {"first": t, "last": t, "ips": set()})
        s["last"] = t
        s["ips"].add(ip)

        if prev_mac != mac:
            claims = sorted(self.mac_ips[mac])
            evidence = {
                "trusted_mac": b.trusted_mac, "trusted_vendor": vendor(b.trusted_mac),
                "claimant_vendor": vendor(mac), "via": via, "unsolicited": unsolicited,
                "is_gateway": is_gw, "claimant_ips": claims,
                "trusted_mac_last_seen_s_ago": self._ago(b.trusted_mac, t),
            }
            if is_gw:
                self._emit(res, pkt, "gateway_mac_change", "critical", mac,
                           f"gateway {ip} is now claimed by {mac}; trusted MAC is {b.trusted_mac}",
                           ip=ip, mac=mac, old_mac=b.trusted_mac, evidence=evidence)
            else:
                self._emit(res, pkt, "ip_mac_conflict", "medium", mac,
                           f"{ip} claimed by {mac}; trusted MAC is {b.trusted_mac}",
                           ip=ip, mac=mac, old_mac=b.trusted_mac, evidence=evidence)
            self._check_flipflop(pkt, b, actor=mac, res=res)
        if unsolicited:
            self._emit(res, pkt, "unsolicited_reply", "low", mac,
                       f"unrequested ARP reply: {ip} is-at {mac}",
                       ip=ip, mac=mac, evidence={"target_ip": pkt.arp.tpa})
        return "spoofed_claim"

    def _check_flipflop(self, pkt: Packet, b: Binding, actor: str, res: PacketResult) -> None:
        # history[0] is the first sighting; every later entry is a change
        changes = [h for h in b.history[1:] if pkt.ts - h[0] <= self.cfg.flipflop_window]
        macs = {h[1] for h in changes} | {b.trusted_mac}
        transitions = len(changes)
        if transitions >= self.cfg.flipflop_min_changes and len(macs) >= 2:
            self._emit(res, pkt, "binding_flip_flop", "high", actor,
                       f"{b.ip} flipped between {len(macs)} MACs {transitions} times in "
                       f"{self.cfg.flipflop_window:g}s",
                       ip=b.ip, mac=actor, old_mac=b.trusted_mac,
                       evidence={"macs": sorted(macs), "transitions": transitions,
                                 "is_gateway": self._is_gateway(b.ip, b.trusted_mac)})

    def _track_mac_ips(self, pkt: Packet, mac: str, ip: str, res: PacketResult) -> None:
        ips = self.mac_ips[mac]
        is_new = ip not in ips
        ips[ip] = pkt.ts
        if not is_new:
            return
        for old_ip in [i for i, ts in ips.items() if pkt.ts - ts > self.cfg.multi_ip_window]:
            del ips[old_ip]
        if len(ips) < 2:
            return
        foreign = [i for i in ips if (b := self.bindings.get(i)) and b.trusted_mac != mac]
        if not foreign:
            return  # a host with several of its own addresses
        gw_ip = self.gateway()[0]
        severity = "high" if gw_ip in foreign else "medium"
        self._emit(res, pkt, "mac_multiple_ips", severity, mac,
                   f"{mac} claims {len(ips)} IPs, {len(foreign)} of them owned by other MACs",
                   mac=mac, evidence={"ips": sorted(ips), "foreign_ips": sorted(foreign),
                                      "vendor": vendor(mac)})

    def _mitm_check(self, pkt: Packet, res: PacketResult) -> None:
        for mac, endpoint in ((pkt.eth_dst, pkt.ip_dst), (pkt.eth_src, pkt.ip_src)):
            s = self.suspects.get(mac)
            if s is None or pkt.ts - s["last"] > self.cfg.suspect_timeout:
                continue
            owner = self.bindings.get(endpoint)
            if owner is None or owner.trusted_mac != mac:
                res.flag, res.actor = "mitm_path", mac
                return

    # --------------------------------------------------------------- gateway
    def _learn_next_hop(self, pkt: Packet) -> None:
        if not self.local_prefixes or pkt.eth_dst.startswith(("ff:", "01:", "33:")):
            return
        if not self.is_local(pkt.ip_dst) and not pkt.ip_dst.startswith(("224.", "239.", "255.")):
            if self.next_hops.total() < 200:   # learn early, before anyone can poison it
                self.next_hops[pkt.eth_dst] += 1

    def _inferred_gateway_ip(self) -> Optional[str]:
        if self.next_hops.total() < 20:
            return None
        mac, n = self.next_hops.most_common(1)[0]
        if n / self.next_hops.total() < 0.6:
            return None
        for ip, b in self.bindings.items():
            if b.trusted_mac == mac:
                return ip
        return None

    def _is_gateway(self, ip: str, trusted_mac: str) -> bool:
        gw = self.gateway_ip or self._inferred_gateway_ip()
        if gw is not None:
            return ip == gw
        return bool(self.next_hops) and self.next_hops.most_common(1)[0][0] == trusted_mac

    def _ago(self, mac: str, t: float) -> Optional[float]:
        seen = self.mac_last_seen.get(mac)
        return None if seen is None else round(t - seen, 1)

    # ---------------------------------------------------------------- export
    def binding_table(self, t0: float = 0.0) -> list[dict]:
        rows = []
        for ip, b in sorted(self.bindings.items(), key=lambda kv: tuple(int(x) for x in kv[0].split("."))):
            rows.append({
                "ip": ip, "mac": b.mac, "trusted_mac": b.trusted_mac, "vendor": vendor(b.mac),
                "first_t": round(b.first_seen - t0, 3), "last_t": round(b.last_seen - t0, 3),
                "changes": b.changes,
                "history": [[round(h[0] - t0, 3), h[1], h[2]] for h in b.history],
            })
        return rows
