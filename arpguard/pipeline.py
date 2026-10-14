"""End-to-end pipeline: packets -> rules + Kitsune -> fusion -> result JSON.

`Session` processes packets one at a time, so the same code drives batch
analysis of a pcap, the replay data for the dashboard, and live sniffing.
"""
from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import numpy as np

from . import __version__
from .core.detector import ArpRuleEngine, RuleConfig
from .core.fusion import SPOOFING_VERDICTS, VERDICTS, FusionConfig, FusionEngine
from .core.oui import mac_kind, vendor
from .core.parser import Packet, Source, iter_frames, read_packets
from .ml.kitsune_runner import KitsuneConfig, KitsuneRunner

MAX_ARP_EVENTS = 20000
SCORE_POINTS = 1500


@dataclass
class PerPacket:
    """Per-packet columns kept for evaluation."""
    index: list = field(default_factory=list)       # frame number in the capture
    ts: list = field(default_factory=list)
    score: list = field(default_factory=list)
    flag: list = field(default_factory=list)       # rule flag in the fused pipeline
    actor: list = field(default_factory=list)
    rules_only: list = field(default_factory=list)  # rule flag with no fusion feedback


class Session:
    def __init__(self, gateway_ip: Optional[str] = None, use_kitsune: bool = True,
                 kitsune_config: Optional[KitsuneConfig] = None,
                 fusion_config: Optional[FusionConfig] = None,
                 rule_config: Optional[RuleConfig] = None,
                 keep_per_packet: bool = False, source_name: str = "capture",
                 on_event: Optional[Callable[[dict], None]] = None):
        rc = rule_config or RuleConfig()
        if gateway_ip:
            rc.gateway_ip = gateway_ip
        self.rules = ArpRuleEngine(rc)
        self.kitsune = KitsuneRunner(kitsune_config) if use_kitsune else None
        self.fusion = FusionEngine(None, fusion_config, on_verdict=self._on_verdict)
        self.shadow = ArpRuleEngine(RuleConfig(**vars(rc))) if keep_per_packet else None
        self.per_packet = PerPacket() if keep_per_packet else None
        self.source_name = source_name
        self.on_event = on_event
        self.t0: Optional[float] = None
        self.last_ts = 0.0
        self.packets = 0
        self.arp_events: list = []
        self.arp_dropped = 0
        self.host_stats: dict[str, dict] = {}
        self.proto_counts: Counter = Counter()
        self._raw_scores: list = []      # (ts, score) after grace
        self._traffic: list = []         # ts of every packet (for the volume chart)
        self._arp_ts: list = []
        self.started = time.time()

    # ---------------------------------------------------------------- core
    def process(self, pkt: Packet) -> None:
        if self.t0 is None:
            self.t0 = pkt.ts
        self.last_ts = pkt.ts
        self.packets += 1
        self._traffic.append(pkt.ts)
        self._account(pkt)

        res = self.rules.process(pkt)
        score = None
        if self.kitsune is not None:
            s = self.kitsune.process(pkt)
            if self.kitsune.threshold is not None:
                if self.fusion.threshold is None:
                    self.fusion.set_threshold(self.kitsune.threshold)
                    self._emit({"type": "threshold", "threshold": self.kitsune.threshold,
                                "t": self._rel(pkt.ts)})
                score = s
                self._raw_scores.append((pkt.ts, s))
        talker = None
        if score is not None and self.fusion.threshold is not None and score > self.fusion.threshold:
            talker = f"{pkt.ip_src or pkt.eth_src} > {pkt.ip_dst or pkt.eth_dst}"
        self.fusion.on_packet(pkt.ts, res.alerts, score, res.flag, res.actor, talker)

        if pkt.arp is not None:
            self._arp_ts.append(pkt.ts)
            self._record_arp(pkt, res.flag)
        for a in res.alerts:
            self._emit({"type": "alert", "alert": a.to_dict(self.t0)})

        if self.per_packet is not None:
            pp = self.per_packet
            pp.index.append(pkt.index)
            pp.ts.append(pkt.ts)
            pp.score.append(np.nan if score is None else score)
            pp.flag.append(res.flag is not None)
            pp.actor.append(res.actor)
            pp.rules_only.append(self.shadow.process(pkt).flag is not None)

    def finish(self) -> None:
        self.fusion.finish(self.last_ts)

    def _on_verdict(self, inc, old, new) -> None:
        # A one-off change the model considers normal: stop treating the new
        # MAC as an attacker (the "log only" row of the fusion table).
        if new == "likely_legitimate" and inc.actor:
            for ip in inc.ips:
                self.rules.accept_binding(ip, inc.actor)
        if self.t0 is not None:
            self._emit({"type": "verdict", "incident": inc.id, "actor": inc.actor,
                        "from": old, "to": new, "label": VERDICTS[new]["label"],
                        "t": self._rel(inc.verdict_ts)})

    def _emit(self, event: dict) -> None:
        if self.on_event:
            self.on_event(event)

    def _rel(self, ts: float) -> float:
        return round(ts - (self.t0 or ts), 3)

    def _account(self, pkt: Packet) -> None:
        h = self.host_stats.get(pkt.eth_src)
        if h is None:
            h = self.host_stats[pkt.eth_src] = {"first": pkt.ts, "packets": 0, "bytes": 0}
        h["packets"] += 1
        h["bytes"] += pkt.length
        if pkt.arp is not None:
            self.proto_counts["ARP"] += 1
        elif pkt.dhcp is not None:
            self.proto_counts["DHCP"] += 1
        elif pkt.ip_version == 4:
            self.proto_counts[{6: "TCP", 17: "UDP", 1: "ICMP"}.get(pkt.ip_proto, "IPv4 other")] += 1
        elif pkt.ip_version == 6:
            self.proto_counts["IPv6"] += 1
        else:
            self.proto_counts["Other L2"] += 1

    def _record_arp(self, pkt: Packet, flag: Optional[str]) -> None:
        a = pkt.arp
        ev = [self._rel(pkt.ts), a.kind, a.sha, a.spa, a.tha, a.tpa, pkt.eth_src, pkt.eth_dst, flag]
        if len(self.arp_events) < MAX_ARP_EVENTS:
            self.arp_events.append(ev)
        else:
            self.arp_dropped += 1
        self._emit({"type": "arp", "event": ev})

    # -------------------------------------------------------------- export
    def _series(self) -> dict:
        t0, t1 = self.t0 or 0.0, self.last_ts
        duration = max(t1 - t0, 1e-6)
        width = max(0.25, duration / SCORE_POINTS)
        nbins = int(duration // width) + 1
        traffic = np.bincount(((np.array(self._traffic) - t0) // width).astype(int), minlength=nbins)
        arp = np.bincount(((np.array(self._arp_ts or [t0]) - t0) // width).astype(int), minlength=nbins)
        if not self._arp_ts:
            arp[:] = 0
        score_max = [None] * nbins
        hits = [0] * nbins
        thr = self.fusion.threshold
        for ts, s in self._raw_scores:
            b = int((ts - t0) // width)
            if score_max[b] is None or s > score_max[b]:
                score_max[b] = s
            if thr is not None and s > thr:
                hits[b] += 1
        return {
            "bin": width,
            "t": [round(i * width, 3) for i in range(nbins)],
            "score": [None if v is None else round(float(v), 6) for v in score_max],
            "hits": hits,
            "pps": [round(int(c) / width, 2) for c in traffic[:nbins]],
            "arp_pps": [round(int(c) / width, 2) for c in arp[:nbins]],
        }

    def result(self) -> dict:
        t0 = self.t0 or 0.0
        alerts_by_id = {a.id: a for a in self.rules.alerts}
        incidents = self.fusion.export(t0, alerts_by_id)
        gw_ip, gw_mac = self.rules.gateway()
        hosts = []
        claimed: dict[str, set] = {}
        for ip, b in self.rules.bindings.items():
            for _, mac, _ in b.history:
                claimed.setdefault(mac, set()).add(ip)
        for mac, h in self.host_stats.items():
            kind = mac_kind(mac)
            if kind != "unicast" and kind != "local":
                continue
            own = sorted(ip for ip, b in self.rules.bindings.items() if b.trusted_mac == mac)
            hosts.append({"mac": mac, "vendor": vendor(mac), "kind": kind,
                          "ips": own, "claimed": sorted(claimed.get(mac, set())),
                          "first_t": round(h["first"] - t0, 3), "packets": h["packets"],
                          "bytes": h["bytes"], "gateway": mac == gw_mac,
                          "suspect": mac in self.rules.suspects})
        worst = max((i for i in incidents), key=lambda i: VERDICTS[i["verdict"]]["level"], default=None)
        return {
            "meta": {
                "tool": "ARPGuard", "version": __version__, "source": self.source_name,
                "packets": self.packets, "arp_packets": self.rules.arp_packets,
                "arp_events_dropped": self.arp_dropped,
                "duration": round(self.last_ts - t0, 3), "start_epoch": t0,
                "protocols": dict(self.proto_counts.most_common()),
                "processing_seconds": round(time.time() - self.started, 2),
                "kitsune": self.kitsune.summary() if self.kitsune else None,
                "verdict": worst["verdict"] if worst else "normal",
                "verdict_label": VERDICTS[worst["verdict"] if worst else "normal"]["label"],
            },
            "gateway": {"ip": gw_ip, "mac": gw_mac, "source": self.rules.gateway_source
                        or ("inferred" if gw_ip else None)},
            "series": self._series(),
            "alerts": [a.to_dict(t0) for a in self.rules.alerts],
            "incidents": incidents,
            "bindings": self.rules.binding_table(t0),
            "hosts": sorted(hosts, key=lambda h: (-h["packets"])),
            "arp_events": self.arp_events,
            "verdicts": VERDICTS,
        }


def count_frames(source: Source) -> int:
    return sum(1 for _ in iter_frames(source))


def analyze(source: Source, *, gateway_ip: Optional[str] = None, use_kitsune: bool = True,
            limit: Optional[int] = None, start: int = 0,
            fm_grace: Optional[int] = None, ad_grace: Optional[int] = None,
            margin: Optional[float] = None, threshold_mode: Optional[str] = None,
            keep_per_packet: bool = False,
            source_name: Optional[str] = None,
            progress: Optional[Callable[[int], None]] = None) -> Session:
    """Analyse a capture (path or bytes). Returns the finished `Session`."""
    if isinstance(source, (bytearray, memoryview)):
        source = bytes(source)
    kcfg = None
    if use_kitsune:
        n = count_frames(source) - start
        if limit is not None:
            n = min(n, limit)
        kcfg = KitsuneConfig.for_capture(n, fm_grace=fm_grace, ad_grace=ad_grace, margin=margin,
                                         threshold_mode=threshold_mode)
    name = source_name or (Path(source).name if isinstance(source, (str, Path)) else "upload")
    sess = Session(gateway_ip=gateway_ip, use_kitsune=use_kitsune, kitsune_config=kcfg,
                   keep_per_packet=keep_per_packet, source_name=name)
    for i, pkt in enumerate(read_packets(source, limit=limit, start=start)):
        sess.process(pkt)
        if progress and i % 5000 == 0:
            progress(i)
    sess.finish()
    return sess


def spoofing_flags_combined(sess: Session) -> np.ndarray:
    """Per-packet output of the fused system, computed causally: a rule-flagged
    packet counts only once its incident's verdict has reached a spoofing level."""
    pp = sess.per_packet
    if pp is None:
        raise ValueError("session was created without keep_per_packet=True")
    by_actor: dict[str, list] = {}
    for inc in sess.fusion.incidents:
        if inc.actor:
            by_actor.setdefault(inc.actor, []).append(inc)
    out = np.zeros(len(pp.ts), dtype=bool)
    for i, (ts, flagged, actor) in enumerate(zip(pp.ts, pp.flag, pp.actor)):
        if not flagged or actor is None:
            continue
        for inc in by_actor.get(actor, ()):
            if inc.detect_ts is not None and inc.detect_ts <= ts and inc.verdict in SPOOFING_VERDICTS \
                    and ts <= inc.last_ts + sess.fusion.cfg.incident_gap:
                out[i] = True
                break
    return out

