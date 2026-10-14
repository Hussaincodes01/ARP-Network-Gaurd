"""Live mode: sniff your own LAN with Scapy and feed the same pipeline.

Needs raw-socket rights (run as root/Administrator, or give Python
CAP_NET_RAW) and Scapy (`pip install scapy`; Windows also needs Npcap).
Only run it on a network you own or administer.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Optional

from ..ml.kitsune_runner import KitsuneConfig
from ..pipeline import Session
from .parser import decode_frame, write_pcap


def scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
        return True
    except Exception:
        return False


class LiveMonitor:
    """Runs a Scapy sniffer in a background thread and keeps a Session updated."""

    def __init__(self, iface: Optional[str] = None, gateway_ip: Optional[str] = None,
                 use_kitsune: bool = True, fm_grace: int = 1000, ad_grace: int = 5000,
                 record_to: Optional[str] = None, max_events: int = 5000):
        self.iface = iface
        self.lock = threading.Lock()
        self.events: deque = deque(maxlen=max_events)
        self.seq = 0
        kcfg = KitsuneConfig(fm_grace=fm_grace, ad_grace=ad_grace)
        self.session = Session(gateway_ip=gateway_ip, use_kitsune=use_kitsune, kitsune_config=kcfg,
                               source_name=f"live:{iface or 'default'}", on_event=self._push)
        self.record_to = record_to
        self._frames: list = [] if record_to else None
        self.sniffer = None
        self.started_at: Optional[float] = None
        self._last_tick = 0.0
        self._tick_max = 0.0

    def _push(self, event: dict) -> None:
        self.seq += 1
        event["seq"] = self.seq
        self.events.append(event)

    def _on_packet(self, sp) -> None:
        raw = bytes(sp)
        ts = float(sp.time)
        wirelen = getattr(sp, "wirelen", None) or len(raw)
        with self.lock:
            pkt = decode_frame(raw, ts, wirelen, index=self.session.packets)
            if pkt is None:
                return
            self.session.process(pkt)
            if self._frames is not None:
                self._frames.append((ts, raw, wirelen))
            k = self.session.kitsune
            score = self.session._raw_scores[-1][1] if self.session._raw_scores else 0.0
            self._tick_max = max(self._tick_max, score)
            if ts - self._last_tick >= 1.0:
                self._push({"type": "tick", "t": round(ts - self.session.t0, 3),
                            "packets": self.session.packets, "arp": self.session.rules.arp_packets,
                            "score": round(self._tick_max, 6),
                            "phase": k.phase() if k else "off",
                            "threshold": k.threshold if k else None})
                self._last_tick, self._tick_max = ts, 0.0

    def start(self) -> None:
        from scapy.all import AsyncSniffer
        self.sniffer = AsyncSniffer(iface=self.iface, prn=self._on_packet, store=False)
        self.sniffer.start()
        self.started_at = time.time()

    def stop(self) -> None:
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None
        with self.lock:
            self.session.finish()
            if self.record_to and self._frames:
                write_pcap(self.record_to, self._frames)

    @property
    def running(self) -> bool:
        return self.sniffer is not None

    def events_after(self, seq: int) -> list:
        return [e for e in list(self.events) if e["seq"] > seq]

    def snapshot(self) -> dict:
        with self.lock:
            return self.session.result()
