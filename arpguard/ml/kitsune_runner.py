"""Run the vendored Kitsune (KitNET + AfterImage features) over parsed packets.

Kitsune is unsupervised and online: it is never trained offline. It spends
its grace period learning what "normal" looks like on the first packets of
the capture, then scores every later packet by reconstruction error (RMSE).

  * FM grace:  packets used to learn the feature map (which of the 100
               features go into which small autoencoder)
  * AD grace:  packets used to train the autoencoder ensemble
  * calibration: during the last `calib_frac` of the AD grace, each packet is
               scored *before* it is trained on, giving a sample of benign scores.

Threshold (per packet):
  * "max":      highest calibration score x margin (the project plan's rule)
  * "quantile": the `quantile` (default 99th percentile) of calibration scores
                x margin. This is the default. The maximum of a few thousand
                benign scores is just its single largest outlier, so the
                max-based bar jumps around: on two generations of the same
                synthetic capture it caught 0.2% and then 31% of attack packets
                (see eval/RESULTS.md).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional

import numpy as np

from ..core.parser import Packet
from .kitsune import KitNET, netStat


@dataclass
class KitsuneConfig:
    fm_grace: int = 5000
    ad_grace: int = 50000
    max_autoencoder_size: int = 10
    learning_rate: float = 0.1
    hidden_ratio: float = 0.75
    margin: float = 1.1
    calib_frac: float = 0.2
    threshold_mode: str = "quantile"   # or "max"
    quantile: float = 0.99

    @classmethod
    def for_capture(cls, n_packets: int, **overrides) -> "KitsuneConfig":
        """Scale the grace periods to the capture size (paper: 5k + 50k of ~1M+)."""
        fm = max(500, min(5000, int(n_packets * 0.05)))
        ad = max(2000, min(50000, int(n_packets * 0.25)))
        cfg = cls(fm_grace=fm, ad_grace=ad)
        for k, v in overrides.items():
            if v is not None:
                setattr(cfg, k, v)
        return cfg


def kitsune_fields(pkt: Packet) -> tuple:
    """Map a packet to the (IPtype, srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto)
    tuple exactly like upstream Kitsune's tshark feature extractor."""
    ip_type = math.nan
    src_ip = dst_ip = ""
    if pkt.ip_version == 4 and pkt.arp is None:
        src_ip, dst_ip, ip_type = pkt.ip_src, pkt.ip_dst, 0
    elif pkt.ip_version == 6:
        src_ip, dst_ip, ip_type = pkt.ip_src, pkt.ip_dst, 1
    srcproto = str(pkt.sport) if pkt.sport is not None else ""
    dstproto = str(pkt.dport) if pkt.dport is not None else ""
    if srcproto == "":
        if pkt.arp is not None:
            srcproto = dstproto = "arp"
            src_ip, dst_ip, ip_type = pkt.arp.spa, pkt.arp.tpa, 0
        elif pkt.icmp:
            srcproto = dstproto = "icmp"
            ip_type = 0 if pkt.ip_version == 4 else ip_type
        elif src_ip + dst_ip == "":
            src_ip, dst_ip = pkt.eth_src, pkt.eth_dst
    return ip_type, pkt.eth_src, pkt.eth_dst, src_ip, srcproto, dst_ip, dstproto


class KitsuneRunner:
    def __init__(self, config: Optional[KitsuneConfig] = None):
        self.cfg = config or KitsuneConfig()
        # Upstream caps tracked hosts at 255 and stops on overflow; a scan of a
        # /24 plus internet peers exceeds that, so the cap is raised.
        self.stats = netStat(np.nan, HostLimit=100_000, HostSimplexLimit=1000)
        self.n_features = len(self.stats.getNetStatHeaders())
        self.net = KitNET(self.n_features, self.cfg.max_autoencoder_size,
                          self.cfg.fm_grace, self.cfg.ad_grace,
                          self.cfg.learning_rate, self.cfg.hidden_ratio)
        self.calibration: list[float] = []
        self.threshold: Optional[float] = None
        self.processed = 0
        self._calib_start = self.cfg.fm_grace + int(self.cfg.ad_grace * (1 - self.cfg.calib_frac))
        self._last_x: Optional[np.ndarray] = None

    @property
    def grace_total(self) -> int:
        return self.cfg.fm_grace + self.cfg.ad_grace

    def phase(self) -> str:
        n = self.net.n_trained
        if n <= self.cfg.fm_grace:
            return "feature-mapping"
        if n <= self.grace_total:
            return "training"
        return "detecting"

    def features(self, pkt: Packet) -> np.ndarray:
        ip_type, smac, dmac, sip, sproto, dip, dproto = kitsune_fields(pkt)
        try:
            x = self.stats.updateGetStats(ip_type, smac, dmac, sip, sproto, dip, dproto,
                                          int(pkt.length), float(pkt.ts))
        except LookupError:
            x = self._last_x if self._last_x is not None else np.zeros(self.n_features)
        x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)
        self._last_x = x
        return x

    def process(self, pkt: Packet) -> float:
        """Learn from or score one packet. Returns 0.0 during the grace period."""
        x = self.features(pkt)
        self.processed += 1
        net = self.net
        if net.n_trained > self.grace_total:
            return float(net.execute(x))
        if net.v is not None and net.n_trained >= self._calib_start:
            self.calibration.append(float(net.execute(x)))
        net.train(x)
        if net.n_trained > self.grace_total and self.threshold is None:
            self._set_threshold()
        return 0.0

    def _set_threshold(self) -> None:
        self.threshold = self.threshold_for(self.cfg.threshold_mode)

    def threshold_for(self, mode: str) -> float:
        if not self.calibration:
            return math.inf
        if mode == "max":
            base = max(self.calibration)
        elif mode == "quantile":
            base = float(np.quantile(self.calibration, self.cfg.quantile))
        else:
            raise ValueError(f"unknown threshold mode {mode!r}")
        return base * self.cfg.margin

    def summary(self) -> dict:
        cal = np.array(self.calibration) if self.calibration else np.array([0.0])
        return {
            "fm_grace": self.cfg.fm_grace, "ad_grace": self.cfg.ad_grace,
            "margin": self.cfg.margin, "threshold": self.threshold,
            "threshold_mode": self.cfg.threshold_mode, "quantile": self.cfg.quantile,
            "threshold_max_rule": self.threshold_for("max") if self.calibration else None,
            "calibration_packets": len(self.calibration),
            "calibration_median": float(np.median(cal)),
            "calibration_max": float(cal.max()),
            "features": self.n_features,
            "autoencoders": len(self.net.v) if self.net.v is not None else 0,
        }
