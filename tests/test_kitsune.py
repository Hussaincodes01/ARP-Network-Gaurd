import math
import random

import numpy as np
import pytest
from helpers import GW_IP, GW_MAC, HOST_IP, HOST_MAC, ZERO_MAC, arp

from arpguard.core.parser import Packet
from arpguard.ml.kitsune.KitNET import _linkage
from arpguard.ml.kitsune_runner import KitsuneConfig, KitsuneRunner, kitsune_fields


def test_arp_fields_follow_upstream_feature_extractor():
    p = arp(1, HOST_MAC, HOST_IP, ZERO_MAC, GW_IP, 1.0)
    assert kitsune_fields(p) == (0, HOST_MAC, "ff:ff:ff:ff:ff:ff", HOST_IP, "arp", GW_IP, "arp")


def test_linkage_fallback_matches_scipy():
    hierarchy = pytest.importorskip("scipy.cluster.hierarchy")
    rng = np.random.default_rng(1)
    for _ in range(10):
        n = int(rng.integers(5, 60))
        y = rng.random(n * (n - 1) // 2)
        y[rng.integers(0, len(y), len(y) // 3)] = 1.0   # ties
        assert np.allclose(hierarchy.linkage(y), _linkage.linkage(y))


def test_runner_calibrates_and_scores():
    r = KitsuneRunner(KitsuneConfig(fm_grace=200, ad_grace=800))
    random.seed(0)
    t = 100.0
    scores = []
    for i in range(1300):
        t += random.expovariate(50)
        h = random.randint(10, 14)
        p = Packet(index=i, ts=t, length=random.choice([60, 600, 1500]), eth_src=f"00:00:00:00:00:{h:02x}",
                   eth_dst=GW_MAC, ethertype=0x800, ip_version=4, ip_src=f"192.168.1.{h}",
                   ip_dst="8.8.8.8", ip_proto=6, sport=40000 + h, dport=443)
        scores.append(r.process(p))
    assert r.threshold is not None and math.isfinite(r.threshold)
    assert len(r.calibration) > 100
    assert all(s == 0.0 for s in scores[:1000]) and any(s > 0 for s in scores[1001:])
    assert r.threshold_for("max") >= r.threshold_for("quantile")
