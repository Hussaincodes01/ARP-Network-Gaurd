from arpguard.core.detector import Alert
from arpguard.core.fusion import FusionConfig, FusionEngine

MAC = "00:0c:29:7d:e1:66"


def alert(i, t, rule, severity, ip="192.168.1.1"):
    return Alert(id=i, ts=t, packet_index=i, rule=rule, severity=severity, actor=MAC, ip=ip, mac=MAC,
                 old_mac="50:c7:bf:3a:1c:01", last_ts=t)


def run(alerts, score_fn, until=60.0, threshold=1.0, step=0.1):
    f = FusionEngine(threshold, FusionConfig())
    pending = sorted(alerts, key=lambda a: a.ts)
    t = 0.0
    while t < until:
        due = [a for a in pending if a.ts <= t]
        pending = [a for a in pending if a.ts > t]
        f.on_packet(t, due, score_fn(t), "spoofed_claim" if due else None, MAC if due else None, "a > b")
        t = round(t + step, 3)
    f.finish(t)
    return f


def test_strong_rules_and_high_kitsune_confirm():
    f = run([alert(1, 10, "gateway_mac_change", "critical")], lambda t: 5.0 if t >= 10 else 0.1)
    inc = f.incidents[0]
    assert inc.verdict == "confirmed_spoofing" and inc.detect_ts is not None and inc.detect_ts < 11


def test_one_off_conflict_with_quiet_model_is_legitimate():
    f = run([alert(1, 10, "ip_mac_conflict", "medium", "192.168.1.30")], lambda t: 0.1)
    assert f.incidents[0].verdict == "likely_legitimate"
    assert [v for _, v in f.incidents[0].timeline] == ["pending", "likely_legitimate"]


def test_gateway_change_once_with_quiet_model_is_legitimate_but_flip_flop_is_suspicious():
    once = run([alert(1, 10, "gateway_mac_change", "critical")], lambda t: 0.1)
    assert once.incidents[0].verdict == "likely_legitimate"
    flip = run([alert(1, 10, "gateway_mac_change", "critical"), alert(2, 11, "binding_flip_flop", "high")], lambda t: 0.1)
    assert flip.incidents[0].verdict == "suspicious"


def test_conflict_with_high_kitsune_is_probable():
    f = run([alert(1, 10, "ip_mac_conflict", "medium", "192.168.1.20")], lambda t: 5.0 if 10 <= t <= 15 else 0.1)
    assert f.incidents[0].verdict == "probable_spoofing"


def test_kitsune_only_episode_is_anomaly_not_arp():
    f = run([], lambda t: 5.0 if 20 <= t <= 25 else 0.1)
    assert [i.verdict for i in f.incidents] == ["anomaly_not_arp"]
    assert f.incidents[0].kind == "kitsune" and f.incidents[0].hits >= 3


def test_scattered_noise_is_not_an_episode():
    f = run([], lambda t: 5.0 if int(t * 10) % 37 == 0 else 0.1)   # ~3% of packets
    assert f.incidents == []


def test_spoofing_verdict_is_never_downgraded():
    f = run([alert(1, 10, "gateway_mac_change", "critical")], lambda t: 5.0 if 10 <= t <= 12 else 0.1, until=200)
    assert f.incidents[0].verdict == "confirmed_spoofing"
