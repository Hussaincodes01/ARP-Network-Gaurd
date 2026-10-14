from helpers import (EVIL_IP, EVIL_MAC, GW_IP, GW_MAC, HOST_IP, HOST_MAC, ZERO_MAC, arp, dhcp_ack,
                     ip_packet)

from arpguard.core.detector import ArpRuleEngine, RuleConfig


def rules_of(results):
    return [a.rule for r in results for a in r.alerts]


def baseline(engine, t=0.0):
    out = [engine.process(arp(1, HOST_MAC, HOST_IP, ZERO_MAC, GW_IP, t))]
    out.append(engine.process(arp(2, GW_MAC, GW_IP, HOST_MAC, HOST_IP, t + 0.01)))
    out.append(engine.process(arp(1, EVIL_MAC, EVIL_IP, ZERO_MAC, GW_IP, t + 1)))
    return out


def test_gateway_spoof_is_critical_and_flip_flop_follows():
    e = ArpRuleEngine(RuleConfig(gateway_ip=GW_IP))
    baseline(e)
    res = []
    t = 10.0
    for i in range(3):   # attacker poisons, real gateway answers again, ...
        res.append(e.process(arp(2, EVIL_MAC, GW_IP, HOST_MAC, HOST_IP, t)))
        res.append(e.process(arp(2, GW_MAC, GW_IP, HOST_MAC, HOST_IP, t + 1)))
        t += 10
    rules = rules_of(res)
    assert "gateway_mac_change" in rules and "binding_flip_flop" in rules
    assert "unsolicited_reply" in rules and "binding_restored" in rules
    crit = next(a for a in e.alerts if a.rule == "gateway_mac_change")
    assert crit.severity == "critical" and crit.actor == EVIL_MAC and crit.old_mac == GW_MAC
    assert res[0].flag == "spoofed_claim" and res[0].actor == EVIL_MAC


def test_relayed_traffic_is_flagged_as_mitm_path():
    e = ArpRuleEngine(RuleConfig(gateway_ip=GW_IP))
    baseline(e)
    e.process(arp(2, EVIL_MAC, GW_IP, HOST_MAC, HOST_IP, 10))
    victim_to_attacker = e.process(ip_packet(HOST_IP, "8.8.8.8", HOST_MAC, EVIL_MAC, 11))
    attacker_forwards = e.process(ip_packet(HOST_IP, "8.8.8.8", EVIL_MAC, GW_MAC, 11.001))
    attackers_own = e.process(ip_packet(EVIL_IP, "8.8.8.8", EVIL_MAC, GW_MAC, 12))
    assert victim_to_attacker.flag == attacker_forwards.flag == "mitm_path"
    assert attackers_own.flag is None


def test_dhcp_backed_change_is_low_and_unflagged():
    e = ArpRuleEngine()
    baseline(e)
    new_mac = "24:0a:c4:9d:33:12"
    e.process(dhcp_ack(new_mac, HOST_IP, 50))
    r = e.process(arp(1, new_mac, HOST_IP, ZERO_MAC, HOST_IP, 51))
    assert [a.rule for a in r.alerts] == ["ip_mac_change"] and r.alerts[0].severity == "low"
    assert r.flag is None and e.bindings[HOST_IP].trusted_mac == new_mac


def test_static_nic_swap_is_a_medium_conflict():
    e = ArpRuleEngine(RuleConfig(gateway_ip=GW_IP))
    baseline(e)
    r = e.process(arp(1, "b8:ac:6f:00:00:99", HOST_IP, ZERO_MAC, HOST_IP, 100))
    assert [a.rule for a in r.alerts] == ["ip_mac_conflict"] and r.alerts[0].severity == "medium"
    e.accept_binding(HOST_IP, "b8:ac:6f:00:00:99")
    again = e.process(arp(1, "b8:ac:6f:00:00:99", HOST_IP, ZERO_MAC, GW_IP, 160))
    assert again.flag is None and not again.alerts


def test_scan_and_mismatch_rules():
    e = ArpRuleEngine()
    baseline(e)
    res = [e.process(arp(1, EVIL_MAC, EVIL_IP, ZERO_MAC, f"192.168.1.{i}", 20 + i * 0.01)) for i in range(2, 40)]
    assert "arp_scan" in rules_of(res)
    mis = e.process(arp(2, GW_MAC, GW_IP, HOST_MAC, HOST_IP, 30, eth_src=EVIL_MAC))
    assert "eth_arp_mismatch" in [a.rule for a in mis.alerts] and mis.flag == "eth_arp_mismatch"


def test_gateway_inferred_from_dhcp_and_traffic():
    e = ArpRuleEngine()
    e.process(dhcp_ack(HOST_MAC, HOST_IP, 0))
    assert e.gateway() == (GW_IP, None)
    e2 = ArpRuleEngine()
    baseline(e2)
    for i in range(30):
        e2.process(ip_packet(HOST_IP, "1.1.1.1", HOST_MAC, GW_MAC, 2 + i))
    assert e2.gateway() == (GW_IP, GW_MAC)


def test_alert_cooldown_counts_repeats():
    e = ArpRuleEngine(RuleConfig(gateway_ip=GW_IP))
    baseline(e)
    for i in range(5):
        e.process(arp(2, EVIL_MAC, HOST_IP, GW_MAC, GW_IP, 10 + i))
    unsolicited = [a for a in e.alerts if a.rule == "unsolicited_reply"]
    assert len(unsolicited) == 1 and unsolicited[0].repeats == 5
