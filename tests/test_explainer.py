import json

import pytest

from arpguard.ai import explainer


@pytest.fixture(scope="module")
def demo():
    from pathlib import Path
    return json.loads((Path(__file__).resolve().parents[1] / "public" / "data" / "demo-attack.json").read_text())


def test_every_demo_incident_has_evidence_and_explanation(demo):
    for inc in demo["incidents"]:
        e = inc["explanation"]
        assert e["verdict"] == inc["verdict"] and e["headline"] and e["what_happened"]
        assert len(json.dumps(inc["evidence"])) < explainer.MAX_EVIDENCE_BYTES


def test_spoofing_explanation_names_attacker_from_evidence(demo):
    inc = next(i for i in demo["incidents"] if i["verdict"] == "confirmed_spoofing")
    e = explainer.template_explanation(inc["evidence"])
    assert e["attacker"]["mac"] == inc["actor"]
    assert any(f["action"].startswith("Turn on Dynamic ARP Inspection") for f in e["fixes"])


def test_guardrails_strip_invented_addresses(demo):
    inc = next(i for i in demo["incidents"] if i["verdict"] == "confirmed_spoofing")
    ev = inc["evidence"]
    bad = {"attacker": {"mac": "de:ad:be:ef:00:01", "ip": "10.9.9.9", "vendor": "", "reasoning": ""},
           "victims": [{"ip": "8.8.4.4", "role": "x"}, {"ip": ev["impersonated_ips"][0], "role": "y"}],
           "confidence": {"level": "low", "reason": "made up"}}
    out = explainer.enforce_guardrails(bad, ev)
    assert out["attacker"]["mac"] == inc["actor"] and out["attacker"]["ip"] == ""
    assert [v["ip"] for v in out["victims"]] == [ev["impersonated_ips"][0]]
    assert out["confidence"]["level"] == ev["confidence"]["level"]
    assert len(out["caveats"]) == 3


def test_explain_without_key_uses_template(demo, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ARPGUARD_LLM", "auto")
    ev = demo["incidents"][0]["evidence"]
    out = explainer.explain(ev)
    assert out["source"]["provider"] == "template" and out["verdict"] == ev["verdict"]


def test_llm_failure_falls_back_to_template(demo, monkeypatch):
    monkeypatch.setenv("ARPGUARD_LLM", "anthropic")

    def boom(ev):
        raise explainer.ExplainError("no network")
    monkeypatch.setattr(explainer, "_claude", boom)
    explainer._cache.clear()
    out = explainer.explain(demo["incidents"][1]["evidence"])
    assert out["source"]["provider"] == "template" and out["source"]["fallback_reason"] == "no network"
