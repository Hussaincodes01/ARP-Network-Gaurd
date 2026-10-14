import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from arpguard.api.main import app

ROOT = Path(__file__).resolve().parents[1]
client = TestClient(app)


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_analyze_rules_only_upload():
    body = (ROOT / "data" / "arp_mitm_synthetic.pcap").read_bytes()
    r = client.post("/api/analyze?kitsune=false&name=t.pcap", content=body,
                    headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["meta"]["packets"] > 40000 and d["gateway"]["ip"] == "192.168.1.1"
    spoof = [i for i in d["incidents"] if i["actor"] == "00:0c:29:7d:e1:66"]
    assert spoof and spoof[0]["verdict"] == "suspicious"          # rules alone can't confirm
    assert all("explanation" in i and "evidence" in i for i in d["incidents"])


def test_analyze_rejects_junk_and_empty():
    assert client.post("/api/analyze", content=b"").status_code == 400
    assert client.post("/api/analyze", content=b"definitely not a pcap").status_code == 400


def test_explain_endpoint_with_demo_evidence(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    demo = json.loads((ROOT / "public" / "data" / "demo-attack.json").read_text())
    ev = demo["incidents"][0]["evidence"]
    r = client.post("/api/explain", json={"evidence": ev})
    assert r.status_code == 200 and r.json()["verdict"] == ev["verdict"]
    assert client.post("/api/explain", json={"evidence": {"verdict": "x"}}).status_code == 400


@pytest.mark.parametrize("path", ["/api/live/snapshot", "/api/live/stream"])
def test_live_endpoints_404_when_not_running(path):
    assert client.get(path).status_code == 404
