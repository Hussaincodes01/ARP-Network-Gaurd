#!/usr/bin/env python3
"""Build the dashboard's replay data from the bundled captures.

Runs the full pipeline (rules + Kitsune + fusion + template explanations)
and the evaluation on each capture, and writes public/data/*.json, which the
dashboard replays in the browser. Re-run after changing detection logic:

  python scripts/make_synthetic_capture.py   # only if the captures changed
  python scripts/build_demo.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from arpguard.ai.explainer import explain_result  # noqa: E402
from eval.evaluate import METHOD_LABELS, evaluate_capture, markdown  # noqa: E402

DEMOS = [
    {"id": "attack", "title": "Office network with an ARP spoofing attack",
     "pcap": "data/arp_mitm_synthetic.pcap", "labels": "data/arp_mitm_synthetic_labels.csv",
     "blurb": "A small office network (simulated, 13 minutes). A smart plug joins, the printer gets a new "
              "network card, a laptop scans another computer, and then an attacker's virtual machine starts "
              "pretending to be the router (an Ettercap-style ARP spoofing attack)."},
    {"id": "benign", "title": "Same network, no attack",
     "pcap": "data/home_benign_synthetic.pcap", "labels": None,
     "blurb": "Another day on the same network (simulated, 10 minutes): a new device joins, and the internet "
              "router is swapped for a backup router with a different MAC address. There is no attack: "
              "ARPGuard should stay calm."},
]


def main() -> None:
    out_dir = ROOT / "public" / "data"
    out_dir.mkdir(parents=True, exist_ok=True)
    evaluations = []
    index = []
    for d in DEMOS:
        t = time.time()
        metrics, sess = evaluate_capture(str(ROOT / d["pcap"]), str(ROOT / d["labels"]) if d["labels"] else None)
        result = explain_result(sess.result(), use_llm=False)
        result["meta"]["demo"] = {k: d[k] for k in ("id", "title", "blurb")}
        result["meta"]["synthetic"] = True
        result["evaluation"] = metrics
        if d["labels"]:
            # Ground-truth attack window for the chart (from the labels)
            result["meta"]["attack_window"] = [metrics["attack_start_t"],
                                               max((i["last_t"] for i in result["incidents"]
                                                    if i["verdict"] == "confirmed_spoofing"), default=None)]
        path = out_dir / f"demo-{d['id']}.json"
        path.write_text(json.dumps(result, separators=(",", ":")))
        evaluations.append(metrics)
        index.append({"id": d["id"], "title": d["title"], "blurb": d["blurb"], "file": f"data/{path.name}",
                      "packets": result["meta"]["packets"], "verdict": result["meta"]["verdict"]})
        print(f"{d['id']}: {result['meta']['packets']:,} packets, {len(result['incidents'])} incidents, "
              f"{path.stat().st_size / 1e3:.0f} kB, {time.time() - t:.0f} s")
    (out_dir / "index.json").write_text(json.dumps({"demos": index, "methods": METHOD_LABELS}, indent=1))
    (out_dir / "evaluation.json").write_text(json.dumps(evaluations, indent=1))
    (ROOT / "eval" / "RESULTS.md").write_text("# Evaluation results\n\nSynthetic captures from "
                                              "`scripts/make_synthetic_capture.py`; regenerate with "
                                              "`python scripts/build_demo.py`.\n\n" + markdown(evaluations))


if __name__ == "__main__":
    main()
