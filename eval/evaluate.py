#!/usr/bin/env python3
"""Measure ARPGuard against per-packet labels (no training: just measurement).

Compares four detectors on the same packets:
  rules only            ArpRuleEngine on its own (no feedback from the model)
  Kitsune only (p99)    score > 99th percentile of benign calibration x 1.1
  Kitsune only (max)    score > highest benign calibration score x 1.1 (plan's rule)
  combined (ARPGuard)   rule-flagged packets whose incident the fusion table has
                        judged spoofing, counted only from the moment it did

All four are scored on the packets after Kitsune's grace period, where every
method is active. Time-to-detect is measured from the first malicious packet
to each method's first true positive.

Usage:
  python -m eval.evaluate data/arp_mitm_synthetic.pcap --labels data/arp_mitm_synthetic_labels.csv \\
      --benign data/home_benign_synthetic.pcap --out eval/results.json --markdown eval/RESULTS.md
  # Kitsune dataset (after scripts/fetch_kitsune.py), first 200k packets:
  python -m eval.evaluate data/kitsune/ARP_MitM_pcap.pcapng --labels data/kitsune/ARP_MitM_labels.csv --limit 200000
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Optional

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from arpguard.core.fusion import VERDICTS  # noqa: E402
from arpguard.pipeline import Session, analyze, spoofing_flags_combined  # noqa: E402

METHODS = ["rules", "kitsune_p99", "kitsune_max", "combined"]
METHOD_LABELS = {
    "rules": "Rules only",
    "kitsune_p99": "Kitsune only (p99 x 1.1)",
    "kitsune_max": "Kitsune only (max x 1.1, plan rule)",
    "combined": "Combined (ARPGuard)",
}


def load_labels(path: Path) -> np.ndarray:
    """Read a labels CSV; the label is the last column, header rows are skipped."""
    out = []
    with open(path, newline="") as fh:
        for row in csv.reader(fh):
            if not row:
                continue
            try:
                out.append(int(float(row[-1])))
            except ValueError:
                continue  # header
    return np.array(out, dtype=bool)


def predictions(sess: Session) -> dict[str, np.ndarray]:
    pp = sess.per_packet
    scores = np.array(pp.score, dtype=float)
    k = sess.kitsune
    preds = {"rules": np.array(pp.rules_only, dtype=bool),
             "combined": spoofing_flags_combined(sess)}
    if k is not None and k.calibration:
        valid = ~np.isnan(scores)
        preds["kitsune_p99"] = valid & (np.nan_to_num(scores) > k.threshold_for("quantile"))
        preds["kitsune_max"] = valid & (np.nan_to_num(scores) > k.threshold_for("max"))
    return preds


def metrics(pred: np.ndarray, truth: np.ndarray, ts: np.ndarray, attack_t0: Optional[float]) -> dict:
    tp = int((pred & truth).sum())
    fp = int((pred & ~truth).sum())
    fn = int((~pred & truth).sum())
    tn = int((~pred & ~truth).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    ttd = None
    if attack_t0 is not None:
        hits = np.nonzero(pred & truth)[0]
        if len(hits):
            ttd = round(float(ts[hits[0]] - attack_t0), 3)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "detection_rate": round(recall, 4), "fpr": round(fp / (fp + tn), 5) if fp + tn else 0.0,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "time_to_detect_s": ttd}


def evaluate_capture(path: str, labels_path: Optional[str], limit: Optional[int] = None,
                     gateway_ip: Optional[str] = None, sess: Optional[Session] = None) -> tuple[dict, Session]:
    if sess is None:
        sess = analyze(path, keep_per_packet=True, limit=limit, gateway_ip=gateway_ip)
    pp = sess.per_packet
    idx = np.array(pp.index)
    ts = np.array(pp.ts)
    if labels_path:
        labels = load_labels(Path(labels_path))
        if idx.max() >= len(labels):
            raise SystemExit(f"labels file has {len(labels)} rows but the capture has frame {idx.max()}")
        truth = labels[idx]
    else:
        truth = np.zeros(len(idx), dtype=bool)
    grace = sess.kitsune.grace_total if sess.kitsune else 0
    scope = np.arange(len(idx)) >= grace
    t0 = sess.t0
    attack_t0 = float(ts[truth][0]) if truth.any() else None
    preds = predictions(sess)
    result = {
        "capture": Path(path).name,
        "packets": int(len(idx)), "evaluated_packets": int(scope.sum()),
        "evaluated_from_t": round(float(ts[scope][0] - t0), 3) if scope.any() else None,
        "malicious_packets": int(truth[scope].sum()),
        "attack_start_t": round(attack_t0 - t0, 3) if attack_t0 is not None else None,
        "kitsune": sess.kitsune.summary() if sess.kitsune else None,
        "methods": {m: metrics(preds[m][scope], truth[scope], ts[scope], attack_t0)
                    for m in METHODS if m in preds},
        "incidents": [{"id": i["id"], "kind": i["kind"], "actor": i["actor"], "first_t": i["first_t"],
                       "verdict": i["verdict"], "detect_t": i["detect_t"],
                       "related_incident": i.get("related_incident")}
                      for i in sess.result()["incidents"]],
    }
    return result, sess


def markdown(results: list[dict]) -> str:
    lines = []
    for r in results:
        k = r.get("kitsune") or {}
        lines.append(f"### {r['capture']}\n")
        lines.append(f"{r['evaluated_packets']:,} packets evaluated (after Kitsune's grace period of "
                     f"{k.get('fm_grace', 0) + k.get('ad_grace', 0):,} packets), "
                     f"{r['malicious_packets']:,} labelled malicious"
                     + (f"; attack starts at t = {r['attack_start_t']} s." if r["attack_start_t"] is not None else "."))
        lines.append("")
        lines.append("| Method | Detection rate | FPR | Precision | Recall | F1 | Time to detect |")
        lines.append("|---|---|---|---|---|---|---|")
        for m, v in r["methods"].items():
            ttd = f"{v['time_to_detect_s']:.1f} s" if v["time_to_detect_s"] is not None else "n/a"
            lines.append(f"| {METHOD_LABELS[m]} | {v['detection_rate']:.3f} | {v['fpr']:.4f} | "
                         f"{v['precision']:.3f} | {v['recall']:.3f} | {v['f1']:.3f} | {ttd} |")
        lines.append("")
        lines.append("Incidents: " + "; ".join(
            f"#{i['id']} {VERDICTS[i['verdict']]['label']} at t={i['first_t']} s" for i in r["incidents"]) + "\n")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture")
    ap.add_argument("--labels")
    ap.add_argument("--benign", help="an attack-free capture to measure false alarms on")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--gateway")
    ap.add_argument("--out", help="write JSON results here")
    ap.add_argument("--markdown", help="write a Markdown table here")
    args = ap.parse_args()

    results = [evaluate_capture(args.capture, args.labels, args.limit, args.gateway)[0]]
    if args.benign:
        results.append(evaluate_capture(args.benign, None, args.limit, args.gateway)[0])
    md = markdown(results)
    print(md)
    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2))
    if args.markdown:
        Path(args.markdown).write_text("# Evaluation results\n\n" + md)


if __name__ == "__main__":
    main()
