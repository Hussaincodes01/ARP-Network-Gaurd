# Evaluation results

Synthetic captures from `scripts/make_synthetic_capture.py`; regenerate with `python scripts/build_demo.py`.

### arp_mitm_synthetic.pcap

28,787 packets evaluated (after Kitsune's grace period of 12,336 packets), 16,194 labelled malicious; attack starts at t = 449.91 s.

| Method | Detection rate | FPR | Precision | Recall | F1 | Time to detect |
|---|---|---|---|---|---|---|
| Rules only | 0.996 | 0.0108 | 0.992 | 0.996 | 0.994 | 0.2 s |
| Kitsune only (p99 x 1.1) | 0.623 | 0.3357 | 0.705 | 0.623 | 0.661 | 0.1 s |
| Kitsune only (max x 1.1, plan rule) | 0.308 | 0.1348 | 0.746 | 0.308 | 0.436 | 3.0 s |
| Combined (ARPGuard) | 0.983 | 0.0000 | 1.000 | 0.983 | 0.992 | 2.3 s |

Incidents: #1 Likely legitimate change at t=332.034 s; #2 Likely legitimate change at t=384.91 s; #3 Anomaly, not ARP-related at t=410.719 s; #4 Anomaly, not ARP-related at t=430.751 s; #5 Confirmed spoofing at t=450.1 s; #6 Anomaly, not ARP-related at t=694.941 s

### home_benign_synthetic.pcap

15,933 packets evaluated (after Kitsune's grace period of 6,826 packets), 0 labelled malicious.

| Method | Detection rate | FPR | Precision | Recall | F1 | Time to detect |
|---|---|---|---|---|---|---|
| Rules only | 0.000 | 0.1776 | 0.000 | 0.000 | 0.000 | n/a |
| Kitsune only (p99 x 1.1) | 0.000 | 0.0133 | 0.000 | 0.000 | 0.000 | n/a |
| Kitsune only (max x 1.1, plan rule) | 0.000 | 0.0000 | 0.000 | 0.000 | 0.000 | n/a |
| Combined (ARPGuard) | 0.000 | 0.0000 | 0.000 | 0.000 | 0.000 | n/a |

Incidents: #1 Likely legitimate change at t=261.884 s; #2 Likely legitimate change at t=399.5 s
