# Report material

Put screenshots, figures and Wireshark captures for the write-up here.

Useful sources in this repo:

* `eval/RESULTS.md`: the comparison table (rules only, Kitsune only, combined); regenerate it with `python scripts/build_demo.py`, or run `python -m eval.evaluate` on the Kitsune capture
* `public/data/demo-attack.json`: every alert, incident, verdict timeline and explanation for the demo capture
* Wireshark display filters for screenshots: `arp`, `arp.duplicate-address-detected`, `arp.opcode == 2 && eth.src == 00:0c:29:7d:e1:66`, `bootp.option.dhcp == 5`
