"""ARPGuard command line.

  python -m arpguard analyze capture.pcap [--gateway IP] [--json out.json] [--explain]
  python -m arpguard serve [--port 8000]            dashboard + API on http://localhost:8000
  python -m arpguard live [--iface eth0] [--seconds 300] [--record home.pcap]
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from .core.fusion import VERDICTS


def _print_result(result: dict) -> None:
    m = result["meta"]
    print(f"\n{m['source']}: {m['packets']:,} packets ({m['arp_packets']:,} ARP) over {m['duration']:.0f} s")
    gw = result["gateway"]
    print(f"gateway: {gw['ip']} at {gw['mac']} ({gw['source']})")
    k = m.get("kitsune")
    if k:
        print(f"kitsune: grace {k['fm_grace']}+{k['ad_grace']} packets, threshold {k['threshold']:.4f}")
    print(f"\nverdict: {m['verdict_label'].upper()}\n")
    for inc in result["incidents"]:
        print(f"  #{inc['id']} {VERDICTS[inc['verdict']]['label']:28s} t={inc['first_t']:>8.1f}s  "
              f"actor={inc['actor'] or '-'} ({inc['actor_vendor'] or 'kitsune only'})")
        e = inc.get("explanation")
        if e:
            print(f"      {e['headline']}")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="arpguard", description="AI-assisted ARP spoofing detection")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyse a pcap/pcapng file")
    a.add_argument("capture")
    a.add_argument("--gateway")
    a.add_argument("--no-kitsune", action="store_true")
    a.add_argument("--limit", type=int, help="only the first N packets (Kitsune is slow in Python)")
    a.add_argument("--start", type=int, default=0, help="skip the first N packets")
    a.add_argument("--threshold", choices=["quantile", "max"], default="quantile")
    a.add_argument("--json", help="write the full result JSON here (the dashboard can replay it)")
    a.add_argument("--explain", action="store_true", help="use the LLM for explanations (else templates)")

    s = sub.add_parser("serve", help="run the dashboard and API locally")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)

    lv = sub.add_parser("live", help="sniff this machine's LAN (needs root; your own network only)")
    lv.add_argument("--iface")
    lv.add_argument("--gateway")
    lv.add_argument("--seconds", type=float, default=0, help="stop after this long (0 = until Ctrl-C)")
    lv.add_argument("--record", help="also save the traffic to this pcap (e.g. data/home_benign.pcap)")
    lv.add_argument("--no-kitsune", action="store_true")
    args = ap.parse_args(argv)

    if args.cmd == "analyze":
        from .ai.explainer import explain_result
        from .pipeline import analyze, count_frames
        t = time.time()
        n = count_frames(args.capture) - args.start
        if args.limit:
            n = min(n, args.limit)
        print(f"analysing {n:,} packets (Kitsune runs at roughly 700 packets/s in Python)...", file=sys.stderr)
        sess = analyze(args.capture, gateway_ip=args.gateway, use_kitsune=not args.no_kitsune,
                       limit=args.limit, start=args.start, threshold_mode=args.threshold,
                       progress=lambda i: print(f"  {i:,} packets", file=sys.stderr))
        result = explain_result(sess.result(), use_llm=args.explain)
        _print_result(result)
        print(f"\n({time.time() - t:.1f} s)", file=sys.stderr)
        if args.json:
            with open(args.json, "w") as fh:
                json.dump(result, fh, separators=(",", ":"))
            print(f"wrote {args.json}", file=sys.stderr)

    elif args.cmd == "serve":
        import uvicorn
        print(f"ARPGuard dashboard: http://{args.host}:{args.port}")
        uvicorn.run("arpguard.api.main:app", host=args.host, port=args.port)

    elif args.cmd == "live":
        from .core.live import LiveMonitor
        mon = LiveMonitor(iface=args.iface, gateway_ip=args.gateway, use_kitsune=not args.no_kitsune,
                          record_to=args.record)
        mon.start()
        print("sniffing; Ctrl-C to stop. Kitsune learns on the first 6,000 packets.", file=sys.stderr)
        seen = 0
        t0 = time.time()
        try:
            while not args.seconds or time.time() - t0 < args.seconds:
                time.sleep(0.5)
                for ev in mon.events_after(seen):
                    seen = ev["seq"]
                    if ev["type"] == "alert":
                        al = ev["alert"]
                        print(f"[{al['t']:8.1f}s] {al['severity'].upper():8s} {al['rule']}: {al['message']}")
                    elif ev["type"] == "verdict":
                        print(f"[{ev['t']:8.1f}s] VERDICT incident #{ev['incident']}: {ev['label']}")
        except KeyboardInterrupt:
            pass
        mon.stop()
        _print_result(mon.snapshot())


if __name__ == "__main__":
    main()
