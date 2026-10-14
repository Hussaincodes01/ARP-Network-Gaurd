#!/usr/bin/env python3
"""Fetch the Kitsune "ARP MitM" capture and labels (Mirsky et al., NDSS 2018).

The UCI archive bundles all nine Kitsune attacks in one large zip. This
script streams it to disk, then extracts only the ARP MitM members into
data/kitsune/ (decompressing any .gz inside). If the download is blocked or
slow, download the zip yourself and pass it with --zip.

  python scripts/fetch_kitsune.py                       # download from UCI
  python scripts/fetch_kitsune.py --zip ~/Downloads/kitsune.zip

Then evaluate on a slice (Python Kitsune is slow, about 700 packets/s):

  python -m eval.evaluate data/kitsune/ARP_MitM_pcap.pcapng \\
      --labels data/kitsune/ARP_MitM_labels.csv --limit 200000

The member names inside the archive are matched loosely ("arp" anywhere in
the path), so the script prints what it extracted; use those paths above.
"""
from __future__ import annotations

import argparse
import gzip
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UCI_URL = "https://archive.ics.uci.edu/static/public/516/kitsune+network+attack.zip"


def download(url: str, dest: Path) -> None:
    print(f"downloading {url}\n  -> {dest} (several GB; Ctrl-C to stop)")
    with urllib.request.urlopen(url) as resp, open(dest, "wb") as out:
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        while chunk := resp.read(1 << 20):
            out.write(chunk)
            done += len(chunk)
            if total:
                print(f"\r  {done / 1e6:,.0f} / {total / 1e6:,.0f} MB", end="", flush=True)
    print()


def extract_arp(zip_path: Path, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    with zipfile.ZipFile(zip_path) as zf:
        members = [m for m in zf.namelist() if "arp" in m.lower() and not m.endswith("/")]
        if not members:
            sys.exit("no ARP MitM files found in the archive; members are:\n  " + "\n  ".join(zf.namelist()[:50]))
        for m in members:
            name = Path(m).name
            target = out_dir / (name[:-3] if name.endswith(".gz") else name)
            print(f"extracting {m} -> {target.relative_to(ROOT)}")
            with zf.open(m) as src:
                stream = gzip.GzipFile(fileobj=src) if name.endswith(".gz") else src
                with open(target, "wb") as dst:
                    shutil.copyfileobj(stream, dst, 1 << 20)
            if target.suffix == ".zip":   # nested archive
                with zipfile.ZipFile(target) as inner:
                    inner.extractall(out_dir)
            written.append(target)
    return written


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zip", type=Path, help="an already-downloaded Kitsune dataset zip")
    ap.add_argument("--url", default=UCI_URL)
    args = ap.parse_args()
    out_dir = ROOT / "data" / "kitsune"
    zip_path = args.zip
    if zip_path is None:
        out_dir.mkdir(parents=True, exist_ok=True)
        zip_path = out_dir / "kitsune.zip"
        if not zip_path.exists():
            download(args.url, zip_path)
    files = extract_arp(zip_path, out_dir)
    print("\nextracted:\n  " + "\n  ".join(str(f.relative_to(ROOT)) for f in files))


if __name__ == "__main__":
    main()
