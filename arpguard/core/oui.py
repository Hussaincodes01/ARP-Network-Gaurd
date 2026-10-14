"""MAC address analysis: OUI vendor lookup and address-type bits.

The built-in table is a small offline subset of the IEEE registry covering
common home/campus/lab devices. Drop the full IEEE file at `data/oui.csv`
(https://standards-oui.ieee.org/oui/oui.csv) to resolve everything.
"""
from __future__ import annotations

import csv
from functools import lru_cache
from pathlib import Path

_BUILTIN = {
    # Virtualisation (an attacker VM shows up as one of these)
    "00:0c:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware",
    "08:00:27": "Oracle VirtualBox", "00:15:5d": "Microsoft Hyper-V",
    "52:54:00": "QEMU/KVM",
    # Routers, switches, access points
    "00:00:0c": "Cisco", "00:09:5b": "Netgear",
    "00:14:6c": "Netgear", "20:4e:7f": "Netgear", "50:c7:bf": "TP-Link",
    "f4:f2:6d": "TP-Link", "14:cc:20": "TP-Link", "00:05:5d": "D-Link",
    "00:0d:88": "D-Link", "00:15:6d": "Ubiquiti", "24:a4:3c": "Ubiquiti",
    "04:18:d6": "Ubiquiti", "00:e0:fc": "Huawei", "00:1a:92": "ASUSTek",
    "00:1e:8c": "ASUSTek", "00:0b:86": "Aruba",
    "00:1a:1e": "Aruba", "00:0f:e2": "H3C",
    # Computers and NICs
    "00:14:22": "Dell", "b8:ac:6f": "Dell", "f8:bc:12": "Dell", "18:03:73": "Dell",
    "00:1b:21": "Intel", "00:e0:4c": "Realtek",
    "00:03:93": "Apple", "00:0a:95": "Apple", "00:17:f2": "Apple",
    "00:1e:c2": "Apple", "00:25:00": "Apple", "00:1b:63": "Apple",
    "00:21:5a": "Hewlett Packard", "00:1b:78": "Hewlett Packard",
    "00:50:f2": "Microsoft", "00:1c:42": "Parallels",
    # Phones, IoT, cameras, printers
    "00:1a:11": "Google", "3c:5a:b4": "Google", "f4:f5:d8": "Google",
    "54:60:09": "Google", "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "24:0a:c4": "Espressif", "30:ae:a4": "Espressif", "84:f3:eb": "Espressif",
    "ec:fa:bc": "Espressif", "44:19:b6": "Hikvision", "c0:56:e3": "Hikvision",
    "bc:ad:28": "Hikvision", "00:40:8c": "Axis Communications",
    "ac:cc:8e": "Axis Communications", "00:80:77": "Brother",
    "00:09:bf": "Nintendo", "00:17:ab": "Nintendo",
}

_DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "oui.csv"


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    table = dict(_BUILTIN)
    if _DATA_FILE.exists():
        with open(_DATA_FILE, newline="", encoding="utf-8") as fh:
            for row in csv.reader(fh):
                # IEEE format: Registry, Assignment (hex), Organization Name, Address
                if len(row) >= 3 and len(row[1]) == 6:
                    h = row[1].lower()
                    table[f"{h[0:2]}:{h[2:4]}:{h[4:6]}"] = row[2].strip()
    return table


def mac_kind(mac: str) -> str:
    """'broadcast', 'multicast', 'local' (locally administered) or 'unicast'."""
    if mac == "ff:ff:ff:ff:ff:ff":
        return "broadcast"
    first = int(mac[:2], 16)
    if first & 0x01:
        return "multicast"
    if first & 0x02:
        return "local"
    return "unicast"


@lru_cache(maxsize=4096)
def vendor(mac: str) -> str:
    kind = mac_kind(mac)
    if kind == "broadcast":
        return "Broadcast"
    if kind == "multicast":
        return "Multicast"
    name = _table().get(mac[:8].lower())
    if name:
        return name
    if kind == "local":
        return "Locally administered (randomised or virtual)"
    return "Unknown vendor"
