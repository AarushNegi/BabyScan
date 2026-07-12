from datetime import datetime

from scapy.all import sniff
from scapy.layers.l2 import ARP


def build_baseline(devices: list[dict]) -> dict[str, str]:
    return {d["ip"]: d["mac"] for d in devices}


def check_reply(seen: dict[str, str], ip: str, mac: str) -> dict | None:
    alert = None

    if ip in seen and seen[ip] != mac:
        alert = {
            "time": datetime.now().isoformat(),
            "ip": ip,
            "expected_mac": seen[ip],
            "seen_mac": mac,
        }

    seen[ip] = mac
    return alert


def watch_arp(baseline: dict[str, str], iface: str | None = None, on_alert=None) -> None:
    seen = dict(baseline)

    def handler(pkt):
        if not pkt.haslayer(ARP) or pkt[ARP].op != 2:
            return

        alert = check_reply(seen, pkt[ARP].psrc, pkt[ARP].hwsrc)

        if alert and on_alert:
            on_alert(alert)

    sniff(filter="arp", iface=iface, prn=handler, store=False)