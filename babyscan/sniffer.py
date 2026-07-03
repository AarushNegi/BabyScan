from datetime import datetime

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw


def build_filter(hosts: list[str]) -> str:
    return " or ".join(f"host {h}" for h in hosts)


def summarize_packet(pkt) -> dict:
    info = {
        "time": datetime.now().isoformat(),
        "src": None,
        "dst": None,
        "proto": None,
        "sport": None,
        "dport": None,
        "length": len(pkt),
        "payload": None,
    }

    if pkt.haslayer(IP):
        info["src"] = pkt[IP].src
        info["dst"] = pkt[IP].dst
        info["proto"] = str(pkt[IP].proto)

    if pkt.haslayer(TCP):
        info["proto"] = "TCP"
        info["sport"] = pkt[TCP].sport
        info["dport"] = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        info["proto"] = "UDP"
        info["sport"] = pkt[UDP].sport
        info["dport"] = pkt[UDP].dport

    if pkt.haslayer(Raw):
        info["payload"] = bytes(pkt[Raw].load).hex()

    return info


def sniff_traffic(hosts: list[str], iface: str | None = None, on_packet=None) -> list[dict]:
    packets = []
    bpf_filter = build_filter(hosts)

    def handler(pkt):
        info = summarize_packet(pkt)
        packets.append(info)
        if on_packet:
            on_packet(info)

    sniff(filter=bpf_filter, iface=iface, prn=handler, store=False)

    return packets