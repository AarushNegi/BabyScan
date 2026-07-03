import argparse
import json
from datetime import datetime

from babyscan.discovery import arp_scan
from babyscan.scanner import scan_hosts
from babyscan.sniffer import sniff_traffic


def print_packet(info: dict) -> None:
    src = f"{info['src']}:{info['sport']}" if info["sport"] else info["src"]
    dst = f"{info['dst']}:{info['dport']}" if info["dport"] else info["dst"]

    print(f"{info['time']}  {info['proto'] or '-':5} {src} -> {dst}  {info['length']}B")

    if info["payload"]:
        printable = bytes.fromhex(info["payload"]).decode(errors="ignore").strip()
        if printable:
            print(f"    {printable[:80]}")


def parse_ports(port_range: str) -> list[int]:
    if "," in port_range:
        return [int(p.strip()) for p in port_range.split(",")]

    if "-" in port_range:
        start, end = port_range.split("-")
        return list(range(int(start), int(end) + 1))

    return [int(port_range)]


def build_report(devices: list[dict], scan_results: dict[str, list[dict]]) -> dict:
    return {
        "scan_timestamp": datetime.now().isoformat(),
        "devices": [
            {
                "ip": device["ip"],
                "mac": device["mac"],
                "open_ports": scan_results.get(device["ip"], []),
            }
            for device in devices
        ],
    }


def print_report(report: dict) -> None:
    for device in report["devices"]:
        print(f"\n{device['ip']:15} {device['mac']}")

        if device["open_ports"]:
            for p in device["open_ports"]:
                print(f"    {p['port']}/tcp  {p['service']}")
                if p.get("banner"):
                    print(f"        {p['banner'][:80]}")
        else:
            print("    no open ports")


def main():
    parser = argparse.ArgumentParser(description="BabyScan - ARP discovery + port scan")
    parser.add_argument("network", help="Target network CIDR, e.g. 192.168.1.0/24")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range (default: 1-1000)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Threads per host (default: 100)")
    parser.add_argument("--export", help="Export results to JSON file")
    parser.add_argument("--no-banners", action="store_true", help="Skip banner grabbing (faster)")
    parser.add_argument("--sniff", action="store_true", help="Sniff live traffic from discovered devices (Ctrl+C to stop)")
    parser.add_argument("--iface", help="Interface for sniffing (default: auto)")

    args = parser.parse_args()

    print(f"Scanning {args.network}")
    devices = arp_scan(args.network)

    if not devices:
        print("No devices found.")
        return

    print(f"Found {len(devices)} device(s).")
    hosts = [d["ip"] for d in devices]

    if args.sniff:
        print(f"Sniffing traffic from {len(hosts)} device(s). Press Ctrl+C to stop.\n")

        try:
            packets = sniff_traffic(hosts, iface=args.iface, on_packet=print_packet)
        except KeyboardInterrupt:
            packets = []

        print(f"\nCaptured {len(packets)} packet(s).")

        if args.export:
            with open(args.export, "w") as f:
                json.dump(packets, f, indent=2)
            print(f"Exported to {args.export}")

        return

    print(f"Scanning ports {args.ports}...")

    ports = parse_ports(args.ports)
    scan_results = scan_hosts(hosts, ports, args.threads, banners=not args.no_banners)

    report = build_report(devices, scan_results)
    print_report(report)

    if args.export:
        with open(args.export, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nExported to {args.export}")


if __name__ == "__main__":
    main()