from flask import Flask, render_template, request, jsonify

from babyscan.discovery import arp_scan
from babyscan.scanner import scan_hosts
from babyscan.cve import enrich_with_cves
from babyscan.hostname import resolve_hostnames
from babyscan.utils import parse_ports

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True)
    network = (data.get("network") or "").strip()
    port_range = (data.get("ports") or "1-1000").strip()
    include_cve = bool(data.get("cve", False))

    if not network:
        return jsonify({"error": "Network CIDR is required (e.g. 192.168.1.0/24)"}), 400

    try:
        ports = parse_ports(port_range)
    except ValueError:
        return jsonify({"error": f"Invalid port range: {port_range}"}), 400

    devices = arp_scan(network)

    if not devices:
        return jsonify({"devices": [], "message": "No devices found. Run as Administrator?"})

    devices = resolve_hostnames(devices)

    hosts = [d["ip"] for d in devices]
    scan_results = scan_hosts(hosts, ports, threads=100, banners=True)

    if include_cve:
        scan_results = enrich_with_cves(scan_results)

    report = [
        {
            "ip": d["ip"],
            "mac": d["mac"],
            "hostname": d.get("hostname", "unknown"),
            "open_ports": scan_results.get(d["ip"], []),
        }
        for d in devices
    ]

    return jsonify({"devices": report})


if __name__ == "__main__":
    app.run(debug=True, port=5000)