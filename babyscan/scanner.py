import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from babyscan.banner import grab_banner


def scan_port(host: str, port: int, timeout: float = 0.2) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex((host, port))

            return result == 0

    except Exception:
        return False


def get_service(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def scan_host(host: str, ports: list[int], threads: int = 100, banners: bool = True) -> list[dict]:
    open_ports = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, host, port): port
            for port in ports
        }

        for future in as_completed(futures):
            port = futures[future]

            if future.result():
                open_ports.append({"port": port, "service": get_service(port)})

    if banners and open_ports:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(grab_banner, host, p["port"]): p
                for p in open_ports
            }

            for future in as_completed(futures):
                entry = futures[future]
                entry["banner"] = future.result()

    return sorted(open_ports, key=lambda p: p["port"])


def scan_hosts(hosts: list[str], ports: list[int], threads: int = 100, banners: bool = True) -> dict[str, list[dict]]:
    results = {}

    for host in hosts:
        results[host] = scan_host(host, ports, threads, banners)

    return results