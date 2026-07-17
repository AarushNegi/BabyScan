import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def resolve_hostname(ip: str, timeout: float = 1.0) -> str:
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return "unknown"
    finally:
        socket.setdefaulttimeout(old_timeout)


def resolve_hostnames(devices: list[dict], threads: int = 50) -> list[dict]:
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(resolve_hostname, d["ip"]): d for d in devices}

        for future in as_completed(futures):
            device = futures[future]
            device["hostname"] = future.result()

    return devices