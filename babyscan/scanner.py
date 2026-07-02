import socket


def scan_port(host: str, port: int, timeout: float = 0.2) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex((host, port))

            return result == 0

    except Exception:
        return False