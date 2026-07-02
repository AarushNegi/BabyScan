import socket


def scan_port(host: str, port: int, timeout: float = 0.2) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((host, port))
        return result == 0

    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        return False

    finally:
        sock.close()