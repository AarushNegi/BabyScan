import socket


def grab_banner(host: str, port: int, timeout: float = 1.0) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))

            banner = _try_recv(sock)

            if not banner:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = _try_recv(sock)

            return banner.decode(errors="ignore").strip()

    except Exception:
        return ""


def _try_recv(sock: socket.socket, size: int = 1024) -> bytes:
    try:
        return sock.recv(size)
    except socket.timeout:
        return b""
    except Exception:
        return b""