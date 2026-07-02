from babyscan.scanner import scan_port
import socket

TARGET = "scanme.nmap.org"

for port in range(20, 101):
    if scan_port(TARGET, port):
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "unknown"

        print(f"{port}/tcp OPEN ({service})")