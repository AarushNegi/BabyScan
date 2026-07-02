from concurrent.futures import ThreadPoolExecutor, as_completed
from babyscan.scanner import scan_port
import socket
import argparse
import sys

COMMON_SERVICES = {
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
}


parser = argparse.ArgumentParser(
    description="BabyScan - Multi-threaded Port Scanner"
)

parser.add_argument(
    "target",
    help="Target IP address or hostname"
)

parser.add_argument(
    "-p",
    "--ports",
    default="1-1024",
    help="Port range (example: 1-1024)"
)

parser.add_argument(
    "-t",
    "--threads",
    type=int,
    default=100,
    help="Number of worker threads (default: 100)"
)

args = parser.parse_args()

TARGET = args.target
MAX_WORKERS = args.threads

try:
    START_PORT, END_PORT = map(int, args.ports.split("-"))

    if START_PORT < 1 or END_PORT > 65535 or START_PORT > END_PORT:
        raise ValueError

except ValueError:
    print("Invalid port range. Example: 1-1024")
    sys.exit(1)


def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return COMMON_SERVICES.get(port, "unknown")


def check_port(port):
    if scan_port(TARGET, port):
        service = get_service_name(port)
        return port, service

    return None


def main():
    print("Starting BabyScan...")
    print(f"Target: {TARGET}")

    try:
        resolved_ip = socket.gethostbyname(TARGET)
        print(f"Resolved IP: {resolved_ip}")
    except socket.gaierror:
        print("Failed to resolve target hostname.")
        return

    print(f"Scanning ports {START_PORT}-{END_PORT}")
    print(f"Threads: {MAX_WORKERS}")
    print("-" * 50)

    total_ports = END_PORT - START_PORT + 1
    completed = 0
    open_ports = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(check_port, port): port
            for port in range(START_PORT, END_PORT + 1)
        }

        for future in as_completed(futures):
            completed += 1

            print(
                f"\rProgress: {completed}/{total_ports}",
                end="",
                flush=True
            )

            result = future.result()

            if result:
                port, service = result
                open_ports.append((port, service))
                print(f"\n[OPEN] {port}/tcp ({service})")

    print("\n" + "-" * 50)

    if open_ports:
        print("Open ports discovered:")
        for port, service in sorted(open_ports):
            print(f"  {port}/tcp -> {service}")
    else:
        print("No open ports found.")

    print("-" * 50)
    print("Scan complete.")


if __name__ == "__main__":
    main()