from concurrent.futures import ThreadPoolExecutor, as_completed
from babyscan.scanner import scan_port
import socket

TARGET = "127.0.0.1"
START_PORT = 1
END_PORT = 10000
MAX_WORKERS = 100


def check_port(port):
    if scan_port(TARGET, port):
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "unknown"

        return port, service

    return None


def main():
    print("Starting BabyScan...")
    print(f"Target: {TARGET}")
    print(f"Scanning ports {START_PORT}-{END_PORT}")
    print("-" * 40)

    total_ports = END_PORT - START_PORT + 1
    completed = 0

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
                print(f"\n[OPEN] {port}/tcp ({service})")

    print("\n" + "-" * 40)
    print("Scan complete.")


if __name__ == "__main__":
    main()