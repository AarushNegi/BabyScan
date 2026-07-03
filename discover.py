from babyscan.discovery import arp_scan

NETWORK = "192.168.1.0/24"

print(f"Scanning {NETWORK}")
print("-" * 40)

devices = arp_scan(NETWORK)

if devices:
    print("Discovered devices:\n")

    for device in devices:
        print(
            f"{device['ip']:15} "
            f"{device['mac']}"
        )
else:
    print("No devices found.")