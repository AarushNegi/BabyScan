"""
ARP Scanner Module for BabyScan
Discovers active devices on the local network using ARP packets via Npcap
"""

import subprocess
import re
import ipaddress
from typing import List, Dict, Optional
import sys
import os

# Check if scapy is installed; if not, suggest installation
try:
    from scapy.all import ARP, Ether, srp, get_if_list, get_if_hwaddr
except ImportError:
    print("⚠️  Scapy not found. Install with:")
    print("   pip install scapy")
    sys.exit(1)


class ARPScanner:
    """
    Scans local network using ARP requests to discover active devices.
    Requires Npcap to be installed on Windows.
    """

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.discovered_devices = []

    def get_local_network(self) -> Optional[str]:
        """
        Auto-detect the local network CIDR from active network interfaces.
        Tries to find the primary active interface and derive the subnet.
        """
        try:
            # Get all network interfaces
            interfaces = get_if_list()
            if not interfaces:
                print("❌ No network interfaces found. Npcap may not be installed correctly.")
                return None

            if self.verbose:
                print(f"📡 Available interfaces: {interfaces}")

            # Try to use the first non-loopback interface
            for iface in interfaces:
                try:
                    hwaddr = get_if_hwaddr(iface)
                    if hwaddr and hwaddr != "00:00:00:00:00:00":
                        if self.verbose:
                            print(f"🔗 Using interface: {iface} ({hwaddr})")
                        return iface
                except Exception as e:
                    continue

            # Fallback: use the first interface
            if self.verbose:
                print(f"🔗 Using default interface: {interfaces[0]}")
            return interfaces[0]

        except Exception as e:
            print(f"❌ Error detecting network interface: {e}")
            return None

    def get_gateway_ip(self) -> Optional[str]:
        """
        Attempt to retrieve the default gateway IP address.
        On Windows, uses 'ipconfig' output.
        On Linux/Mac, uses 'route' or 'ip' commands.
        """
        try:
            if sys.platform.startswith("win"):
                # Windows: parse ipconfig output
                result = subprocess.run(
                    ["ipconfig"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                # Look for "Default Gateway" line
                for line in result.stdout.split("\n"):
                    if "Default Gateway" in line:
                        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                        if match:
                            return match.group(1)
            else:
                # Linux/Mac: try 'ip route'
                result = subprocess.run(
                    ["ip", "route"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                for line in result.stdout.split("\n"):
                    if "default via" in line:
                        match = re.search(r"via (\d+\.\d+\.\d+\.\d+)", line)
                        if match:
                            return match.group(1)
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Could not retrieve gateway IP: {e}")

        return None

    def calculate_network_cidr(self, ip_or_gateway: str) -> str:
        """
        Given an IP address, calculate the network CIDR.
        Assumes a standard /24 subnet (255.255.255.0) for most home/office networks.
        """
        try:
            # Remove trailing .0 or .1 if present and assume /24
            parts = ip_or_gateway.split(".")
            network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            # Validate the CIDR
            ipaddress.ip_network(network, strict=False)
            return network
        except Exception as e:
            if self.verbose:
                print(f"❌ Error calculating network CIDR: {e}")
            return None

    def scan(self, target_network: Optional[str] = None, timeout: int = 2) -> List[Dict]:
        """
        Perform ARP scan on the target network.

        Args:
            target_network: CIDR notation (e.g., "192.168.1.0/24"). 
                          If None, auto-detect the local network.
            timeout: Timeout for ARP responses in seconds.

        Returns:
            List of dicts containing discovered devices with keys:
            - ip: IP address
            - mac: MAC address
            - vendor: Attempted vendor lookup (optional)
        """
        # Auto-detect network if not provided
        if not target_network:
            gateway = self.get_gateway_ip()
            if gateway:
                if self.verbose:
                    print(f"🌐 Gateway detected: {gateway}")
                target_network = self.calculate_network_cidr(gateway)
            else:
                if self.verbose:
                    print("⚠️  Could not auto-detect network. Please specify target_network.")
                return []

        if not target_network:
            return []

        if self.verbose:
            print(f"\n🔍 Scanning network: {target_network}")
            print(f"⏱️  Timeout: {timeout}s\n")

        try:
            # Create ARP request packet
            arp = ARP(pdst=target_network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            # Send ARP request and capture responses
            answered, unanswered = srp(packet, timeout=timeout, verbose=False)

            self.discovered_devices = []
            for sent, received in answered:
                device = {
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                }

                # Try to resolve hostname (optional, can be slow)
                try:
                    import socket
                    hostname = socket.gethostbyaddr(received.psrc)[0]
                    device["hostname"] = hostname
                except Exception:
                    device["hostname"] = "N/A"

                self.discovered_devices.append(device)

                if self.verbose:
                    print(f"✅ {received.psrc:15} | {received.hwsrc:17} | {device.get('hostname', 'N/A')}")

            if self.verbose:
                print(f"\n📊 Total devices found: {len(self.discovered_devices)}")

            return self.discovered_devices

        except Exception as e:
            print(f"❌ ARP scan failed: {e}")
            print("\n⚠️  Troubleshooting:")
            print("   - Ensure Npcap is installed: https://npcap.com/")
            print("   - Run as Administrator (required for raw socket access)")
            print("   - Check your network interface is active")
            return []

    def get_devices(self) -> List[Dict]:
        """Return the last scan results."""
        return self.discovered_devices

    def export_json(self, filepath: str) -> bool:
        """Export discovered devices to JSON file."""
        try:
            import json
            with open(filepath, "w") as f:
                json.dump(self.discovered_devices, f, indent=2)
            if self.verbose:
                print(f"💾 Devices exported to {filepath}")
            return True
        except Exception as e:
            print(f"❌ Export failed: {e}")
            return False


def scan_wifi_devices(target_network: Optional[str] = None, timeout: int = 2) -> List[Dict]:
    """
    Convenience function to scan WiFi devices with one line.

    Args:
        target_network: CIDR notation (e.g., "192.168.1.0/24")
        timeout: Timeout for ARP responses

    Returns:
        List of discovered devices
    """
    scanner = ARPScanner(verbose=True)
    return scanner.scan(target_network=target_network, timeout=timeout)