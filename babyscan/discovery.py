import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import ARP, Ether, srp

def is_host_alive(ip, timeout=0.2):
    common_ports = [80, 443, 22, 445]

    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)

                if sock.connect_ex((str(ip), port)) == 0:
                    return True

        except Exception:
            pass

    return False


def discover_hosts(network):
    active_hosts = []

    net = ipaddress.ip_network(network, strict=False)

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {
            executor.submit(is_host_alive, ip): ip
            for ip in net.hosts()
        }

        for future in as_completed(futures):
            ip = futures[future]

            if future.result():
                active_hosts.append(str(ip))

    return sorted(active_hosts)



def arp_scan(network):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)

    answered, _ = srp(
        packet,
        timeout=2,
        verbose=False
    )

    devices = []

    for _, received in answered:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return sorted(devices, key=lambda x: x["ip"])