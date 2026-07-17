import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353


def resolve_hostname(ip: str, timeout: float = 1.0) -> str:
    """Standard reverse DNS / NetBIOS lookup via the OS resolver."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return "unknown"
    finally:
        socket.setdefaulttimeout(old_timeout)


def _build_mdns_ptr_query(ip: str) -> bytes:
    # Reverse-lookup name, e.g. 192.168.1.4 -> "4.1.168.192.in-addr.arpa"
    reversed_octets = ".".join(reversed(ip.split(".")))
    qname = f"{reversed_octets}.in-addr.arpa"

    # DNS header: ID=0, flags=0 (standard query), 1 question, 0 answers/auth/extra
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)

    # QNAME as length-prefixed labels, terminated with 0x00
    qname_bytes = b"".join(
        struct.pack("B", len(label)) + label.encode()
        for label in qname.split(".")
    ) + b"\x00"

    # QTYPE = PTR (12), QCLASS = IN (1)
    question = qname_bytes + struct.pack(">HH", 12, 1)

    return header + question


def _parse_mdns_ptr_response(data: bytes) -> str | None:
    try:
        # Header: 6 fields of 2 bytes each
        _id, _flags, qdcount, ancount, _nscount, _arcount = struct.unpack(">HHHHHH", data[:12])
        offset = 12

        # Skip the question section
        for _ in range(qdcount):
            while data[offset] != 0:
                offset += data[offset] + 1
            offset += 1  # null terminator
            offset += 4  # QTYPE + QCLASS

        for _ in range(ancount):
            # NAME (often a compression pointer, 2 bytes)
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while data[offset] != 0:
                    offset += data[offset] + 1
                offset += 1

            rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            offset += rdlength

            if rtype == 12:  # PTR
                return _decode_dns_name(data, rdata, offset - rdlength)

        return None
    except Exception:
        return None


def _decode_dns_name(full_packet: bytes, _rdata: bytes, rdata_offset: int) -> str:
    labels = []
    offset = rdata_offset
    visited = 0

    while True:
        length = full_packet[offset]

        if length == 0:
            break

        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = struct.unpack(">H", full_packet[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            visited += 1
            if visited > 20:  # guard against malformed loops
                break
            continue

        offset += 1
        labels.append(full_packet[offset:offset + length].decode(errors="ignore"))
        offset += length

    return ".".join(labels)


def resolve_mdns(ip: str, timeout: float = 1.5) -> str:
    """
    Fallback for devices that don't answer classic reverse DNS/NetBIOS
    (Macs, phones, IoT, printers, smart-home gear) but do announce
    themselves over multicast DNS (Bonjour/Avahi) on UDP 5353.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        query = _build_mdns_ptr_query(ip)
        sock.sendto(query, (MDNS_GROUP, MDNS_PORT))

        data, _addr = sock.recvfrom(2048)
        name = _parse_mdns_ptr_response(data)
        return name if name else "unknown"
    except Exception:
        return "unknown"
    finally:
        sock.close()


def resolve_hostname_full(ip: str) -> str:
    """Try reverse DNS/NetBIOS first, fall back to mDNS if that fails."""
    name = resolve_hostname(ip)
    if name != "unknown":
        return name
    return resolve_mdns(ip)


def resolve_hostnames(devices: list[dict], threads: int = 50, use_mdns: bool = True) -> list[dict]:
    resolver = resolve_hostname_full if use_mdns else resolve_hostname

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(resolver, d["ip"]): d for d in devices}

        for future in as_completed(futures):
            device = futures[future]
            device["hostname"] = future.result()

    return devices