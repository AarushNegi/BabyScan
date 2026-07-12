def parse_ports(port_range: str) -> list[int]:
    if "," in port_range:
        return [int(p.strip()) for p in port_range.split(",")]

    if "-" in port_range:
        start, end = port_range.split("-")
        return list(range(int(start), int(end) + 1))

    return [int(port_range)]