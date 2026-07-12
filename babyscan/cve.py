import re
import time

import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


_NOT_PRODUCTS = {"http", "https", "tcp", "udp", "ftp"}


def extract_product_version(banner: str) -> str | None:
    # SSH banners: "SSH-2.0-OpenSSH_8.9"
    match = re.search(r"SSH-[\d.]+-([A-Za-z]+)[_/]([\d.]+)", banner)
    if match:
        return f"{match.group(1)} {match.group(2)}"

    # HTTP Server header: "Server: Apache/2.4.41"
    match = re.search(r"Server:\s*([A-Za-z][\w.]*)/([\d]+(?:\.\d+)+)", banner)
    if match:
        return f"{match.group(1)} {match.group(2)}"

    # Generic "Name/Version" anywhere in the text
    for match in re.finditer(r"([A-Za-z][\w.]*)/([\d]+(?:\.\d+)+)", banner):
        product = match.group(1)
        if product.lower() not in _NOT_PRODUCTS:
            return f"{product} {match.group(2)}"

    return None


def _best_severity(metrics: dict) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss = entries[0].get("cvssData", {})
            score = cvss.get("baseScore")
            severity = entries[0].get("baseSeverity") or cvss.get("baseSeverity")
            return score, severity

    return None, None


def search_cve(keyword: str, max_results: int = 5, timeout: float = 10) -> list[dict]:
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}

    try:
        resp = requests.get(NVD_API, params=params, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []

    results = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        score, severity = _best_severity(cve.get("metrics", {}))

        results.append({
            "id": cve.get("id"),
            "description": description[:200],
            "score": score,
            "severity": severity,
        })

    return results


def enrich_with_cves(scan_results: dict, max_results: int = 3, delay: float = 2.0) -> dict:
    for host, ports in scan_results.items():
        for p in ports:
            banner = p.get("banner") or ""
            keyword = extract_product_version(banner)

            if keyword:
                p["cves"] = search_cve(keyword, max_results=max_results)
                time.sleep(delay)  # stay under NVD's unauthenticated rate limit
            else:
                p["cves"] = []

    return scan_results