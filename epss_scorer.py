import json
import re
import time
import urllib.error
import urllib.request
from typing import Any

EPSS_API_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100
CACHE: dict[str, dict[str, Any]] = {}


def _cve_ids(results: list) -> list[str]:
    seen: set[str] = set()
    ids: list[str] = []
    for scan in results:
        vulns = scan.vulnerabilities if hasattr(scan, "vulnerabilities") else scan.get("vulnerabilities", [])
        for v in vulns:
            cve = v.id if hasattr(v, "id") else v.get("id", "")
            if re.match(r"^CVE-\d{4}-\d+$", cve, re.IGNORECASE) and cve.upper() not in seen:
                seen.add(cve.upper())
                ids.append(cve.upper())
    return ids


def _batch_query(cves: list[str]) -> dict[str, dict[str, Any]]:
    if not cves:
        return {}
    url = f"{EPSS_API_URL}?cve={','.join(cves)}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
        return {}

    results: dict[str, dict[str, Any]] = {}
    for entry in data.get("data", []):
        cve = entry.get("cve", "").upper()
        if cve:
            results[cve] = {
                "epss": float(entry.get("epss", 0)),
                "percentile": float(entry.get("percentile", 0)),
                "date": entry.get("date", ""),
            }
    return results


def fetch(results: list) -> dict[str, dict[str, Any]]:
    cves = _cve_ids(results)
    if not cves:
        return {}

    result_map: dict[str, dict[str, Any]] = {}
    uncached: list[str] = []

    for cve in cves:
        if cve in CACHE:
            result_map[cve] = CACHE[cve]
        else:
            uncached.append(cve)

    for i in range(0, len(uncached), BATCH_SIZE):
        batch = uncached[i : i + BATCH_SIZE]
        batch_data = _batch_query(batch)
        for cve, data in batch_data.items():
            CACHE[cve] = data
            result_map[cve] = data
        if i + BATCH_SIZE < len(uncached):
            time.sleep(0.3)

    return result_map


def enrich(results: list) -> list:
    epss_data = fetch(results)

    for scan in results:
        for v in scan.vulnerabilities:
            cve = v.id.upper()
            if cve in epss_data:
                v.epss = epss_data[cve]["epss"]
                v.epss_percentile = epss_data[cve]["percentile"]

    return results


def filter_by_threshold(results: list, threshold: float) -> list:
    for scan in results:
        scan.vulnerabilities = [
            v for v in scan.vulnerabilities
            if v.epss is None or v.epss >= threshold
        ]
    return results
