"""
cve.py — look up known vulnerabilities (CVEs) for detected software.

This is the free stand-in for Shodan's paid "vulns" field. Shodan tells us WHAT
software a host runs (via CPE identifiers). The NVD — the U.S. government's
National Vulnerability Database — is a free, authoritative list of every public
vulnerability (CVE). We hand the CPEs to NVD and get back the matching CVEs.

That's the whole trick most commercial tools charge for: match "software +
version" to "known vulnerabilities." Doing it yourself teaches how it works.

Optional: set NVD_API_KEY in .env to raise NVD's rate limit (free at
nvd.nist.gov/developers/request-an-api-key). Without one it still works, just
slower (5 requests per 30 seconds).
"""

import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_API_KEY = os.getenv("NVD_API_KEY")
_HEADERS = {"apiKey": _API_KEY} if _API_KEY else {}


def _to_cpe23(cpe: str) -> str:
    """
    Convert Shodan's older CPE 2.2 format to the CPE 2.3 format NVD expects.
    'cpe:/a:apache:http_server:2.4.7'  ->  'cpe:2.3:a:apache:http_server:2.4.7'
    (NVD then treats missing trailing fields as wildcards for matching.)
    """
    if cpe.startswith("cpe:2.3:"):
        return cpe
    body = cpe.replace("cpe:/", "")          # a:apache:http_server:2.4.7
    return "cpe:2.3:" + body


def _cvss(cve: dict):
    """Pull the CVSS base score + severity out of an NVD record (tries v3 then v2)."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            return data.get("baseScore"), data.get("baseSeverity", "UNKNOWN")
    if metrics.get("cvssMetricV2"):
        entry = metrics["cvssMetricV2"][0]
        return entry["cvssData"].get("baseScore"), entry.get("baseSeverity", "UNKNOWN")
    return None, "UNKNOWN"


def _description(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _lookup_by_id(cve_id: str):
    """Fetch one CVE's details from NVD by its ID (for CVEs InternetDB pre-matched)."""
    try:
        resp = requests.get(NVD_URL, params={"cveId": cve_id},
                            headers=_HEADERS, timeout=30)
        if resp.status_code != 200:
            return None
        vulns = resp.json().get("vulnerabilities", [])
    except Exception:
        return None
    if not vulns:
        return None
    c = vulns[0].get("cve", {})
    score, severity = _cvss(c)
    return {"id": c.get("id"), "score": score, "severity": severity,
            "desc": _description(c)[:200], "cpe": "Shodan InternetDB"}


def _has_version(cpe: str) -> bool:
    """
    True only if a CPE carries a SPECIFIC software version we can trust for CVE
    matching. Two ways this goes wrong and creates false positives:

      * No version at all — 'cpe:/a:cloudflare:cloudflare' (just "uses Cloudflare")
        matches every Cloudflare CVE.
      * A bare, generic version — 'cpe:/a:ntp:ntp:3' where "3" is really the NTP
        *protocol* version, not the daemon build. Since 3 < 4.2.8, it matches
        every "NTP before 4.2.8" CVE for any NTP server anywhere.

    A real, specific software version has a dot (2.4.7, 6.6.1p1, 1.18.0). We
    require that — a versionless CPE or a single-number "version" is skipped.
    """
    body = cpe.replace("cpe:/a:", "").strip(":")
    parts = [p for p in body.split(":") if p]
    if len(parts) < 3:
        return False                 # vendor:product only — no version
    version = parts[2]
    return "." in version            # a trustworthy version looks like 2.4.7


def lookup_cves(cpes: list[str], known_ids: list[str] = None,
                max_cpes: int = 4, per_cpe: int = 5, max_ids: int = 10) -> list[dict]:
    """
    Find known vulnerabilities two ways and merge them:
      1. For each VERSIONED CPE (software ID + version), ask NVD which CVEs affect it.
      2. For any CVE IDs InternetDB already matched (known_ids), fetch their details.

    Each finding: {"id", "score", "severity", "desc", "cpe"}. We cap counts to
    respect NVD's rate limit and keep the report readable.
    """
    findings = []
    seen = set()

    # Only match CVEs from CPEs that include a version — see _has_version.
    versioned_cpes = [c for c in cpes if _has_version(c)]

    for cpe in versioned_cpes[:max_cpes]:
        try:
            resp = requests.get(
                NVD_URL,
                params={"virtualMatchString": _to_cpe23(cpe), "resultsPerPage": 30},
                headers=_HEADERS,
                timeout=30,
            )
            if resp.status_code != 200:
                continue
            vulns = resp.json().get("vulnerabilities", [])
        except Exception:
            continue

        scored = []
        for v in vulns:
            cve = v.get("cve", {})
            cid = cve.get("id")
            if not cid or cid in seen:
                continue
            score, severity = _cvss(cve)
            scored.append({
                "id": cid,
                "score": score,
                "severity": severity,
                "desc": _description(cve)[:200],
                "cpe": cpe,
            })

        # Keep the most severe few for this service.
        scored.sort(key=lambda c: c["score"] or 0, reverse=True)
        for item in scored[:per_cpe]:
            seen.add(item["id"])
            findings.append(item)

        # Respect NVD rate limits: with a key we can go fast; without, slow down.
        time.sleep(0.7 if _API_KEY else 2.0)

    # Add any CVEs InternetDB already matched to this host (not already seen).
    for cve_id in (known_ids or [])[:max_ids]:
        if cve_id in seen:
            continue
        detail = _lookup_by_id(cve_id)
        if detail:
            seen.add(cve_id)
            findings.append(detail)
        time.sleep(0.7 if _API_KEY else 2.0)

    findings.sort(key=lambda c: c["score"] or 0, reverse=True)
    return findings
