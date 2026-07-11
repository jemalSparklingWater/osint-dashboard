"""
recon.py — the "intelligence gathering" functions.

Each function here talks to ONE public data source and returns clean Python data.
Keeping these separate from the web app is good design: app.py handles
"the web stuff," recon.py handles "the OSINT stuff." That separation is a habit
worth building early.
"""

import os
import time
import ipaddress
from urllib.parse import urlparse

import requests
import urllib3
import dns.resolver
import whois
from dotenv import load_dotenv

# We deliberately hit origin candidates by IP, so the TLS cert won't match —
# silence the noisy "insecure request" warning that causes.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Read the .env file and load its values into the environment. This is how we
# keep secrets (like the Shodan key) OUT of our source code. os.getenv then
# reads the key at runtime — if .env is missing, we just get None and handle it.
load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

# A User-Agent identifies our program to servers. Some services are friendlier
# when you send one instead of the default "python-requests" string.
HEADERS = {"User-Agent": "osint-dashboard/1.0"}


def _fetch_crtsh(domain: str, retries: int = 2):
    """
    Low-level helper: fetch the raw certificate records from crt.sh, with retries.

    Returns (records, error). On success records is a list and error is None.
    On failure records is None and error is a short message.

    crt.sh is frequently overloaded — and when it is, it HANGS rather than failing
    fast. So we keep the per-request timeout short (8s) and only try twice: if
    crt.sh is having a bad moment, we bail quickly and let the caller fall back to
    certspotter, instead of making the user wait ~100 seconds.
    """
    # The %25 is a URL-encoded "%", which is a wildcard on crt.sh: "%.domain"
    # means "anything.domain". output=json asks for machine-readable results.
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    last_problem = "unknown error"
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=HEADERS, timeout=8)
            if response.status_code == 200:
                return response.json(), None
            # A 5xx/4xx here usually means crt.sh is just busy; note it and retry.
            last_problem = f"HTTP {response.status_code}"
        except Exception as e:
            last_problem = str(e)
        time.sleep(1)  # brief pause before the second attempt

    return None, f"crt.sh unavailable ({last_problem})"


# Cloudflare's published IPv4 ranges. If a subdomain resolves OUTSIDE these, it's
# a "direct" host that bypasses Cloudflare — a candidate real/origin server.
_CLOUDFLARE_V4 = [ipaddress.ip_network(c) for c in [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]]


def is_cloudflare_ip(ip: str) -> bool:
    """True if the IP belongs to Cloudflare (so the real server is hidden behind it)."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _CLOUDFLARE_V4)
    except ValueError:
        return False


def find_direct_ips(subdomains: list[str], limit: int = 30) -> dict:
    """
    Try to see PAST Cloudflare. Resolve each subdomain; if one points to an IP
    that ISN'T Cloudflare's, that host bypasses the CDN — it's a candidate origin
    / real server whose true ports you could then scan. Returns {subdomain: ip}.

    We prioritise subdomains that commonly leak the origin (mail, ftp, dev...),
    then fill in the rest, capped so the scan stays fast.
    """
    leaky = ("mail", "ftp", "cpanel", "webmail", "smtp", "direct", "origin",
             "dev", "staging", "test", "vpn", "old", "server", "mx", "ns")
    ordered = sorted(subdomains, key=lambda s: 0 if any(k in s for k in leaky) else 1)

    direct = {}
    for sub in ordered[:limit]:
        try:
            answers = dns.resolver.resolve(sub, "A", lifetime=3)
        except Exception:
            continue
        for a in answers:
            ip = str(a)
            if not is_cloudflare_ip(ip):
                direct[sub] = ip
                break
    return direct


def verify_origin(ip: str, domain: str) -> dict:
    """
    Check whether a candidate IP is REALLY the site's origin — i.e. whether the
    Cloudflare bypass actually works. We connect straight to the IP but send the
    target's Host header; if it serves the real site, we've reached the origin.

    Returns {"status": "confirmed" | "maybe" | "no", "detail": ...}:
      * confirmed — it serves the target site directly (bypass works!)
      * maybe     — it answers, but the content doesn't clearly match
      * no        — it doesn't serve the site (a different/unrelated host)
    """
    root = domain.split(".")[0]
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{ip}/", headers={**HEADERS, "Host": domain},
                             timeout=6, verify=False, allow_redirects=False)
        except Exception:
            continue
        if r.status_code >= 400:
            return {"status": "no",
                    "detail": f"answers HTTP {r.status_code} — not serving {domain}"}
        body = (r.text or "")[:8000].lower()
        if domain in body or (len(root) > 3 and root in body):
            return {"status": "confirmed",
                    "detail": f"HTTP {r.status_code} — serves {domain} directly (bypass works!)"}
        return {"status": "maybe",
                "detail": f"HTTP {r.status_code} — answers, but content doesn't clearly match {domain}"}
    return {"status": "no", "detail": "no direct HTTP response for this site"}


def _belongs(host: str, domain: str) -> bool:
    """
    True only if `host` is the domain itself or a real subdomain of it.
    Certificate logs return every name on a cert, so a cert shared with a
    lookalike/phishing domain (e.g. 'pornhub.com--com.com', 'www--pornhub.com')
    would otherwise pollute the list. A plain endswith() isn't enough:
    'notpornhub.com'.endswith('pornhub.com') is True — so we require the dot.
    """
    return host == domain or host.endswith("." + domain)


def _fetch_certspotter(domain: str) -> tuple:
    """
    Backup subdomain source for when crt.sh is down. certspotter (by SSLMate)
    reads the same public Certificate Transparency logs but is far more reliable.
    Returns (set_of_subdomains, error). It gives hostnames only — no emails.
    """
    url = "https://api.certspotter.com/v1/issuances"
    params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
    try:
        response = requests.get(url, params=params, headers=HEADERS, timeout=25)
        if response.status_code != 200:
            return set(), f"HTTP {response.status_code}"
        issuances = response.json()
    except Exception as e:
        return set(), str(e)

    subdomains = set()
    for issuance in issuances:
        for name in issuance.get("dns_names", []):
            name = name.strip().lower()
            if name and not name.startswith("*") and _belongs(name, domain):
                subdomains.add(name)
    return subdomains, None


def get_certificate_data(domain: str) -> dict:
    """
    Discover a domain's subdomains (and any emails) from public Certificate
    Transparency logs. We try crt.sh first; if it's down (it often is), we
    automatically fall back to certspotter so a flaky service doesn't leave the
    user with nothing. Using two sources with a fallback is how you make a tool
    resilient to any single provider having a bad day.

    Returns {"subdomains": [...], "emails": [...], "error": None or str}.
    """
    records, error = _fetch_crtsh(domain)
    if not error:
        subdomains = set()
        emails = set()
        for record in records:
            for name in record.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if not name or name.startswith("*"):
                    continue
                if "@" in name:
                    # keep the email only if its domain belongs to the target
                    if _belongs(name.split("@")[-1], domain):
                        emails.add(name)
                elif _belongs(name, domain):
                    subdomains.add(name)                # a real subdomain of the target
        return {"subdomains": sorted(subdomains), "emails": sorted(emails),
                "error": None, "source": "crt.sh"}

    # crt.sh failed — fall back to certspotter (subdomains only, no emails).
    subdomains, cs_error = _fetch_certspotter(domain)
    if not cs_error:
        return {"subdomains": sorted(subdomains), "emails": [],
                "error": None, "source": "certspotter (crt.sh was down)"}

    # Both sources failed — now it's genuinely a failure.
    return {"subdomains": [], "emails": [],
            "error": f"crt.sh failed ({error}); certspotter also failed ({cs_error})"}


def get_redirect(domain: str) -> dict:
    """
    Visit the domain and see if it redirects to a DIFFERENT domain (like jew.com
    -> mybible.com). If it does, we surface the target so the user can scan that
    domain next. We compare hostnames ignoring "www." so an http->https or
    www redirect on the SAME site doesn't count as a real redirect.

    Returns {"redirected": bool, "final_domain": str or None, "final_url": str or None}.
    """
    def _base(host: str) -> str:
        return (host or "").lower().rstrip(".").removeprefix("www.")

    for scheme in ("https://", "http://"):
        try:
            response = requests.get(scheme + domain, timeout=6,
                                    allow_redirects=True, headers=HEADERS)
        except Exception:
            continue  # try the other scheme
        final_host = urlparse(response.url).hostname or ""
        redirected = _base(final_host) != _base(domain) and bool(final_host)
        return {
            "redirected": redirected,
            "final_domain": final_host.lower() if redirected else None,
            "final_url": response.url if redirected else None,
        }

    return {"redirected": False, "final_domain": None, "final_url": None}


def get_dns_records(domain: str) -> dict:
    """
    Look up the domain's core DNS records: its IP addresses (A), mail servers
    (MX), name servers (NS), and text records (TXT, often used for verification).
    """
    record_types = ["A", "MX", "NS", "TXT"]
    results = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(answer) for answer in answers]
        except Exception:
            # e.g. the domain has no MX record — that's normal, not an error.
            results[record_type] = []

    return results


def _clean(value) -> str:
    """
    WHOIS fields are messy: a value might be a single item, a LIST of items
    (e.g. two creation dates), or None. This helper turns any of those into one
    readable string so the rest of our code doesn't have to worry about it.
    """
    if value is None:
        return "—"
    if isinstance(value, list):
        # Take the first entry; that's enough for a summary.
        value = value[0] if value else "—"
    return str(value)


def get_whois(domain: str) -> dict:
    """
    Look up the domain's registration record: who registered it, when it was
    created, when it expires, and where. This is public "who owns this domain"
    information that every registered domain must publish.
    """
    try:
        w = whois.whois(domain)
    except Exception:
        # Some registries (e.g. Israel's .il) return a format our WHOIS library
        # can't parse. Not a real error — just unsupported. Keep it friendly.
        return {"error": "WHOIS unavailable for this domain — its registry's "
                         "format isn't supported (common for some country TLDs)."}

    return {
        "registrar": _clean(w.registrar),
        "created": _clean(w.creation_date),
        "expires": _clean(w.expiration_date),
        "country": _clean(w.country),
        "organization": _clean(w.org),
    }


def _shodan_authenticated(ip: str):
    """
    The rich, key-based Shodan host lookup. Returns the full data dict on success,
    or None if it can't get data (bad key, or the IP needs a paid plan → 403/404).
    Returning None signals the caller to fall back to the free InternetDB.
    """
    if not SHODAN_API_KEY:
        return None
    try:
        response = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=25)
    except Exception:
        return None
    if response.status_code != 200:   # 401 bad key, 403 needs paid plan, 404 no data
        return None

    host = response.json()
    # Each entry is one service; we build a readable label AND collect CPEs
    # (standardized software IDs like cpe:/a:apache:http_server:2.4.7 that we
    # match against known CVEs). Keep application CPEs ("a:"); skip noisy OS ones.
    services, cpes = [], set()
    for item in host.get("data", []):
        product = item.get("product") or item.get("_shodan", {}).get("module", "")
        label = f"{item.get('port')}/{item.get('transport', 'tcp')}"
        if product:
            label += f" — {product}"
        services.append(label)
        for cpe in item.get("cpe", []) or []:
            if cpe.startswith("cpe:/a:"):
                cpes.add(cpe)

    return {
        "ip": ip,
        "org": host.get("org", "—"),
        "os": host.get("os") or "—",
        "ports": sorted(host.get("ports", [])),
        "services": services,
        "cpes": sorted(cpes),
        "vulns": [],
        "source": "Shodan (authenticated)",
    }


def _shodan_internetdb(ip: str) -> dict:
    """
    Shodan's FREE fallback service: internetdb.shodan.io. No API key, no
    membership, works on any IP (including ones the paid host lookup blocks with
    a 403). It returns open ports, software CPEs, and even a list of known CVEs.
    Less detail than the authenticated lookup (no software versions), but it means
    the "open ports" panel keeps working for every target until the paid plan
    is available.
    """
    try:
        response = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=20)
    except Exception as e:
        return {"ip": ip, "ports": [], "services": [], "cpes": [], "vulns": [],
                "error": f"InternetDB request failed: {e}"}
    if response.status_code == 404:
        return {"ip": ip, "ports": [], "services": [], "cpes": [], "vulns": [],
                "note": "No data for this IP (nothing indexed yet)."}
    if response.status_code != 200:
        return {"ip": ip, "ports": [], "services": [], "cpes": [], "vulns": [],
                "note": f"InternetDB returned HTTP {response.status_code}."}

    data = response.json()
    ports = sorted(data.get("ports", []))
    hostnames = data.get("hostnames") or ["—"]
    return {
        "ip": ip,
        "org": hostnames[0],                       # InternetDB gives a hostname, not org
        "os": "—",
        "ports": ports,
        "services": [f"{p}/tcp" for p in ports],   # ports only, no product banners
        "cpes": [c for c in data.get("cpes", []) if c.startswith("cpe:/a:")],
        "vulns": data.get("vulns", []),            # pre-matched CVE IDs — a free bonus!
        "source": "Shodan InternetDB (free)",
    }


def get_shodan_host(ip: str) -> dict:
    """
    Find a target's exposed ports/services for a given IP. We try the rich
    authenticated Shodan lookup first; if that can't return data (bad key, or the
    IP requires a paid plan), we fall back to the free InternetDB so the feature
    keeps working on every target. This fallback is what lets us cover IPs like
    Google's that the free key alone gets a 403 on.
    """
    if not ip:
        return {"error": "No IP address to look up."}

    result = _shodan_authenticated(ip)
    if result is not None:
        return result
    return _shodan_internetdb(ip)
