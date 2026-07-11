"""
risk.py — turn raw recon data into a judgement.

IMPORTANT distinction this module is built around:
  * "attack surface" = how MUCH a target exposes (subdomains, emails). Big
    companies naturally have a lot; that alone is not danger.
  * "risk" = genuinely dangerous things you could get breached through: exposed
    databases/remote-desktop, cleartext services, an expired domain.

So we score dangerous *misconfigurations* heavily and treat surface size / names
as low-weight, capped context. That's why a huge-but-well-run site (e.g. google)
should land Low, while a small site exposing a database should land High.
"""

import re
from datetime import datetime

# Subdomain LABELS that suggest a sensitive/non-public system. We match these as
# whole words (see _labels), never as substrings — so "dev" no longer trips
# "developers" and "db" no longer trips "sandbox".
SENSITIVE_KEYWORDS = {
    "admin", "dev", "staging", "stage", "test", "qa", "internal", "vpn",
    "remote", "jenkins", "gitlab", "jira", "portal", "backup", "db",
    "database", "sql", "phpmyadmin", "grafana", "kibana",
}

# Open ports that are genuinely dangerous to expose to the public internet.
# THESE are the real "risk" signals — an exposed database or remote-desktop is a
# direct path to compromise, unlike a subdomain simply existing.
RISKY_PORTS = {
    21: "FTP — usually unencrypted file transfer",
    23: "Telnet — unencrypted remote login",
    445: "SMB — Windows file sharing (worm/ransomware target)",
    3389: "RDP — remote desktop (common ransomware entry point)",
    3306: "MySQL — database exposed to the internet",
    5432: "PostgreSQL — database exposed to the internet",
    27017: "MongoDB — database exposed to the internet",
    6379: "Redis — database, often with no authentication",
    9200: "Elasticsearch — frequently exposed with no auth",
    5900: "VNC — remote screen sharing",
    1433: "MSSQL — database exposed to the internet",
}

# Weights and caps. Dangerous services dominate; names/size are minor context.
POINTS_PER_RISKY_PORT = 25       # each dangerous open port
POINTS_EXPIRING_DOMAIN = 20      # domain expiring within 30 days
POINTS_PER_SENSITIVE_SUB = 5     # each sensitive-named subdomain...
CAP_SENSITIVE_SUBS = 15          # ...but capped, so size can't dominate
POINTS_EMAILS = 3                # any exposed emails (flat, informational-ish)
MANY_PORTS_THRESHOLD = 60        # above this, the port list is a WAF/CDN artifact


def _labels(subdomain: str) -> set[str]:
    """
    Break a subdomain into its individual word-labels for exact matching.
    'cert-test.sandbox.google.com' -> {'cert','test','sandbox','google','com'}
    We split on dots AND hyphens because both separate real words.
    """
    return set(re.split(r"[.\-]", subdomain.lower()))


def _parse_date(value) -> datetime | None:
    """Best-effort parse of a WHOIS expiry string into a date. None on failure."""
    if not value or value == "—":
        return None
    text = str(value)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text[:len(fmt) + 2].strip(), fmt)
        except ValueError:
            continue
    return None


def assess(results: dict) -> dict:
    """
    Score a scan. Returns {score, level, findings, context}.
      * findings: things that actually add risk, each with a severity.
      * context: informational notes (surface size) that do NOT inflate the score.
    """
    findings = []
    context = []
    score = 0
    shodan = results.get("shodan", {}) or {}

    # --- Confidence gate: can we even assess this target? ---------------------
    # A low score only means "safe" if we actually collected data. If crt.sh
    # failed (no subdomains) AND Shodan gave us no ports, we saw essentially
    # nothing — so the honest answer is "Unknown", not "Low". This stops the
    # tool from confidently calling an un-scannable target "well locked-down".
    have_subdomains = bool(results.get("subdomains"))
    have_ports = bool(shodan.get("ports"))
    subdomains_failed = bool(results.get("subdomains_error")) or not have_subdomains
    if subdomains_failed and not have_ports:
        return {
            "score": None,
            "level": "Unknown",
            "summary": ("Not enough data to assess this target — the external "
                        "lookups (crt.sh and Shodan) returned nothing. This is "
                        "usually crt.sh being rate-limited; re-scan for a real result."),
            "findings": [],
            "context": [],
        }

    # --- Risky open ports (the real danger) -----------------------------------
    # A host reporting HUNDREDS of open ports isn't running hundreds of services —
    # it's a CDN/WAF/load-balancer (or tarpit) that answers a SYN on every port.
    # The port list is then meaningless, so we don't score it, and we say why.
    ports = shodan.get("ports") or []
    if len(ports) > MANY_PORTS_THRESHOLD:
        context.append(
            f"{len(ports)} ports report as 'open' — the signature of a CDN / WAF / "
            f"load-balancer that answers on every port, not real exposed services. "
            f"Port-based risk was skipped as unreliable.")
    else:
        for port in ports:
            if port in RISKY_PORTS:
                score += POINTS_PER_RISKY_PORT
                findings.append({"severity": "high",
                                 "text": f"Dangerous port {port} open: {RISKY_PORTS[port]}"})

    # --- Known vulnerabilities (CVEs) — the strongest risk signal -------------
    # Only count matches the AI rated trustworthy. Low-confidence matches (likely
    # false positives from vague fingerprints) are shown in the UI but don't
    # inflate the score. "unrated" (no AI available) counts, to stay safe.
    def _trusted(c):
        return c.get("confidence", "unrated") in ("high", "medium", "unrated")

    cves = [c for c in results.get("cves", []) if _trusted(c)]
    critical = [c for c in cves if (c.get("score") or 0) >= 9.0]
    high = [c for c in cves if 7.0 <= (c.get("score") or 0) < 9.0]
    # A known CRITICAL vuln (CVSS >= 9) on an exposed service is High risk on its
    # own — one is enough to reach the High threshold (50). A HIGH vuln (7-8.9)
    # is at least Medium (25). Anything less would contradict the finding itself.
    if critical:
        score += min(len(critical) * 50, 60)
        example = critical[0]["id"]
        findings.append({"severity": "high",
                         "text": f"{len(critical)} CRITICAL known vulnerability(ies) "
                                 f"in exposed services (e.g. {example}, CVSS {critical[0]['score']})"})
    if high:
        score += min(len(high) * 25, 40)
        findings.append({"severity": "high",
                         "text": f"{len(high)} high-severity known vulnerability(ies) "
                                 f"in exposed services (e.g. {high[0]['id']})"})

    # --- Domain expiring soon -------------------------------------------------
    expires = _parse_date(results.get("whois", {}).get("expires"))
    if expires:
        days_left = (expires - datetime.now()).days
        if 0 <= days_left <= 30:
            score += POINTS_EXPIRING_DOMAIN
            findings.append({"severity": "high",
                             "text": f"Domain expires in {days_left} days — risk of hijacking/lapse"})

    # --- Sensitive subdomains (low weight, capped, exact-word match) ----------
    sensitive = []
    for sub in results.get("subdomains", []):
        hit = SENSITIVE_KEYWORDS & _labels(sub)   # set intersection = exact matches
        if hit:
            sensitive.append((sub, sorted(hit)[0]))
    if sensitive:
        added = min(len(sensitive) * POINTS_PER_SENSITIVE_SUB, CAP_SENSITIVE_SUBS)
        score += added
        for sub, kw in sensitive[:10]:            # show up to 10, don't flood
            findings.append({"severity": "medium",
                             "text": f"Sensitive subdomain: {sub} (label '{kw}')"})
        if len(sensitive) > 10:
            findings.append({"severity": "medium",
                             "text": f"...and {len(sensitive) - 10} more sensitive-named subdomains"})

    # --- Exposed emails (small, flat) -----------------------------------------
    emails = results.get("emails", [])
    if emails:
        score += POINTS_EMAILS
        findings.append({"severity": "low",
                         "text": f"{len(emails)} email address(es) exposed in certificates (phishing targets)"})

    # --- Context only (NOT scored) --------------------------------------------
    sub_count = len(results.get("subdomains", []))
    if sub_count:
        context.append(f"Attack surface: {sub_count} subdomains discovered "
                       f"(size alone is not risk — big orgs naturally have many).")

    score = min(score, 100)
    if score >= 50:
        level = "High"
        summary = ("High risk — dangerous services or misconfigurations are exposed. "
                   "This target needs attention.")
    elif score >= 25:
        level = "Medium"
        summary = ("Medium risk — some exposures worth reviewing, but nothing critical "
                   "found.")
    else:
        level = "Low"
        summary = ("Low risk — few or no dangerous exposures found. This target looks "
                   "well locked-down.")

    return {
        "score": score,
        "level": level,
        "summary": summary,
        "findings": findings,
        "context": context,
    }
