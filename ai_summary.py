"""
ai_summary.py — the "AI analyst" layer (powered by OpenAI).

This is the AI *narrative* layer that sits on top of the deterministic risk
engine (risk.py). The rules produce the score and the findings — consistent,
free, reproducible. Here we hand those same facts to an LLM and ask it to write
a short, human-readable analyst summary. That plays to the LLM's strength
(judgement + plain language) without making the score itself random.

Needs an OpenAI API key in .env as OPENAI_API_KEY. If it's missing, we return a
friendly message instead of crashing, so the app still runs.
"""

import os
import json

from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# One reusable client. OpenAI() automatically reads OPENAI_API_KEY from the
# environment (which load_dotenv put there from our .env file).
_client = None

# Which OpenAI model to use. gpt-4o-mini is fast and very cheap — ideal for a
# short per-scan summary. Swap to "gpt-4o" if you want higher quality.
MODEL = "gpt-4o-mini"


def _get_client():
    global _client
    if _client is None and os.getenv("OPENAI_API_KEY"):
        # 30s timeout so a slow/hung AI response can't stall the whole scan.
        _client = OpenAI(timeout=30, max_retries=1)
    return _client


def rate_cve_confidence(shodan: dict, cves: list[dict]) -> list[dict]:
    """
    Ask the LLM how confident we should be in each candidate CVE match.

    Fingerprint-based CVE matching is noisy: Shodan might report a protocol
    version ("ntp:3") instead of the real build, or a generic product. Rather
    than hard-code a filter for every case, we let the AI reason about each match
    and tag it high / medium / low confidence with a short reason. That confidence
    then drives what the risk score counts and what the UI emphasizes.

    Adds "confidence" and "confidence_reason" to each CVE. If no API key or the
    call fails, everything is left "unrated" (treated as medium by the scorer).
    """
    client = _get_client()
    if client is None or not cves:
        for c in cves:
            c.setdefault("confidence", "unrated")
            c.setdefault("confidence_reason", "")
        return cves

    detected = (f"CPEs: {shodan.get('cpes', [])}\n"
                f"Services: {shodan.get('services', [])}\n"
                f"Open ports: {shodan.get('ports', [])}")
    candidates = "\n".join(
        f"{c['id']} (CVSS {c['score']}, matched from {c.get('cpe','?')}): {c.get('desc','')[:140]}"
        for c in cves
    )

    try:
        response = client.chat.completions.create(
            model=MODEL,
            max_tokens=2000,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": (
                    "You are a vulnerability-matching analyst. You're given software "
                    "detected on a host via network fingerprints (often imprecise) and "
                    "candidate CVEs a naive version-match flagged. For EACH CVE, rate how "
                    "confident we should be that the host is ACTUALLY vulnerable. Be "
                    "skeptical — fingerprint matches are frequently false positives. "
                    "Rate 'low' when the detected version looks generic or like a protocol "
                    "version (e.g. 'ntp:3') rather than a real build, or when the product is "
                    "generic (e.g. a CDN). "
                    "IMPORTANT — distro backporting: Debian/Ubuntu/RHEL and shared hosts "
                    "(DreamHost, cPanel, etc.) patch security holes while KEEPING the version "
                    "string unchanged. So common server software (OpenSSH, Apache, nginx, PHP) "
                    "showing a distro version — e.g. OpenSSH 8.9p1 (Ubuntu 22.04) — is often "
                    "ALREADY PATCHED despite matching the CVE's version range. For such cases "
                    "rate 'medium' (not high) and say 'may be backport-patched' in the reason. "
                    "Rate 'high' only when a specific vulnerable version is detected AND "
                    "backporting is unlikely. Return JSON: {\"ratings\":[{\"id\":\"CVE-..\","
                    "\"confidence\":\"high|medium|low\",\"reason\":\"<=12 words\"}]}."
                )},
                {"role": "user", "content": f"Detected on host:\n{detected}\n\nCandidate CVEs:\n{candidates}"},
            ],
        )
        data = json.loads(response.choices[0].message.content)
        ratings = {r["id"]: r for r in data.get("ratings", [])}
    except Exception:
        ratings = {}

    for c in cves:
        r = ratings.get(c["id"], {})
        c["confidence"] = r.get("confidence", "unrated")
        c["confidence_reason"] = r.get("reason", "")
    return cves


def _facts_block(domain: str, results: dict, assessment: dict) -> str:
    """Turn the scan results into a compact plain-text brief for the model."""
    shodan = results.get("shodan", {}) or {}
    lines = [
        f"Target domain: {domain}",
        f"Subdomains discovered: {len(results.get('subdomains', []))}",
        f"Exposed emails: {len(results.get('emails', []))}",
        f"Open ports (Shodan): {shodan.get('ports', [])}",
        f"Services: {shodan.get('services', [])}",
        f"WHOIS registrar: {results.get('whois', {}).get('registrar', '—')}",
        f"WHOIS expires: {results.get('whois', {}).get('expires', '—')}",
    ]
    # Be honest if a data source failed — otherwise the model reads empty data as
    # "all clear" and gives a falsely reassuring summary.
    if results.get("subdomains_error") or not results.get("subdomains"):
        lines.append("NOTE: the subdomain lookup (crt.sh) appears to have FAILED "
                     "for this scan, so the data is incomplete. Say so, and do NOT "
                     "claim the target is secure based on missing data.")
    cves = results.get("cves", [])
    if cves:
        top = ", ".join(f"{c['id']} (CVSS {c['score']})" for c in cves[:5])
        lines.append(f"Known vulnerabilities (top {min(5, len(cves))} of {len(cves)}): {top}")
    # Give the model the SAME framing the risk engine used, so its narrative
    # doesn't contradict the score. Two common traps: treating benign web/CDN
    # ports as scary "exposed services", and ignoring the WAF/CDN explanation.
    import risk
    ports = shodan.get("ports", []) or []
    dangerous = [p for p in ports if p in risk.RISKY_PORTS]
    if ports and not dangerous and len(ports) <= risk.MANY_PORTS_THRESHOLD:
        lines.append("NOTE: none of the open ports are dangerous services — they are "
                     "standard web/CDN ports (80, 443, and the Cloudflare 2052-2096 / "
                     "8080-8880 set). Do NOT describe them as concerning exposed services.")
    for ctx in assessment.get("context", []):
        lines.append(f"Context: {ctx}")

    lines += [
        f"Computed risk score: {assessment['score']}/100 ({assessment['level']})",
        "Risk findings:",
    ]
    for f in assessment.get("findings", []):
        lines.append(f"  - [{f['severity']}] {f['text']}")
    return "\n".join(lines)


def generate_summary(domain: str, results: dict, assessment: dict) -> str:
    """
    Ask the LLM to write a 2-4 sentence analyst summary of the scan. Returns the
    text, or a friendly message if no API key is set or the call fails.
    """
    client = _get_client()
    if client is None:
        return ("AI summary unavailable — add OPENAI_API_KEY to your .env file "
                "(get a key at platform.openai.com).")

    facts = _facts_block(domain, results, assessment)

    try:
        # A single chat-completion call. The system message sets the role; the
        # user message carries the facts. max_tokens caps the reply length.
        response = client.chat.completions.create(
            model=MODEL,
            max_tokens=400,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a concise cybersecurity threat-intelligence analyst. "
                        "Given reconnaissance findings about a domain, write a 2-4 "
                        "sentence plain-English summary of the target's security "
                        "exposure: what stands out, what a defender should look at "
                        "first, and whether the overall picture is concerning or "
                        "benign. Do not invent facts not in the data. Do not use "
                        "markdown or bullet points — just prose."
                    ),
                },
                {"role": "user", "content": facts},
            ],
        )
    except Exception as e:
        return f"AI summary failed: {e}"

    return response.choices[0].message.content.strip()
