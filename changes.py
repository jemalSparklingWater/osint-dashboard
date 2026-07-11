"""
changes.py — compare two scans of the same domain and report what changed.

This is the "diff over time" feature. The core trick is Python SETS: if you put
last scan's subdomains in one set and this scan's in another, then
  new     = now - before   (in now, not in before)
  removed = before - now    (in before, not in now)
Set math does the heavy lifting — no manual loops needed.

Why it matters for security: a NEW subdomain or a NEWLY-OPENED port is fresh
attack surface that appeared since you last looked. That's exactly the kind of
change a defender wants flagged the moment it happens.
"""


def _ports(results: dict) -> set:
    """Pull the set of open ports out of a scan's Shodan data (empty if none)."""
    shodan = results.get("shodan") or {}
    return set(shodan.get("ports") or [])


def compare(before: dict, now: dict) -> dict:
    """
    Compare two results dicts. Returns lists of what appeared and disappeared.
    'before' and 'now' are each the `results` dict of a scan.
    """
    # `... or []` (not `.get(k, [])`) so a stored None also becomes an empty set.
    before_subs = set(before.get("subdomains") or [])
    now_subs = set(now.get("subdomains") or [])

    before_emails = set(before.get("emails") or [])
    now_emails = set(now.get("emails") or [])

    before_ports = _ports(before)
    now_ports = _ports(now)

    # Guard against a FAILED data fetch looking like a real change. External
    # services (crt.sh, Shodan) sometimes return nothing; if we then diffed a
    # good previous scan against an empty current one, every subdomain would
    # show as "removed" and every port as "closed" — a scary false alarm.
    #
    # A domain doesn't lose ALL its subdomains at once, so if this scan found
    # zero, treat the crt.sh lookup as failed and don't report removals.
    subs_reliable = len(now_subs) > 0
    # We can only call something "new" if the PREVIOUS scan actually had a
    # subdomain list to compare against. If the previous scan came back empty
    # (crt.sh had failed then), everything would look "new" — pure noise.
    prev_had_subs = len(before_subs) > 0
    # Ports are only comparable if this scan actually got Shodan port data
    # (no error, no "requires paid plan"/"no data" note).
    now_shodan = now.get("shodan", {}) or {}
    ports_reliable = "error" not in now_shodan and not now_shodan.get("note")

    return {
        "new_subdomains": sorted(now_subs - before_subs) if prev_had_subs else [],
        "removed_subdomains": sorted(before_subs - now_subs) if subs_reliable else [],
        "new_emails": sorted(now_emails - before_emails),
        "new_ports": sorted(now_ports - before_ports) if ports_reliable else [],
        "closed_ports": sorted(before_ports - now_ports) if ports_reliable else [],
    }


def has_changes(diff: dict) -> bool:
    """True if anything at all changed between the two scans."""
    return any(diff.values())
