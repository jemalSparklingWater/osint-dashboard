"""
app.py — the web server (the "backend").

FastAPI is the framework that turns Python functions into web pages / API
endpoints. uvicorn is the actual server program that runs it.

Run it with:   venv/Scripts/uvicorn app:app --reload
Then open:      http://127.0.0.1:8000
"""

import uuid
import threading
import ipaddress

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

import recon       # our OSINT functions (recon.py)
import database    # our save/load functions (database.py)
import risk         # our scoring logic (risk.py)
import changes      # our scan-to-scan diff (changes.py)
import cve          # known-vulnerability lookup via NVD (cve.py)
import ai_summary   # our AI analyst narrative (ai_summary.py)

# Create the application object. Everything hangs off of this.
app = FastAPI()

# Make sure the database table exists before we handle any requests.
database.init_db()


def normalize_domain(raw: str) -> str:
    """
    Clean whatever the user typed into a bare apex domain to scan. People paste
    full URLs ("https://www.example.com/path") or the www host ("www.example.com"),
    but WHOIS, name servers, and the full subdomain list all live on the APEX
    domain — so we strip the scheme, path, port, and a leading "www.".
    """
    d = raw.strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]                 # strip http:// or https://
    d = d.split("/")[0].split("?")[0].split("#")[0]  # strip path/query/fragment
    d = d.split(":")[0]                          # strip :port
    d = d.strip(".")                             # strip stray dots
    if d.startswith("www."):
        d = d[4:]                                # scan the apex, not the www host
    return d


def build_scan_status(results: dict) -> list[dict]:
    """
    Build a plain-English health report of every data source for a scan, so the
    user can SEE what worked, what fell back to a backup, and what failed/was
    blocked — instead of silently getting partial results. Computed from the
    saved results, so it works for any scan (old or new).

    Each entry: {"label", "state": ok|warn|fail|info, "detail"}.
    """
    s = []
    subs = results.get("subdomains") or []
    src = results.get("subdomains_source") or ""
    if results.get("subdomains_error"):
        s.append({"label": "Subdomains (crt.sh + certspotter)", "state": "fail",
                  "detail": results["subdomains_error"]})
    elif src.startswith("certspotter"):
        s.append({"label": "Subdomains", "state": "warn",
                  "detail": f"crt.sh was down — used certspotter fallback ({len(subs)} found)"})
    else:
        s.append({"label": "Subdomains", "state": "ok",
                  "detail": f"{len(subs)} found via crt.sh"})

    dns = results.get("dns") or {}
    if dns.get("A"):
        s.append({"label": "DNS", "state": "ok",
                  "detail": f"resolved — {len(dns.get('A', []))} A record(s)"})
    else:
        s.append({"label": "DNS", "state": "fail",
                  "detail": "no A record — the domain may not resolve"})

    whois = results.get("whois") or {}
    if whois.get("error"):
        s.append({"label": "WHOIS", "state": "warn", "detail": whois["error"]})
    else:
        s.append({"label": "WHOIS", "state": "ok", "detail": "registration data retrieved"})

    sh = results.get("shodan") or {}
    ports = sh.get("ports") or []
    if sh.get("error"):
        s.append({"label": "Shodan (ports/services)", "state": "fail", "detail": sh["error"]})
    elif sh.get("note"):
        s.append({"label": "Shodan (ports/services)", "state": "warn", "detail": sh["note"]})
    elif "InternetDB" in (sh.get("source") or ""):
        s.append({"label": "Shodan (ports/services)", "state": "warn",
                  "detail": f"paid lookup unavailable — used free InternetDB ({len(ports)} ports)"})
    elif sh.get("source"):
        s.append({"label": "Shodan (ports/services)", "state": "ok",
                  "detail": f"{len(ports)} ports via {sh['source']}"})
    else:
        s.append({"label": "Shodan (ports/services)", "state": "info", "detail": "no IP to look up"})

    cves = results.get("cves") or []
    if cves:
        s.append({"label": "Vulnerabilities (NVD)", "state": "ok",
                  "detail": f"{len(cves)} candidate CVEs checked"})
    else:
        s.append({"label": "Vulnerabilities (NVD)", "state": "info",
                  "detail": "no specific software versions detected to match"})

    ai = results.get("ai_summary") or ""
    if ai.startswith("AI summary unavailable") or ai.startswith("AI summary failed"):
        s.append({"label": "AI analyst summary", "state": "warn", "detail": ai})
    elif ai:
        s.append({"label": "AI analyst summary", "state": "ok", "detail": "generated"})

    if cves:
        if any((c.get("confidence") or "unrated") != "unrated" for c in cves):
            s.append({"label": "AI vulnerability confidence", "state": "ok", "detail": "matches rated"})
        else:
            s.append({"label": "AI vulnerability confidence", "state": "warn",
                      "detail": "unavailable — CVE matches left unrated"})
    return s


def _is_ip(value: str) -> bool:
    """True if the string is a valid IPv4/IPv6 address (so we scan it directly)."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

# Jinja2 lets us build HTML pages that have Python data plugged into them.
# It looks for .html files inside a folder called "templates".
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    """
    The home page. When a browser visits "/", show the search form plus a list
    of recent scans pulled from the database.
    """
    return templates.TemplateResponse(
        request,
        "index.html",
        {"domain": None, "results": None, "recent": database.get_recent_scans()},
    )


class _Job:
    """Adapter so run_scan can keep calling job.update(...) while the progress is
    persisted to SQLite instead of an in-memory dict. In production the app runs
    several worker processes, and the request that STARTS a scan may hit a
    different worker than the one that POLLS its progress — a shared store (the
    DB) is what lets them both see the same job, so status never says 'unknown'."""

    def __init__(self, job_id: str):
        self.job_id = job_id

    def update(self, **fields):
        database.update_job(self.job_id, **fields)


def run_scan(job_id: str, domain: str):
    """
    Do the actual scanning in a BACKGROUND THREAD, updating JOBS[job_id] after
    each step so the browser can show progress. Each source is a "stage"; we bump
    the percentage as we finish each one.
    """
    job = _Job(job_id)
    try:
        domain = normalize_domain(domain)
        is_ip = _is_ip(domain)

        # Reject junk before wasting time on network calls. A real target is
        # either an IP or a name with a dot (example.com). "localhost", "", and
        # garbage like "@#$%" don't qualify.
        if not domain or (not is_ip and "." not in domain):
            job.update(stage="Invalid input", percent=100, done=True,
                       error="Enter a valid domain (like example.com) or an IP address.")
            return

        job.update(stage="Querying crt.sh (subdomains + emails)…", percent=15)
        certs = recon.get_certificate_data(domain)

        job.update(stage="Looking up DNS records…", percent=45)
        dns = recon.get_dns_records(domain)
        # For an IP input, use it directly; otherwise take the first A record.
        first_ip = domain if is_ip else (dns["A"][0] if dns.get("A") else None)

        job.update(stage="Fetching WHOIS registration…", percent=60)
        whois_data = recon.get_whois(domain)

        # Redirect check only makes sense for a resolving domain (not an IP, not
        # a non-resolving name) — and it's slow, so we skip it otherwise.
        redirect = {"redirected": False, "final_domain": None, "final_url": None}
        if first_ip and not is_ip:
            job.update(stage="Checking for redirects…", percent=68)
            redirect = recon.get_redirect(domain)

        # If the site is behind Cloudflare, try to find the REAL origin server by
        # resolving subdomains that might bypass the CDN.
        direct_ips = {}
        if first_ip and not is_ip and recon.is_cloudflare_ip(first_ip):
            job.update(stage="Looking for origin server behind Cloudflare…", percent=72)
            candidates = recon.find_direct_ips(certs["subdomains"])
            # Verify each candidate actually serves the site (does the bypass work?)
            job.update(stage="Verifying origin candidates…", percent=76)
            for sub, ip in candidates.items():
                check = recon.verify_origin(ip, domain)
                direct_ips[sub] = {"ip": ip, **check}

        job.update(stage="Querying Shodan for open ports…", percent=80)
        shodan = recon.get_shodan_host(first_ip)

        # Look up known vulnerabilities (CVEs) for the software Shodan detected,
        # plus any CVEs InternetDB already flagged for this host.
        job.update(stage="Checking NVD for known vulnerabilities…", percent=84)
        cves = cve.lookup_cves(shodan.get("cpes", []), known_ids=shodan.get("vulns", []))

        # Have the AI rate how trustworthy each match is — fingerprint-based CVE
        # matching is noisy, so we tag each high/medium/low confidence and let the
        # risk score only count the trustworthy ones.
        if cves:
            job.update(stage="AI-rating vulnerability match confidence…", percent=88)
            cves = ai_summary.rate_cve_confidence(shodan, cves)

        # Store the RAW facts (plus the CVE + AI results, which are slow/costly to
        # produce so we make them once here rather than on every page view). The
        # risk *score* stays derived — computed fresh whenever a scan is viewed.
        results = {
            "subdomains": certs["subdomains"],
            "emails": certs["emails"],
            "subdomains_error": certs["error"],   # set only if BOTH sources failed
            "subdomains_source": certs.get("source"),
            "dns": dns,
            "whois": whois_data,
            "shodan": shodan,
            "cves": cves,
            "redirect": redirect,
            "direct_ips": direct_ips,
        }

        # Generate the AI analyst narrative from the facts + the risk assessment.
        # risk.assess now sees the CVEs, so both the score and the AI summary
        # reflect any known vulnerabilities.
        job.update(stage="Generating AI analyst summary…", percent=92)
        assessment = risk.assess(results)
        results["ai_summary"] = ai_summary.generate_summary(domain, results, assessment)

        job.update(stage="Saving results…", percent=95)
        scan_id = database.save_scan(domain, results)

        job.update(stage="Done", percent=100, done=True, scan_id=scan_id)
    except Exception as e:
        # If anything blows up, record it so the browser can show the message.
        job.update(stage="Error", error=str(e), done=True)


@app.post("/scan/start")
def scan_start(domain: str = Form("")):
    """
    Start a scan and return a job id immediately (without waiting for it to
    finish). The real work runs in a background thread via run_scan.
    """
    job_id = uuid.uuid4().hex  # a random unique id like "3f9a1c..."
    database.create_job(job_id)
    threading.Thread(target=run_scan, args=(job_id, domain), daemon=True).start()
    return {"job_id": job_id}


@app.get("/scan/status/{job_id}")
def scan_status(job_id: str):
    """The browser polls this to read a job's current progress (as JSON)."""
    return database.get_job(job_id) or {"error": "unknown job", "done": True}


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
def view_scan(request: Request, scan_id: int):
    """
    View a past scan by its id. The {scan_id} in the path is a variable — visit
    /scan/3 and scan_id becomes 3. This is how you make pages for saved records.
    """
    saved = database.get_scan(scan_id)
    if saved is None:
        return HTMLResponse("Scan not found.", status_code=404)

    results = saved["results"]
    # Older saved scans predate some features, so they're missing keys the page
    # expects (shodan, emails, cves...). Fill in safe defaults so any scan — no
    # matter how old — renders instead of crashing.
    for key, default in {
        "subdomains": [], "emails": [], "dns": {}, "whois": {},
        "shodan": {}, "cves": [], "redirect": {}, "direct_ips": {},
    }.items():
        results.setdefault(key, default)

    # Older scans stored direct_ips as {subdomain: ip_string}; upgrade to the
    # verified {subdomain: {ip, status, detail}} shape so the page renders.
    results["direct_ips"] = {
        sub: (v if isinstance(v, dict) else {"ip": v, "status": "no",
                                             "detail": "not verified (older scan)"})
        for sub, v in (results.get("direct_ips") or {}).items()
    }

    # Compute the risk judgment now, from the saved raw facts, using current rules.
    results["risk"] = risk.assess(results)

    # Detect an INCOMPLETE scan (an external service failed when it ran). A real
    # domain almost never has zero subdomains — that means crt.sh was down. We
    # warn the user AND skip change tracking, because you can't meaningfully
    # compare a failed scan against a good one (it'd look like everything vanished).
    warnings = []
    if results.get("subdomains_error"):
        warnings.append("crt.sh (subdomain lookup) failed — it's frequently "
                        "rate-limited. Re-scan for complete results.")
    elif not results.get("subdomains"):
        warnings.append("No subdomains were returned. crt.sh was likely "
                        "unavailable when this scan ran — re-scan to be sure.")
    incomplete = bool(warnings)

    # Risk trend over time: compute the risk score for every past scan of this
    # domain so we can chart how it changed. This is the Chart.js "visualize
    # trends" piece — a line of risk score across the domain's scan history.
    trend = []
    for past in database.get_scans_for_domain(saved["domain"]):
        past_score = risk.assess(past["results"])["score"]   # may be None (Unknown)
        trend.append({"time": past["scanned_at"][5:16].replace("T", " "),  # MM-DD HH:MM
                      "score": past_score})

    # Change tracking: only when this scan is complete enough to trust.
    diff = None
    if not incomplete:
        previous = database.get_previous_scan(saved["domain"], scan_id)
        if previous is not None:
            diff = changes.compare(previous["results"], results)
            # Compute "did anything change?" from ONLY the change lists, BEFORE
            # we add metadata below (a date string would otherwise read as truthy
            # and make this always True).
            diff["any"] = changes.has_changes(diff)
            diff["since"] = previous["scanned_at"]
            diff["prev_score"] = risk.assess(previous["results"])["score"]
            diff["now_score"] = results["risk"]["score"]

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "domain": saved["domain"],
            "results": results,
            "diff": diff,
            "trend": trend,
            "status": build_scan_status(results),
            "warnings": warnings,
            "recent": database.get_recent_scans(),
            "viewing_past": saved["scanned_at"],
        },
    )
