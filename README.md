# RECON — OSINT Surface Intelligence Dashboard

### 🔗 Live demo: **[osint-dashboard-ykcop.ondigitalocean.app](https://osint-dashboard-ykcop.ondigitalocean.app/)**

A web app that gathers **public reconnaissance** on a domain or IP and turns it
into a clean, single-page threat-intelligence report: subdomains, DNS, WHOIS,
open ports & services, likely known vulnerabilities (CVEs), exposed emails,
Cloudflare-origin discovery, and an AI-assessed risk score.

Everything it collects comes from **public sources** (certificate transparency
logs, DNS, WHOIS, Shodan). Only scan targets you own or have permission to test.

---

## What it does

| Feature | Source | Notes |
|---|---|---|
| **Subdomains** | crt.sh → certspotter (fallback) | Certificate-transparency logs |
| **DNS records** | live DNS | A / AAAA / MX / NS / TXT |
| **WHOIS** | WHOIS | registrar, org, created/expires, country |
| **Open ports & services** | Shodan → InternetDB (fallback) | authenticated Shodan if key present |
| **Known vulnerabilities** | NVD | version-matched CVEs, **AI-rated confidence** |
| **Exposed emails** | certificate data | addresses leaked in certs |
| **Cloudflare-origin discovery** | direct-connect probing | finds subdomains that bypass the CDN, then *verifies* the origin |
| **Risk score (0–100)** | `risk.py` | deterministic rules; "Unknown" when data is too thin to judge |
| **AI analyst summary** | OpenAI | plain-English narrative over the same facts |
| **Change tracking** | SQLite history | diffs each scan against the previous one |

The risk score is **rule-based and reproducible** (not the AI's opinion). The AI
only writes the narrative and rates how much to trust each fingerprinted CVE — so
the number stays consistent while the prose stays readable.

---

## Setup

```bash
# 1. create + activate a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

# 2. install dependencies
pip install -r requirements.txt

# 3. add your secrets (optional but recommended)
#    create a file named .env in this folder:
```

`.env` (never commit this file — it is gitignored):

```
SHODAN_API_KEY=your_shodan_key_here
OPENAI_API_KEY=your_openai_key_here
```

Both keys are **optional** — without them the app still runs and falls back to
free sources (InternetDB for ports; a placeholder message instead of the AI
summary). With them you get authenticated Shodan data and the AI analyst.

```bash
# 4. run it
venv\Scripts\python.exe -m uvicorn app:app --reload --port 8000
```

Then open **http://127.0.0.1:8000** and scan a domain.

> **Serve, don't open.** Always reach the app through `http://127.0.0.1:8000`.
> Opening `index.html` as a `file://` won't work — there's no server behind it.

---

## Project layout

```
osint-dashboard/
├── app.py              # FastAPI routes + background scan jobs (the web server)
├── recon.py            # the OSINT functions (subdomains, DNS, WHOIS, Shodan, origin discovery)
├── risk.py             # deterministic risk scoring (score, level, findings)
├── cve.py              # NVD CVE lookup + version matching
├── ai_summary.py       # OpenAI: analyst summary + CVE-confidence rating
├── changes.py          # diff a scan against the previous one
├── database.py         # SQLite: save / load / history
├── templates/
│   └── index.html      # the whole UI (light-theme app shell, one file)
├── requirements.txt
├── .env                # secrets — gitignored, never commit
└── osint.db            # SQLite database (created on first run)
```

---

## How a scan works (the flow)

1. You submit a domain → `POST /scan/start` kicks off a **background thread** and
   returns a `job_id` immediately (so the page never hangs).
2. The browser **polls** `/scan/status/{job_id}` and animates a progress bar.
3. `run_scan()` calls each `recon.py` function, then `risk.assess()`, then the
   AI layer, and **saves the result** to SQLite.
4. You're redirected to `/scan/{scan_id}` — the full report.
5. Every section reports its own success/failure in the **Scan status** panel, so
   when something is blocked (rate-limited, Cloudflare, no key) you *see it*
   instead of getting a silently-empty section.

---

## Deploying (later)

1. `pip freeze > requirements.txt` (already done).
2. Push to GitHub — **`.env` is gitignored**, so set `SHODAN_API_KEY` and
   `OPENAI_API_KEY` as environment variables in your host's dashboard instead.
3. Host: [Render](https://render.com) works well for FastAPI —
   start command: `uvicorn app:app --host 0.0.0.0 --port $PORT`.

---

## Security notes

- **Only scan what you own or are authorized to test.** This tool touches public
  data only, but active scanning of third parties can still be unwelcome.
- Keep API keys in `.env`; never commit them. If a key is ever pasted somewhere
  public, **rotate it** immediately.
