# SCANLINE — Domain Security Scanner

A web app that checks any domain for common phishing/security red flags and
returns a single risk score (0–100), backed by real threat-intelligence
APIs — not just a static rule list.

**Live demo:** _add your deployed link here once hosted_
**Screenshot:**  _add a screenshot of the results screen here_

## What it checks

| Check | Source | What it's looking for |
|---|---|---|
| Domain age | WHOIS | Domains registered in the last 30 days are a classic phishing signal |
| Security headers | Direct HTTP request | Presence of HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| IP abuse history | AbuseIPDB | Whether the domain's IP has been reported for malicious activity |
| Domain reputation | VirusTotal | How many security vendors flag the domain as malicious/suspicious |

All four checks run together behind `/scan/full`, which combines them into
one score with a plain-English breakdown of every deduction — so the score
isn't a black box.

## How the score works

Starts at 100 and deducts points per risk signal:
- **−20** if the domain is under 30 days old
- **−6 per missing security header** (up to −30 across 5 headers)
- **up to −30** based on AbuseIPDB's abuse confidence score (scaled)
- **up to −20** if VirusTotal vendors flag it as malicious

Final label: **Low** (80+), **Medium** (50–79), **High** (below 50).

This logic is intentionally simple and fully documented in `main.py` — the
point isn't a perfect model, it's a defensible, explainable one.

## Tech stack

- **Backend:** Python, FastAPI
- **Frontend:** Vanilla HTML/CSS/JS (no framework — kept dependency-free)
- **APIs:** WHOIS (via `python-whois`), AbuseIPDB, VirusTotal

## Project structure

```
domain-scanner/
├── main.py              # FastAPI backend — all 4 endpoints
├── requirements.txt
├── .env                 # your API keys (not committed)
└── frontend/
    ├── index.html
    ├── style.css
    └── script.js
```

## Running it locally

1. **Clone and install:**
   ```bash
   git clone <your-repo-url>
   cd domain-scanner
   pip install -r requirements.txt
   ```

2. **Add your API keys.** Copy `.env.example` to `.env` and fill in:
   - [AbuseIPDB](https://www.abuseipdb.com/register) — free, 1,000 checks/day
   - [VirusTotal](https://www.virustotal.com/gui/join-us) — free, 500 checks/day

3. **Start the backend:**
   ```bash
   uvicorn main:app --reload
   ```
   API docs available at `http://127.0.0.1:8000/docs`

4. **Open the frontend:** open `frontend/index.html` directly in your browser.

## API endpoints

- `GET /scan/whois?domain=example.com`
- `GET /scan/headers?domain=example.com`
- `GET /scan/reputation?domain=example.com`
- `GET /scan/full?domain=example.com` — combined score (used by the frontend)

## Notes / limitations

- This is a portfolio project, not a production security tool — it's not a
  substitute for a professional audit.
- WHOIS data isn't always available for every TLD/registrar.
- Rate limits apply on the free API tiers (AbuseIPDB: 1,000/day, VirusTotal:
  4/min, 500/day).
