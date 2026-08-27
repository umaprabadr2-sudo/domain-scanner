"""
Domain Security & Reputation Scanner
Endpoints:
  /scan/whois       - domain registration age
  /scan/headers     - security header check
  /scan/reputation  - AbuseIPDB + VirusTotal reputation
  /scan/full        - runs all three and returns one combined risk score
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
import whois
import requests
import socket
import os
from dotenv import load_dotenv

load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

app = FastAPI(title="Domain Security Scanner", version="0.2.0")

# Allow the frontend (opened as a local file, or a local dev server) to call
# this API. Wide open here since this only runs on your own machine for now -
# if you ever deploy this publicly, replace "*" with your actual frontend URL.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"status": "ok", "message": "Domain Security Scanner API is running"}


# ---------------------------------------------------------------------------
# Core check logic - plain functions so /scan/full can call them directly
# ---------------------------------------------------------------------------

def _whois_check(domain: str) -> dict:
    """Looks up WHOIS registration data and computes domain age in days."""
    try:
        w = whois.whois(domain)
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}

    creation_date = w.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    if not creation_date:
        return {
            "creation_date": None,
            "age_days": None,
            "note": "Could not determine creation date for this domain",
        }

    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=timezone.utc)

    age_days = (datetime.now(timezone.utc) - creation_date).days

    return {
        "registrar": w.registrar,
        "creation_date": creation_date.isoformat(),
        "age_days": age_days,
        "flag_new_domain": age_days < 30,
    }


CHECKED_HEADERS = {
    "Strict-Transport-Security": "Forces browsers to use HTTPS, preventing downgrade attacks",
    "Content-Security-Policy": "Restricts what scripts/resources can load, mitigating XSS",
    "X-Frame-Options": "Prevents clickjacking by blocking the site from being iframed",
    "X-Content-Type-Options": "Stops browsers from MIME-sniffing, reducing drive-by download risk",
    "Referrer-Policy": "Controls how much referrer info leaks to other sites",
}


def _headers_check(domain: str) -> dict:
    """Fetches the site over HTTPS and checks which security headers are present."""
    url = f"https://{domain}"
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
    except requests.exceptions.SSLError:
        return {"error": "HTTPS connection failed (invalid/missing SSL cert)"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Could not reach {url}: {e}"}

    results = {}
    present_count = 0
    for header, reason in CHECKED_HEADERS.items():
        is_present = header in resp.headers
        if is_present:
            present_count += 1
        results[header] = {
            "present": is_present,
            "value": resp.headers.get(header),
            "why_it_matters": reason,
        }

    return {
        "final_url": resp.url,
        "headers_checked": len(CHECKED_HEADERS),
        "headers_present": present_count,
        "details": results,
    }


def _reputation_check(domain: str) -> dict:
    """Resolves domain -> IP, then checks AbuseIPDB and VirusTotal."""
    if not ABUSEIPDB_API_KEY or not VIRUSTOTAL_API_KEY:
        return {"error": "API keys not configured in .env"}

    try:
        ip_address = socket.gethostbyname(domain)
    except socket.gaierror:
        return {"error": f"Could not resolve domain: {domain}"}

    result = {"resolved_ip": ip_address}

    try:
        abuse_resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip_address, "maxAgeInDays": 90},
            timeout=10,
        )
        abuse_data = abuse_resp.json().get("data", {})
        result["abuseipdb"] = {
            "abuse_confidence_score": abuse_data.get("abuseConfidenceScore"),
            "total_reports": abuse_data.get("totalReports"),
            "isp": abuse_data.get("isp"),
            "country": abuse_data.get("countryCode"),
        }
    except Exception as e:
        result["abuseipdb"] = {"error": str(e)}

    try:
        vt_resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10,
        )
        vt_data = vt_resp.json().get("data", {}).get("attributes", {})
        stats = vt_data.get("last_analysis_stats", {})
        result["virustotal"] = {
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "harmless_votes": stats.get("harmless", 0),
            "reputation_score": vt_data.get("reputation"),
        }
    except Exception as e:
        result["virustotal"] = {"error": str(e)}

    return result


# ---------------------------------------------------------------------------
# Individual endpoints (unchanged behavior, now backed by the shared functions)
# ---------------------------------------------------------------------------

@app.get("/scan/whois")
def scan_whois(domain: str = Query(..., description="Domain to look up, e.g. example.com")):
    data = _whois_check(domain)
    if "error" in data:
        raise HTTPException(status_code=502, detail=data["error"])
    return {"domain": domain, **data}


@app.get("/scan/headers")
def scan_headers(domain: str = Query(..., description="Domain to check, e.g. example.com")):
    data = _headers_check(domain)
    if "error" in data:
        raise HTTPException(status_code=502, detail=data["error"])
    return {"domain": domain, **data}


@app.get("/scan/reputation")
def scan_reputation(domain: str = Query(..., description="Domain to check, e.g. example.com")):
    data = _reputation_check(domain)
    if "error" in data:
        raise HTTPException(status_code=500 if "not configured" in data["error"] else 502, detail=data["error"])
    return {"domain": domain, **data}


# ---------------------------------------------------------------------------
# Combined scoring endpoint
# ---------------------------------------------------------------------------

def _compute_score(whois_data: dict, headers_data: dict, reputation_data: dict) -> dict:
    """
    Starts at 100 and deducts points for each risk signal found.
    This scoring logic is intentionally simple and documented -
    it's meant to be defensible in an interview, not a black box.
    """
    score = 100
    reasons = []

    # WHOIS signal: newly registered domain (-20)
    if whois_data.get("flag_new_domain"):
        score -= 20
        reasons.append(f"Domain registered only {whois_data.get('age_days')} days ago (-20)")
    elif whois_data.get("age_days") is None:
        score -= 5
        reasons.append("Could not verify domain age (-5)")

    # Headers signal: -6 points per missing recommended header (5 headers max = -30)
    if "details" in headers_data:
        missing = headers_data["headers_checked"] - headers_data["headers_present"]
        deduction = missing * 6
        score -= deduction
        if missing > 0:
            reasons.append(f"{missing} of {headers_data['headers_checked']} security headers missing (-{deduction})")
    else:
        score -= 10
        reasons.append("Could not check security headers (-10)")

    # Reputation signal: AbuseIPDB confidence score contributes directly (-up to 30)
    abuse = reputation_data.get("abuseipdb", {})
    abuse_score = abuse.get("abuse_confidence_score")
    if isinstance(abuse_score, (int, float)) and abuse_score > 0:
        deduction = min(30, round(abuse_score * 0.3))
        score -= deduction
        reasons.append(f"AbuseIPDB confidence score {abuse_score}% (-{deduction})")

    # Reputation signal: VirusTotal malicious votes (-10 per vendor flag, up to 20)
    vt = reputation_data.get("virustotal", {})
    malicious_votes = vt.get("malicious_votes", 0)
    if malicious_votes:
        deduction = min(20, malicious_votes * 10)
        score -= deduction
        reasons.append(f"{malicious_votes} security vendor(s) flagged this domain as malicious (-{deduction})")

    score = max(0, min(100, score))

    if score >= 80:
        risk_level = "Low"
    elif score >= 50:
        risk_level = "Medium"
    else:
        risk_level = "High"

    return {"score": score, "risk_level": risk_level, "reasons": reasons}


@app.get("/scan/full")
def scan_full(domain: str = Query(..., description="Domain to scan, e.g. example.com")):
    """
    Runs the WHOIS, headers, and reputation checks together and returns
    one combined risk score with a plain-English breakdown of why.
    """
    whois_data = _whois_check(domain)
    headers_data = _headers_check(domain)
    reputation_data = _reputation_check(domain)

    scoring = _compute_score(whois_data, headers_data, reputation_data)

    return {
        "domain": domain,
        "score": scoring["score"],
        "risk_level": scoring["risk_level"],
        "reasons": scoring["reasons"],
        "details": {
            "whois": whois_data,
            "headers": headers_data,
            "reputation": reputation_data,
        },
    }