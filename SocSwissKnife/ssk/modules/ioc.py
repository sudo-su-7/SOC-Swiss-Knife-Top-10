"""IOC lookup: IP, domain, URL via VirusTotal and AbuseIPDB."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import quote

import httpx

from ssk.config import get_abuseipdb_key, get_vt_key
from ssk.models import IOCResult, Verdict, score_to_verdict

_VT_BASE = "https://www.virustotal.com/api/v3"
_ABUSE_BASE = "https://api.abuseipdb.com/api/v2"

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(r"^(?!https?://)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def classify_ioc(ioc: str) -> str:
    if _IP_RE.match(ioc):
        return "ip"
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    if _DOMAIN_RE.match(ioc):
        return "domain"
    return "unknown"


def _vt_headers() -> dict:
    return {"x-apikey": get_vt_key()}


def _vt_url_for(ioc: str, ioc_type: str) -> str:
    if ioc_type == "ip":
        return f"{_VT_BASE}/ip_addresses/{ioc}"
    if ioc_type == "domain":
        return f"{_VT_BASE}/domains/{ioc}"
    # URL — VT requires base64url-encoded ID without padding
    import base64
    url_id = base64.urlsafe_b64encode(ioc.encode()).rstrip(b"=").decode()
    return f"{_VT_BASE}/urls/{url_id}"


def _parse_vt(data: dict) -> tuple[int, int, str]:
    """Return (malicious_count, total_engines, gui_link)."""
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0
    ioc_id = data.get("data", {}).get("id", "")
    link = f"https://www.virustotal.com/gui/search/{ioc_id}"
    return malicious, total, link


def _check_abuseipdb(ip: str) -> int:
    """Return abuse confidence score (0-100)."""
    try:
        resp = httpx.get(
            f"{_ABUSE_BASE}/check",
            headers={"Key": get_abuseipdb_key(), "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("data", {}).get("abuseConfidenceScore", 0)
    except Exception:
        return -1  # -1 = could not fetch


def lookup(ioc: str) -> IOCResult:
    """Look up a single IOC and return an IOCResult."""
    ioc = ioc.strip()
    ioc_type = classify_ioc(ioc)
    result = IOCResult(ioc=ioc, ioc_type=ioc_type)

    if ioc_type == "unknown":
        result.error = "Cannot classify IOC — not a valid IP, domain, or URL"
        result.verdict = Verdict.UNKNOWN
        return result

    # VirusTotal
    try:
        resp = httpx.get(_vt_url_for(ioc, ioc_type), headers=_vt_headers(), timeout=15)
        resp.raise_for_status()
        result.vt_score, result.vt_total, result.vt_link = _parse_vt(resp.json())
    except httpx.HTTPStatusError as e:
        result.error = f"VT HTTP {e.response.status_code}"
    except Exception as e:
        result.error = str(e)

    # AbuseIPDB — only for IPs
    if ioc_type == "ip":
        result.abuseipdb_score = _check_abuseipdb(ioc)

    # Verdict: VT is authoritative; AbuseIPDB can upgrade to SUSPICIOUS
    result.verdict = score_to_verdict(result.vt_score)
    if result.verdict == Verdict.CLEAN and result.abuseipdb_score >= 25:
        result.verdict = Verdict.SUSPICIOUS

    return result
