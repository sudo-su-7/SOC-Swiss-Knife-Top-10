"""File hash reputation via VirusTotal and MalwareBazaar."""
from __future__ import annotations

import re

import httpx

from ssk.config import get_vt_key
from ssk.models import HashResult, Verdict, score_to_verdict

_VT_BASE = "https://www.virustotal.com/api/v3"
_MB_URL = "https://mb-api.abuse.ch/api/v1/"

_HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}


def classify_hash(h: str) -> str:
    for hash_type, pattern in _HASH_PATTERNS.items():
        if pattern.match(h):
            return hash_type
    return "unknown"


def _vt_check(hash_value: str) -> tuple[int, int, str]:
    resp = httpx.get(
        f"{_VT_BASE}/files/{hash_value}",
        headers={"x-apikey": get_vt_key()},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0
    link = f"https://www.virustotal.com/gui/file/{hash_value}"
    return malicious, total, link


def _mb_check(hash_value: str) -> tuple[bool, list[str]]:
    """Query MalwareBazaar. Returns (found, tags)."""
    resp = httpx.post(
        _MB_URL,
        data={"query": "get_info", "hash": hash_value},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("query_status") != "ok":
        return False, []
    tags = data.get("data", [{}])[0].get("tags") or []
    return True, tags


def check(hash_value: str) -> HashResult:
    hash_value = hash_value.strip().lower()
    hash_type = classify_hash(hash_value)
    result = HashResult(hash_value=hash_value, hash_type=hash_type)

    if hash_type == "unknown":
        result.error = "Unrecognised hash format (expected MD5/SHA1/SHA256)"
        result.verdict = Verdict.UNKNOWN
        return result

    # VirusTotal
    try:
        result.vt_score, result.vt_total, result.vt_link = _vt_check(hash_value)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            result.error = "Not found in VirusTotal"
        else:
            result.error = f"VT HTTP {e.response.status_code}"
    except Exception as e:
        result.error = str(e)

    # MalwareBazaar
    try:
        result.mb_found, result.mb_tags = _mb_check(hash_value)
    except Exception:
        pass  # MB is supplementary — don't fail the whole check

    # Verdict
    result.verdict = score_to_verdict(result.vt_score)
    if result.verdict == Verdict.CLEAN and result.mb_found:
        result.verdict = Verdict.SUSPICIOUS

    return result
