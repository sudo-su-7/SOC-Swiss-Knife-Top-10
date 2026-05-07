"""Core data models for SOC-Swiss-Knife."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


def score_to_verdict(detections: int) -> Verdict:
    if detections >= 5:
        return Verdict.MALICIOUS
    if detections >= 1:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


@dataclass
class IOCResult:
    ioc: str
    ioc_type: str  # "ip" | "domain" | "url"
    vt_score: int = 0
    vt_total: int = 0
    vt_link: str = ""
    abuseipdb_score: int = 0
    verdict: Verdict = Verdict.UNKNOWN
    checked_at: datetime = field(default_factory=_now)
    error: str = ""


@dataclass
class HashResult:
    hash_value: str
    hash_type: str  # "md5" | "sha1" | "sha256"
    vt_score: int = 0
    vt_total: int = 0
    vt_link: str = ""
    mb_found: bool = False
    mb_tags: list[str] = field(default_factory=list)
    verdict: Verdict = Verdict.UNKNOWN
    checked_at: datetime = field(default_factory=_now)
    error: str = ""


class Severity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    CRITICAL = "CRITICAL"


@dataclass
class LogEvent:
    timestamp: str
    user: str
    source_ip: str
    action: str
    severity: Severity
    raw: str = ""


@dataclass
class LogReport:
    file: str
    events: list[LogEvent] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    analysed_at: datetime = field(default_factory=_now)
