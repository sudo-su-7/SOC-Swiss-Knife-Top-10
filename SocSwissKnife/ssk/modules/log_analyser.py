"""Parse auth.log / syslog and flag anomalies."""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from ssk.models import LogEvent, LogReport, Severity

# Pattern: standard syslog/auth.log prefix
_SYSLOG_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+[\d:]+)\s+\S+\s+(?P<proc>\S+):\s+(?P<msg>.+)"
)

# Anomaly detection patterns
_RULES: list[tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"),
     "SSH brute force / failed password", Severity.WARN),
    (re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"),
     "Login attempt with unknown user", Severity.WARN),
    (re.compile(r"sudo:.*USER=(?P<user>\S+).*COMMAND=(?P<cmd>.+)"),
     "Sudo command executed", Severity.INFO),
    (re.compile(r"sudo:.*authentication failure.*user=(?P<user>\S+)"),
     "Sudo authentication failure", Severity.CRITICAL),
    (re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"),
     "Successful SSH login", Severity.INFO),
    (re.compile(r"session opened for user (?P<user>\S+)"),
     "Session opened", Severity.INFO),
    (re.compile(r"BREAK-IN ATTEMPT"),
     "Break-in attempt detected", Severity.CRITICAL),
]


def _extract_fields(msg: str, pattern: re.Pattern) -> tuple[str, str]:
    m = pattern.search(msg)
    if not m:
        return "", ""
    user = m.groupdict().get("user", "") or m.groupdict().get("cmd", "")
    ip = m.groupdict().get("ip", "")
    return user, ip


def _brute_force_upgrade(events: list[LogEvent]) -> list[LogEvent]:
    """Upgrade WARN→CRITICAL for IPs with ≥10 failed password attempts."""
    fail_counts: Counter = Counter(
        e.source_ip for e in events
        if e.severity == Severity.WARN and "brute force" in e.action
    )
    upgraded = set(ip for ip, count in fail_counts.items() if count >= 10)
    for e in events:
        if e.source_ip in upgraded and "brute force" in e.action:
            e.severity = Severity.CRITICAL
    return events


def analyse(log_path: str) -> LogReport:
    path = Path(log_path)
    report = LogReport(file=str(path))

    if not path.exists():
        report.summary["error"] = f"File not found: {log_path}"
        return report

    events: list[LogEvent] = []

    with path.open(errors="replace") as f:
        for raw_line in f:
            raw_line = raw_line.strip()
            m = _SYSLOG_RE.match(raw_line)
            if not m:
                continue
            ts = m.group("ts")
            msg = m.group("msg")

            for pattern, action_label, severity in _RULES:
                if pattern.search(msg):
                    user, ip = _extract_fields(msg, pattern)
                    events.append(LogEvent(
                        timestamp=ts,
                        user=user,
                        source_ip=ip,
                        action=action_label,
                        severity=severity,
                        raw=raw_line,
                    ))
                    break  # first matching rule wins

    events = _brute_force_upgrade(events)
    report.events = events

    # Summary
    sev_counts = Counter(e.severity.value for e in events)
    top_ips = Counter(e.source_ip for e in events if e.source_ip).most_common(5)
    top_users = Counter(e.user for e in events if e.user).most_common(5)

    report.summary = {
        "total_events": len(events),
        "severity_breakdown": dict(sev_counts),
        "top_source_ips": dict(top_ips),
        "top_users": dict(top_users),
    }
    return report
