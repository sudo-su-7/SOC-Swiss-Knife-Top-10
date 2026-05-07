"""Unit tests for models and classifiers — no network required."""
import pytest
from ssk.models import score_to_verdict, Verdict
from ssk.modules.ioc import classify_ioc
from ssk.modules.hash_check import classify_hash
from ssk.modules.log_analyser import analyse
from pathlib import Path
import tempfile, textwrap


def test_verdict_thresholds():
    assert score_to_verdict(0) == Verdict.CLEAN
    assert score_to_verdict(1) == Verdict.SUSPICIOUS
    assert score_to_verdict(4) == Verdict.SUSPICIOUS
    assert score_to_verdict(5) == Verdict.MALICIOUS
    assert score_to_verdict(99) == Verdict.MALICIOUS


def test_classify_ioc():
    assert classify_ioc("8.8.8.8") == "ip"
    assert classify_ioc("192.168.1.1") == "ip"
    assert classify_ioc("google.com") == "domain"
    assert classify_ioc("sub.example.co.uk") == "domain"
    assert classify_ioc("https://evil.com/payload") == "url"
    assert classify_ioc("http://x.com") == "url"
    assert classify_ioc("notvalid") == "unknown"


def test_classify_hash():
    assert classify_hash("d" * 32) == "md5"
    assert classify_hash("a" * 40) == "sha1"
    assert classify_hash("b" * 64) == "sha256"
    assert classify_hash("short") == "unknown"
    assert classify_hash("D" * 32) == "md5"          # case-insensitive


def test_log_analyser_brute_force():
    """Ten failed passwords from same IP → CRITICAL."""
    lines = []
    for i in range(10):
        lines.append(
            f"May  7 10:0{i}:00 host sshd[{1000+i}]: "
            f"Failed password for root from 1.2.3.4 port 4444{i} ssh2"
        )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("\n".join(lines))
        tmp = f.name

    report = analyse(tmp)
    criticals = [e for e in report.events if e.severity.value == "CRITICAL"]
    assert len(criticals) == 10
    assert report.summary["severity_breakdown"]["CRITICAL"] == 10
    Path(tmp).unlink()


def test_log_analyser_successful_login():
    line = "May  7 11:00:00 host sshd[999]: Accepted password for daniel from 10.0.0.5 port 22 ssh2"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(line)
        tmp = f.name

    report = analyse(tmp)
    assert len(report.events) == 1
    assert report.events[0].user == "daniel"
    assert report.events[0].source_ip == "10.0.0.5"
    Path(tmp).unlink()


def test_log_analyser_missing_file():
    report = analyse("/nonexistent/path/auth.log")
    assert "error" in report.summary


def test_log_analyser_empty_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("")
        tmp = f.name
    report = analyse(tmp)
    assert report.summary["total_events"] == 0
    Path(tmp).unlink()
