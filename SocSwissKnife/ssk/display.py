"""Rich console display helpers."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from ssk.models import IOCResult, HashResult, LogReport, Verdict, Severity

console = Console()

_VERDICT_STYLE = {
    Verdict.CLEAN: "[bold green]✔ CLEAN[/]",
    Verdict.SUSPICIOUS: "[bold yellow]⚠ SUSPICIOUS[/]",
    Verdict.MALICIOUS: "[bold red]✖ MALICIOUS[/]",
    Verdict.UNKNOWN: "[dim]? UNKNOWN[/]",
}

_SEV_STYLE = {
    Severity.INFO: "[cyan]INFO[/]",
    Severity.WARN: "[yellow]WARN[/]",
    Severity.CRITICAL: "[bold red]CRITICAL[/]",
}


def show_ioc(r: IOCResult) -> None:
    verdict_str = _VERDICT_STYLE.get(r.verdict, str(r.verdict))
    abuse_str = f"{r.abuseipdb_score}%" if r.abuseipdb_score >= 0 else "n/a"

    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 1))
    table.add_column("Field", style="bold cyan", width=20)
    table.add_column("Value")

    table.add_row("IOC", r.ioc)
    table.add_row("Type", r.ioc_type)
    table.add_row("VT Detections", f"{r.vt_score}/{r.vt_total}")
    table.add_row("AbuseIPDB Score", abuse_str)
    table.add_row("Verdict", verdict_str)
    if r.vt_link:
        table.add_row("VT Link", f"[link={r.vt_link}]{r.vt_link}[/link]")
    if r.error:
        table.add_row("Error", f"[red]{r.error}[/]")

    console.print(Panel(table, title=f"[bold]IOC Lookup — {r.ioc}[/]"))


def show_hash(r: HashResult) -> None:
    verdict_str = _VERDICT_STYLE.get(r.verdict, str(r.verdict))
    mb_str = f"[red]YES[/] — {', '.join(r.mb_tags)}" if r.mb_found else "[green]not found[/]"

    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 1))
    table.add_column("Field", style="bold cyan", width=20)
    table.add_column("Value")

    table.add_row("Hash", r.hash_value)
    table.add_row("Type", r.hash_type.upper())
    table.add_row("VT Detections", f"{r.vt_score}/{r.vt_total}")
    table.add_row("MalwareBazaar", mb_str)
    table.add_row("Verdict", verdict_str)
    if r.vt_link:
        table.add_row("VT Link", f"[link={r.vt_link}]{r.vt_link}[/link]")
    if r.error:
        table.add_row("Error", f"[red]{r.error}[/]")

    console.print(Panel(table, title=f"[bold]Hash Check — {r.hash_value[:16]}…[/]"))


def show_log_report(report: LogReport) -> None:
    s = report.summary

    if s.get("error"):
        console.print(f"[red]Error:[/] {s['error']}")
        return

    # Summary panel
    sev = s.get("severity_breakdown", {})
    summary_lines = [
        f"File: [bold]{report.file}[/]",
        f"Total events: [bold]{s.get('total_events', 0)}[/]",
        f"CRITICAL: [bold red]{sev.get('CRITICAL', 0)}[/]  "
        f"WARN: [bold yellow]{sev.get('WARN', 0)}[/]  "
        f"INFO: [cyan]{sev.get('INFO', 0)}[/]",
    ]
    if s.get("top_source_ips"):
        top = ", ".join(f"{ip}({c})" for ip, c in s["top_source_ips"].items())
        summary_lines.append(f"Top IPs: {top}")

    console.print(Panel("\n".join(summary_lines), title="[bold]Log Analysis Summary[/]"))

    if not report.events:
        console.print("[dim]No anomalies detected.[/]")
        return

    # Events table — show CRITICAL first, then WARN, then INFO
    table = Table(box=box.SIMPLE_HEAD, show_lines=False)
    table.add_column("Time", style="dim", width=16)
    table.add_column("Severity", width=10)
    table.add_column("User", width=14)
    table.add_column("Source IP", width=16)
    table.add_column("Action")

    sorted_events = sorted(
        report.events,
        key=lambda e: ["CRITICAL", "WARN", "INFO"].index(e.severity.value),
    )

    for e in sorted_events[:200]:  # cap display at 200 rows
        table.add_row(
            e.timestamp,
            _SEV_STYLE[e.severity],
            e.user or "—",
            e.source_ip or "—",
            e.action,
        )

    console.print(table)
    if len(report.events) > 200:
        console.print(f"[dim]… {len(report.events) - 200} more events not shown[/]")
