"""SOC-Swiss-Knife CLI."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from ssk.display import console, show_hash, show_ioc, show_log_report
from ssk.modules import hash_check, ioc, log_analyser

app = typer.Typer(
    name="ssk",
    help="[bold cyan]SOC-Swiss-Knife[/] — IOC lookup · Hash checker · Log analyser",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


@app.command("ioc")
def cmd_ioc(
    indicators: list[str] = typer.Argument(..., help="IP(s), domain(s), or URL(s) to check"),
):
    """Look up one or more IOCs against VirusTotal and AbuseIPDB."""
    for indicator in indicators:
        with console.status(f"Checking {indicator}…"):
            result = ioc.lookup(indicator)
        show_ioc(result)


@app.command("hash")
def cmd_hash(
    hashes: list[str] = typer.Argument(..., help="MD5/SHA1/SHA256 hash(es) to check"),
):
    """Check file hash(es) against VirusTotal and MalwareBazaar."""
    for h in hashes:
        with console.status(f"Checking {h[:16]}…"):
            result = hash_check.check(h)
        show_hash(result)


@app.command("logs")
def cmd_logs(
    log_file: Path = typer.Argument(..., help="Path to auth.log or syslog"),
):
    """Analyse a log file for brute force, sudo abuse, and anomalies."""
    with console.status(f"Analysing {log_file}…"):
        report = log_analyser.analyse(str(log_file))
    show_log_report(report)


@app.command("web")
def cmd_web(
    host: str = typer.Option("0.0.0.0", help="Bind host"),
    port: int = typer.Option(8000, help="Bind port"),
):
    """Launch the web dashboard."""
    try:
        import uvicorn
        from ssk.web.app import create_app
        console.print(f"[bold cyan]SOC-Swiss-Knife[/] web dashboard → http://{host}:{port}")
        uvicorn.run(create_app(), host=host, port=port)
    except ImportError:
        console.print("[red]uvicorn not installed. Run: pip install uvicorn[/]")
        raise typer.Exit(1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
