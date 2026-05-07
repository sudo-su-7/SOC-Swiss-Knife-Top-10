# ⚔ SOC-Swiss-Knife

> A SOC analyst's toolkit in a single Docker container — IOC lookup, file hash checking, and log analysis with a rich CLI and optional web dashboard.

![Python](https://img.shields.io/badge/Python-3.11+-blue) ![Docker](https://img.shields.io/badge/Docker-ready-2496ED) ![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

| Tool | What it does |
|------|-------------|
| **IOC Lookup** | Checks IPs, domains, and URLs against VirusTotal + AbuseIPDB |
| **Hash Checker** | MD5/SHA1/SHA256 reputation via VirusTotal + MalwareBazaar |
| **Log Analyser** | Parses `auth.log`/`syslog` — flags brute force, sudo abuse, unknown users |

---

## Quick Start

### Docker (recommended)

```bash
# 1. Clone
git clone https://github.com/sudo-su-7/SOC-Swiss-Knife-Top-10
cd SOC-Swiss-Knife-Top-10

# 2. Configure API keys
cp .env.example .env
# Edit .env — add your VT_API_KEY and ABUSEIPDB_API_KEY

# 3. Run web dashboard
docker compose up --build
# Open http://localhost:8000
```

### CLI via Docker

```bash
# IOC lookup
docker compose run --rm ssk ssk ioc 8.8.8.8 malicious-domain.com

# Hash check
docker compose run --rm ssk ssk hash d41d8cd98f00b204e9800998ecf8427e

# Log analysis (mount your log file)
docker compose run --rm -v /var/log/auth.log:/tmp/auth.log ssk ssk logs /tmp/auth.log
```

### Local install

```bash
pip install -e .
cp .env.example .env  # fill in keys
ssk --help
```

---

## CLI Usage

```
ssk ioc <IP|domain|URL> [...]     # IOC reputation lookup
ssk hash <MD5|SHA1|SHA256> [...]  # File hash reputation
ssk logs <path/to/auth.log>       # Log file analysis
ssk web [--host 0.0.0.0] [--port 8000]  # Launch web dashboard
```

---

## API Keys

| Key | Source | Free tier |
|-----|--------|-----------|
| `VT_API_KEY` | [virustotal.com](https://www.virustotal.com) | ✅ 4 req/min |
| `ABUSEIPDB_API_KEY` | [abuseipdb.com](https://www.abuseipdb.com) | ✅ 1000 req/day |

MalwareBazaar requires no API key.

---

## Log Detection Rules

| Pattern | Severity |
|---------|----------|
| Failed SSH password | WARN |
| Unknown user login attempt | WARN |
| ≥ 10 failures from same IP | **CRITICAL** |
| Sudo authentication failure | **CRITICAL** |
| Successful SSH login | INFO |
| BREAK-IN ATTEMPT | **CRITICAL** |

---

## Project Structure

```
ssk/
├── cli.py              # Typer CLI entry point
├── models.py           # IOCResult, HashResult, LogReport
├── config.py           # Env var loading
├── display.py          # Rich terminal output
├── modules/
│   ├── ioc.py          # VirusTotal + AbuseIPDB
│   ├── hash_check.py   # VirusTotal + MalwareBazaar
│   └── log_analyser.py # auth.log / syslog parser
└── web/
    ├── app.py          # FastAPI application
    └── templates/      # Jinja2 HTML dashboard
```

---

## Author

**Daniel Mutuma** — Junior Cybersecurity Analyst @ Infonex Solutions
[github.com/sudo-su-7](https://github.com/sudo-su-7)
