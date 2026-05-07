"""Load and validate environment configuration."""
from __future__ import annotations

import os
from dotenv import load_dotenv

load_dotenv()


def get_vt_key() -> str:
    key = os.getenv("VT_API_KEY", "")
    if not key:
        raise EnvironmentError("VT_API_KEY not set. Add it to .env or export it.")
    return key


def get_abuseipdb_key() -> str:
    key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not key:
        raise EnvironmentError("ABUSEIPDB_API_KEY not set. Add it to .env or export it.")
    return key
